//! File-backed exporter. See [`FileExporter`].

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use varta_vlp::Status;

use crate::config::MIN_EXPORT_FILE_MAX_BYTES;
use crate::observer::Event;

/// Sink for an [`Event`] stream.
///
/// `varta-watch` runs the observer poll loop, event recording, recovery
/// reaping, and the `/metrics` HTTP server on a single thread. Every
/// method on this trait executes inside that thread's per-tick budget.
/// Implementations MAY perform synchronous I/O — both shipped exporters
/// do — but MUST respect a hard wall-clock bound so the beat pipeline
/// cannot stall behind a slow disk or a slow scrape client:
///
/// - [`FileExporter::record`] performs a synchronous `write(2)` into a
///   `BufWriter<File>`. With `--export-file-sync-every <N>`, every Nth
///   record adds an `fdatasync(2)`. Latency is bounded by disk and
///   `fdatasync` cost; operators on slow / contended disks should keep
///   the event file on a dedicated volume.
/// - [`PromExporter::serve_pending`] accepts and serves up to
///   `PROM_MAX_CONNECTIONS_PER_SERVE` TCP connections per call, gated by
///   `PROM_SERVE_DEADLINE` (≈100 ms accept + 100 ms drain) and per
///   connection `PROM_READ_DEADLINE` (10 ms) / `PROM_WRITE_TIMEOUT`
///   (50 ms). See `book/src/architecture/observer-liveness.md`
///   §"Why /metrics is on the poll thread".
///
/// Implementations MUST NOT panic. Transient I/O failures are returned
/// as `Err` so the caller can log, retry, or fall back.
pub trait Exporter {
    /// Record a single observer event. May perform synchronous I/O bounded
    /// by the per-implementation budget documented on the trait. Errors are
    /// returned as `Err`, never panicked.
    fn record(&mut self, ev: &Event) -> io::Result<()>;
    /// Flush any internally buffered output. For network exporters that
    /// hold no per-event buffer this is a no-op that returns `Ok(())`.
    /// File-backed exporters flush the `BufWriter` to the kernel; the
    /// per-record `fdatasync` cadence is controlled separately by
    /// `--export-file-sync-every`.
    fn flush(&mut self) -> io::Result<()>;
}

/// File-backed exporter. Appends one line per event in the schema:
///
/// ```text
/// <observer_ns>\t<kind>\t<pid>\t<nonce>\t<status>\t<payload>\n
/// ```
///
/// `kind` ∈ `{beat, stall, decode, io, mismatch}`. For `decode`, `io`, and
/// `mismatch` events the pid / nonce / status / payload columns are written
/// as `-` so the line count and column count remain stable. Text payloads are
/// backslash-escaped (`\t`, `\n`, `\r`, `\\`, and `\xNN` for other ASCII
/// control bytes) before they are written into the final field.
///
/// `observer_ns` is the observer-local nanosecond timestamp carried by every
/// [`Event`], captured at observer poll time. All exporters sharing an event
/// stream see the same timestamps.
///
/// When `max_bytes` is set, the exporter rotates the file after every write
/// that pushes the size over the limit. Rotation shifts `PATH` → `PATH.1`,
/// `PATH.1` → `PATH.2`, …, up to 5 generations, then re-opens `PATH` in
/// append mode. Without `max_bytes` the file grows unbounded.
///
/// The live path must resolve to a readable and writable regular file owned by
/// the observer with exactly one hard link. Leaf symlinks and multiply-linked
/// files are rejected before any event data is written.
pub struct FileExporter {
    sink: BufWriter<File>,
    pending_err: Option<io::Error>,
    path: PathBuf,
    max_bytes: Option<u64>,
    bytes_written: u64,
    /// Records between forced `fdatasync(2)` calls. `0` (default) means
    /// "no per-record sync"; the BufWriter is only flushed on clean
    /// shutdown and during rotation. Non-zero values trade IO for
    /// crash-time durability — operator sets via
    /// `--export-file-sync-every <N>`. Mirrors the audit log's
    /// `AuditConfig::sync_every` pattern.
    sync_every: u32,
    /// Records appended since the last successful `flush_and_sync`. Reset
    /// to 0 every time durability is forced. Counts every successful
    /// `writeln!` (beats, stalls, decode errors, IO errors, AuthFailures,
    /// evictions) and is checked at the bottom of `after_write`.
    writes_since_sync: u32,
    /// Set when a rotation renamed the live file to `.1` but could not recreate
    /// the live `PATH` (e.g. ENOSPC / EMFILE after the rename already
    /// succeeded). While set, [`Self::after_write`] retries ONLY the reopen and
    /// must NOT re-run [`Self::rotate`] — otherwise the stale sink fd (which now
    /// holds the rotated `.1` inode) would be carried down the generation chain
    /// on every record and deleted at the oldest generation, silently
    /// destroying the rotated content. Mirrors the audit log's
    /// retry-the-open-only rotation posture.
    rotation_reopen_pending: bool,
    /// Test-only override: when set, forces the live-file reopen to fail so the
    /// rename-succeeded-but-create-failed window can be exercised
    /// deterministically (no portable way to provoke real ENOSPC/EMFILE).
    #[cfg(test)]
    reopen_must_fail: bool,
    /// Test-only count of parent-directory fsync *attempts* (initial create
    /// plus each rotation). The durability regression test asserts the
    /// `fsync_parent_dir` sweep actually runs: reverting the fix drops this
    /// to zero and the test goes red. Mirrors the audit log exposing
    /// `fsync_durations` for the same purpose; absent from production builds.
    #[cfg(test)]
    dir_fsyncs: u32,
}

/// Number of rotated file generations kept.
const MAX_ROTATION_GENERATIONS: u32 = 5;

/// POSIX `EXDEV` ("cross-device link"). Used directly so the rotation fallback
/// remains compatible with Rust 1.70, where `ErrorKind::CrossesDevices` is not
/// available.
const EXDEV: i32 = 18;

impl FileExporter {
    /// Open `path` in append mode (creating it if necessary) and wrap it
    /// in a [`BufWriter`].
    ///
    /// `max_bytes` is the optional size limit after which the file is
    /// rotated. When set, it must be at least
    /// [`MIN_EXPORT_FILE_MAX_BYTES`]; use `None` for an unbounded file.
    ///
    /// `sync_every` is the number of records between forced `fdatasync(2)`
    /// calls. `0` disables per-record durability — the BufWriter is only
    /// flushed on clean shutdown and during rotation, matching the v0.1
    /// behavior. Non-zero values trade IO for crash-time durability
    /// (mirrors the audit log's `AuditConfig::sync_every`). Operators set
    /// this via `--export-file-sync-every <N>`.
    pub fn create(
        path: impl AsRef<Path>,
        max_bytes: Option<u64>,
        sync_every: u32,
    ) -> io::Result<Self> {
        validate_export_max_bytes(max_bytes)?;
        Self::create_unchecked(path.as_ref(), max_bytes, sync_every)
    }

    #[cfg(test)]
    fn create_unchecked_for_test(
        path: impl AsRef<Path>,
        max_bytes: Option<u64>,
        sync_every: u32,
    ) -> io::Result<Self> {
        Self::create_unchecked(path.as_ref(), max_bytes, sync_every)
    }

    fn create_unchecked(path: &Path, max_bytes: Option<u64>, sync_every: u32) -> io::Result<Self> {
        let file = open_or_create_export_file(path)?;
        let bytes_written = file.metadata()?.len();
        let mut exporter = FileExporter {
            sink: BufWriter::new(file),
            pending_err: None,
            path: path.to_path_buf(),
            max_bytes,
            bytes_written,
            sync_every,
            writes_since_sync: 0,
            rotation_reopen_pending: false,
            #[cfg(test)]
            reopen_must_fail: false,
            #[cfg(test)]
            dir_fsyncs: 0,
        };
        // A freshly-created export file's directory entry is not durable until
        // the parent directory is fsynced (`open_or_create` may have created
        // it). See [`Self::sync_parent_dir`].
        exporter.sync_parent_dir();
        Ok(exporter)
    }

    /// Make the export file's *directory entries* durable after a dirent
    /// mutation (initial create, or a rotation rename/create/unlink). Per
    /// `fsync(2)`, fsyncing the file *data* does not persist the entry that
    /// names it — only an explicit parent-directory fsync does. Without this,
    /// a power cut can lose a rotated generation (`PATH.1`), resurrect an
    /// unlinked live inode, or orphan the live file, even when the operator
    /// opted into durability via `--export-file-sync-every`. Failure is a soft
    /// degradation (some platforms reject directory fsync), latched into
    /// `pending_err` for the caller to surface — mirroring the audit log's
    /// create() and `SyncingDir` rotation stages (`audit/mod.rs`,
    /// `audit/rotation.rs`) and the UDS-bind posture. A single call covers
    /// every dirent change since the previous one (they share one directory).
    fn sync_parent_dir(&mut self) {
        #[cfg(test)]
        {
            self.dir_fsyncs = self.dir_fsyncs.saturating_add(1);
        }
        if let Err(e) = crate::file_security::fsync_parent_dir(&self.path) {
            self.remember_error(&e);
        }
    }

    /// Flush the `BufWriter` to the kernel and then `fdatasync(2)` the
    /// underlying file. Both must succeed for the data to be considered
    /// durable across a host-level crash. Mirrors the audit log's
    /// `flush_and_sync` (`audit.rs::flush_and_sync`).
    fn flush_and_sync(&mut self) -> io::Result<()> {
        self.sink.flush()?;
        self.sink.get_ref().sync_data()
    }

    /// Record an evicted pid line into the file export. This is called from
    /// the main loop when a tracker slot is reclaimed, so the operator has
    /// a per-pid trace of eviction events.
    pub fn record_eviction_pid(&mut self, pid: u32, observer_ns: u64) -> io::Result<()> {
        let result = writeln!(self.sink, "{observer_ns}\teviction\t{pid}\t-\t-\t-",);
        if let Err(e) = result {
            self.remember_error(&e);
            Err(e)
        } else {
            let line_len = decimal_digits(observer_ns) as u64
                + 1  // \t
                + 8  // "eviction"
                + 1  // \t
                + decimal_digits(pid as u64) as u64
                + 1  // \t
                + 1  // -
                + 1  // \t
                + 1  // -
                + 1  // \t
                + 1  // -
                + 1; // \n
            self.after_write(line_len)
        }
    }

    fn remember_error(&mut self, e: &io::Error) {
        self.pending_err = Some(io::Error::new(e.kind(), e.to_string()));
    }

    /// Called after every successful write. Drives optional per-record
    /// `fdatasync` (when `--export-file-sync-every` is set) and file
    /// rotation (when `--export-file-max-bytes` is set).
    fn after_write(&mut self, line_len: u64) -> io::Result<()> {
        let mut first_err = None;

        // Per-record durability: mirror `audit.rs::write_line`. When
        // disabled (sync_every == 0) the counter is never touched.
        if self.sync_every > 0 {
            self.writes_since_sync = self.writes_since_sync.saturating_add(1);
            if self.writes_since_sync >= self.sync_every {
                match self.flush_and_sync() {
                    Ok(()) => self.writes_since_sync = 0,
                    Err(e) => {
                        // Latch the error; rotation below still runs so
                        // we don't deadlock on a stuck sync.
                        self.remember_error(&e);
                        first_err = Some(e);
                    }
                }
            }
        }

        let Some(max) = self.max_bytes else {
            return match first_err {
                Some(e) => Err(e),
                None => Ok(()),
            };
        };
        // A prior rotation rotated the live file to `.1` but could not recreate
        // the live `PATH` (the sink still holds the `.1` inode and
        // `bytes_written >= max`). Retry ONLY the reopen — re-running rotate()
        // would carry the stale fd down `.1`→…→`.5` and delete it at the oldest
        // generation, silently destroying the rotated records.
        if self.rotation_reopen_pending {
            return match self.reopen_live() {
                Ok(()) => match first_err {
                    Some(e) => Err(e),
                    None => Ok(()),
                },
                Err(e) => Err(first_err.unwrap_or(e)),
            };
        }

        self.bytes_written = self.bytes_written.saturating_add(line_len);
        if self.bytes_written < max {
            return match first_err {
                Some(e) => Err(e),
                None => Ok(()),
            };
        }
        // Rotation needed.
        if let Err(e) = self.sink.flush() {
            self.remember_error(&e);
            return Err(first_err.unwrap_or(e));
        }
        if let Err(e) = self.rotate() {
            self.remember_error(&e);
            return Err(first_err.unwrap_or(e));
        }
        match self.reopen_live() {
            Ok(()) => match first_err {
                Some(e) => Err(e),
                None => Ok(()),
            },
            Err(e) => Err(first_err.unwrap_or(e)),
        }
    }

    /// (Re)create the live export file and re-point the sink at it.
    ///
    /// On success the rotation is complete: the byte/sync counters reset, the
    /// reopen-pending latch clears, and the parent directory is fsynced. On
    /// failure the OLD sink is left untouched — it still holds the already-
    /// rotated `.1` inode — and `rotation_reopen_pending` is SET so the next
    /// record retries the create WITHOUT re-running [`Self::rotate`]. Re-running
    /// rotate would migrate the stale fd's inode `.1`→…→`.5` and delete it at
    /// the oldest generation, silently destroying the rotated records (the bug
    /// this guard closes).
    fn reopen_live(&mut self) -> io::Result<()> {
        #[cfg(test)]
        if self.reopen_must_fail {
            let e = io::Error::new(io::ErrorKind::Other, "forced reopen failure (test)");
            return self.reopen_failed(e);
        }
        match create_new_export_file(&self.path) {
            Ok(file) => {
                self.sink = BufWriter::new(file);
                self.bytes_written = 0;
                self.writes_since_sync = 0;
                self.rotation_reopen_pending = false;
                // `rotate()` renamed `PATH`→`PATH.1` (or, on EXDEV, copied then
                // unlinked the live path) and we just created the new live
                // `PATH`; one parent-dir fsync makes every dirent of this
                // rotation durable. See [`Self::sync_parent_dir`].
                self.sync_parent_dir();
                Ok(())
            }
            Err(e) => self.reopen_failed(e),
        }
    }

    /// Handle a failed live-file recreate after [`Self::rotate`] has already
    /// committed its directory-entry mutation (`rename PATH`→`PATH.1`, or the
    /// `EXDEV` copy-then-unlink). The recreate is deferred to the next write via
    /// `rotation_reopen_pending`, but the rotation's dirent change has ALREADY
    /// happened — so fsync the parent directory now to make it durable. Without
    /// this, a power cut in the deferred-reopen window can orphan the
    /// freshly-rotated `PATH.1` (its data was `fdatasync`'d in `rotate` /
    /// `copy_live_to_first`, but the dirent naming it was not) and silently lose
    /// those records; the prior code returned here without any parent-dir fsync,
    /// leaving the rotation durable only once the *next* reopen happened to
    /// succeed. The next successful `reopen_live` fsyncs again for the new live
    /// dirent. `sync_parent_dir` is a soft latch (best-effort, never returns),
    /// so a platform that rejects directory fsync degrades gracefully; the
    /// recreate error `e` is remembered LAST so it stays the surfaced failure
    /// (`remember_error` is last-write-wins). Single chokepoint shared by the
    /// real create-failure arm and the `reopen_must_fail` test seam so the two
    /// cannot drift.
    fn reopen_failed(&mut self, e: io::Error) -> io::Result<()> {
        self.sync_parent_dir();
        self.remember_error(&e);
        self.rotation_reopen_pending = true;
        Err(e)
    }

    /// Rotate `path`: shift `path` → `path.1`, `path.1` → `path.2`, …
    /// up to [`MAX_ROTATION_GENERATIONS`]. The oldest generation is deleted.
    fn rotate(&mut self) -> io::Result<()> {
        let oldest = generation_path(&self.path, MAX_ROTATION_GENERATIONS);
        match std::fs::remove_file(&oldest) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        for gen in (1..MAX_ROTATION_GENERATIONS).rev() {
            let src = generation_path(&self.path, gen);
            let dst = generation_path(&self.path, gen + 1);
            match std::fs::rename(&src, &dst) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let first = generation_path(&self.path, 1);
        match std::fs::rename(&self.path, &first) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) if is_cross_device_error(&e) => {
                self.copy_live_to_first(&first)?;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Copy the live generation through the writer's owned descriptor.
    ///
    /// This is the `EXDEV` fallback for unusual mount layouts where the live
    /// leaf and its `.1` sibling cannot be renamed atomically. The destination
    /// is exclusively created and synced before the live pathname is removed.
    fn copy_live_to_first(&mut self, first: &Path) -> io::Result<()> {
        let mut source = self.sink.get_ref().try_clone()?;
        source.seek(SeekFrom::Start(0))?;

        let mut destination = create_new_export_file(first)?;
        let mut destination_guard = CreatedPathGuard::new(first, &destination)?;
        io::copy(&mut source, &mut destination)?;
        destination.sync_data()?;
        std::fs::remove_file(&self.path)?;
        destination_guard.disarm();
        Ok(())
    }
}

fn validate_export_max_bytes(max_bytes: Option<u64>) -> io::Result<()> {
    let Some(max_bytes) = max_bytes else {
        return Ok(());
    };
    if max_bytes >= MIN_EXPORT_FILE_MAX_BYTES {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "export file max_bytes must be >= {MIN_EXPORT_FILE_MAX_BYTES} bytes; \
             omit max_bytes to disable rotation"
        ),
    ))
}

fn is_cross_device_error(e: &io::Error) -> bool {
    e.raw_os_error() == Some(EXDEV)
}

fn generation_path(path: &Path, generation: u32) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{generation}"));
    PathBuf::from(value)
}

fn open_or_create_export_file(path: &Path) -> io::Result<File> {
    match create_new_export_file(path) {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => open_existing_export_file(path),
        Err(e) => Err(e),
    }
}

fn create_new_export_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.read(true).append(true).create_new(true).mode(0o600);
    let file = crate::file_security::open_nofollow(path, &mut options)?;
    let mut created_guard = CreatedPathGuard::new(path, &file)?;
    validate_export_file(&file, path)?;
    created_guard.disarm();
    Ok(file)
}

fn open_existing_export_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).append(true);
    let file = crate::file_security::open_nofollow(path, &mut options)?;
    validate_export_file(&file, path)?;
    Ok(file)
}

fn validate_export_file(file: &File, path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let meta = crate::file_security::validate_regular_file(file, path)?;
    if meta.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{}: export file must have exactly one hard link",
                path.display()
            ),
        ));
    }
    Ok(())
}

struct CreatedPathGuard {
    path: PathBuf,
    dev: u64,
    ino: u64,
    armed: bool,
}

impl CreatedPathGuard {
    fn new(path: &Path, file: &File) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let meta = file.metadata()?;
        Ok(Self {
            path: path.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
            armed: true,
        })
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CreatedPathGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;

        if !self.armed {
            return;
        }
        match std::fs::symlink_metadata(&self.path) {
            Ok(meta) if meta.dev() == self.dev && meta.ino() == self.ino => {
                let _ = std::fs::remove_file(&self.path);
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) => {}
            Err(_) => {}
        }
    }
}

impl Exporter for FileExporter {
    fn record(&mut self, ev: &Event) -> io::Result<()> {
        let mut escaped_line_len = None;
        let line_len: u64 = match ev {
            Event::Beat {
                pid,
                status,
                payload,
                nonce,
                observer_ns,
                origin: _,
                pid_ns_inode: _,
            } => {
                let label = status_label(*status);
                decimal_digits(*observer_ns) as u64
                    + 1  // \t
                    + 4  // "beat"
                    + 1  // \t
                    + decimal_digits(*pid as u64) as u64
                    + 1  // \t
                    + decimal_digits(*nonce) as u64
                    + 1  // \t
                    + label.len() as u64
                    + 1  // \t
                    + decimal_digits(*payload as u64) as u64
                    + 1 // \n
            }
            Event::Stall {
                pid,
                last_nonce,
                observer_ns,
                ..
            } => {
                decimal_digits(*observer_ns) as u64
                + 1  // \t
                + 5  // "stall"
                + 1  // \t
                + decimal_digits(*pid as u64) as u64
                + 1  // \t
                + decimal_digits(*last_nonce) as u64
                + 1  // \t
                + 5  // "stall"
                + 1  // \t
                + 1  // "-"
                + 1
            } // \n
            // Error events with variable-length messages: compute exact
            // length after the write below rather than using a fixed
            // estimate (prevents file-rotation timing drift).
            Event::Decode(_, _)
            | Event::Io(_, _)
            | Event::CtrlTruncated(_, _)
            | Event::OriginConflict { .. }
            | Event::NamespaceConflict { .. } => 0,
            Event::AuthFailure {
                claimed_pid,
                observer_ns,
            } => {
                decimal_digits(*observer_ns) as u64
                + 1  // \t
                + 8  // "mismatch"
                + 1  // \t
                + decimal_digits(*claimed_pid as u64) as u64
                + 1  // \t
                + 1  // "-"
                + 1  // \t
                + 1  // "-"
                + 1  // \t
                + 12 // "auth_failure"
                + 1
            } // \n
        };
        let result = match ev {
            Event::Beat {
                pid,
                status,
                payload,
                nonce,
                observer_ns,
                origin: _,
                pid_ns_inode: _,
            } => writeln!(
                self.sink,
                "{observer_ns}\tbeat\t{pid}\t{nonce}\t{}\t{payload}",
                status_label(*status),
            ),
            Event::Stall {
                pid,
                last_nonce,
                last_ns: _,
                observer_ns,
                origin: _,
                pid_ns_inode: _,
                generation: _,
            } => writeln!(
                self.sink,
                "{observer_ns}\tstall\t{pid}\t{last_nonce}\tstall\t-",
            ),
            Event::Decode(err, observer_ns) => {
                let msg = format!("{err:?}");
                escaped_line_len = Some(text_event_line_len(*observer_ns, "decode", &msg));
                write_text_event_line(&mut self.sink, *observer_ns, "decode", &msg)
            }
            Event::Io(err, observer_ns) => {
                let msg = err.to_string();
                escaped_line_len = Some(text_event_line_len(*observer_ns, "io", &msg));
                write_text_event_line(&mut self.sink, *observer_ns, "io", &msg)
            }
            Event::AuthFailure {
                claimed_pid,
                observer_ns,
            } => {
                writeln!(
                    self.sink,
                    "{observer_ns}\tmismatch\t{claimed_pid}\t-\t-\tauth_failure",
                )
            }
            Event::OriginConflict {
                claimed_pid,
                observer_ns,
                ..
            } => {
                writeln!(
                    self.sink,
                    "{observer_ns}\tmismatch\t{claimed_pid}\t-\t-\torigin_conflict",
                )
            }
            Event::NamespaceConflict {
                claimed_pid,
                observer_ns,
                ..
            } => {
                writeln!(
                    self.sink,
                    "{observer_ns}\tmismatch\t{claimed_pid}\t-\t-\tnamespace_conflict",
                )
            }
            Event::CtrlTruncated(err, observer_ns) => {
                let msg = err.to_string();
                escaped_line_len = Some(text_event_line_len(*observer_ns, "ctrunc", &msg));
                write_text_event_line(&mut self.sink, *observer_ns, "ctrunc", &msg)
            }
        };
        if let Err(ref e) = result {
            self.remember_error(e);
        }
        match result {
            Err(e) => Err(e),
            Ok(()) => {
                let actual_len = if let Some(len) = escaped_line_len {
                    len
                } else if line_len > 0 {
                    line_len
                } else {
                    match ev {
                        Event::OriginConflict {
                            claimed_pid,
                            observer_ns,
                            ..
                        } => format!(
                            "{observer_ns}\tmismatch\t{claimed_pid}\t-\t-\torigin_conflict\n"
                        )
                        .len() as u64,
                        Event::NamespaceConflict {
                            claimed_pid,
                            observer_ns,
                            ..
                        } => format!(
                            "{observer_ns}\tmismatch\t{claimed_pid}\t-\t-\tnamespace_conflict\n"
                        )
                        .len() as u64,
                        _ => unreachable!(),
                    }
                };
                self.after_write(actual_len)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let sink_result = self.sink.flush();
        match (self.pending_err.take(), sink_result) {
            (Some(e), _) => Err(e),
            (None, Err(e)) => Err(e),
            (None, Ok(())) => Ok(()),
        }
    }
}

fn write_text_event_line<W: Write>(
    sink: &mut W,
    observer_ns: u64,
    kind: &str,
    raw: &str,
) -> io::Result<()> {
    write!(sink, "{observer_ns}\t{kind}\t-\t-\t-\t")?;
    write_escaped_tsv_field(sink, raw)?;
    writeln!(sink)
}

fn text_event_line_len(observer_ns: u64, kind: &str, raw: &str) -> u64 {
    decimal_digits(observer_ns) as u64
        + 1 // \t
        + kind.len() as u64
        + 1 // \t
        + 1 // -
        + 1 // \t
        + 1 // -
        + 1 // \t
        + 1 // -
        + 1 // \t
        + escaped_tsv_field_len(raw) as u64
        + 1 // \n
}

fn write_escaped_tsv_field<W: Write>(sink: &mut W, raw: &str) -> io::Result<()> {
    for byte in raw.bytes() {
        match byte {
            b'\\' => sink.write_all(br"\\")?,
            b'\t' => sink.write_all(br"\t")?,
            b'\n' => sink.write_all(br"\n")?,
            b'\r' => sink.write_all(br"\r")?,
            0x00..=0x1f | 0x7f => {
                sink.write_all(&[b'\\', b'x', lower_hex(byte >> 4), lower_hex(byte & 0x0f)])?;
            }
            _ => sink.write_all(&[byte])?,
        }
    }
    Ok(())
}

fn escaped_tsv_field_len(raw: &str) -> usize {
    raw.bytes()
        .map(|byte| match byte {
            b'\\' | b'\t' | b'\n' | b'\r' => 2,
            0x00..=0x1f | 0x7f => 4,
            _ => 1,
        })
        .sum()
}

fn lower_hex(nibble: u8) -> u8 {
    let nibble = nibble & 0x0f;
    if nibble < 10 {
        b'0' + nibble
    } else {
        b'a' + (nibble - 10)
    }
}

/// Return the number of decimal digits needed to represent `n`.
fn decimal_digits(mut n: u64) -> usize {
    if n == 0 {
        return 1;
    }
    let mut digits = 0;
    while n > 0 {
        n /= 10;
        digits += 1;
    }
    digits
}

fn status_label(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Degraded => "degraded",
        Status::Critical => "critical",
        Status::Stall => "stall",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rotation_reopen_fixture(name: &str) -> (PathBuf, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("varta-file-export-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = dir.join("export.tsv");
        (dir, path)
    }

    fn sample_beat(observer_ns: u64) -> Event {
        Event::Beat {
            pid: 42,
            status: Status::Ok,
            payload: 7,
            nonce: 1,
            origin: crate::peer_cred::BeatOrigin::KernelAttested,
            pid_ns_inode: None,
            observer_ns,
        }
    }

    #[test]
    fn create_rejects_symlink_without_modifying_target() {
        use std::os::unix::fs::symlink;

        let (dir, path) = rotation_reopen_fixture("create-symlink");
        let victim = dir.join("victim");
        let original = b"must remain unchanged\n";
        std::fs::write(&victim, original).expect("seed victim");
        symlink(&victim, &path).expect("plant export symlink");

        let err = match FileExporter::create(&path, None, 0) {
            Ok(_) => panic!("file exporter must reject a symlink"),
            Err(e) => e,
        };

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            std::fs::read(&victim).expect("read victim"),
            original,
            "export startup must not append to the symlink target"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_rejects_hard_link_without_modifying_target() {
        let (dir, path) = rotation_reopen_fixture("create-hard-link");
        let victim = dir.join("victim");
        let original = b"must remain unchanged\n";
        std::fs::write(&victim, original).expect("seed victim");
        std::fs::hard_link(&victim, &path).expect("plant export hard link");

        let err = match FileExporter::create(&path, None, 0) {
            Ok(_) => panic!("file exporter must reject a multiply-linked inode"),
            Err(e) => e,
        };

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            std::fs::read(&victim).expect("read victim"),
            original,
            "export startup must not append to the hard-linked target"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_device_fallback_refuses_symlink_destination_without_modifying_target() {
        use std::os::unix::fs::symlink;

        let (dir, path) = rotation_reopen_fixture("copy-symlink");
        let first = generation_path(&path, 1);
        let victim = dir.join("victim");
        let original = b"must remain unchanged\n";
        std::fs::write(&victim, original).expect("seed victim");

        let mut fe = FileExporter::create(&path, None, 0).expect("create exporter");
        fe.record(&sample_beat(123)).expect("record beat");
        fe.flush().expect("flush beat");
        symlink(&victim, &first).expect("plant destination symlink");

        let err = fe
            .copy_live_to_first(&first)
            .expect_err("copy fallback must reject an existing symlink");

        assert!(matches!(
            err.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::InvalidInput
        ));
        assert!(
            std::fs::symlink_metadata(&first)
                .expect("destination symlink remains")
                .file_type()
                .is_symlink(),
            "fallback must not unlink a destination it did not create"
        );
        assert_eq!(
            std::fs::read(&victim).expect("read victim"),
            original,
            "fallback must not overwrite the destination symlink target"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_device_fallback_reads_owned_descriptor_after_live_path_swap() {
        use std::os::unix::fs::symlink;

        let (dir, path) = rotation_reopen_fixture("copy-source-swap");
        let displaced = dir.join("displaced-export.tsv");
        let first = generation_path(&path, 1);
        let victim = dir.join("victim");
        let original = b"must remain unchanged\n";
        std::fs::write(&victim, original).expect("seed victim");

        let mut fe = FileExporter::create(&path, None, 0).expect("create exporter");
        fe.record(&sample_beat(123)).expect("record beat");
        fe.flush().expect("flush beat");
        std::fs::rename(&path, &displaced).expect("displace live export path");
        symlink(&victim, &path).expect("replace live path with symlink");

        fe.copy_live_to_first(&first).expect("copy fallback");

        assert_eq!(
            std::fs::read(&victim).expect("read victim"),
            original,
            "fallback must not read from or write to the replacement target"
        );
        assert_eq!(
            std::fs::read(&first).expect("read rotated export"),
            std::fs::read(&displaced).expect("read original export inode"),
            "rotated generation must come from the descriptor owned by the exporter"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn created_path_guard_preserves_replacement_inode() {
        let (dir, path) = rotation_reopen_fixture("guard-replacement");
        let displaced = dir.join("displaced-export.tsv");
        let replacement = b"replacement must survive\n";
        let file = create_new_export_file(&path).expect("create guarded file");
        let guard = CreatedPathGuard::new(&path, &file).expect("capture created inode");

        std::fs::rename(&path, &displaced).expect("displace guarded inode");
        std::fs::write(&path, replacement).expect("install replacement");
        drop(guard);

        assert_eq!(
            std::fs::read(&path).expect("read replacement"),
            replacement,
            "cleanup must not unlink a leaf that no longer names the created inode"
        );
        assert!(
            displaced.exists(),
            "the created inode must remain displaced"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn namespace_conflict_does_not_panic() {
        let dir = std::env::temp_dir().join("varta-file-export-ns-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("export.tsv");
        let mut fe = FileExporter::create(&path, Some(1_000_000), 0).unwrap();
        let ev = Event::NamespaceConflict {
            claimed_pid: 42,
            observed_ns_inode: Some(111),
            observer_ns_inode: Some(222),
            observer_ns: 9999,
        };
        fe.record(&ev).expect("NamespaceConflict should not panic");
        fe.flush().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("namespace_conflict"),
            "expected namespace_conflict in TSV, got: {content}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn io_error_message_is_escaped_as_one_tsv_field() {
        let (dir, path) = rotation_reopen_fixture("io-error-escape");
        let mut fe = FileExporter::create(&path, Some(1_000_000), 0).unwrap();

        fe.record(&Event::Io(
            io::Error::new(io::ErrorKind::Other, "bad\tcell\nrow\rslash\\\x01"),
            77,
        ))
        .expect("record escaped io error");
        fe.flush().expect("flush escaped io error");

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(
            lines.len(),
            1,
            "an error message newline must not forge a second TSV record: {content:?}"
        );
        let cols: Vec<_> = lines[0].split('\t').collect();
        assert_eq!(
            cols.len(),
            6,
            "an error message tab must not forge an extra TSV column: {content:?}"
        );
        assert_eq!(cols[5], r"bad\tcell\nrow\rslash\\\x01");
        assert_eq!(
            fe.bytes_written,
            std::fs::metadata(&path).unwrap().len(),
            "escaped byte accounting must match the real file size"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The AuthFailure length estimate must exactly equal the bytes written,
    /// or rotation accounting drifts and the file rotates early. Regression
    /// for the `+ 13` vs 12-byte `auth_failure` off-by-one: the running
    /// `bytes_written` counter must track the real on-disk size byte-for-byte.
    #[test]
    fn auth_failure_length_estimate_matches_bytes_written() {
        let (dir, path) = rotation_reopen_fixture("auth-failure-len");
        // Large cap so nothing rotates; we only assert the byte counter.
        let mut fe = FileExporter::create(&path, Some(1_000_000), 0).unwrap();
        fe.record(&Event::AuthFailure {
            claimed_pid: 4242,
            observer_ns: 1_234_567,
        })
        .unwrap();
        fe.flush().unwrap();
        let on_disk = std::fs::metadata(&path).unwrap().len();
        assert_eq!(
            fe.bytes_written, on_disk,
            "estimated bytes_written ({}) must equal the real file size ({on_disk})",
            fe.bytes_written
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_rejects_tiny_max_bytes_without_creating_file() {
        let (dir, path) = rotation_reopen_fixture("tiny-max-bytes");
        let err = match FileExporter::create(&path, Some(MIN_EXPORT_FILE_MAX_BYTES - 1), 0) {
            Ok(_) => panic!("create must reject tiny max_bytes"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            !path.exists(),
            "invalid max_bytes must be rejected before creating the export file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_reports_rotation_reopen_failure() {
        let (dir, path) = rotation_reopen_fixture("record-rotation-error");
        let mut fe = FileExporter::create_unchecked_for_test(&path, Some(1), 0).unwrap();

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();

        let err = fe
            .record(&sample_beat(123))
            .expect_err("rotation reopen failure must be returned");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        let pending = fe
            .flush()
            .expect_err("rotation reopen failure must remain latched");
        assert_eq!(pending.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn rotation_reopen_failure_does_not_migrate_records_to_deletion() {
        // Regression (bug-479): when a rotation renames the live file to `.1`
        // but then cannot recreate `PATH` (ENOSPC/EMFILE *after* the rename
        // succeeded), the sink still holds the `.1` inode. Re-running rotate()
        // on every subsequent record carried that stale fd down `.1`→…→`.5` and
        // deleted it at the oldest generation, silently destroying the rotated
        // records. The reopen-pending latch must retry ONLY the reopen, leaving
        // `.1` in place.
        let (dir, path) = rotation_reopen_fixture("reopen-no-loss");
        let mut fe = FileExporter::create_unchecked_for_test(&path, Some(1), 0).unwrap();

        // Emulate rename-succeeds-but-create-fails for every reopen.
        fe.reopen_must_fail = true;
        // Write well more records than MAX_ROTATION_GENERATIONS, so the buggy
        // path would migrate the fd off the end of `.5` and delete it.
        for ns in 200..220u64 {
            let _ = fe.record(&sample_beat(ns)); // Err during the pending window
        }
        // Flush the buffered tail to whatever inode the sink currently holds:
        // with the fix that is the retained `.1`; with the bug it is the stale
        // fd's inode, already unlinked after migrating off the end of `.5`.
        let _ = fe.flush();

        // Every windowed record must survive on disk — not vanish into a stale
        // fd whose inode was deleted at `.5`. Concatenate every generation.
        let mut all = String::new();
        if let Ok(b) = std::fs::read_to_string(&path) {
            all.push_str(&b);
        }
        for g in 1..=MAX_ROTATION_GENERATIONS {
            if let Ok(b) = std::fs::read_to_string(generation_path(&path, g)) {
                all.push_str(&b);
            }
        }
        assert!(
            all.contains("200\t"),
            "earliest windowed record (200) must survive the reopen-failure window"
        );
        assert!(
            all.contains("219\t"),
            "latest windowed record (219) must survive — with the bug the stale \
             fd's inode is deleted at .5 and the tail of the window is lost"
        );

        // Recovery: once the reopen can succeed, the live PATH is recreated.
        fe.reopen_must_fail = false;
        fe.record(&sample_beat(300))
            .expect("reopen succeeds once create can");
        assert!(path.exists(), "live PATH recreated once reopen succeeds");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopen_failure_fsyncs_parent_dir_to_persist_the_rotation() {
        // Regression (bug-482): a reopen failure *after* a committed rotation
        // must still fsync the parent directory. `rotate()` renames
        // `PATH`→`PATH.1` (or, on EXDEV, copies then unlinks the live path)
        // BEFORE `reopen_live` recreates `PATH`. When that recreate fails
        // (ENOSPC/EMFILE) the live recreate is deferred via
        // `rotation_reopen_pending` — but the rename's dirent mutation has
        // already happened, and the prior code returned without an `fsync(2)`
        // of the parent. A power cut in the deferred window could then orphan
        // the freshly-rotated `.1` (its data was `fdatasync`'d in `rotate`, but
        // the dirent naming it was not) and silently lose those records. The
        // `dir_fsyncs` counter makes this red->green: without the fix it does
        // NOT advance on a reopen failure.
        let (dir, path) = rotation_reopen_fixture("reopen-fail-fsync");
        // max_bytes = 1 => the first record rotates; the reopen then fails.
        let mut fe = FileExporter::create_unchecked_for_test(&path, Some(1), 0).unwrap();
        let before = fe.dir_fsyncs;

        fe.reopen_must_fail = true;
        let err = fe
            .record(&sample_beat(200))
            .expect_err("rotation reopen failure must be returned");
        assert_eq!(err.kind(), io::ErrorKind::Other);

        assert!(
            fe.rotation_reopen_pending,
            "reopen failure must set the reopen-pending latch"
        );
        assert_eq!(
            fe.dir_fsyncs,
            before + 1,
            "reopen failure must fsync the parent dir once to persist the \
             committed rotation (rename PATH->.1), not leave it non-durable \
             until the next successful reopen"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn successful_record_does_not_clear_latched_rotation_error() {
        let (dir, path) = rotation_reopen_fixture("record-latched-error");
        let mut fe = FileExporter::create_unchecked_for_test(&path, Some(1), 0).unwrap();

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();

        let err = fe
            .record(&sample_beat(123))
            .expect_err("first rotation reopen must fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(fe.pending_err.is_some());

        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        fe.record(&sample_beat(124))
            .expect("second rotation can reopen after parent dir is restored");
        assert!(fe.pending_err.is_some());

        let pending = fe
            .flush()
            .expect_err("latched rotation error must survive later successful writes");
        assert_eq!(pending.kind(), io::ErrorKind::NotFound);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_eviction_pid_reports_rotation_reopen_failure() {
        let (dir, path) = rotation_reopen_fixture("eviction-rotation-error");
        let mut fe = FileExporter::create_unchecked_for_test(&path, Some(1), 0).unwrap();

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();

        let err = fe
            .record_eviction_pid(42, 123)
            .expect_err("eviction rotation reopen failure must be returned");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// Rotation must make its directory-entry mutations durable. A rotation
    /// renames `PATH`→`PATH.1` (or, on EXDEV, copies then unlinks the live
    /// path) and creates a fresh `PATH`; the per-record `fdatasync` only
    /// persists file *data*, never the directory entries, so the parent
    /// directory needs an explicit fsync (`fsync(2)`). This pins the
    /// `fsync_parent_dir` sweep added to `create()` and the rotation reopen
    /// (mirroring the audit log, bug-403): the call must run on the happy path
    /// without breaking rotation or spuriously latching an error. The
    /// `dir_fsyncs` counter makes it red->green — reverting the fix leaves it
    /// at 0. True durability across a power cut can only be shown by fault
    /// injection; this guards the fix's behavior on a healthy filesystem.
    #[test]
    fn rotation_under_sync_every_preserves_generation_without_latching_error() {
        let (dir, path) = rotation_reopen_fixture("rotation-dir-fsync");
        // sync_every = 1 => durability opt-in; max_bytes = 1 => every record
        // rotates. create() already fsynced the parent for the live dirent.
        let mut fe =
            FileExporter::create_unchecked_for_test(&path, Some(1), 1).expect("create exporter");
        assert_eq!(
            fe.dir_fsyncs, 1,
            "create() must fsync the parent dir once for the live dirent"
        );
        assert!(
            fe.pending_err.is_none(),
            "create() parent-dir fsync must not latch an error on a healthy dir"
        );

        fe.record(&sample_beat(123))
            .expect("first record + rotation");
        assert_eq!(
            fe.dir_fsyncs, 2,
            "rotation must fsync the parent dir to make the rename/create durable"
        );

        let first_gen = generation_path(&path, 1);
        let rotated = std::fs::read_to_string(&first_gen).expect("rotated generation exists");
        assert!(
            rotated.contains("\tbeat\t42\t"),
            "rotated PATH.1 must hold the pre-rotation beat, got: {rotated:?}"
        );
        assert_eq!(
            std::fs::metadata(&path).expect("live path reopened").len(),
            0,
            "post-rotation live PATH must be freshly created (empty)"
        );
        assert!(
            fe.pending_err.is_none(),
            "rotation parent-dir fsync must succeed on a healthy dir, not latch"
        );

        // The reopened live file is writable and a further rotation still works.
        fe.record(&sample_beat(124))
            .expect("second record + rotation");
        assert_eq!(
            fe.dir_fsyncs, 3,
            "the second rotation fsyncs the parent again"
        );
        fe.flush()
            .expect("flush after rotations leaves no latched error");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
