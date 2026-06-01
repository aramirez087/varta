//! File-backed exporter. See [`FileExporter`].

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use varta_vlp::Status;

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
/// as `-` so the line count and column count remain stable.
///
/// `observer_ns` is the observer-local nanosecond timestamp carried by every
/// [`Event`], captured at observer poll time. All exporters sharing an event
/// stream see the same timestamps.
///
/// When `max_bytes` is set, the exporter rotates the file after every write
/// that pushes the size over the limit. Rotation shifts `PATH` → `PATH.1`,
/// `PATH.1` → `PATH.2`, …, up to 5 generations, then re-opens `PATH` in
/// append mode. Without `max_bytes` the file grows unbounded.
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
    /// rotated.
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
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())?;
        let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(FileExporter {
            sink: BufWriter::new(file),
            pending_err: None,
            path: path.as_ref().to_path_buf(),
            max_bytes,
            bytes_written,
            sync_every,
            writes_since_sync: 0,
        })
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
        if let Err(e) = Self::rotate(&self.path) {
            self.remember_error(&e);
            return Err(first_err.unwrap_or(e));
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => {
                self.sink = BufWriter::new(file);
                self.bytes_written = 0;
                self.writes_since_sync = 0;
                match first_err {
                    Some(e) => Err(e),
                    None => Ok(()),
                }
            }
            Err(e) => {
                self.remember_error(&e);
                Err(first_err.unwrap_or(e))
            }
        }
    }

    /// Rotate `path`: shift `path` → `path.1`, `path.1` → `path.2`, …
    /// up to [`MAX_ROTATION_GENERATIONS`]. The oldest generation is deleted.
    fn rotate(path: &Path) -> io::Result<()> {
        let path_str = path.to_string_lossy();
        let oldest = format!("{path_str}.{MAX_ROTATION_GENERATIONS}");
        match std::fs::remove_file(&oldest) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        for gen in (1..MAX_ROTATION_GENERATIONS).rev() {
            let src = format!("{path_str}.{gen}");
            let dst = format!("{path_str}.{}", gen + 1);
            match std::fs::rename(&src, &dst) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let first = format!("{path_str}.1");
        match std::fs::rename(path, &first) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) if is_cross_device_error(&e) => {
                std::fs::copy(path, &first)?;
                std::fs::remove_file(path)?;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

fn is_cross_device_error(e: &io::Error) -> bool {
    e.raw_os_error() == Some(EXDEV)
}

impl Exporter for FileExporter {
    fn record(&mut self, ev: &Event) -> io::Result<()> {
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
                + 13 // "auth_failure"
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
            } => writeln!(
                self.sink,
                "{observer_ns}\tstall\t{pid}\t{last_nonce}\tstall\t-",
            ),
            Event::Decode(err, observer_ns) => {
                writeln!(self.sink, "{observer_ns}\tdecode\t-\t-\t-\t{err:?}")
            }
            Event::Io(err, observer_ns) => {
                writeln!(self.sink, "{observer_ns}\tio\t-\t-\t-\t{err}")
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
                writeln!(self.sink, "{observer_ns}\tctrunc\t-\t-\t-\t{err}")
            }
        };
        if let Err(ref e) = result {
            self.remember_error(e);
        }
        match result {
            Err(e) => Err(e),
            Ok(()) => {
                let actual_len = if line_len > 0 {
                    line_len
                } else {
                    match ev {
                        Event::Decode(err, observer_ns) => {
                            format!("{observer_ns}\tdecode\t-\t-\t-\t{err:?}\n").len() as u64
                        }
                        Event::Io(err, observer_ns) => {
                            let msg = err.to_string();
                            format!("{observer_ns}\tio\t-\t-\t-\t{msg}\n").len() as u64
                        }
                        Event::CtrlTruncated(err, observer_ns) => {
                            let msg = err.to_string();
                            format!("{observer_ns}\tctrunc\t-\t-\t-\t{msg}\n").len() as u64
                        }
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
    fn record_reports_rotation_reopen_failure() {
        let (dir, path) = rotation_reopen_fixture("record-rotation-error");
        let mut fe = FileExporter::create(&path, Some(1), 0).unwrap();

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
    fn successful_record_does_not_clear_latched_rotation_error() {
        let (dir, path) = rotation_reopen_fixture("record-latched-error");
        let mut fe = FileExporter::create(&path, Some(1), 0).unwrap();

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
        let mut fe = FileExporter::create(&path, Some(1), 0).unwrap();

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();

        let err = fe
            .record_eviction_pid(42, 123)
            .expect_err("eviction rotation reopen failure must be returned");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
