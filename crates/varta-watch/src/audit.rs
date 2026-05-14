//! Recovery audit log — TSV record of every recovery spawn/complete/refused.
//!
//! In safety-critical deployments (hospital / airport) every recovery action
//! must be auditable: *who* fired, *what* ran, *when*, *with what outcome*,
//! *in which order*, and *whether the file has been tampered with*. IEC 62304
//! Class C anomaly records cannot tolerate silent record loss, page-cache
//! data loss across power cuts, or retroactive editing of historical lines.
//!
//! This module emits **schema v2**, which satisfies those three needs:
//!
//! 1. **Sequencing.** Every record carries a leading `seq` column — a `u64`
//!    that is strictly monotonic across the daemon's lifetime *and* resumes
//!    from the prior file's tail on restart. A consumer sees gaps as
//!    `seq[i+1] - seq[i] > 1`.
//!
//! 2. **Durability.** Every record path calls `File::sync_data()` (=
//!    `fdatasync(2)` on Linux) at the configured cadence — default once per
//!    record. Rotation always syncs before the rename and again after the
//!    post-rotation `boot` record is written. The `Drop` impl flushes and
//!    syncs best-effort.
//!
//! 3. **Tamper-evidence (`audit-chain` feature).** Every record carries a
//!    trailing `chain` column. With the feature on, it is a full SHA-256
//!    over `DOMAIN || kind || prev_chain_raw || body_with_seq`. The
//!    construction lives behind a single helper in `varta-vlp` so callers
//!    cannot accidentally drop the domain separation. With the feature off,
//!    the column is a literal `-` and the daemon prints one startup warning
//!    saying the build is not Class-C-conforming.
//!
//! All three are checked end-to-end by the integration tests in
//! `crates/varta-tests/tests/end_to_end.rs`.
//!
//! # Schema (v2)
//!
//! Two header lines, then per-record-kind layouts. Every record kind has a
//! leading `seq` and a trailing `chain`:
//!
//! ```text
//! # varta-watch recovery audit v2
//! # boot:     seq\twallclock_ms\tobserver_ns\tboot\tdaemon_pid\tprev_chain|-\treason\tchain
//! # spawn:    seq\twallclock_ms\tobserver_ns\tspawn\tagent_pid\tchild_pid\tmode\tprogram\tsource\ttemplate_len\tchain
//! # complete: seq\twallclock_ms\tobserver_ns\tcomplete\tagent_pid\tchild_pid\toutcome\texit_code|-\tsignal|-\tduration_ns\tstdout_len\tstderr_len\ttruncated\tchain
//! # refused:  seq\twallclock_ms\tobserver_ns\trefused\tagent_pid\treason\tchain
//! ```
//!
//! `wallclock_ms` is milliseconds since the UNIX epoch. `observer_ns` is the
//! monotonic timestamp consistent with the event-stream TSV; operators
//! correlate audit lines against the event log via `observer_ns`. `chain`
//! is 64 lowercase hex characters or a literal `-`.
//!
//! # Boot records
//!
//! A `boot` record is the **only** record kind synthesised internally; all
//! other kinds are explicit calls from `recovery.rs`. A `boot` is written:
//!
//! - When `create()` opens a brand-new file — `reason=fresh`,
//!   `prev_chain=-`.
//! - When `create()` opens an existing v2 file and the tail parses cleanly
//!   — `reason=resume`, `prev_chain` is the decoded chain of the prior
//!   tail record.
//! - When `create()` opens an existing v1 file — `reason=legacy_v1`,
//!   `prev_chain=-`. The v1 prefix stays on disk for forensic continuity;
//!   a fresh v2 header is appended on a new line.
//! - When `create()` opens an existing v2 file whose tail is torn — the
//!   file is `ftruncate`'d back to the last `\n`, then `reason=corrupt_tail`,
//!   `prev_chain` taken from the prior recoverable record if any.
//! - When `create()` opens an existing file with neither v1 nor v2 header
//!   — `reason=schema_drift`, `prev_chain=-`. In-band evidence of drift
//!   so an auditor sees it without parsing the whole file.
//! - Immediately after every rotation rename — `reason=rotation`,
//!   `prev_chain` is the *last chain of the just-rotated file* (captured
//!   before the rename). This keeps the chain continuous *across* rotation
//!   generations.
//!
//! `boot` records always increment `seq` like any other record.
//!
//! # Rotation
//!
//! When `max_bytes` is configured, the file rotates after every write that
//! pushes its size over the limit: `PATH` → `PATH.1` → … → `PATH.5`. Same
//! generation count as the event-stream `FileExporter`.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Number of rotated file generations kept. Mirrors
/// `crate::exporter::MAX_ROTATION_GENERATIONS`.
const AUDIT_ROTATION_GENERATIONS: u32 = 5;

/// Header line written to a freshly-created v2 audit file.
const AUDIT_HEADER_V2: &str = "# varta-watch recovery audit v2\n";

/// Legacy v1 header — used to detect a v1 file on restart so we can append
/// a fresh v2 section with a `legacy_v1` boot rather than silently mixing
/// schemas.
const AUDIT_HEADER_V1_PREFIX: &str = "# varta-watch recovery audit v1";

/// Maximum bytes read from the tail of an existing file when resuming.
/// Bounded so the read is O(1) regardless of file size. A single record is
/// far smaller than this, so a torn write at the end is always within the
/// window.
const TAIL_SCAN_BYTES: u64 = 4096;

/// Outcome category surfaced in the `complete` record.
#[derive(Debug, Clone, Copy)]
pub enum CompleteOutcome {
    /// Child exited and was reaped.
    Reaped,
    /// Child exceeded its timeout and was killed.
    Killed,
    /// `try_wait`/`kill` syscall failed for the outstanding child.
    ReapFailed,
}

impl CompleteOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reaped => "reaped",
            Self::Killed => "killed",
            Self::ReapFailed => "reap_failed",
        }
    }
}

/// One spawn-time record. Fields are borrowed so callers can format the
/// line without allocating new strings on the hot path.
#[derive(Debug)]
pub struct SpawnRecord<'a> {
    /// Wall-clock time of the spawn, milliseconds since UNIX epoch.
    pub wallclock_ms: u64,
    /// Observer-local monotonic ns at spawn time (matches event stream).
    pub observer_ns: u64,
    /// Agent pid whose stall triggered the recovery.
    pub agent_pid: u32,
    /// Child pid of the freshly-spawned recovery process.
    pub child_pid: u32,
    /// "shell" or "exec".
    pub mode: &'a str,
    /// Program path actually invoked (`/bin/sh` for shell mode, `argv[0]`
    /// for exec mode).
    pub program: &'a str,
    /// Source of the command: `"inline"` for `--recovery-cmd` /
    /// `--recovery-exec`, or the path-string for the `*-file` variants.
    pub source: &'a str,
    /// Length in bytes of the resolved command template (shell) or full
    /// argv (exec). The contents themselves are not written — they may
    /// embed secrets and the source path is already auditable.
    pub template_len: u32,
}

/// One completion record (reap, kill, or reap failure).
#[derive(Debug)]
pub struct CompleteRecord {
    /// Wall-clock time of completion, milliseconds since UNIX epoch.
    pub wallclock_ms: u64,
    /// Observer-local monotonic ns at completion (matches event stream).
    pub observer_ns: u64,
    /// Agent pid whose recovery this completion belongs to.
    pub agent_pid: u32,
    /// Child pid of the recovery process.
    pub child_pid: u32,
    /// Outcome category — see [`CompleteOutcome`].
    pub outcome: CompleteOutcome,
    /// Numeric exit code (`Some` only when `outcome == Reaped` and the
    /// child exited normally; rendered as `-` otherwise).
    pub exit_code: Option<i32>,
    /// Signal number (`Some` only when reaped from a signal; rendered as
    /// `-` otherwise).
    pub signal: Option<i32>,
    /// Wall-clock duration from spawn to completion in ns.
    pub duration_ns: u64,
    /// Number of bytes captured from child stdout (0 when capture disabled).
    pub stdout_len: u32,
    /// Number of bytes captured from child stderr (0 when capture disabled).
    pub stderr_len: u32,
    /// True iff capture was enabled and either stream hit its byte cap.
    pub truncated: bool,
}

/// One refusal record — recovery was structurally declined for an agent
/// even though the stall threshold was met.
///
/// Currently fired by the transport-origin gate: a `NetworkUnverified` stall
/// (any UDP variant) is refused unless the operator has explicitly opted in
/// via `--i-accept-recovery-on-unauthenticated-transport`.  See
/// `docs/architecture/peer-authentication.md` for the trust model.
#[derive(Debug)]
pub struct RefusedRecord<'a> {
    /// Wall-clock time of the refusal, milliseconds since UNIX epoch.
    pub wallclock_ms: u64,
    /// Observer-local monotonic ns at refusal time (matches event stream).
    pub observer_ns: u64,
    /// Agent pid whose stall triggered the refused recovery.
    pub agent_pid: u32,
    /// Stable, short token describing why recovery was refused.
    /// Example: `"unauthenticated_transport"`.
    pub reason: &'a str,
}

/// Why a `boot` record was written. Stable tokens for SIEM consumers.
#[derive(Debug, Clone, Copy)]
enum BootReason {
    /// Fresh file — no prior audit history.
    Fresh,
    /// Resumed cleanly from a v2 tail.
    Resume,
    /// Opened a legacy v1 file; v2 section starts here.
    LegacyV1,
    /// Opened a v2 file with a torn / unparseable tail; file was
    /// `ftruncate`'d to the last newline before writing this record.
    CorruptTail,
    /// File header is neither v1 nor v2 — explicit drift evidence.
    SchemaDrift,
    /// Synthesised immediately after rotation rename. Carries the final
    /// chain of the just-rotated file.
    Rotation,
}

impl BootReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Resume => "resume",
            Self::LegacyV1 => "legacy_v1",
            Self::CorruptTail => "corrupt_tail",
            Self::SchemaDrift => "schema_drift",
            Self::Rotation => "rotation",
        }
    }
}

/// Kind label baked into both the TSV `record_kind` column and the chain
/// hash input. Keep the wire string and the hash input in lock-step so a
/// chain verifier rebuilt from scratch in the future cannot disagree with
/// the daemon over the label byte string.
#[derive(Debug, Clone, Copy)]
enum AuditKind {
    Boot,
    Spawn,
    Complete,
    Refused,
}

impl AuditKind {
    #[cfg_attr(not(feature = "audit-chain"), allow(dead_code))]
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Boot => b"boot",
            Self::Spawn => b"spawn",
            Self::Complete => b"complete",
            Self::Refused => b"refused",
        }
    }
}

/// Abstraction over the underlying file so unit tests can verify the
/// flush/sync/rotate call order without depending on the kernel's fdatasync
/// semantics.
trait DurableSink: Write + Send {
    /// `File::sync_data()` on the real impl; counted by the test fake.
    fn sync_data(&self) -> io::Result<()>;
}

/// Real backing — wraps a `File` and delegates `sync_data` to the OS.
struct FileSink(File);

impl Write for FileSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl DurableSink for FileSink {
    fn sync_data(&self) -> io::Result<()> {
        self.0.sync_data()
    }
}

/// Result of probing an existing audit file for restart continuity.
struct TailProbe {
    /// `seq` of the most recent parseable record, or 0 if none recovered.
    last_seq: u64,
    /// Raw 32-byte chain of the most recent parseable record. `[0; 32]` if
    /// no chain could be recovered (legacy v1, schema drift, fresh, or
    /// torn-without-fallback).
    last_chain: [u8; 32],
    /// Why we are emitting an initial `boot` record on top of the existing
    /// content.
    reason: BootReason,
    /// If `Some`, the existing file must be `ftruncate`'d to this length
    /// before the v2 header / boot record can be appended safely (only set
    /// for `CorruptTail`).
    truncate_to: Option<u64>,
    /// True if the existing file already contains a v2 header that the
    /// caller must *not* re-emit. False if the caller needs to write a
    /// fresh `AUDIT_HEADER_V2` after opening for append.
    has_v2_header: bool,
}

/// Append-only audit sink. One file descriptor held for the daemon's life,
/// reopened on rotation. Writes never block the recovery path: on IO error
/// the failure is latched in `pending_err` and the daemon's main loop
/// drains it via [`take_pending_err`] (mirrors `FileExporter`).
pub struct RecoveryAuditLog {
    sink: BufWriter<Box<dyn DurableSink>>,
    path: PathBuf,
    max_bytes: Option<u64>,
    bytes_written: u64,
    pending_err: Option<io::Error>,
    next_seq: u64,
    prev_chain: [u8; 32],
    sync_every: u32,
    writes_since_sync: u32,
    daemon_pid: u32,
    /// Reentry guard: true while we are inside `maybe_rotate`'s post-
    /// rotation `boot` write. Without this, a tiny `max_bytes` whose
    /// threshold is crossed by the boot record itself would re-trigger
    /// rotation recursively until the stack overflows.
    rotating: bool,
}

/// Configuration accepted by [`RecoveryAuditLog::create`]. Grouped into a
/// struct so future flags (key file, signing mode, …) don't keep widening
/// the `create()` signature.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Size at which the file rotates; `None` disables rotation.
    pub max_bytes: Option<u64>,
    /// How many records between forced `fdatasync` calls. `1` (= every
    /// record) is the only IEC 62304 Class C-conforming value; values >1
    /// are accepted with a startup warning surfaced via the returned
    /// `CreateOutcome`.
    pub sync_every: u32,
    /// `getpid()` of the varta-watch daemon; recorded on every `boot`
    /// record so forensic tooling can correlate the audit chain to the
    /// systemd journal / PID-namespace transitions.
    pub daemon_pid: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_bytes: None,
            sync_every: 1,
            daemon_pid: std::process::id(),
        }
    }
}

/// Side-channel from [`RecoveryAuditLog::create`] — warnings the daemon
/// should surface via `eprintln!` / json-log before entering its main loop.
/// Returned alongside the log itself so the create path stays infallible
/// for non-fatal conditions.
#[derive(Debug, Default)]
pub struct CreateWarnings {
    /// True iff the build is missing the `audit-chain` feature. The daemon
    /// MUST log this prominently — operators in Class C deployments who
    /// rely on chain verification will otherwise discover only at audit
    /// time that the chain column is `-`.
    pub chain_disabled: bool,
    /// True iff `sync_every > 1`. Same Class C deviation; lower visibility.
    pub sync_relaxed: bool,
    /// True iff the file existed with a v1 header — operators see this so
    /// they know the chain restarts here.
    pub legacy_v1: bool,
    /// True iff the file existed with a torn tail that was truncated.
    pub corrupt_tail: bool,
    /// True iff the file existed with an unrecognised header.
    pub schema_drift: bool,
}

impl RecoveryAuditLog {
    /// Open `path` in append mode, creating it (and writing the header)
    /// if necessary. The file is opened with mode 0600 on create so an
    /// operator who configured `--recovery-audit-file /tmp/foo` does not
    /// accidentally publish recovery activity world-readable.
    ///
    /// On success the returned [`CreateWarnings`] flags any non-fatal
    /// conditions the daemon should surface (notably: build missing the
    /// `audit-chain` feature, or `sync_every` relaxed above 1).
    pub fn create(path: impl AsRef<Path>, cfg: AuditConfig) -> io::Result<(Self, CreateWarnings)> {
        use std::os::unix::fs::OpenOptionsExt;

        let path_buf = path.as_ref().to_path_buf();
        let existed = path_buf.exists();

        let mut warnings = CreateWarnings::default();
        if !chain_enabled() {
            warnings.chain_disabled = true;
        }
        if cfg.sync_every == 0 {
            // Sanity floor — never silently fold "every 0 records" into a
            // never-sync policy; that's the opposite of what the operator
            // would want.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit sync_every must be >= 1",
            ));
        }
        if cfg.sync_every > 1 {
            warnings.sync_relaxed = true;
        }

        // Probe the existing file (if any) to derive a continuity story.
        let probe = if existed {
            match Self::probe_tail(&path_buf) {
                Ok(p) => p,
                Err(_) => TailProbe {
                    last_seq: 0,
                    last_chain: [0u8; 32],
                    reason: BootReason::SchemaDrift,
                    truncate_to: None,
                    has_v2_header: false,
                },
            }
        } else {
            TailProbe {
                last_seq: 0,
                last_chain: [0u8; 32],
                reason: BootReason::Fresh,
                truncate_to: None,
                has_v2_header: false,
            }
        };

        match probe.reason {
            BootReason::LegacyV1 => warnings.legacy_v1 = true,
            BootReason::CorruptTail => warnings.corrupt_tail = true,
            BootReason::SchemaDrift => warnings.schema_drift = true,
            _ => {}
        }

        // For CorruptTail we need to truncate before the open-for-append.
        if let Some(len) = probe.truncate_to {
            let file = OpenOptions::new().write(true).open(&path_buf)?;
            file.set_len(len)?;
            file.sync_all()?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path_buf)?;
        let mut bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);

        let sink_box: Box<dyn DurableSink> = Box::new(FileSink(file));
        let mut sink = BufWriter::new(sink_box);

        // Write a v2 header iff one is not already present at the top of
        // the file. (Existing v2 files keep their original header line;
        // legacy v1 / drift / corrupt-tail files get a v2 header appended
        // after the truncate so the v2 section is self-describing.)
        if !probe.has_v2_header {
            sink.write_all(AUDIT_HEADER_V2.as_bytes())?;
            sink.flush()?;
            bytes_written = bytes_written.saturating_add(AUDIT_HEADER_V2.len() as u64);
        }

        let mut log = RecoveryAuditLog {
            sink,
            path: path_buf,
            max_bytes: cfg.max_bytes,
            bytes_written,
            pending_err: None,
            next_seq: probe.last_seq.saturating_add(1),
            prev_chain: probe.last_chain,
            sync_every: cfg.sync_every,
            writes_since_sync: 0,
            daemon_pid: cfg.daemon_pid,
            rotating: false,
        };

        // Write the opening boot record covering whichever continuity case
        // we landed in. Chain continuity for `Rotation` is handled inside
        // `maybe_rotate`, not here.
        let prev_for_boot = match probe.reason {
            BootReason::Resume => Some(probe.last_chain),
            _ => None,
        };
        log.emit_boot(probe.reason, prev_for_boot);

        Ok((log, warnings))
    }

    /// Wall-clock ms since UNIX epoch for the current instant. Saturates
    /// at 0 if the clock is before the epoch (e.g. on a broken VM).
    pub fn wallclock_ms_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Emit one spawn record. Failures are latched; subsequent recoveries
    /// still attempt to write.
    pub fn record_spawn(&mut self, rec: &SpawnRecord<'_>) {
        let mut body = String::with_capacity(160);
        let _ = write!(
            body,
            "{ms}\t{ns}\tspawn\t{apid}\t{cpid}\t{mode}\t{program}\t{source}\t{tlen}",
            ms = rec.wallclock_ms,
            ns = rec.observer_ns,
            apid = rec.agent_pid,
            cpid = rec.child_pid,
            mode = rec.mode,
            program = sanitize(rec.program),
            source = sanitize(rec.source),
            tlen = rec.template_len,
        );
        self.emit(AuditKind::Spawn, &body);
    }

    /// Emit one "refused" record — the daemon detected a stall but the
    /// recovery command was *not* spawned because of a structural safety
    /// gate (e.g. unauthenticated transport origin).
    pub fn record_refused(&mut self, rec: &RefusedRecord<'_>) {
        let mut body = String::with_capacity(96);
        let _ = write!(
            body,
            "{ms}\t{ns}\trefused\t{apid}\t{reason}",
            ms = rec.wallclock_ms,
            ns = rec.observer_ns,
            apid = rec.agent_pid,
            reason = sanitize(rec.reason),
        );
        self.emit(AuditKind::Refused, &body);
    }

    /// Emit one complete record.
    pub fn record_complete(&mut self, rec: &CompleteRecord) {
        let mut body = String::with_capacity(160);
        let exit = match rec.exit_code {
            Some(c) => format!("{c}"),
            None => "-".to_string(),
        };
        let sig = match rec.signal {
            Some(s) => format!("{s}"),
            None => "-".to_string(),
        };
        let _ = write!(
            body,
            "{ms}\t{ns}\tcomplete\t{apid}\t{cpid}\t{out}\t{exit}\t{sig}\t{dur}\t{olen}\t{elen}\t{trunc}",
            ms = rec.wallclock_ms,
            ns = rec.observer_ns,
            apid = rec.agent_pid,
            cpid = rec.child_pid,
            out = rec.outcome.as_str(),
            exit = exit,
            sig = sig,
            dur = rec.duration_ns,
            olen = rec.stdout_len,
            elen = rec.stderr_len,
            trunc = if rec.truncated { "true" } else { "false" },
        );
        self.emit(AuditKind::Complete, &body);
    }

    /// Take and clear the latched IO error from the most recent failed
    /// write or rotation. Called by the daemon's main loop tick.
    pub fn take_pending_err(&mut self) -> Option<io::Error> {
        self.pending_err.take()
    }

    /// Emit a `boot` record. `prev` is the prior chain to record in the
    /// `prev_chain` column (rendered as hex). Pass `None` to record `-`.
    fn emit_boot(&mut self, reason: BootReason, prev: Option<[u8; 32]>) {
        let prev_str = match prev {
            Some(raw) => hex_encode_32_string(&raw),
            None => "-".to_string(),
        };
        let now_ms = Self::wallclock_ms_now();
        let mut body = String::with_capacity(96);
        let _ = write!(
            body,
            "{ms}\t{ns}\tboot\t{pid}\t{prev}\t{reason}",
            ms = now_ms,
            ns = 0u64,
            pid = self.daemon_pid,
            prev = prev_str,
            reason = reason.as_str(),
        );
        self.emit(AuditKind::Boot, &body);
    }

    /// Common emit path. Owns seq assignment, chain computation, line
    /// write, durability sync, and rotation.
    fn emit(&mut self, kind: AuditKind, body: &str) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        // Hash input is `seq\tbody` so a tampered seq invalidates the
        // chain even when the rest of the line is left alone.
        let mut hash_body = String::with_capacity(body.len() + 24);
        let _ = write!(hash_body, "{seq}\t{body}");

        let chain_hex = self.compute_and_advance_chain(kind, hash_body.as_bytes());

        let mut line = String::with_capacity(hash_body.len() + chain_hex.len() + 2);
        let _ = writeln!(line, "{hash_body}\t{chain_hex}");
        self.write_line(&line);
    }

    /// Compute the next chain hash, advance `self.prev_chain`, and return
    /// the hex (or `-` when audit-chain is off).
    fn compute_and_advance_chain(&mut self, kind: AuditKind, hash_body: &[u8]) -> String {
        #[cfg(feature = "audit-chain")]
        {
            let raw =
                varta_vlp::crypto::audit_chain_hash(&self.prev_chain, kind.as_bytes(), hash_body);
            self.prev_chain = raw;
            hex_encode_32_string(&raw)
        }
        #[cfg(not(feature = "audit-chain"))]
        {
            let _ = (kind, hash_body);
            "-".to_string()
        }
    }

    fn write_line(&mut self, line: &str) {
        match self.sink.write_all(line.as_bytes()) {
            Ok(()) => {
                self.bytes_written = self.bytes_written.saturating_add(line.len() as u64);
                self.writes_since_sync = self.writes_since_sync.saturating_add(1);
                if self.writes_since_sync >= self.sync_every {
                    if let Err(e) = self.flush_and_sync() {
                        self.pending_err = Some(e);
                    } else {
                        self.writes_since_sync = 0;
                    }
                }
                self.maybe_rotate();
            }
            Err(e) => {
                self.pending_err = Some(e);
            }
        }
    }

    /// Flush BufWriter to the kernel, then `fdatasync` the file. Both must
    /// succeed for the data to be considered durable.
    fn flush_and_sync(&mut self) -> io::Result<()> {
        self.sink.flush()?;
        self.sink.get_ref().sync_data()
    }

    fn maybe_rotate(&mut self) {
        let Some(max) = self.max_bytes else {
            return;
        };
        if self.bytes_written < max {
            return;
        }
        if self.rotating {
            // Reentry guard. A `max_bytes` so small that the post-rotation
            // header + boot record alone exceed it would otherwise cause
            // unbounded recursion via emit_boot → write_line → maybe_rotate.
            return;
        }
        self.rotating = true;
        // Capture the final chain *before* the rename — this becomes the
        // `prev_chain` field on the post-rotation `boot` record so chain
        // continuity spans across generations.
        let final_chain = self.prev_chain;
        if let Err(e) = self.flush_and_sync() {
            self.pending_err = Some(e);
            return;
        }
        if let Err(e) = Self::rotate(&self.path) {
            self.pending_err = Some(e);
            return;
        }
        use std::os::unix::fs::OpenOptionsExt;
        let file = match OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
        {
            Ok(f) => f,
            Err(e) => {
                self.pending_err = Some(e);
                return;
            }
        };
        let sink_box: Box<dyn DurableSink> = Box::new(FileSink(file));
        self.sink = BufWriter::new(sink_box);
        self.bytes_written = 0;
        self.writes_since_sync = 0;
        // Fresh v2 header on the post-rotation file.
        if let Err(e) = self.sink.write_all(AUDIT_HEADER_V2.as_bytes()) {
            self.pending_err = Some(e);
            return;
        }
        self.bytes_written = AUDIT_HEADER_V2.len() as u64;
        // Boot record stitches the chain across the rotation.
        self.emit_boot(BootReason::Rotation, Some(final_chain));
        if let Err(e) = self.flush_and_sync() {
            self.pending_err = Some(e);
        } else {
            self.writes_since_sync = 0;
        }
        self.rotating = false;
    }

    fn rotate(path: &Path) -> io::Result<()> {
        let path_str = path.to_string_lossy();
        let oldest = format!("{path_str}.{AUDIT_ROTATION_GENERATIONS}");
        match std::fs::remove_file(&oldest) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        for gen in (1..AUDIT_ROTATION_GENERATIONS).rev() {
            let src = format!("{path_str}.{gen}");
            let dst = format!("{path_str}.{}", gen + 1);
            match std::fs::rename(&src, &dst) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let first = format!("{path_str}.1");
        // CrossesDevices: stable 1.85, MSRV 1.70; correct on Linux/macOS
        #[allow(clippy::incompatible_msrv)]
        match std::fs::rename(path, &first) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
                std::fs::copy(path, &first)?;
                std::fs::remove_file(path)?;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Read up to the last [`TAIL_SCAN_BYTES`] of `path` and parse the
    /// most recent record line to derive seq + chain + boot reason.
    ///
    /// Branches:
    /// - First line is the v1 header → `LegacyV1`.
    /// - First line is the v2 header → try to parse last full line:
    ///   - parse OK → `Resume` with `last_seq` + decoded chain.
    ///   - last line is torn (no trailing `\n` and parse fails) → walk back
    ///     to the prior `\n`, retry. If a prior record parses → `CorruptTail`
    ///     with that prior record's seq + chain and `truncate_to = position
    ///     just past the last full \n`. If nothing parses → `CorruptTail`
    ///     with seq=0, chain=zero, truncate_to=header_end.
    /// - File has neither v1 nor v2 marker → `SchemaDrift`.
    fn probe_tail(path: &Path) -> io::Result<TailProbe> {
        let mut file = OpenOptions::new().read(true).open(path)?;
        let total = file.metadata()?.len();

        if total == 0 {
            return Ok(TailProbe {
                last_seq: 0,
                last_chain: [0u8; 32],
                reason: BootReason::Fresh,
                truncate_to: None,
                has_v2_header: false,
            });
        }

        // Read the first 64 bytes to classify the header.
        let mut head = [0u8; 64];
        let head_read = {
            let n = file.read(&mut head)?;
            &head[..n]
        };
        let head_str = core::str::from_utf8(head_read).unwrap_or("");
        let has_v2_header = head_str.starts_with(AUDIT_HEADER_V2.trim_end_matches('\n'));
        let is_v1 = head_str.starts_with(AUDIT_HEADER_V1_PREFIX);

        if !has_v2_header && is_v1 {
            return Ok(TailProbe {
                last_seq: 0,
                last_chain: [0u8; 32],
                reason: BootReason::LegacyV1,
                truncate_to: None,
                has_v2_header: false,
            });
        }
        if !has_v2_header && !is_v1 {
            return Ok(TailProbe {
                last_seq: 0,
                last_chain: [0u8; 32],
                reason: BootReason::SchemaDrift,
                truncate_to: None,
                has_v2_header: false,
            });
        }

        // v2 header confirmed. Slurp the last TAIL_SCAN_BYTES.
        let scan_len = TAIL_SCAN_BYTES.min(total);
        let scan_start = total - scan_len;
        file.seek(SeekFrom::Start(scan_start))?;
        let mut buf = vec![0u8; scan_len as usize];
        file.read_exact(&mut buf)?;

        // The well-formed case: file ends in `\n`. Find the last newline
        // before the final byte (= start of the last full record), parse.
        if buf.last() == Some(&b'\n') {
            // Strip trailing `\n` so `rsplit` finds the line above.
            let view = &buf[..buf.len() - 1];
            let last_line_start = view
                .iter()
                .rposition(|&b| b == b'\n')
                .map(|p| p + 1)
                .unwrap_or(0);
            let last_line = &view[last_line_start..];
            if let Some((seq, chain)) = parse_record(last_line) {
                return Ok(TailProbe {
                    last_seq: seq,
                    last_chain: chain,
                    reason: BootReason::Resume,
                    truncate_to: None,
                    has_v2_header: true,
                });
            }
            // Trailing `\n` present but the last line is unparseable.
            // Treat as schema drift on a v2 file; do not truncate (the line
            // is whole, it's just garbage we don't recognise).
            return Ok(TailProbe {
                last_seq: 0,
                last_chain: [0u8; 32],
                reason: BootReason::SchemaDrift,
                truncate_to: None,
                has_v2_header: true,
            });
        }

        // No trailing `\n` → torn write. Find the last `\n` and treat
        // everything after it as garbage to be truncated away. Recover seq
        // + chain from the *previous* line if we can.
        let last_nl = buf.iter().rposition(|&b| b == b'\n');
        let truncate_to = match last_nl {
            Some(rel) => Some(scan_start + (rel as u64) + 1),
            None => {
                // No newline at all in the scan window — file is small and
                // entirely torn after the header. Truncate to the end of
                // the header.
                Some(AUDIT_HEADER_V2.len() as u64)
            }
        };

        if let Some(rel) = last_nl {
            // The byte before this `\n` is the end of the last good line.
            // Walk back to find that line's start.
            let view = &buf[..rel];
            let prev_start = view
                .iter()
                .rposition(|&b| b == b'\n')
                .map(|p| p + 1)
                .unwrap_or(0);
            let prev_line = &view[prev_start..];
            if let Some((seq, chain)) = parse_record(prev_line) {
                return Ok(TailProbe {
                    last_seq: seq,
                    last_chain: chain,
                    reason: BootReason::CorruptTail,
                    truncate_to,
                    has_v2_header: true,
                });
            }
        }

        Ok(TailProbe {
            last_seq: 0,
            last_chain: [0u8; 32],
            reason: BootReason::CorruptTail,
            truncate_to,
            has_v2_header: true,
        })
    }
}

impl Drop for RecoveryAuditLog {
    fn drop(&mut self) {
        let _ = self.sink.flush();
        // Best-effort durability on shutdown.
        let _ = self.sink.get_ref().sync_data();
    }
}

/// True iff the build includes the `audit-chain` feature.
#[inline]
pub fn chain_enabled() -> bool {
    cfg!(feature = "audit-chain")
}

/// Parse a single TSV record line of v2 format. Returns `(seq, chain_raw)`
/// if both the leading seq column and trailing chain column decode.
///
/// We are deliberately permissive about *which* record kind the line is —
/// continuity only needs seq and chain. A line we don't understand (e.g. a
/// future record kind in a forward-compatible v2 schema extension) is fine
/// to skip as long as those two columns are well-formed.
fn parse_record(line: &[u8]) -> Option<(u64, [u8; 32])> {
    let s = core::str::from_utf8(line).ok()?;
    // Comment lines (alternative header sections) carry no record state.
    if s.starts_with('#') {
        return None;
    }
    let mut cols = s.split('\t');
    let seq_str = cols.next()?;
    let seq: u64 = seq_str.parse().ok()?;
    let chain_str = s.rsplit('\t').next()?;
    if chain_str == "-" {
        // Pre-existing audit-chain-off section. Continue with zero
        // prev_chain — the auditor will see in the column itself that the
        // chain was not running.
        return Some((seq, [0u8; 32]));
    }
    if chain_str.len() != 64 {
        return None;
    }
    let raw = varta_vlp::util::decode_hex_32(chain_str.as_bytes()).ok()?;
    Some((seq, raw))
}

/// Replace tab/newline bytes in a free-form audit field with a literal
/// space so a maliciously-chosen file path or argv[0] can never inject
/// a fake column into the TSV.
fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\t' | '\n' | '\r' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}

/// Hex-encode a 32-byte chain hash into a 64-char lowercase string.
fn hex_encode_32_string(bytes: &[u8; 32]) -> String {
    let hex = varta_vlp::util::encode_hex_32(bytes);
    // SAFETY: encode_hex_32 always emits ASCII bytes.
    String::from_utf8(hex.to_vec()).expect("hex output is ASCII")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;

    fn tmpdir(tag: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "varta-audit-test-{tag}-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir(&dir).expect("create tempdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod tempdir");
        dir
    }

    fn cfg(max_bytes: Option<u64>, sync_every: u32) -> AuditConfig {
        AuditConfig {
            max_bytes,
            sync_every,
            daemon_pid: 1234,
        }
    }

    /// Count fdatasync calls without depending on the kernel. Used in
    /// cadence tests.
    #[derive(Default)]
    struct SyncCounter {
        writes: Mutex<usize>,
        syncs: Mutex<usize>,
        buf: Mutex<Vec<u8>>,
    }

    struct CountingSink(Arc<SyncCounter>);

    impl Write for CountingSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            *self.0.writes.lock().unwrap() += 1;
            self.0.buf.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl DurableSink for CountingSink {
        fn sync_data(&self) -> io::Result<()> {
            *self.0.syncs.lock().unwrap() += 1;
            Ok(())
        }
    }

    fn synthetic_log_with_counter(sync_every: u32) -> (RecoveryAuditLog, Arc<SyncCounter>) {
        let ctr = Arc::new(SyncCounter::default());
        let sink: Box<dyn DurableSink> = Box::new(CountingSink(ctr.clone()));
        let log = RecoveryAuditLog {
            sink: BufWriter::new(sink),
            path: PathBuf::from("/dev/null"),
            max_bytes: None,
            bytes_written: 0,
            pending_err: None,
            next_seq: 1,
            prev_chain: [0u8; 32],
            sync_every,
            writes_since_sync: 0,
            daemon_pid: 1234,
            rotating: false,
        };
        (log, ctr)
    }

    #[test]
    fn header_is_written_on_fresh_file() {
        let dir = tmpdir("hdr");
        let path = dir.join("audit.log");
        let (log, w) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        drop(log);
        let body = std::fs::read_to_string(&path).expect("read");
        assert!(body.starts_with("# varta-watch recovery audit v2\n"));
        // Fresh file → fresh boot record on the second line.
        let lines: Vec<&str> = body.lines().collect();
        assert!(lines.len() >= 2);
        assert!(lines[1].contains("\tboot\t"));
        assert!(lines[1].contains("\tfresh\t") || lines[1].ends_with("\tfresh\t-"));
        assert!(!w.legacy_v1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spawn_and_complete_round_trip_with_seq_and_chain_columns() {
        let dir = tmpdir("rt");
        let path = dir.join("audit.log");
        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        log.record_spawn(&SpawnRecord {
            wallclock_ms: 1_700_000_000_000,
            observer_ns: 42,
            agent_pid: 7,
            child_pid: 9001,
            mode: "exec",
            program: "/usr/bin/restart-agent",
            source: "inline",
            template_len: 22,
        });
        log.record_complete(&CompleteRecord {
            wallclock_ms: 1_700_000_001_500,
            observer_ns: 1_500_000_042,
            agent_pid: 7,
            child_pid: 9001,
            outcome: CompleteOutcome::Reaped,
            exit_code: Some(0),
            signal: None,
            duration_ns: 1_500_000_000,
            stdout_len: 0,
            stderr_len: 0,
            truncated: false,
        });
        drop(log);
        let body = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = body.lines().filter(|l| !l.starts_with('#')).collect();
        // boot + spawn + complete = 3 record lines.
        assert_eq!(lines.len(), 3, "got: {body}");

        // All record lines start with their seq column and end with a
        // chain column (literal `-` when audit-chain is off, 64 hex chars
        // otherwise).
        for (expected_seq, line) in (1..=3u64).zip(&lines) {
            let cols: Vec<&str> = line.split('\t').collect();
            let seq: u64 = cols[0].parse().expect("seq column parses");
            assert_eq!(seq, expected_seq);
            let chain = cols.last().expect("chain column");
            if chain_enabled() {
                assert_eq!(chain.len(), 64, "chain column should be 64 hex chars");
            } else {
                assert_eq!(*chain, "-");
            }
        }

        // Spawn record body fields are preserved.
        assert!(lines[1].contains("\tspawn\t7\t9001\texec\t"));
        // Complete record body fields are preserved.
        assert!(lines[2].contains("\tcomplete\t7\t9001\treaped\t0\t-\t1500000000\t0\t0\tfalse"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refused_record_emits_seq_and_chain() {
        let dir = tmpdir("ref");
        let path = dir.join("audit.log");
        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        log.record_refused(&RefusedRecord {
            wallclock_ms: 1_700_000_000_000,
            observer_ns: 99,
            agent_pid: 12,
            reason: "unauthenticated_transport",
        });
        drop(log);
        let body = std::fs::read_to_string(&path).expect("read");
        let last = body.lines().next_back().expect("at least one line");
        let cols: Vec<&str> = last.split('\t').collect();
        assert_eq!(cols[0], "2", "seq increments after boot");
        assert!(cols.contains(&"refused"));
        assert!(cols.contains(&"unauthenticated_transport"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_engages_at_max_bytes_with_chain_continuity() {
        let dir = tmpdir("rot");
        let path = dir.join("audit.log");
        // Tiny cap forces rotation.
        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(Some(160), 1)).expect("create");
        for i in 0..8u32 {
            log.record_spawn(&SpawnRecord {
                wallclock_ms: i as u64,
                observer_ns: i as u64,
                agent_pid: i,
                child_pid: 1000 + i,
                mode: "exec",
                program: "/bin/true",
                source: "inline",
                template_len: 9,
            });
        }
        drop(log);
        assert!(path.with_extension("log.1").exists());

        // The post-rotation file must start with a v2 header followed by a
        // `rotation` boot record carrying a non-`-` prev_chain when
        // audit-chain is on.
        let head = std::fs::read_to_string(&path).expect("read");
        assert!(head.starts_with("# varta-watch recovery audit v2"));
        let first_record = head
            .lines()
            .find(|l| !l.starts_with('#'))
            .expect("at least one record");
        assert!(first_record.contains("\tboot\t"));
        assert!(first_record.contains("\trotation\t"));
        if chain_enabled() {
            // The prev_chain column is column index 4 in a boot record:
            // seq\tms\tns\tboot\tpid\tprev\treason\tchain.
            let cols: Vec<&str> = first_record.split('\t').collect();
            assert_eq!(cols.len(), 8, "boot record column count");
            assert_eq!(cols[3], "boot");
            let prev = cols[5];
            assert_eq!(prev.len(), 64, "prev_chain should carry pre-rotation hash");
            assert_ne!(prev, "0".repeat(64), "prev_chain should be non-zero");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_resumes_seq_and_chain_from_v2_tail() {
        let dir = tmpdir("resume");
        let path = dir.join("audit.log");

        // First session — write a few records.
        let (mut log1, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        log1.record_spawn(&SpawnRecord {
            wallclock_ms: 1,
            observer_ns: 1,
            agent_pid: 1,
            child_pid: 100,
            mode: "exec",
            program: "/bin/x",
            source: "inline",
            template_len: 1,
        });
        log1.record_spawn(&SpawnRecord {
            wallclock_ms: 2,
            observer_ns: 2,
            agent_pid: 2,
            child_pid: 200,
            mode: "exec",
            program: "/bin/x",
            source: "inline",
            template_len: 1,
        });
        drop(log1);

        // Second session — should resume with a `resume` boot.
        let (mut log2, w) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        assert!(!w.legacy_v1);
        assert!(!w.corrupt_tail);
        assert!(!w.schema_drift);
        log2.record_spawn(&SpawnRecord {
            wallclock_ms: 3,
            observer_ns: 3,
            agent_pid: 3,
            child_pid: 300,
            mode: "exec",
            program: "/bin/x",
            source: "inline",
            template_len: 1,
        });
        drop(log2);

        let body = std::fs::read_to_string(&path).expect("read");
        let records: Vec<&str> = body.lines().filter(|l| !l.starts_with('#')).collect();
        // boot(fresh) + spawn + spawn + boot(resume) + spawn = 5 records.
        assert_eq!(records.len(), 5, "got: {body}");
        // Seq strictly monotonic.
        let mut last_seq = 0u64;
        for rec in &records {
            let seq: u64 = rec.split('\t').next().unwrap().parse().unwrap();
            assert!(
                seq > last_seq,
                "seq must be monotonic: {seq} after {last_seq}"
            );
            last_seq = seq;
        }
        // The 4th record should be a boot with reason=resume.
        assert!(records[3].contains("\tboot\t"));
        assert!(records[3].contains("\tresume"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_v1_file_gets_legacy_v1_boot() {
        let dir = tmpdir("v1");
        let path = dir.join("audit.log");
        // Forge a v1 file with one fake record.
        std::fs::write(
            &path,
            "# varta-watch recovery audit v1\n\
             1700000000000\t42\tspawn\t7\t9001\texec\t/bin/true\tinline\t9\n",
        )
        .expect("write v1");

        let (log, w) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        assert!(w.legacy_v1);
        drop(log);

        let body = std::fs::read_to_string(&path).expect("read");
        assert!(body.contains("# varta-watch recovery audit v1\n"));
        assert!(body.contains("# varta-watch recovery audit v2\n"));
        // The v2 section begins with a legacy_v1 boot record.
        let v2_section_start = body.find("# varta-watch recovery audit v2").unwrap();
        let v2_section = &body[v2_section_start..];
        let first_record = v2_section
            .lines()
            .find(|l| !l.starts_with('#'))
            .expect("v2 record");
        assert!(first_record.contains("\tboot\t"));
        assert!(first_record.contains("\tlegacy_v1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn schema_drift_file_gets_schema_drift_boot() {
        let dir = tmpdir("drift");
        let path = dir.join("audit.log");
        std::fs::write(&path, "not an audit log at all\n").expect("write drift");

        let (log, w) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        assert!(w.schema_drift);
        drop(log);

        let body = std::fs::read_to_string(&path).expect("read");
        // The v2 header was appended on a new line.
        assert!(body.contains("# varta-watch recovery audit v2\n"));
        let v2_section_start = body.find("# varta-watch recovery audit v2").unwrap();
        let v2_section = &body[v2_section_start..];
        let first_record = v2_section
            .lines()
            .find(|l| !l.starts_with('#'))
            .expect("v2 record");
        assert!(first_record.contains("\tboot\t"));
        assert!(first_record.contains("\tschema_drift"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_tail_truncates_and_emits_corrupt_tail_boot() {
        let dir = tmpdir("torn");
        let path = dir.join("audit.log");

        let (mut log1, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        log1.record_spawn(&SpawnRecord {
            wallclock_ms: 1,
            observer_ns: 1,
            agent_pid: 1,
            child_pid: 100,
            mode: "exec",
            program: "/bin/x",
            source: "inline",
            template_len: 1,
        });
        drop(log1);

        // Append a torn partial line (no trailing `\n`).
        {
            use std::io::Write;
            let mut f = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open append");
            f.write_all(b"99\t12345\t99\tspaw").expect("torn write");
        }

        let len_before = std::fs::metadata(&path).expect("meta").len();
        let (log2, w) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        assert!(w.corrupt_tail);
        drop(log2);

        let len_after = std::fs::metadata(&path).expect("meta").len();
        // File should have been truncated then re-extended with v2 boot.
        // The torn fragment must NOT be present in the final file.
        let body = std::fs::read_to_string(&path).expect("read");
        assert!(
            !body.contains("99\t12345\t99\tspaw"),
            "torn fragment must be removed"
        );
        // Boot record with corrupt_tail reason is present.
        assert!(body.contains("\tcorrupt_tail"));
        // Sanity: file is at least as big as the truncation point (because
        // we wrote a boot record after).
        assert!(len_after > 0);
        let _ = len_before;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cadence_arithmetic_sync_every_1() {
        let (mut log, ctr) = synthetic_log_with_counter(1);
        log.record_spawn(&SpawnRecord {
            wallclock_ms: 0,
            observer_ns: 0,
            agent_pid: 1,
            child_pid: 1,
            mode: "exec",
            program: "p",
            source: "inline",
            template_len: 0,
        });
        log.record_spawn(&SpawnRecord {
            wallclock_ms: 0,
            observer_ns: 0,
            agent_pid: 2,
            child_pid: 2,
            mode: "exec",
            program: "p",
            source: "inline",
            template_len: 0,
        });
        drop(log);
        // Two records → at least two syncs from the emit path (Drop adds
        // another best-effort flush+sync, but we test the cadence itself).
        let syncs = *ctr.syncs.lock().unwrap();
        assert!(syncs >= 2, "sync_every=1 must sync per record, got {syncs}");
    }

    #[test]
    fn cadence_arithmetic_sync_every_3() {
        let (mut log, ctr) = synthetic_log_with_counter(3);
        for i in 0..6u32 {
            log.record_spawn(&SpawnRecord {
                wallclock_ms: 0,
                observer_ns: 0,
                agent_pid: i,
                child_pid: i,
                mode: "exec",
                program: "p",
                source: "inline",
                template_len: 0,
            });
        }
        // 6 record_spawn calls → exactly 2 sync_data invocations from the
        // emit cadence (Drop adds 1 more best-effort).
        let syncs_pre_drop = *ctr.syncs.lock().unwrap();
        drop(log);
        let syncs_post_drop = *ctr.syncs.lock().unwrap();
        assert_eq!(
            syncs_pre_drop, 2,
            "sync_every=3 over 6 writes should sync 2x"
        );
        assert_eq!(syncs_post_drop, 3, "drop should add one best-effort sync");
    }

    #[test]
    fn sanitize_strips_tabs_and_newlines() {
        assert_eq!(sanitize("a\tb"), "a b");
        assert_eq!(sanitize("a\nb"), "a b");
        assert_eq!(sanitize("/usr/bin/x"), "/usr/bin/x");
    }

    #[test]
    fn sync_every_zero_is_rejected() {
        let dir = tmpdir("syncz");
        let path = dir.join("audit.log");
        let err = match RecoveryAuditLog::create(&path, cfg(None, 0)) {
            Ok(_) => panic!("create must reject sync_every=0"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_relaxed_warning_set_above_one() {
        let dir = tmpdir("syncr");
        let path = dir.join("audit.log");
        let (_, w) = RecoveryAuditLog::create(&path, cfg(None, 5)).expect("create");
        assert!(w.sync_relaxed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Chain determinism — same inputs produce same chain hex across runs.
    /// Only enforced when audit-chain is compiled in.
    #[cfg(feature = "audit-chain")]
    #[test]
    fn chain_is_deterministic_across_identical_runs() {
        let dir = tmpdir("det");
        let path1 = dir.join("a.log");
        let path2 = dir.join("b.log");
        let cfgx = AuditConfig {
            max_bytes: None,
            sync_every: 1,
            daemon_pid: 7777,
        };

        let extract_chain = |p: &Path| -> String {
            let body = std::fs::read_to_string(p).unwrap();
            let last = body
                .lines()
                .rfind(|l| !l.starts_with('#'))
                .unwrap()
                .to_string();
            last.rsplit('\t').next().unwrap().to_string()
        };

        for p in &[&path1, &path2] {
            let (mut log, _) = RecoveryAuditLog::create(p, cfgx.clone()).expect("create");
            // Force the synthetic boot record to have identical inputs by
            // overriding the wall-clock-dependent fields.
            log.next_seq = 1;
            log.prev_chain = [0u8; 32];
            // Re-emit the boot manually with a known timestamp so the chain
            // is reproducible across runs in test conditions.
            let mut body = String::new();
            let _ = write!(
                body,
                "{ms}\t{ns}\tboot\t{pid}\t-\tfresh",
                ms = 1700000000000u64,
                ns = 0u64,
                pid = 7777,
            );
            log.emit(AuditKind::Boot, &body);
            drop(log);
        }

        assert_eq!(extract_chain(&path1), extract_chain(&path2));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
