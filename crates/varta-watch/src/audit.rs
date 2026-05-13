//! Recovery audit log — tab-separated record of every recovery spawn/complete.
//!
//! In safety-critical deployments (hospital/airport) every recovery action
//! must be auditable: who, what, when, outcome. The existing stderr log
//! provides "what" + child pid only — no command identity, no exit code as
//! a number, no duration, no wall-clock timestamp. This module fills the
//! gap with a dedicated append-only TSV file.
//!
//! # Schema
//!
//! Two record kinds, fixed column count per kind. Header line written on
//! file creation:
//!
//! ```text
//! # varta-watch recovery audit v1
//! # spawn:    wallclock_ms\tobserver_ns\tspawn\tagent_pid\tchild_pid\tmode\tprogram\tsource\ttemplate_len
//! # complete: wallclock_ms\tobserver_ns\tcomplete\tagent_pid\tchild_pid\toutcome\texit_code|-\tsignal|-\tduration_ns\tstdout_len\tstderr_len\ttruncated
//! ```
//!
//! `wallclock_ms` is milliseconds since the UNIX epoch. `observer_ns` is the
//! monotonic timestamp consistent with the event-stream TSV. Operators
//! correlate audit lines against the event log via `observer_ns`.
//!
//! # Rotation
//!
//! When `max_bytes` is configured, the file rotates after every write that
//! pushes its size over the limit: `PATH` → `PATH.1` → … → `PATH.5`. Same
//! generation count as the event-stream `FileExporter`.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Number of rotated file generations kept. Mirrors
/// `crate::exporter::MAX_ROTATION_GENERATIONS`.
const AUDIT_ROTATION_GENERATIONS: u32 = 5;

/// Header line written to a freshly-created audit file. Wrapped in a v1 tag
/// so future schema changes are detectable by consumers.
///
/// **v1 schema additions (compatible).** The original v1 schema documented
/// `spawn` and `complete` records. A third record kind, `refused`, was added
/// while the schema tag stayed at v1 because the format is TSV-with-fixed
/// columns-per-record-kind: an old reader keying on the third column
/// (`spawn` / `complete`) will see `refused` lines and ignore them or surface
/// them as "unknown record kind" without misparsing the other lines.
const AUDIT_HEADER: &str = "# varta-watch recovery audit v1\n";

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

/// Append-only audit sink. One file descriptor held for the daemon's life,
/// reopened on rotation. Writes never block the recovery path: on IO error
/// the failure is latched in `pending_err` and the daemon's normal logging
/// surface picks it up (mirrors `FileExporter`).
pub struct RecoveryAuditLog {
    sink: BufWriter<File>,
    path: PathBuf,
    max_bytes: Option<u64>,
    bytes_written: u64,
    pending_err: Option<io::Error>,
}

impl RecoveryAuditLog {
    /// Open `path` in append mode, creating it (and writing the header)
    /// if necessary. The file is opened with mode 0600 on create so an
    /// operator who configured `--recovery-audit-file /tmp/foo` does not
    /// accidentally publish recovery activity world-readable.
    pub fn create(path: impl AsRef<Path>, max_bytes: Option<u64>) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;

        let path_buf = path.as_ref().to_path_buf();
        let existed = path_buf.exists();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path_buf)?;
        let mut bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut sink = BufWriter::new(file);
        if !existed || bytes_written == 0 {
            sink.write_all(AUDIT_HEADER.as_bytes())?;
            sink.flush()?;
            bytes_written = AUDIT_HEADER.len() as u64;
        }
        Ok(RecoveryAuditLog {
            sink,
            path: path_buf,
            max_bytes,
            bytes_written,
            pending_err: None,
        })
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
        // Pre-size the line buffer to skip a couple of small reallocs.
        let mut line = String::with_capacity(160);
        let _ = writeln!(
            line,
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
        self.write_line(&line);
    }

    /// Emit one "refused" record — the daemon detected a stall but the
    /// recovery command was *not* spawned because of a structural safety
    /// gate (e.g. unauthenticated transport origin).
    ///
    /// Schema (third column = `refused`):
    /// ```text
    /// wallclock_ms\tobserver_ns\trefused\tagent_pid\treason
    /// ```
    ///
    /// `reason` is a short stable token (e.g. `unauthenticated_transport`)
    /// so SIEM consumers can alert on it without parsing free text.
    pub fn record_refused(&mut self, rec: &RefusedRecord<'_>) {
        let mut line = String::with_capacity(96);
        let _ = writeln!(
            line,
            "{ms}\t{ns}\trefused\t{apid}\t{reason}",
            ms = rec.wallclock_ms,
            ns = rec.observer_ns,
            apid = rec.agent_pid,
            reason = sanitize(rec.reason),
        );
        self.write_line(&line);
    }

    /// Emit one complete record.
    pub fn record_complete(&mut self, rec: &CompleteRecord) {
        let mut line = String::with_capacity(160);
        let exit = match rec.exit_code {
            Some(c) => format!("{c}"),
            None => "-".to_string(),
        };
        let sig = match rec.signal {
            Some(s) => format!("{s}"),
            None => "-".to_string(),
        };
        let _ = writeln!(
            line,
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
        self.write_line(&line);
    }

    /// Take and clear the latched IO error from the most recent failed
    /// write or rotation.
    pub fn take_pending_err(&mut self) -> Option<io::Error> {
        self.pending_err.take()
    }

    fn write_line(&mut self, line: &str) {
        match self.sink.write_all(line.as_bytes()) {
            Ok(()) => {
                self.bytes_written = self.bytes_written.saturating_add(line.len() as u64);
                self.maybe_rotate();
            }
            Err(e) => {
                self.pending_err = Some(e);
            }
        }
    }

    fn maybe_rotate(&mut self) {
        let Some(max) = self.max_bytes else {
            return;
        };
        if self.bytes_written < max {
            return;
        }
        if let Err(e) = self.sink.flush() {
            self.pending_err = Some(e);
            return;
        }
        if let Err(e) = Self::rotate(&self.path) {
            self.pending_err = Some(e);
            return;
        }
        use std::os::unix::fs::OpenOptionsExt;
        match OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)
        {
            Ok(file) => {
                self.sink = BufWriter::new(file);
                self.bytes_written = 0;
                // Fresh post-rotation file gets a header line so a consumer
                // that only sees the new generation still has a schema tag.
                if let Err(e) = self.sink.write_all(AUDIT_HEADER.as_bytes()) {
                    self.pending_err = Some(e);
                } else {
                    self.bytes_written = AUDIT_HEADER.len() as u64;
                }
            }
            Err(e) => {
                self.pending_err = Some(e);
            }
        }
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
}

impl Drop for RecoveryAuditLog {
    fn drop(&mut self) {
        let _ = self.sink.flush();
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // A parallel `UnixDatagram::bind` in another test installs a
        // 0o177 umask that strips the `x` bit; restore the dir mode so
        // subsequent open() inside this dir doesn't EACCES.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod tempdir");
        dir
    }

    #[test]
    fn header_is_written_on_fresh_file() {
        let dir = tmpdir("hdr");
        let path = dir.join("audit.log");
        let log = RecoveryAuditLog::create(&path, None).expect("create");
        drop(log);
        let body = std::fs::read_to_string(&path).expect("read");
        assert!(body.starts_with("# varta-watch recovery audit v1\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spawn_and_complete_round_trip() {
        let dir = tmpdir("rt");
        let path = dir.join("audit.log");
        let mut log = RecoveryAuditLog::create(&path, None).expect("create");
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
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3, "header + spawn + complete; got: {body}");
        assert!(lines[1].starts_with("1700000000000\t42\tspawn\t7\t9001\texec\t"));
        assert!(lines[2].contains("\tcomplete\t7\t9001\treaped\t0\t-\t1500000000\t0\t0\tfalse"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_engages_at_max_bytes() {
        let dir = tmpdir("rot");
        let path = dir.join("audit.log");
        // Tiny cap forces rotation after the first record line.
        let mut log = RecoveryAuditLog::create(&path, Some(80)).expect("create");
        for i in 0..6u32 {
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
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_strips_tabs_and_newlines() {
        assert_eq!(sanitize("a\tb"), "a b");
        assert_eq!(sanitize("a\nb"), "a b");
        assert_eq!(sanitize("/usr/bin/x"), "/usr/bin/x");
    }
}
