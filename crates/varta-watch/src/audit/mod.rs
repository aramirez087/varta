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
//!    over `DOMAIN || kind || prev_chain_raw || body_with_seq`. With the
//!    feature off, the column is a literal `-` and the daemon prints one
//!    startup warning saying the build is not Class-C-conforming.

mod rotation;
mod schema;
mod writer;

pub use rotation::RotationOutcome;
pub use schema::{chain_enabled, CompleteOutcome, CompleteRecord, RefusedRecord, SpawnRecord};

use rotation::{RotationProgress, TailProbe};
use schema::{sanitize, AuditKind, BootReason, AUDIT_HEADER_V2};
use writer::{DurableSink, FileSink, AUDIT_RING_CAP, FSYNC_HISTORY_CAP};

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Append-only audit sink. One file descriptor held for the daemon's life,
/// reopened on rotation. Writes never block the recovery path: on IO error
/// the failure is latched in `pending_err` and the daemon's main loop
/// drains it via [`take_pending_err`] (mirrors `FileExporter`).
pub struct RecoveryAuditLog {
    pub(in crate::audit) sink: BufWriter<Box<dyn DurableSink>>,
    pub(super) path: PathBuf,
    pub(super) max_bytes: Option<u64>,
    pub(super) bytes_written: u64,
    pub(super) pending_err: Option<io::Error>,
    pub(super) next_seq: u64,
    pub(super) prev_chain: [u8; 32],
    pub(super) sync_every: u32,
    pub(super) writes_since_sync: u32,
    pub(super) daemon_pid: u32,
    /// Ring buffer of fully-formatted lines awaiting the maintenance phase
    /// drain. Hot-path callers enqueue here; `flush_pending` does the actual
    /// BufWriter write + fdatasync, bounded by a per-tick time budget.
    pub(super) pending_lines: VecDeque<String>,
    pub(super) audit_dropped_total: u64,
    pub(super) audit_flush_budget_exceeded_total: u64,
    pub(super) fsync_budget: Duration,
    pub(super) sync_interval: Option<Duration>,
    pub(super) last_sync_at: Option<Instant>,
    pub(super) fsync_durations: VecDeque<Duration>,
    pub(super) audit_fsync_budget_exceeded_total: u64,
    pub(super) audit_rotation_budget_exceeded_total: u64,
    pub(super) audit_ring_watermark_warn_total: u64,
    pub(super) audit_ring_watermark_critical_total: u64,
    pub(super) ring_above_warn: bool,
    pub(super) ring_above_critical: bool,
    pub(super) deferred_fsync_in_drain: bool,
    /// Hot-path flag: set by `direct_write_line` when `bytes_written >=
    /// max_bytes`. The main loop calls `drive_audit_rotation` when set.
    pub(super) needs_rotation: bool,
    pub(in crate::audit) rotation_progress: RotationProgress,
}

/// Configuration accepted by [`RecoveryAuditLog::create`].
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Size at which the file rotates; `None` disables rotation.
    pub max_bytes: Option<u64>,
    /// How many records between forced `fdatasync` calls. `1` (= every
    /// record) is the only IEC 62304 Class C-conforming value.
    pub sync_every: u32,
    /// `getpid()` of the varta-watch daemon; recorded on every `boot` record.
    pub daemon_pid: u32,
    /// Soft per-call budget for a single `fdatasync(2)`. `Duration::ZERO` is
    /// invalid.
    pub fsync_budget: Duration,
    /// Time-based fdatasync cadence. `None` falls back to record cadence only.
    pub sync_interval: Option<Duration>,
    /// Per-tick wall-clock budget for the rotation state machine. `Duration::ZERO`
    /// is invalid.
    pub rotation_budget: Duration,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            max_bytes: None,
            sync_every: 1,
            daemon_pid: std::process::id(),
            fsync_budget: Duration::from_millis(50),
            sync_interval: None,
            rotation_budget: Duration::from_millis(50),
        }
    }
}

/// Side-channel from [`RecoveryAuditLog::create`] — warnings the daemon
/// should surface before entering its main loop.
#[derive(Debug, Default)]
pub struct CreateWarnings {
    /// True iff the build is missing the `audit-chain` feature.
    pub chain_disabled: bool,
    /// True iff `sync_every > 1`.
    pub sync_relaxed: bool,
    /// True iff the file existed with a v1 header.
    pub legacy_v1: bool,
    /// True iff the file existed with a torn tail that was truncated.
    pub corrupt_tail: bool,
    /// True iff the file existed with an unrecognised header.
    pub schema_drift: bool,
}

impl RecoveryAuditLog {
    /// Open `path` in append mode, creating it (and writing the header)
    /// if necessary. The file is opened with mode 0600 on create.
    pub fn create(path: impl AsRef<Path>, cfg: AuditConfig) -> io::Result<(Self, CreateWarnings)> {
        use std::os::unix::fs::OpenOptionsExt;

        let path_buf = path.as_ref().to_path_buf();
        let existed = path_buf.exists();

        let mut warnings = CreateWarnings::default();
        if !chain_enabled() {
            warnings.chain_disabled = true;
        }
        if cfg.sync_every == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit sync_every must be >= 1",
            ));
        }
        if cfg.sync_every > 1 {
            warnings.sync_relaxed = true;
        }
        if cfg.fsync_budget.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit fsync_budget must be > 0",
            ));
        }
        if cfg.rotation_budget.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "audit rotation_budget must be > 0",
            ));
        }

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
            pending_lines: VecDeque::with_capacity(AUDIT_RING_CAP),
            audit_dropped_total: 0,
            audit_flush_budget_exceeded_total: 0,
            fsync_budget: cfg.fsync_budget,
            sync_interval: cfg.sync_interval,
            last_sync_at: None,
            fsync_durations: VecDeque::with_capacity(FSYNC_HISTORY_CAP),
            audit_fsync_budget_exceeded_total: 0,
            audit_rotation_budget_exceeded_total: 0,
            audit_ring_watermark_warn_total: 0,
            audit_ring_watermark_critical_total: 0,
            ring_above_warn: false,
            ring_above_critical: false,
            deferred_fsync_in_drain: false,
            needs_rotation: false,
            rotation_progress: RotationProgress::Idle,
        };

        let prev_for_boot = match probe.reason {
            BootReason::Resume => Some(probe.last_chain),
            _ => None,
        };
        log.emit_boot(probe.reason, prev_for_boot);

        Ok((log, warnings))
    }

    /// Wall-clock ms since UNIX epoch for the current instant.
    pub fn wallclock_ms_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Emit one spawn record.
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

    /// Emit one "refused" record.
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

    /// Take and clear the latched IO error from the most recent failed write or
    /// rotation.
    pub fn take_pending_err(&mut self) -> Option<io::Error> {
        self.pending_err.take()
    }

    /// Drain buffered lines to the BufWriter, stopping when `budget` elapses.
    /// Called once per tick from the maintenance phase.
    pub fn flush_pending(&mut self, budget: Duration) {
        let start = Instant::now();
        self.deferred_fsync_in_drain = false;
        while !self.pending_lines.is_empty() {
            if start.elapsed() >= budget {
                self.audit_flush_budget_exceeded_total =
                    self.audit_flush_budget_exceeded_total.saturating_add(1);
                break;
            }
            let line = self.pending_lines.pop_front().unwrap();
            if self.direct_write_line(&line) {
                self.refresh_falling_edge_watermarks();
            } else {
                self.pending_lines.push_front(line);
                break;
            }
        }
        self.refresh_falling_edge_watermarks();
    }

    /// Take and reset the count of lines dropped because the ring was full.
    pub fn take_audit_dropped(&mut self) -> u64 {
        core::mem::replace(&mut self.audit_dropped_total, 0)
    }

    /// Take and reset the count of ticks where `flush_pending` hit its budget
    /// before emptying the ring.
    pub fn take_audit_flush_budget_exceeded(&mut self) -> u64 {
        core::mem::replace(&mut self.audit_flush_budget_exceeded_total, 0)
    }

    /// Drain (and clear) buffered `fdatasync` durations for the exporter.
    pub fn take_audit_fsync_durations(&mut self) -> Vec<Duration> {
        let n = self.fsync_durations.len();
        let mut out = Vec::with_capacity(n);
        out.extend(self.fsync_durations.drain(..));
        out
    }

    /// Take and reset the count of `fdatasync(2)` calls that exceeded
    /// `fsync_budget`.
    pub fn take_audit_fsync_budget_exceeded(&mut self) -> u64 {
        core::mem::replace(&mut self.audit_fsync_budget_exceeded_total, 0)
    }

    /// Take and reset the count of `drive_audit_rotation` calls that exceeded
    /// `rotation_budget`.
    pub fn take_audit_rotation_budget_exceeded(&mut self) -> u64 {
        core::mem::replace(&mut self.audit_rotation_budget_exceeded_total, 0)
    }

    /// Take and reset the rising-edge ring-warn watermark counter.
    pub fn take_audit_ring_watermark_warn(&mut self) -> u64 {
        core::mem::replace(&mut self.audit_ring_watermark_warn_total, 0)
    }

    /// Take and reset the rising-edge ring-critical watermark counter.
    pub fn take_audit_ring_watermark_critical(&mut self) -> u64 {
        core::mem::replace(&mut self.audit_ring_watermark_critical_total, 0)
    }

    /// Returns `true` while a rotation is in progress across ticks.
    pub fn audit_rotation_pending(&self) -> bool {
        !self.rotation_progress.is_idle()
    }

    /// Returns `true` when the file has crossed its `max_bytes` cap and a
    /// rotation should be started.
    pub fn audit_rotation_due(&self) -> bool {
        self.needs_rotation
    }
}

impl Drop for RecoveryAuditLog {
    fn drop(&mut self) {
        while let Some(line) = self.pending_lines.pop_front() {
            if !self.direct_write_line(&line) {
                break;
            }
        }
        let _ = self.sink.flush();
        let _ = self.sink.get_ref().sync_data();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
            fsync_budget: Duration::from_millis(50),
            sync_interval: None,
            rotation_budget: Duration::from_millis(50),
        }
    }

    #[test]
    fn header_is_written_on_fresh_file() {
        let dir = tmpdir("hdr");
        let path = dir.join("audit.log");
        let (log, w) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        drop(log);
        let body = std::fs::read_to_string(&path).expect("read");
        assert!(body.starts_with("# varta-watch recovery audit v2\n"));
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
        assert_eq!(lines.len(), 3, "got: {body}");

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

        assert!(lines[1].contains("\tspawn\t7\t9001\texec\t"));
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
        log.flush_pending(Duration::MAX);
        let outcome = log.drive_audit_rotation(Duration::from_secs(5));
        assert_eq!(outcome, RotationOutcome::Complete);
        drop(log);
        assert!(path.with_extension("log.1").exists());

        let head = std::fs::read_to_string(&path).expect("read");
        assert!(head.starts_with("# varta-watch recovery audit v2"));
        let first_record = head
            .lines()
            .find(|l| !l.starts_with('#'))
            .expect("at least one record");
        assert!(first_record.contains("\tboot\t"));
        assert!(first_record.contains("\trotation\t"));
        if chain_enabled() {
            let cols: Vec<&str> = first_record.split('\t').collect();
            assert_eq!(cols.len(), 8, "boot record column count");
            assert_eq!(cols[3], "boot");
            let prev = cols[5];
            assert_eq!(prev.len(), 64, "prev_chain should carry pre-rotation hash");
            assert_ne!(prev, "0".repeat(64), "prev_chain should be non-zero");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(feature = "audit-chain")]
    #[test]
    fn rotation_drains_ring_before_renaming_keeps_chain_linear() {
        // Regression: the hash chain advances at emit (ring-enqueue) time,
        // but records are written to disk lazily by `flush_pending` under a
        // per-tick budget. If rotation started while records were still
        // queued in the ring, those records were dropped from the generation
        // rotated to `.1`, and the post-rotation `boot` recorded a
        // `prev_chain` ahead of `.1`'s last on-disk chain — a non-linear
        // chain a tamper-evidence verifier cannot distinguish from forgery.
        // The pre-existing rotation test always flushes with `Duration::MAX`
        // (ring empty at rotation), so it never exercised this path.
        let dir = tmpdir("rot-ring");
        let path = dir.join("audit.log");
        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(Some(160), 1)).expect("create");

        // Phase 1: emit + fully flush enough records to cross max_bytes,
        // which arms `needs_rotation`. The ring is empty after this flush.
        for i in 0..6u32 {
            log.record_spawn(&SpawnRecord {
                wallclock_ms: i as u64,
                observer_ns: i as u64,
                agent_pid: i + 2,
                child_pid: 1000 + i,
                mode: "exec",
                program: "/bin/true",
                source: "inline",
                template_len: 9,
            });
        }
        log.flush_pending(Duration::MAX);
        assert!(
            log.audit_rotation_due(),
            "crossing max_bytes must arm rotation"
        );

        // Phase 2: emit more records that stay queued in the ring (no flush).
        // These advance `prev_chain` ahead of what is on disk — the exact
        // state that produced the chain break before the fix.
        for i in 6..10u32 {
            log.record_spawn(&SpawnRecord {
                wallclock_ms: i as u64,
                observer_ns: i as u64,
                agent_pid: i + 2,
                child_pid: 1000 + i,
                mode: "exec",
                program: "/bin/true",
                source: "inline",
                template_len: 9,
            });
        }
        assert!(
            !log.pending_lines.is_empty(),
            "ring must hold un-drained records at rotation time"
        );

        // Phase 3: rotate. The fix drains the ring into the current file
        // before capturing `final_chain` and renaming.
        let outcome = log.drive_audit_rotation(Duration::from_secs(5));
        assert_eq!(outcome, RotationOutcome::Complete);
        log.flush_pending(Duration::MAX);
        drop(log);

        let rotated = path.with_extension("log.1");
        assert!(rotated.exists(), "rotated generation .1 must exist");
        let rotated_body = std::fs::read_to_string(&rotated).expect("read .1");
        let live_body = std::fs::read_to_string(&path).expect("read live");

        // No emitted record may vanish across the rotation boundary.
        assert_eq!(
            rotated_body.matches("\tspawn\t").count(),
            10,
            "all 10 spawn records must land in `.1`, none dropped at rotation:\n{rotated_body}"
        );

        // The last record physically written to `.1` must carry the same
        // chain the post-rotation `boot` record points back to.
        let rotated_tail_chain = rotated_body
            .lines()
            .rfind(|l| !l.starts_with('#'))
            .expect(".1 has at least one record")
            .rsplit('\t')
            .next()
            .expect("chain column");

        let boot = live_body
            .lines()
            .find(|l| !l.starts_with('#'))
            .expect("live file has a boot record");
        let cols: Vec<&str> = boot.split('\t').collect();
        assert_eq!(cols[3], "boot", "first live record is the rotation boot");
        let boot_prev_chain = cols[5];

        assert_eq!(
            boot_prev_chain, rotated_tail_chain,
            "post-rotation boot prev_chain must equal `.1` last on-disk chain \
             so the hash chain stays linear across the rotation boundary"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_resumes_seq_and_chain_from_v2_tail() {
        let dir = tmpdir("resume");
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
        assert_eq!(records.len(), 5, "got: {body}");
        let mut last_seq = 0u64;
        for rec in &records {
            let seq: u64 = rec.split('\t').next().unwrap().parse().unwrap();
            assert!(
                seq > last_seq,
                "seq must be monotonic: {seq} after {last_seq}"
            );
            last_seq = seq;
        }
        assert!(records[3].contains("\tboot\t"));
        assert!(records[3].contains("\tresume"));
        let _ = std::fs::remove_dir_all(&dir);
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

    #[cfg(feature = "audit-chain")]
    #[test]
    fn chain_is_deterministic_across_identical_runs() {
        use super::schema::AuditKind;
        use std::fmt::Write as _;

        let dir = tmpdir("det");
        let path1 = dir.join("a.log");
        let path2 = dir.join("b.log");
        let cfgx = AuditConfig {
            max_bytes: None,
            sync_every: 1,
            daemon_pid: 7777,
            fsync_budget: Duration::from_millis(50),
            rotation_budget: Duration::from_millis(50),
            sync_interval: None,
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
            log.next_seq = 1;
            log.prev_chain = [0u8; 32];
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
