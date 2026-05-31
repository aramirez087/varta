//! Durable sink abstraction, ring buffer, emit path.

use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use super::schema::{hex_encode_32_string, AuditKind, BootReason};
use super::RecoveryAuditLog;

/// Abstraction over the underlying file so unit tests can verify the
/// flush/sync/rotate call order without depending on the kernel's fdatasync
/// semantics.
pub(super) trait DurableSink: Write + Send {
    /// `File::sync_data()` on the real impl; counted by the test fake.
    fn sync_data(&self) -> io::Result<()>;
}

/// Real backing — wraps a `File` and delegates `sync_data` to the OS.
pub(super) struct FileSink(pub(super) File);

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

/// Maximum number of fully-formatted lines held in the in-memory ring.
pub(super) const AUDIT_RING_CAP: usize = 256;

/// Maximum number of recent `fdatasync(2)` durations buffered for the exporter.
pub(super) const FSYNC_HISTORY_CAP: usize = 32;

/// Ring high-watermark thresholds (75% and 95% of `AUDIT_RING_CAP`).
pub(super) const RING_WATERMARK_WARN: usize = (AUDIT_RING_CAP * 75) / 100;
pub(super) const RING_WATERMARK_CRITICAL: usize = (AUDIT_RING_CAP * 95) / 100;

impl RecoveryAuditLog {
    /// Emit a `boot` record. `prev` is the prior chain to record in the
    /// `prev_chain` column (rendered as hex). Pass `None` to record `-`.
    pub(super) fn emit_boot(&mut self, reason: BootReason, prev: Option<[u8; 32]>) {
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
        self.emit_direct(AuditKind::Boot, &body);
    }

    /// Common emit path — enqueues to the ring (hot path).
    pub(super) fn emit(&mut self, kind: AuditKind, body: &str) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        if self.pending_lines.len() >= AUDIT_RING_CAP {
            // Preserve a durable seq gap while keeping the persisted hash
            // chain linear over records that actually reached the ring.
            self.audit_dropped_total = self.audit_dropped_total.saturating_add(1);
            return;
        }

        let mut hash_body = String::with_capacity(body.len() + 24);
        let _ = write!(hash_body, "{seq}\t{body}");

        let chain_hex = self.compute_and_advance_chain(kind, hash_body.as_bytes());

        let mut line = String::with_capacity(hash_body.len() + chain_hex.len() + 2);
        let _ = writeln!(line, "{hash_body}\t{chain_hex}");
        self.write_line(&line);
    }

    /// Like `emit` but writes directly to the BufWriter — used for boot
    /// records where durability must not be deferred.
    pub(super) fn emit_direct(&mut self, kind: AuditKind, body: &str) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let mut hash_body = String::with_capacity(body.len() + 24);
        let _ = write!(hash_body, "{seq}\t{body}");

        let chain_hex = self.compute_and_advance_chain(kind, hash_body.as_bytes());

        let mut line = String::with_capacity(hash_body.len() + chain_hex.len() + 2);
        let _ = writeln!(line, "{hash_body}\t{chain_hex}");
        self.direct_write_line(&line);
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

    /// Enqueue a fully-formatted line into the in-memory ring. Called by
    /// `emit` on the hot path; the actual BufWriter write is deferred to
    /// `flush_pending` in the maintenance phase.
    fn write_line(&mut self, line: &str) {
        debug_assert!(self.pending_lines.len() < AUDIT_RING_CAP);
        self.pending_lines.push_back(line.to_owned());
        let len = self.pending_lines.len();
        if !self.ring_above_warn && len >= RING_WATERMARK_WARN {
            self.ring_above_warn = true;
            self.audit_ring_watermark_warn_total =
                self.audit_ring_watermark_warn_total.saturating_add(1);
            crate::varta_warn_rl!(
                crate::log_ratelimit::LogKind::AuditRingWarn,
                "audit ring \u{2265} 75% full ({len}/{AUDIT_RING_CAP}); drain not keeping up"
            );
        }
        if !self.ring_above_critical && len >= RING_WATERMARK_CRITICAL {
            self.ring_above_critical = true;
            self.audit_ring_watermark_critical_total =
                self.audit_ring_watermark_critical_total.saturating_add(1);
            crate::varta_error_rl!(
                crate::log_ratelimit::LogKind::AuditRingCritical,
                "audit ring \u{2265} 95% full ({len}/{AUDIT_RING_CAP}); records will start dropping"
            );
        }
    }

    /// Write `line` directly to the BufWriter — bypass the ring.
    ///
    /// Used for boot records (startup / rotation) and by `flush_pending`
    /// when draining. fsync cadence is governed by `sync_every` plus the
    /// optional `sync_interval`.
    pub(super) fn direct_write_line(&mut self, line: &str) {
        match self.sink.write_all(line.as_bytes()) {
            Ok(()) => {
                self.bytes_written = self.bytes_written.saturating_add(line.len() as u64);
                self.writes_since_sync = self.writes_since_sync.saturating_add(1);
                let by_record = self.writes_since_sync >= self.sync_every;
                let by_time = match (self.sync_interval, self.last_sync_at) {
                    (Some(interval), Some(last)) => last.elapsed() >= interval,
                    (Some(_), None) => true,
                    (None, _) => false,
                };
                if (by_record || by_time) && !self.deferred_fsync_in_drain {
                    match self.flush_and_sync() {
                        Ok(d) => {
                            self.writes_since_sync = 0;
                            if d > self.fsync_budget {
                                self.deferred_fsync_in_drain = true;
                            }
                        }
                        Err(e) => {
                            self.pending_err = Some(e);
                        }
                    }
                }
                if let Some(max) = self.max_bytes {
                    if self.rotation_progress.is_idle()
                        && !self.needs_rotation
                        && self.bytes_written >= max
                    {
                        self.needs_rotation = true;
                    }
                }
            }
            Err(e) => {
                self.pending_err = Some(e);
            }
        }
    }

    /// Flush BufWriter to the kernel, then `fdatasync` the file.
    /// Returns the wall-clock duration of the fsync.
    pub(super) fn flush_and_sync(&mut self) -> io::Result<Duration> {
        self.sink.flush()?;
        let t0 = Instant::now();
        self.sink.get_ref().sync_data()?;
        let d = t0.elapsed();
        if self.fsync_durations.len() >= FSYNC_HISTORY_CAP {
            self.fsync_durations.pop_front();
        }
        self.fsync_durations.push_back(d);
        if d > self.fsync_budget {
            self.audit_fsync_budget_exceeded_total =
                self.audit_fsync_budget_exceeded_total.saturating_add(1);
        }
        self.last_sync_at = Some(Instant::now());
        Ok(d)
    }

    /// Clear watermark edge flags when the ring falls back below each threshold.
    pub(super) fn refresh_falling_edge_watermarks(&mut self) {
        let len = self.pending_lines.len();
        if self.ring_above_critical && len < RING_WATERMARK_CRITICAL {
            self.ring_above_critical = false;
        }
        if self.ring_above_warn && len < RING_WATERMARK_WARN {
            self.ring_above_warn = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditConfig, RecoveryAuditLog};
    use std::collections::VecDeque;
    use std::io::{BufWriter, Write};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use super::super::rotation::RotationProgress;
    use super::super::schema::SpawnRecord;

    /// Count fdatasync calls without depending on the kernel.
    #[derive(Default)]
    pub(super) struct SyncCounter {
        pub(super) writes: Mutex<usize>,
        pub(super) syncs: Mutex<usize>,
        pub(super) buf: Mutex<Vec<u8>>,
    }

    pub(super) struct CountingSink(pub(super) Arc<SyncCounter>);

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

    pub(super) fn synthetic_log_with_counter(
        sync_every: u32,
    ) -> (RecoveryAuditLog, Arc<SyncCounter>) {
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
            pending_lines: VecDeque::with_capacity(AUDIT_RING_CAP),
            audit_dropped_total: 0,
            audit_flush_budget_exceeded_total: 0,
            fsync_budget: Duration::from_secs(1),
            sync_interval: None,
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
        (log, ctr)
    }

    /// Sink whose `sync_data()` sleeps for `delay`.
    struct SlowSink {
        ctr: Arc<SyncCounter>,
        delay: Duration,
    }

    impl Write for SlowSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            *self.ctr.writes.lock().unwrap() += 1;
            self.ctr.buf.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl DurableSink for SlowSink {
        fn sync_data(&self) -> io::Result<()> {
            *self.ctr.syncs.lock().unwrap() += 1;
            std::thread::sleep(self.delay);
            Ok(())
        }
    }

    /// Build a synthetic log around a test sink with explicit knobs.
    fn synthetic_log_with(
        sink: Box<dyn DurableSink>,
        sync_every: u32,
        fsync_budget: Duration,
        sync_interval: Option<Duration>,
        max_bytes: Option<u64>,
    ) -> RecoveryAuditLog {
        RecoveryAuditLog {
            sink: BufWriter::new(sink),
            path: PathBuf::from("/dev/null"),
            max_bytes,
            bytes_written: 0,
            pending_err: None,
            next_seq: 1,
            prev_chain: [0u8; 32],
            sync_every,
            writes_since_sync: 0,
            daemon_pid: 1234,
            pending_lines: VecDeque::with_capacity(AUDIT_RING_CAP),
            audit_dropped_total: 0,
            audit_flush_budget_exceeded_total: 0,
            fsync_budget,
            sync_interval,
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
        }
    }

    fn dummy_spawn(pid: u32) -> SpawnRecord<'static> {
        SpawnRecord {
            wallclock_ms: 0,
            observer_ns: 0,
            agent_pid: pid,
            child_pid: pid,
            mode: "exec",
            program: "p",
            source: "inline",
            template_len: 0,
        }
    }

    #[cfg(feature = "audit-chain")]
    fn assert_spawn_chain_is_linear(records: &[&str]) {
        let mut prev = [0u8; 32];
        for line in records {
            let (hash_body, chain_hex) = line.rsplit_once('\t').expect("chain column");
            let expected =
                varta_vlp::crypto::audit_chain_hash(&prev, b"spawn", hash_body.as_bytes());
            let actual = varta_vlp::util::decode_hex_32(chain_hex.as_bytes()).expect("hex chain");
            assert_eq!(actual, expected, "chain mismatch for record: {line}");
            prev = actual;
        }
    }

    #[cfg(feature = "audit-chain")]
    #[test]
    fn ring_full_drop_preserves_hash_chain_and_seq_gap() {
        let (mut log, ctr) = synthetic_log_with_counter(1);
        for i in 0..AUDIT_RING_CAP as u32 {
            log.record_spawn(&dummy_spawn(i));
        }
        assert_eq!(log.pending_lines.len(), AUDIT_RING_CAP);

        log.record_spawn(&dummy_spawn(99_999));
        assert_eq!(log.audit_dropped_total, 1);
        log.flush_pending(Duration::MAX);

        log.record_spawn(&dummy_spawn(100_000));
        log.flush_pending(Duration::MAX);

        let bytes = ctr.buf.lock().unwrap().clone();
        let body = String::from_utf8(bytes).expect("audit body is utf8");
        let records: Vec<&str> = body.lines().collect();
        assert_eq!(records.len(), AUDIT_RING_CAP + 1, "got: {body}");
        assert_eq!(
            records.last().and_then(|line| line.split('\t').next()),
            Some("258"),
            "the dropped record must leave a durable sequence gap"
        );
        assert_spawn_chain_is_linear(&records);
    }

    #[test]
    fn fsync_stall_skips_remaining_in_drain() {
        let ctr = Arc::new(SyncCounter::default());
        let sink = Box::new(SlowSink {
            ctr: ctr.clone(),
            delay: Duration::from_millis(80),
        });
        let mut log = synthetic_log_with(sink, 1, Duration::from_millis(20), None, None);
        for i in 0..5u32 {
            log.record_spawn(&dummy_spawn(i));
        }
        assert_eq!(log.pending_lines.len(), 5);
        let t0 = Instant::now();
        log.flush_pending(Duration::from_secs(5));
        let drain_wall = t0.elapsed();
        let syncs = *ctr.syncs.lock().unwrap();
        assert_eq!(syncs, 1, "deferral must skip subsequent fsyncs in drain");
        assert_eq!(log.pending_lines.len(), 0);
        assert_eq!(log.audit_fsync_budget_exceeded_total, 1);
        assert!(log.deferred_fsync_in_drain);
        assert!(
            drain_wall < Duration::from_millis(250),
            "drain wall-time {drain_wall:?} should be bounded"
        );
    }

    #[test]
    fn ring_watermark_fires_at_75_and_95() {
        let ctr = Arc::new(SyncCounter::default());
        let sink = Box::new(CountingSink(ctr.clone()));
        let mut log = synthetic_log_with(
            Box::new(CountingSink(ctr.clone())) as Box<dyn DurableSink>,
            1,
            Duration::from_secs(10),
            None,
            None,
        );
        let _ = sink;
        for i in 0..191u32 {
            log.record_spawn(&dummy_spawn(i));
        }
        assert_eq!(log.audit_ring_watermark_warn_total, 0);
        assert_eq!(log.audit_ring_watermark_critical_total, 0);
        log.record_spawn(&dummy_spawn(192));
        assert_eq!(log.audit_ring_watermark_warn_total, 1);
        assert_eq!(log.audit_ring_watermark_critical_total, 0);
        for i in 193..243u32 {
            log.record_spawn(&dummy_spawn(i));
        }
        assert_eq!(log.audit_ring_watermark_critical_total, 0);
        log.record_spawn(&dummy_spawn(243));
        assert_eq!(log.audit_ring_watermark_critical_total, 1);
        log.flush_pending(Duration::from_secs(5));
        assert_eq!(log.pending_lines.len(), 0);
        for i in 0..192u32 {
            log.record_spawn(&dummy_spawn(1_000 + i));
        }
        assert_eq!(
            log.audit_ring_watermark_warn_total, 2,
            "warn counter re-arms after falling-edge"
        );
    }

    #[test]
    fn sync_interval_ms_overrides_record_cadence() {
        let ctr = Arc::new(SyncCounter::default());
        let sink = Box::new(CountingSink(ctr.clone()));
        let mut log = synthetic_log_with(
            sink,
            64,
            Duration::from_secs(10),
            Some(Duration::from_millis(25)),
            None,
        );
        log.record_spawn(&dummy_spawn(1));
        log.flush_pending(Duration::from_secs(1));
        let syncs_after_first = *ctr.syncs.lock().unwrap();
        assert_eq!(
            syncs_after_first, 1,
            "first drain must sync (last_sync_at=None)"
        );
        log.record_spawn(&dummy_spawn(2));
        log.flush_pending(Duration::from_secs(1));
        let syncs_quick = *ctr.syncs.lock().unwrap();
        assert_eq!(syncs_quick, syncs_after_first);
        std::thread::sleep(Duration::from_millis(30));
        log.record_spawn(&dummy_spawn(3));
        log.flush_pending(Duration::from_secs(1));
        let syncs_after_interval = *ctr.syncs.lock().unwrap();
        assert!(syncs_after_interval > syncs_quick);
    }

    #[test]
    fn fsync_budget_default_preserves_class_c() {
        let ctr = Arc::new(SyncCounter::default());
        let sink = Box::new(CountingSink(ctr.clone()));
        let mut log = synthetic_log_with(sink, 1, Duration::from_secs(10), None, None);
        for i in 0..10u32 {
            log.record_spawn(&dummy_spawn(i));
        }
        log.flush_pending(Duration::from_secs(5));
        let syncs = *ctr.syncs.lock().unwrap();
        assert_eq!(syncs, 10, "Class C cadence preserved");
        assert_eq!(log.audit_fsync_budget_exceeded_total, 0);
        assert_eq!(log.audit_dropped_total, 0);
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
        log.flush_pending(Duration::MAX);
        let syncs = *ctr.syncs.lock().unwrap();
        drop(log);
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
        log.flush_pending(Duration::MAX);
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
    fn rotation_resumes_across_ticks() {
        use std::os::unix::fs::PermissionsExt;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "varta-audit-rot-resume-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir(&dir).expect("create tempdir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod tempdir");
        let path = dir.join("audit.log");
        let mut cfg = AuditConfig {
            max_bytes: Some(120),
            sync_every: 1,
            daemon_pid: 1234,
            fsync_budget: Duration::from_millis(50),
            sync_interval: None,
            rotation_budget: Duration::from_micros(1),
        };
        let _ = cfg.rotation_budget;
        cfg.rotation_budget = Duration::from_micros(1);
        let (mut log, _) = RecoveryAuditLog::create(&path, cfg).expect("create");
        for i in 0..8u32 {
            log.record_spawn(&dummy_spawn(i));
        }
        log.flush_pending(Duration::from_secs(1));
        assert!(log.audit_rotation_due() || log.audit_rotation_pending());
        let mut saw_deferred = false;
        let mut completed = false;
        for _ in 0..32 {
            let outcome = log.drive_audit_rotation(Duration::from_micros(1));
            match outcome {
                crate::audit::RotationOutcome::Deferred => saw_deferred = true,
                crate::audit::RotationOutcome::Complete => {
                    completed = true;
                    break;
                }
                crate::audit::RotationOutcome::NotNeeded => {
                    panic!("rotation should be in progress")
                }
            }
        }
        assert!(
            saw_deferred,
            "rotation must defer at least once under a 1us budget"
        );
        assert!(completed, "rotation must eventually complete");
        assert!(log.audit_rotation_budget_exceeded_total >= 1);
        drop(log);
        assert!(path.with_extension("log.1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
