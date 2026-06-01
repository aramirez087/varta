//! File rotation FSM, tail probe, fsync sequencing.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};

use super::schema::{parse_record, BootReason, AUDIT_HEADER_V1_PREFIX, AUDIT_HEADER_V2};
use super::RecoveryAuditLog;

/// Number of rotated file generations kept.
const AUDIT_ROTATION_GENERATIONS: u32 = 5;

/// POSIX `EXDEV` ("cross-device link"). Used directly so the rotation fallback
/// remains compatible with Rust 1.70, where `ErrorKind::CrossesDevices` is not
/// available.
const EXDEV: i32 = 18;

/// Maximum bytes read from the tail of an existing file when resuming.
const TAIL_SCAN_BYTES: u64 = 4096;

/// Result of probing an existing audit file for restart continuity.
pub(super) struct TailProbe {
    /// `seq` of the most recent parseable record, or 0 if none recovered.
    pub(super) last_seq: u64,
    /// Raw 32-byte chain of the most recent parseable record.
    pub(super) last_chain: [u8; 32],
    /// Why we are emitting an initial `boot` record on top of the existing content.
    pub(super) reason: BootReason,
    /// If `Some`, the existing file must be `ftruncate`'d to this length
    /// before the v2 header / boot record can be appended safely.
    pub(super) truncate_to: Option<u64>,
    /// True if the existing file already contains a v2 header.
    pub(super) has_v2_header: bool,
}

/// Outcome of one `drive_audit_rotation` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationOutcome {
    /// Rotation was not required.
    NotNeeded,
    /// Rotation advanced one or more sub-steps and is still in progress.
    Deferred,
    /// Rotation completed (or was abandoned with a latched error).
    Complete,
}

/// Internal rotation state machine.
#[derive(Debug, Clone)]
pub(super) enum RotationProgress {
    /// No rotation in progress.
    Idle,
    /// Generation renames are still pending.
    Renaming {
        next_gen: u32,
        final_chain: [u8; 32],
    },
    /// All renames done; open a fresh fd for the live PATH.
    OpeningFd { final_chain: [u8; 32] },
    /// fd open; write the v2 header.
    WritingHeader { final_chain: [u8; 32] },
    /// Header written; emit the post-rotation boot record and final fsync.
    EmittingBoot { final_chain: [u8; 32] },
}

impl RotationProgress {
    #[inline]
    pub(super) fn is_idle(&self) -> bool {
        matches!(self, RotationProgress::Idle)
    }
}

impl RecoveryAuditLog {
    /// Advance the rotation state machine by one sub-step at most.
    ///
    /// Returns `NotNeeded` when rotation is neither pending nor due,
    /// `Deferred` when the per-tick budget elapsed mid-rotation, and
    /// `Complete` when the new generation is live and the boot record is durable.
    pub fn drive_audit_rotation(&mut self, budget: Duration) -> RotationOutcome {
        if self.rotation_progress.is_idle() && !self.needs_rotation {
            return RotationOutcome::NotNeeded;
        }
        let call_start = Instant::now();
        if self.rotation_progress.is_idle() {
            // Drain any ring-buffered lines into the CURRENT file before
            // capturing `final_chain`. The hash chain advances at emit time
            // (ring-enqueue), not at disk-write time, so `self.prev_chain`
            // can be ahead of the records actually written to the live file
            // whenever `flush_pending` hit its per-tick budget with lines
            // still queued. Rotating without draining first would (a) drop
            // those records out of the generation being rotated to `.1` and
            // (b) record a post-rotation `boot` whose `prev_chain` is ahead
            // of `.1`'s last on-disk chain — a non-linear chain that a
            // tamper-evidence verifier cannot distinguish from forgery.
            // `flush_and_sync` only flushes the BufWriter; it does not touch
            // the ring, so the drain must be explicit (mirrors `Drop`).
            // The ring is bounded by `AUDIT_RING_CAP`, but the underlying
            // writes and sync cadence can still take wall-clock time. Honor
            // the rotation budget while draining so a full ring cannot pin
            // the single-threaded observer before the state machine reaches
            // its first explicit budget check.
            self.deferred_fsync_in_drain = false;
            while let Some(line) = self.pending_lines.pop_front() {
                if call_start.elapsed() >= budget {
                    self.pending_lines.push_front(line);
                    self.audit_rotation_budget_exceeded_total =
                        self.audit_rotation_budget_exceeded_total.saturating_add(1);
                    return RotationOutcome::Deferred;
                }
                self.direct_write_line(&line);
                self.refresh_falling_edge_watermarks();
            }
            self.refresh_falling_edge_watermarks();
            let final_chain = self.prev_chain;
            if let Err(e) = self.flush_and_sync() {
                self.pending_err = Some(e);
                return RotationOutcome::Deferred;
            }
            self.rotation_progress = RotationProgress::Renaming {
                next_gen: AUDIT_ROTATION_GENERATIONS,
                final_chain,
            };
        }
        loop {
            if call_start.elapsed() > budget {
                self.audit_rotation_budget_exceeded_total =
                    self.audit_rotation_budget_exceeded_total.saturating_add(1);
                return RotationOutcome::Deferred;
            }
            let progress = self.rotation_progress.clone();
            match progress {
                RotationProgress::Idle => {
                    return RotationOutcome::Complete;
                }
                RotationProgress::Renaming {
                    next_gen,
                    final_chain,
                } => {
                    let path_str = self.path.to_string_lossy().into_owned();
                    let sub_result = if next_gen == AUDIT_ROTATION_GENERATIONS {
                        let oldest = format!("{path_str}.{AUDIT_ROTATION_GENERATIONS}");
                        match std::fs::remove_file(&oldest) {
                            Ok(()) => Ok(()),
                            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                            Err(e) => Err(e),
                        }
                    } else {
                        let src = format!("{path_str}.{next_gen}");
                        let dst = format!("{path_str}.{}", next_gen + 1);
                        match std::fs::rename(&src, &dst) {
                            Ok(()) => Ok(()),
                            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                            Err(e) => Err(e),
                        }
                    };
                    if let Err(e) = sub_result {
                        self.pending_err = Some(e);
                        self.rotation_progress = RotationProgress::Idle;
                        self.needs_rotation = false;
                        return RotationOutcome::Complete;
                    }
                    if next_gen > 1 {
                        self.rotation_progress = RotationProgress::Renaming {
                            next_gen: next_gen - 1,
                            final_chain,
                        };
                    } else {
                        let first = format!("{path_str}.1");
                        let rename_result = match std::fs::rename(&self.path, &first) {
                            Ok(()) => Ok(()),
                            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                            Err(e) if is_cross_device_error(&e) => {
                                std::fs::copy(&self.path, &first)
                                    .and_then(|_| std::fs::remove_file(&self.path))
                            }
                            Err(e) => Err(e),
                        };
                        if let Err(e) = rename_result {
                            self.pending_err = Some(e);
                            self.rotation_progress = RotationProgress::Idle;
                            self.needs_rotation = false;
                            return RotationOutcome::Complete;
                        }
                        self.rotation_progress = RotationProgress::OpeningFd { final_chain };
                    }
                }
                RotationProgress::OpeningFd { final_chain } => {
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
                            self.rotation_progress = RotationProgress::Idle;
                            self.needs_rotation = false;
                            return RotationOutcome::Complete;
                        }
                    };
                    use super::writer::{DurableSink, FileSink};
                    let sink_box: Box<dyn DurableSink> = Box::new(FileSink(file));
                    self.sink = std::io::BufWriter::new(sink_box);
                    self.bytes_written = 0;
                    self.writes_since_sync = 0;
                    self.rotation_progress = RotationProgress::WritingHeader { final_chain };
                }
                RotationProgress::WritingHeader { final_chain } => {
                    use std::io::Write;
                    if let Err(e) = self.sink.write_all(AUDIT_HEADER_V2.as_bytes()) {
                        self.pending_err = Some(e);
                        self.rotation_progress = RotationProgress::Idle;
                        self.needs_rotation = false;
                        return RotationOutcome::Complete;
                    }
                    self.bytes_written = AUDIT_HEADER_V2.len() as u64;
                    self.rotation_progress = RotationProgress::EmittingBoot { final_chain };
                }
                RotationProgress::EmittingBoot { final_chain } => {
                    self.emit_boot(BootReason::Rotation, Some(final_chain));
                    if let Err(e) = self.flush_and_sync() {
                        self.pending_err = Some(e);
                    } else {
                        self.writes_since_sync = 0;
                    }
                    self.rotation_progress = RotationProgress::Idle;
                    self.needs_rotation = false;
                    return RotationOutcome::Complete;
                }
            }
        }
    }

    /// Read up to the last [`TAIL_SCAN_BYTES`] of `path` and parse the
    /// most recent record line to derive seq + chain + boot reason.
    pub(super) fn probe_tail(path: &Path) -> io::Result<TailProbe> {
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

        let scan_len = TAIL_SCAN_BYTES.min(total);
        let scan_start = total - scan_len;
        file.seek(SeekFrom::Start(scan_start))?;
        let mut buf = vec![0u8; scan_len as usize];
        file.read_exact(&mut buf)?;

        if buf.last() == Some(&b'\n') {
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
            return Ok(TailProbe {
                last_seq: 0,
                last_chain: [0u8; 32],
                reason: BootReason::SchemaDrift,
                truncate_to: None,
                has_v2_header: true,
            });
        }

        let last_nl = buf.iter().rposition(|&b| b == b'\n');
        let truncate_to = match last_nl {
            Some(rel) => Some(scan_start + (rel as u64) + 1),
            None => Some(AUDIT_HEADER_V2.len() as u64),
        };

        if let Some(rel) = last_nl {
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

fn is_cross_device_error(e: &io::Error) -> bool {
    e.raw_os_error() == Some(EXDEV)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditConfig, RecoveryAuditLog};
    use std::collections::VecDeque;
    use std::io::{self, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::super::writer::{DurableSink, FSYNC_HISTORY_CAP};

    struct SlowWriteSink {
        writes: Arc<AtomicUsize>,
        delay: Duration,
    }

    impl Write for SlowWriteSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            std::thread::sleep(self.delay);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl DurableSink for SlowWriteSink {
        fn sync_data(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn synthetic_rotation_log(writes: Arc<AtomicUsize>, delay: Duration) -> RecoveryAuditLog {
        let sink: Box<dyn DurableSink> = Box::new(SlowWriteSink { writes, delay });
        RecoveryAuditLog {
            sink: std::io::BufWriter::new(sink),
            path: PathBuf::from("/dev/null"),
            max_bytes: None,
            bytes_written: 0,
            pending_err: None,
            next_seq: 1,
            prev_chain: [0u8; 32],
            sync_every: 1,
            writes_since_sync: 0,
            daemon_pid: 1234,
            pending_lines: VecDeque::new(),
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
            needs_rotation: true,
            rotation_progress: RotationProgress::Idle,
        }
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "varta-audit-rot-{tag}-{}-{}",
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
    fn rotation_pre_drain_honors_budget() {
        let writes = Arc::new(AtomicUsize::new(0));
        let mut log = synthetic_rotation_log(writes.clone(), Duration::from_millis(10));

        for pid in 1..=3 {
            log.record_spawn(&crate::audit::SpawnRecord {
                wallclock_ms: 1,
                observer_ns: 1,
                agent_pid: pid,
                child_pid: pid + 100,
                mode: "exec",
                program: "/bin/true",
                source: "inline",
                template_len: 9,
            });
        }
        assert_eq!(log.pending_lines.len(), 3);

        let outcome = log.drive_audit_rotation(Duration::from_millis(1));

        assert_eq!(outcome, RotationOutcome::Deferred);
        assert_eq!(
            writes.load(Ordering::Relaxed),
            1,
            "rotation must stop after the first over-budget drain write"
        );
        assert_eq!(
            log.pending_lines.len(),
            2,
            "undrained audit lines must stay queued for the next tick"
        );
        assert!(log.needs_rotation);
        assert!(log.rotation_progress.is_idle());
        assert_eq!(log.audit_rotation_budget_exceeded_total, 1);
    }

    #[test]
    fn legacy_v1_file_gets_legacy_v1_boot() {
        let dir = tmpdir("v1");
        let path = dir.join("audit.log");
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
        log1.record_spawn(&crate::audit::SpawnRecord {
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

        {
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
        let body = std::fs::read_to_string(&path).expect("read");
        assert!(
            !body.contains("99\t12345\t99\tspaw"),
            "torn fragment must be removed"
        );
        assert!(body.contains("\tcorrupt_tail"));
        assert!(len_after > 0);
        let _ = len_before;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
