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
    Renaming { next_gen: u32 },
    /// All renames done (the live file is now `PATH.1`). Drain any records
    /// emitted during the rotation window into `.1`, snapshot the final chain
    /// at the swap boundary, then open the new fd + write the v2 header +
    /// post-rotation `boot` record atomically (no further deferral), so the
    /// boot's `prev_chain` column equals `.1`'s true on-disk tail and no
    /// record (nor the header) is ever displaced ahead of the boot anchor.
    Finalizing,
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
            // Drain any ring-buffered lines into the CURRENT file before the
            // generation renames begin. The hash chain advances at emit time
            // (ring-enqueue), not at disk-write time, so `self.prev_chain` can
            // be ahead of the records actually written to the live file. This
            // pre-drain bounds the ring early and makes the pre-rotation file
            // durable before it is renamed to `.1`.
            //
            // The *authoritative* `final_chain` snapshot — the value the
            // post-rotation `boot` records as its `prev_chain` column — is NOT
            // taken here. Records keep arriving (on_stall / try_reap) and
            // flushing into the soon-to-be `.1` file throughout a multi-tick
            // rotation, so a snapshot captured at rotation start would be stale
            // by the time the boot is written, producing a non-linear chain a
            // tamper-evidence verifier cannot distinguish from forgery. The
            // snapshot is therefore taken at the sink-swap boundary in
            // `Finalizing`, after a second budget-honored drain.
            //
            // `flush_and_sync` only flushes the BufWriter; it does not touch
            // the ring, so the drain must be explicit (mirrors `Drop`). Honor
            // the rotation budget while draining so a full ring cannot pin the
            // single-threaded observer before the first explicit budget check.
            self.deferred_fsync_in_drain = false;
            while let Some(line) = self.pending_lines.pop_front() {
                if call_start.elapsed() >= budget {
                    self.pending_lines.push_front(line);
                    self.audit_rotation_budget_exceeded_total =
                        self.audit_rotation_budget_exceeded_total.saturating_add(1);
                    return RotationOutcome::Deferred;
                }
                if self.direct_write_line(&line) {
                    self.refresh_falling_edge_watermarks();
                } else {
                    self.pending_lines.push_front(line);
                    return RotationOutcome::Deferred;
                }
            }
            self.refresh_falling_edge_watermarks();
            if let Err(e) = self.flush_and_sync() {
                self.pending_err = Some(e);
                return RotationOutcome::Deferred;
            }
            self.rotation_progress = RotationProgress::Renaming {
                next_gen: AUDIT_ROTATION_GENERATIONS,
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
                RotationProgress::Renaming { next_gen } => {
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
                        self.rotation_progress = RotationProgress::Finalizing;
                    }
                }
                RotationProgress::Finalizing => {
                    // The live file has been renamed to `.1`; `self.sink` still
                    // points at that inode (an open fd follows the inode through
                    // a rename). Records emitted during a multi-tick rotation
                    // window (on_stall / try_reap) advanced the chain and were
                    // flushed by `flush_pending` into `.1`, so drain whatever is
                    // still ring-buffered into `.1` before snapshotting. The
                    // sink is still `.1`, so deferring here and resuming next
                    // tick keeps appending to `.1` consistently.
                    self.deferred_fsync_in_drain = false;
                    while let Some(line) = self.pending_lines.pop_front() {
                        if call_start.elapsed() >= budget {
                            self.pending_lines.push_front(line);
                            self.audit_rotation_budget_exceeded_total =
                                self.audit_rotation_budget_exceeded_total.saturating_add(1);
                            return RotationOutcome::Deferred;
                        }
                        if self.direct_write_line(&line) {
                            self.refresh_falling_edge_watermarks();
                        } else {
                            self.pending_lines.push_front(line);
                            return RotationOutcome::Deferred;
                        }
                    }
                    self.refresh_falling_edge_watermarks();

                    // Snapshot at the swap boundary: `self.prev_chain` now equals
                    // the chain of the last record physically written to `.1`.
                    // This is the value the post-rotation `boot` records in its
                    // `prev_chain` column — guaranteeing it matches `.1`'s true
                    // tail rather than a stale rotation-start head.
                    let final_chain = self.prev_chain;
                    if let Err(e) = self.flush_and_sync() {
                        self.pending_err = Some(e);
                        return RotationOutcome::Deferred;
                    }

                    // Everything from the sink swap through the boot record runs
                    // to completion in THIS call — no `Deferred` in between — so
                    // `flush_pending` (which runs before `drive_audit_rotation`
                    // each tick) can never wedge a record, nor displace the v2
                    // header, into the new generation ahead of its boot anchor.
                    use std::os::unix::fs::OpenOptionsExt;
                    let file = match OpenOptions::new()
                        .create(true)
                        .append(true)
                        .mode(0o600)
                        .open(&self.path)
                    {
                        Ok(f) => f,
                        Err(e) => {
                            // The live file was already renamed to `.1` and the
                            // sink still points at that inode. Giving up here
                            // (Idle + needs_rotation=false) would strand every
                            // future record in the rotated `.1` generation with
                            // no live file and no boot boundary — an offline
                            // verifier later reads `.1` as two generations
                            // spliced without a boot anchor (forgery signal on a
                            // clean log). Instead stay in Finalizing with
                            // rotation still armed and Defer: open() failures
                            // (EMFILE/ENFILE/ENOSPC/EACCES) are typically
                            // transient, and a later tick re-drains (a no-op when
                            // empty), re-snapshots `final_chain` from the current
                            // `prev_chain`, and retries the open. The sink stays
                            // consistently on `.1` until the swap succeeds, so
                            // the hash chain remains linear throughout.
                            self.pending_err = Some(e);
                            return RotationOutcome::Deferred;
                        }
                    };
                    use super::writer::{DurableSink, FileSink};
                    let sink_box: Box<dyn DurableSink> = Box::new(FileSink(file));
                    self.sink = std::io::BufWriter::new(sink_box);
                    self.bytes_written = 0;
                    self.writes_since_sync = 0;

                    use std::io::Write;
                    if let Err(e) = self.sink.write_all(AUDIT_HEADER_V2.as_bytes()) {
                        self.pending_err = Some(e);
                        self.rotation_progress = RotationProgress::Idle;
                        self.needs_rotation = false;
                        return RotationOutcome::Complete;
                    }
                    self.bytes_written = AUDIT_HEADER_V2.len() as u64;

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

        // Fast path: scan only the last `TAIL_SCAN_BYTES`. For a file at or
        // below the window this already covers the whole body; for the common
        // small-record case it keeps the restart read cheap.
        let scan_len = TAIL_SCAN_BYTES.min(total);
        let scan_start = total - scan_len;
        file.seek(SeekFrom::Start(scan_start))?;
        let mut buf = vec![0u8; scan_len as usize];
        file.read_exact(&mut buf)?;

        let data_start = AUDIT_HEADER_V2.len() as u64;
        let (probe, recovered) = classify_tail(&buf, scan_start);
        if recovered || scan_start <= data_start {
            return Ok(probe);
        }

        // The tail window yielded no parseable record yet began *after* the
        // data region: a single record larger than `TAIL_SCAN_BYTES` (e.g. a
        // spawn record with long operator-configured program / source paths)
        // can push the true tail entirely out of the window. Concluding "no
        // prior record" here would roll `seq` back to 1, restart the hash
        // chain from zero, or — in the no-trailing-newline case — truncate
        // every durable record back to the bare header. That is precisely the
        // silent record loss + chain break the v2 format guarantees against,
        // so re-scan the whole data region before drawing that conclusion.
        // `probe_tail` runs once at startup and the file is bounded by
        // `max_bytes`, so the wider read is acceptable.
        let scan_start = data_start;
        let scan_len = total - scan_start;
        file.seek(SeekFrom::Start(scan_start))?;
        let mut buf = vec![0u8; scan_len as usize];
        file.read_exact(&mut buf)?;
        let (probe, _) = classify_tail(&buf, scan_start);
        Ok(probe)
    }
}

/// Derive a [`TailProbe`] from `buf`, the trailing bytes of an audit file that
/// begin at absolute offset `scan_start`. Returns the probe plus a `recovered`
/// flag: `true` only when a real prior record's `seq` + chain were parsed.
///
/// A `false` flag means the buffer produced a `seq`-0 / zero-chain reset (no
/// parseable record visible in this window). The caller treats that as
/// authoritative only once the window covers the whole data region; otherwise
/// a record larger than the window may have hidden the true tail and the scan
/// must be widened before the reset is trusted.
fn classify_tail(buf: &[u8], scan_start: u64) -> (TailProbe, bool) {
    if buf.last() == Some(&b'\n') {
        let view = &buf[..buf.len() - 1];
        let last_line_start = view
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(0);
        let last_line = &view[last_line_start..];
        if let Some((seq, chain)) = parse_record(last_line) {
            return (
                TailProbe {
                    last_seq: seq,
                    last_chain: chain,
                    reason: BootReason::Resume,
                    truncate_to: None,
                    has_v2_header: true,
                },
                true,
            );
        }
        return (
            TailProbe {
                last_seq: 0,
                last_chain: [0u8; 32],
                reason: BootReason::SchemaDrift,
                truncate_to: None,
                has_v2_header: true,
            },
            false,
        );
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
            return (
                TailProbe {
                    last_seq: seq,
                    last_chain: chain,
                    reason: BootReason::CorruptTail,
                    truncate_to,
                    has_v2_header: true,
                },
                true,
            );
        }
    }

    (
        TailProbe {
            last_seq: 0,
            last_chain: [0u8; 32],
            reason: BootReason::CorruptTail,
            truncate_to,
            has_v2_header: true,
        },
        false,
    )
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

    /// A cleanly-flushed audit file whose final, fully-durable record is larger
    /// than `TAIL_SCAN_BYTES` must still resume from that record. The fixed
    /// tail window cannot see the record's leading bytes, so the unfixed probe
    /// rolled `seq` back to 1 and restarted the hash chain from zero on the
    /// next restart — silent corruption of an otherwise-clean Class-C log, with
    /// no crash required.
    #[test]
    fn large_durable_record_beyond_tail_window_resumes_not_resets() {
        let dir = tmpdir("big-resume");
        let path = dir.join("audit.log");

        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        // Record A: small. Record B: a spawn whose program path alone exceeds
        // the tail window, so B's leading bytes sit before `total - 4096`.
        let big_program = format!("/{}", "b".repeat(5000));
        log.record_spawn(&crate::audit::SpawnRecord {
            wallclock_ms: 1,
            observer_ns: 1,
            agent_pid: 1,
            child_pid: 100,
            mode: "exec",
            program: "/bin/small",
            source: "inline",
            template_len: 1,
        });
        log.record_spawn(&crate::audit::SpawnRecord {
            wallclock_ms: 2,
            observer_ns: 2,
            agent_pid: 2,
            child_pid: 200,
            mode: "exec",
            program: &big_program,
            source: "inline",
            template_len: 2,
        });
        log.flush_pending(Duration::from_secs(5));
        drop(log);

        let body = std::fs::read_to_string(&path).expect("read");
        let last_line = body
            .lines()
            .rfind(|l| !l.starts_with('#'))
            .expect("a v2 record");
        assert!(
            last_line.len() > TAIL_SCAN_BYTES as usize,
            "test precondition: record B ({} bytes) must exceed the tail window",
            last_line.len()
        );
        let (seq_b, chain_b) = parse_record(last_line.as_bytes()).expect("B parses");
        assert!(seq_b > 1, "B must be a real record past the boot");

        let probe = RecoveryAuditLog::probe_tail(&path).expect("probe");
        assert!(
            matches!(probe.reason, BootReason::Resume),
            "must resume from the large durable record, got {:?}",
            probe.reason
        );
        assert_eq!(probe.last_seq, seq_b, "seq must not roll back");
        assert_eq!(
            probe.truncate_to, None,
            "a clean file must not be truncated"
        );
        #[cfg(feature = "audit-chain")]
        assert_eq!(probe.last_chain, chain_b, "chain must continue from B");
        let _ = chain_b;

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A torn write whose unterminated fragment is itself larger than
    /// `TAIL_SCAN_BYTES` must drop only the fragment and resume from the last
    /// fully-durable record. The unfixed probe saw no newline in its window and
    /// truncated the whole file back to the 32-byte header, destroying every
    /// durable record — exactly the silent record loss the v2 chain forbids.
    #[test]
    fn torn_large_fragment_preserves_durable_records() {
        let dir = tmpdir("big-torn");
        let path = dir.join("audit.log");

        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        let big_program = format!("/{}", "b".repeat(5000));
        log.record_spawn(&crate::audit::SpawnRecord {
            wallclock_ms: 1,
            observer_ns: 1,
            agent_pid: 1,
            child_pid: 100,
            mode: "exec",
            program: "/bin/small",
            source: "inline",
            template_len: 1,
        });
        log.record_spawn(&crate::audit::SpawnRecord {
            wallclock_ms: 2,
            observer_ns: 2,
            agent_pid: 2,
            child_pid: 200,
            mode: "exec",
            program: &big_program,
            source: "inline",
            template_len: 2,
        });
        log.flush_pending(Duration::from_secs(5));
        drop(log);

        // Snapshot the last fully-durable record (B) and the end-of-B offset.
        let body = std::fs::read_to_string(&path).expect("read");
        let last_line = body
            .lines()
            .rfind(|l| !l.starts_with('#'))
            .expect("a v2 record");
        let (seq_b, _chain_b) = parse_record(last_line.as_bytes()).expect("B parses");
        let end_of_b = std::fs::metadata(&path).expect("meta").len();

        // Append a torn fragment with no trailing newline, larger than the
        // tail window so the window contains no newline at all.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open append");
            f.write_all(&vec![b'9'; 5000]).expect("torn write");
        }

        let probe = RecoveryAuditLog::probe_tail(&path).expect("probe");
        assert!(
            matches!(probe.reason, BootReason::CorruptTail),
            "torn tail must be reported, got {:?}",
            probe.reason
        );
        assert_eq!(
            probe.last_seq, seq_b,
            "must recover B's seq, not reset to 0"
        );
        assert_eq!(
            probe.truncate_to,
            Some(end_of_b),
            "must truncate only the torn fragment, not back to the header"
        );

        // End-to-end: create() applies the truncation, then resumes. The big
        // durable record must survive; only the torn fragment is dropped.
        let (log2, w) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("re-create");
        assert!(w.corrupt_tail);
        drop(log2);
        let body = std::fs::read_to_string(&path).expect("read");
        assert!(
            body.contains(&big_program),
            "the large durable record must not be destroyed"
        );
        assert!(!body.contains("99999"), "the torn fragment must be removed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Records emitted DURING a multi-tick rotation (on_stall / try_reap) are
    /// flushed into the file that becomes `.1`. The post-rotation `boot` must
    /// record `.1`'s true on-disk tail as its `prev_chain` column — not a chain
    /// head snapshotted at rotation start — and the new generation must open
    /// with that boot (no record displaced ahead of it). Otherwise an offline
    /// tamper-evidence verifier reads the generation boundary as forgery on an
    /// otherwise-clean Class-C log.
    #[cfg(feature = "audit-chain")]
    #[test]
    fn records_emitted_during_deferred_rotation_keep_boot_chain_linear() {
        let dir = tmpdir("emit-during-rotation");
        let path = dir.join("audit.log");
        // Small max_bytes makes rotation due fast; a 1 µs budget forces the
        // rotation FSM to span multiple ticks — the only window the bug lives in.
        let mut c = cfg(Some(120), 1);
        c.rotation_budget = Duration::from_micros(1);
        let (mut log, _) = RecoveryAuditLog::create(&path, c).expect("create");

        let spawn = |pid: u32| crate::audit::SpawnRecord {
            wallclock_ms: 1,
            observer_ns: 1,
            agent_pid: pid,
            child_pid: pid + 100,
            mode: "exec",
            program: "/bin/true",
            source: "inline",
            template_len: 9,
        };

        // Push the file past max_bytes so rotation becomes due.
        for pid in 0..8u32 {
            log.record_spawn(&spawn(pid));
        }
        log.flush_pending(Duration::from_secs(1));
        assert!(log.audit_rotation_due() || log.audit_rotation_pending());

        // Kick off rotation; with a 1 µs budget it defers mid-flight, before
        // the live file is renamed to `.1`.
        let _ = log.drive_audit_rotation(Duration::from_micros(1));
        assert!(
            !log.rotation_progress.is_idle(),
            "rotation must still be in progress after one budgeted step"
        );

        // Emit records DURING the rotation window, then flush — exactly the
        // main-loop ordering (flush_audit_pending runs before drive_audit_rotation
        // each tick). These advance the hash chain and land in the file that is
        // about to become `.1`.
        for pid in 100..104u32 {
            log.record_spawn(&spawn(pid));
        }
        log.flush_pending(Duration::from_secs(5));

        // Finish the rotation.
        for _ in 0..256 {
            if matches!(
                log.drive_audit_rotation(Duration::from_secs(5)),
                crate::audit::RotationOutcome::Complete
            ) {
                break;
            }
        }
        assert!(log.rotation_progress.is_idle(), "rotation must complete");
        drop(log);

        let one = std::fs::read_to_string(path.with_extension("log.1")).expect("read .1");
        let live = std::fs::read_to_string(&path).expect("read live");

        // (a) The new generation opens with the rotation boot record.
        let first_live = live
            .lines()
            .find(|l| !l.starts_with('#'))
            .expect("a record in the new generation");
        let boot_cols: Vec<&str> = first_live.split('\t').collect();
        assert_eq!(
            boot_cols.get(3),
            Some(&"boot"),
            "new generation must open with a boot record, got: {first_live}"
        );
        assert_eq!(
            boot_cols.get(6),
            Some(&"rotation"),
            "boot reason must be rotation, got: {first_live}"
        );

        // (b) The boot's prev_chain column must equal `.1`'s on-disk tail chain.
        let last_one = one
            .lines()
            .rfind(|l| !l.starts_with('#'))
            .expect("a record in .1");
        let one_tail_chain = last_one.rsplit('\t').next().unwrap();
        let boot_prev = boot_cols.get(5).copied().expect("boot prev_chain column");
        assert_eq!(
            boot_prev, one_tail_chain,
            "rotation boot prev_chain must equal .1's tail chain (stale-snapshot bug)"
        );

        // (c) The boot's own chain folds linearly from `.1`'s tail chain.
        let one_tail_raw =
            varta_vlp::util::decode_hex_32(one_tail_chain.as_bytes()).expect("hex tail chain");
        let boot_body = first_live.rsplit_once('\t').unwrap().0;
        let expected =
            varta_vlp::crypto::audit_chain_hash(&one_tail_raw, b"boot", boot_body.as_bytes());
        let expected_hex =
            String::from_utf8(varta_vlp::util::encode_hex_32(&expected).to_vec()).unwrap();
        let boot_chain = boot_cols.last().copied().unwrap();
        assert_eq!(
            boot_chain, expected_hex,
            "boot chain must fold linearly from .1's tail chain"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
