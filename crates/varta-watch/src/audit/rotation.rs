//! File rotation FSM, tail probe, fsync sequencing.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::schema::{
    parse_leading_seq, parse_record, BootReason, AUDIT_HEADER_V1_PREFIX, AUDIT_HEADER_V2,
};
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
    /// The generation renames and the new live file's `create_new` are
    /// visible in the directory but not yet durable: per `fsync(2)`, fsyncing
    /// a file does NOT persist the directory entry that names it. One fsync
    /// of the parent directory makes the whole rename chain plus the new
    /// live entry (and the EXDEV fallback's `create_new`/`unlink` pair)
    /// durable. This runs as its OWN stage — never inside the `Finalizing`
    /// tail — so the tail keeps the exact two-fsync cost its budget model is
    /// sized for (bug-363/373/379): per-call worst case stays
    /// drain(≤budget) + 2·fsync, and this stage's worst case is a budget
    /// check + 1·fsync on a fresh `call_start`.
    SyncingDir,
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
                    // Recheck budget before the last Renaming step (live→`.1`).
                    // The fast path is a single `rename(2)`, but on EXDEV
                    // (overlayfs / cross-device bind mounts) `rotate_live_to_first`
                    // falls back to `copy_live_to_first`, an unbounded whole-file
                    // I/O that can overrun the Maintenance self-watchdog stage when
                    // stacked on top of an already-spent rotation budget →
                    // `process::abort()` of a healthy observer (same abort-class
                    // hazard as bug-363/373/379). The check is placed BEFORE the
                    // `.1→.2` generation sub-step to avoid a livelock: if placed
                    // after, a tight budget fires every tick after the (idempotent,
                    // ENOENT-fast) sub-step and the FSM never advances.
                    if next_gen == 1 && call_start.elapsed() >= budget {
                        self.audit_rotation_budget_exceeded_total =
                            self.audit_rotation_budget_exceeded_total.saturating_add(1);
                        return RotationOutcome::Deferred;
                    }
                    let sub_result = if next_gen == AUDIT_ROTATION_GENERATIONS {
                        let oldest = generation_path(&self.path, AUDIT_ROTATION_GENERATIONS);
                        match std::fs::remove_file(&oldest) {
                            Ok(()) => Ok(()),
                            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                            Err(e) => Err(e),
                        }
                    } else {
                        let src = generation_path(&self.path, next_gen);
                        let dst = generation_path(&self.path, next_gen + 1);
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
                        let first = generation_path(&self.path, 1);
                        if let Err(e) = self.rotate_live_to_first(&first) {
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

                    // The tail below — `.1` fsync, sink swap, v2 header, boot
                    // record, new-generation fsync — is atomic (chain linearity
                    // forbids a `Deferred` between the header and its boot anchor;
                    // see the block comment at the OpenOptions call) and runs TWO
                    // ordered fsyncs UNBUDGETED. If the drain above already spent
                    // the rotation budget, running the tail now stacks those
                    // fsyncs on top of a full-budget call: the per-call wall time
                    // becomes drain(≤budget) + 2·fsync, which defeats the
                    // `MAX_AUDIT_ROTATION_BUDGET_MS ≤ MAINTENANCE_STAGE_ABORT_MS/2`
                    // clamp (bug-363) and can overrun the Maintenance self-watchdog
                    // stage → `process::abort()` of a HEALTHY observer on a slow
                    // disk. The drain is now empty, so defer: the next tick
                    // re-enters `Finalizing`, re-drains (a no-op when empty),
                    // re-snapshots `final_chain` from the current `prev_chain`, and
                    // runs the atomic tail with a fresh `call_start` — restoring
                    // the one-call-≤-budget invariant the clamp relies on.
                    if call_start.elapsed() >= budget {
                        self.audit_rotation_budget_exceeded_total =
                            self.audit_rotation_budget_exceeded_total.saturating_add(1);
                        return RotationOutcome::Deferred;
                    }

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
                    let mut options = OpenOptions::new();
                    options.read(true).create_new(true).append(true).mode(0o600);
                    let file = match crate::file_security::open_nofollow(&self.path, &mut options) {
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
                        // Give up on the boot anchor, but still route through
                        // `SyncingDir`: the renames and the `create_new` above
                        // already mutated the directory and deserve durability
                        // regardless of the header failure.
                        self.rotation_progress = RotationProgress::SyncingDir;
                        continue;
                    }
                    self.bytes_written = AUDIT_HEADER_V2.len() as u64;

                    // Suppress the boot record's own cadence fsync so the tail
                    // runs exactly the TWO ordered fsyncs its budget model is
                    // sized for (the `.1` sync above + the new-generation sync
                    // below). At default `sync_every == 1` the single boot write
                    // makes `writes_since_sync` reach the cadence and
                    // `direct_write_line` would otherwise fire a THIRD,
                    // unbudgeted `fdatasync` — the explicit `flush_and_sync`
                    // immediately after already makes the boot anchor durable,
                    // so that extra syscall is pure overrun that defeats the
                    // `MAX_AUDIT_ROTATION_BUDGET_MS ≤ MAINTENANCE_STAGE_ABORT_MS/2`
                    // clamp (bug-363/373) and can `process::abort()` a healthy
                    // observer on a slow disk (bug-379). `flush_pending` resets
                    // this flag at the start of the next tick's drain, so the
                    // suppression cannot leak into normal cadence syncing.
                    self.deferred_fsync_in_drain = true;
                    self.emit_boot(BootReason::Rotation, Some(final_chain));
                    if let Err(e) = self.flush_and_sync() {
                        self.pending_err = Some(e);
                    } else {
                        self.writes_since_sync = 0;
                    }
                    // The boot anchor's bytes are durable, but the directory
                    // entries (renames + the new live file's `create_new`)
                    // are not until `SyncingDir` fsyncs the parent directory.
                    // The residual window — boot fdatasync returned, dirent
                    // sync pending — lasts at most until the next tick's
                    // re-entry (vs. unbounded before this stage existed);
                    // closing it fully would require a third fsync inside
                    // this tail, re-creating the bug-379 abort hazard.
                    self.rotation_progress = RotationProgress::SyncingDir;
                    continue;
                }
                RotationProgress::SyncingDir => {
                    // Same pre-step recheck as the live→`.1` move: the fsync
                    // below is unbudgeted, so enter it only while budget
                    // remains; otherwise resume next tick with a fresh
                    // `call_start` (loop-top `>` alone is not deterministic
                    // for a `Duration::ZERO` budget on a coarse clock).
                    if call_start.elapsed() >= budget {
                        self.audit_rotation_budget_exceeded_total =
                            self.audit_rotation_budget_exceeded_total.saturating_add(1);
                        return RotationOutcome::Deferred;
                    }
                    // On failure, latch and give up rather than wedge the FSM:
                    // the in-memory state is already past the renames, the
                    // error surfaces via `take_pending_err`, and some
                    // platforms reject directory fsync outright (same soft
                    // posture as the UDS-bind parent-dir fsync).
                    if let Err(e) = crate::file_security::fsync_parent_dir(&self.path) {
                        self.pending_err = Some(e);
                    }
                    self.rotation_progress = RotationProgress::Idle;
                    self.needs_rotation = false;
                    return RotationOutcome::Complete;
                }
            }
        }
    }

    /// Move the live file to `.1` to open the post-rotation generation.
    ///
    /// Fast path is `rename(2)`: `self.sink`'s open fd follows the inode into
    /// `.1`, so the subsequent `Finalizing` drain + fsync append to — and make
    /// durable — the rotated generation. On `EXDEV` (the audit directory and
    /// its `.N` siblings resolve to different devices — overlayfs upper/lower
    /// splits, certain bind-mount layouts) rename is impossible and we fall
    /// back to copy+unlink, which needs the inode re-point in
    /// [`Self::copy_live_to_first`].
    fn rotate_live_to_first(&mut self, first: &Path) -> io::Result<()> {
        match std::fs::rename(&self.path, first) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) if is_cross_device_error(&e) => self.copy_live_to_first(first),
            Err(e) => Err(e),
        }
    }

    /// `EXDEV` fallback for [`Self::rotate_live_to_first`].
    ///
    /// `copy`+`remove_file` makes `.1` a SEPARATE inode from the one
    /// `self.sink`'s fd holds — unlike the rename fast path, the fd does NOT
    /// follow into `.1`. Left as-is, the `Finalizing` drain and its `fsync`
    /// would write into the now-unlinked original inode: the records silently
    /// vanish, and the post-rotation `boot` anchor's `final_chain` (snapshotted
    /// from `prev_chain`) never matches `.1`'s true tail — a hash-chain break
    /// across the generation boundary that an offline tamper-evidence verifier
    /// cannot distinguish from forgery. So flush first (the copy captures every
    /// durable byte, never a half-written buffer) then re-point `self.sink` at
    /// `.1` so `Finalizing` appends and fsyncs there exactly as the rename path
    /// does.
    fn copy_live_to_first(&mut self, first: &Path) -> io::Result<()> {
        self.flush_and_sync()?;
        // Read from the writer's exact inode, not from a fresh pathname open:
        // an attacker cannot replace `self.path` between flush and copy and
        // redirect the fallback into an unrelated same-UID file.
        let mut source = self.sink.get_ref().try_clone_file()?;
        source.seek(SeekFrom::Start(0))?;

        use std::os::unix::fs::OpenOptionsExt;
        let mut destination_options = OpenOptions::new();
        destination_options
            .create_new(true)
            .append(true)
            .mode(0o600);
        let mut destination = crate::file_security::open_nofollow(first, &mut destination_options)?;
        if let Err(e) = std::io::copy(&mut source, &mut destination) {
            let _ = std::fs::remove_file(first);
            return Err(e);
        }
        if let Err(e) = destination.sync_all() {
            let _ = std::fs::remove_file(first);
            return Err(e);
        }
        if let Err(e) = std::fs::remove_file(&self.path) {
            let _ = std::fs::remove_file(first);
            return Err(e);
        }
        use super::writer::{DurableSink, FileSink};
        let sink_box: Box<dyn DurableSink> = Box::new(FileSink(destination));
        self.sink = std::io::BufWriter::new(sink_box);
        Ok(())
    }

    /// Read up to the last [`TAIL_SCAN_BYTES`] of `path` and parse the
    /// most recent record line to derive seq + chain + boot reason.
    #[cfg(test)]
    pub(super) fn probe_tail(path: &Path) -> io::Result<TailProbe> {
        let mut options = OpenOptions::new();
        options.read(true);
        let mut file = crate::file_security::open_nofollow(path, &mut options)?;
        crate::file_security::validate_regular_file(&file, path)?;
        Self::probe_tail_file(&mut file)
    }

    /// Descriptor-based tail probe used by [`RecoveryAuditLog::create`].
    ///
    /// Keeping the probe on the same descriptor that will be truncated and
    /// appended prevents a pathname replacement from redirecting recovery.
    pub(super) fn probe_tail_file(file: &mut std::fs::File) -> io::Result<TailProbe> {
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
        let head_is_v2 = head_str.starts_with(AUDIT_HEADER_V2.trim_end_matches('\n'));
        let head_is_v1 = head_str.starts_with(AUDIT_HEADER_V1_PREFIX);

        if !head_is_v2 {
            // The head is a v1 header, a drifted header, or arbitrary bytes —
            // but "v2-ness" is a property of the *whole* file, not just the
            // head. `create` MIGRATES a v1/drift file by appending a v2 header
            // (and its `boot` record) BELOW the original leading bytes, which it
            // deliberately preserves as provenance. So a once-migrated file
            // still *starts* with its v1/drift header while carrying a complete
            // v2 region lower down. Concluding "unmigrated" from the head alone
            // re-migrates on every restart: another header is appended, `seq`
            // rolls back to 1, and the hash chain restarts from zero — the exact
            // monotonic-seq + linear-chain break the v2 format exists to prevent
            // (the head-window twin of the tail-window hazard `classify_tail`
            // guards against). Read the file once and locate the last v2 header
            // before drawing that conclusion. This whole-file read runs only for
            // a non-v2 head (a legacy / drifted file, never the common native-v2
            // restart), once at startup, and is bounded by the same `max_bytes`
            // rotation cap the native-v2 widen path already relies on.
            file.seek(SeekFrom::Start(0))?;
            let mut whole = vec![0u8; total as usize];
            file.read_exact(&mut whole)?;
            return Ok(match last_v2_header_end(&whole) {
                None => {
                    // No v2 header anywhere: this file was never migrated.
                    // Classify the head and let `create` migrate it once.
                    let reason = if head_is_v1 {
                        BootReason::LegacyV1
                    } else {
                        BootReason::SchemaDrift
                    };
                    TailProbe {
                        last_seq: 0,
                        last_chain: [0u8; 32],
                        reason,
                        truncate_to: None,
                        has_v2_header: false,
                    }
                }
                Some(data_start) => {
                    // Already migrated: the authoritative v2 region begins right
                    // after the last header. Resume from its tail exactly as a
                    // native v2 file would — no new header, `seq`/chain continue.
                    // `last_v2_header_end` guarantees `data_start <= whole.len()`;
                    // the `get` is a static guard so a future arithmetic slip
                    // degrades to the empty-region path instead of panicking.
                    let region = whole.get(data_start as usize..).unwrap_or(&[]);
                    classify_tail(region, data_start, data_start).0
                }
            });
        }

        // Native v2 file (header at offset 0). Fast path: scan only the last
        // `TAIL_SCAN_BYTES`. For a file at or below the window this already
        // covers the whole body; for the common small-record case it keeps the
        // restart read cheap.
        let scan_len = TAIL_SCAN_BYTES.min(total);
        let scan_start = total - scan_len;
        file.seek(SeekFrom::Start(scan_start))?;
        let mut buf = vec![0u8; scan_len as usize];
        file.read_exact(&mut buf)?;

        let data_start = AUDIT_HEADER_V2.len() as u64;
        let (probe, recovered) = classify_tail(&buf, scan_start, data_start);
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
        let (probe, _) = classify_tail(&buf, scan_start, data_start);
        Ok(probe)
    }
}

/// Return the absolute offset just past the last v2 header line in `buf`, or
/// `None` when no v2 header is present. The offset is the start of the
/// authoritative v2 data region (the bytes a migrated file resumes from).
///
/// The needle includes the trailing newline, so it can only match a real
/// header line: record fields are `sanitize`d (tab/newline stripped) and every
/// record begins with a `seq` digit, never `#`, so the header text can never
/// occur inside a record body.
fn last_v2_header_end(buf: &[u8]) -> Option<u64> {
    let needle = AUDIT_HEADER_V2.as_bytes();
    if buf.len() < needle.len() {
        return None;
    }
    buf.windows(needle.len())
        .rposition(|w| w == needle)
        .map(|pos| (pos + needle.len()) as u64)
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
///
/// `data_start` is the absolute offset of the v2 data region (just past the v2
/// header). When a torn tail leaves no newline in the buffer, truncation falls
/// back to this floor rather than the file head, so a file MIGRATED from v1 —
/// whose v2 header sits below a preserved v1 section — never truncates into its
/// provenance bytes.
fn classify_tail(buf: &[u8], scan_start: u64, data_start: u64) -> (TailProbe, bool) {
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
        // The last line is complete (newline-terminated) yet unparseable: a
        // bit-rot-corrupted record, or a forward-incompatible newer-schema
        // record. Unlike a torn fragment it is NOT truncated — it may be
        // durable data a newer verifier can still read — but `seq` and the
        // hash chain MUST resume from the last record we *can* parse. Falling
        // straight through to a seq-0 / zero-chain reset (as this branch used
        // to) rolls `seq` back to 1 and re-anchors the chain at genesis in the
        // middle of an otherwise-clean file, which an offline tamper-evidence
        // verifier cannot distinguish from forgery across every prior record —
        // the exact silent integrity break the v2 format guarantees against,
        // and the clean-tail sibling of the torn-tail look-back below.
        let prior = if last_line_start == 0 {
            &view[..0]
        } else {
            &view[..last_line_start - 1]
        };
        let prev_start = prior
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(0);
        // `prev_start == 0` is a true line boundary only when the buffer starts
        // at the data region (`scan_start == data_start`). In a windowed read
        // that began *after* the data region, offset 0 is wherever the
        // `TAIL_SCAN_BYTES` window happened to cut — possibly mid-record — so
        // `&prior[0..]` is a leading fragment, not a whole prior record. On the
        // default build (chain column `-`) `parse_record` accepts that fragment
        // with a WRONG `seq` and would falsely report `recovered = true`,
        // suppressing the caller's widen-rescan and resuming the log at a bogus
        // sequence (seq reuse / hash-chain break). Trust the look-back only at a
        // genuine boundary; otherwise fall through to the reset so the caller
        // widens to the full data region, where offset 0 *is* a real boundary.
        if prev_start != 0 || scan_start <= data_start {
            if let Some((seq, chain)) = parse_record(&prior[prev_start..]) {
                // The unparseable drift record (`last_line`) is RETAINED on disk
                // (`truncate_to: None` — it may be newer-schema durable data), so
                // the resumed `seq` cursor must step PAST *its* seq, not just the
                // parseable predecessor's. Otherwise `next_seq = predecessor_seq
                // + 1` reuses the drift record's seq and two records share one
                // seq, false-tripping the gap/loss detector
                // (book/src/architecture/audit-log.md). The drift record's
                // leading seq column is a plain `u64` even when a later column is
                // corrupt; fall back to the predecessor's seq if it does not
                // parse. The hash chain still resumes from the parseable
                // predecessor (`last_chain`), which the verifier links across the
                // skipped drift line.
                let last_seq = match parse_leading_seq(last_line) {
                    Some(drift_seq) => seq.max(drift_seq),
                    None => seq,
                };
                return (
                    TailProbe {
                        last_seq,
                        last_chain: chain,
                        reason: BootReason::SchemaDrift,
                        truncate_to: None,
                        has_v2_header: true,
                    },
                    true,
                );
            }
            // The look-back was a real whole record (a true boundary, or the
            // full data region) that ALSO failed to parse — two or more
            // consecutive complete-but-unparseable drift records. This result
            // is USED (not re-widened) on the full-region rescan, so step `seq`
            // PAST the last drift record's own leading sequence: that record is
            // RETAINED on disk (`truncate_to: None`), and resetting to 0 would
            // reuse its seq and false-trip the gap/loss detector — the same
            // strict-monotonic-seq break the look-back branch above guards
            // (bug-475, this is its consecutive-drift sibling). `last_line` is a
            // complete record (clean-tail branch), so its leading seq column is
            // safe to read even when a later column is corrupt; fall back to 0
            // only if even the seq column is unreadable. The chain cannot be
            // recovered across consecutive corrupt records, so it re-anchors at
            // genesis — appropriate, since the corrupt span is a genuine break.
            return (
                TailProbe {
                    last_seq: parse_leading_seq(last_line).unwrap_or(0),
                    last_chain: [0u8; 32],
                    reason: BootReason::SchemaDrift,
                    truncate_to: None,
                    has_v2_header: true,
                },
                false,
            );
        }
        // Untrusted windowed look-back: `prev_start == 0` in a read that began
        // AFTER the data region, so offset 0 is the window's cut, not a record
        // boundary, and nothing here is trusted. Reset to seq 0 / genesis with
        // `recovered = false` so the caller widens to the full data region —
        // where offset 0 IS a boundary and the branch above recovers the seq.
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
        None => Some(data_start),
    };

    if let Some(rel) = last_nl {
        let view = &buf[..rel];
        let prev_start = view
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|p| p + 1)
            .unwrap_or(0);
        let prev_line = &view[prev_start..];
        // Same windowed-fragment guard as the clean branch above: when
        // `prev_start == 0` and the scan began after the data region, this
        // "prior record" is the leading fragment of a record the window cut
        // through, not a real prior record — trusting it would resume at a
        // wrong `seq`. Fall through to the reset so the caller widens.
        if prev_start != 0 || scan_start <= data_start {
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

fn generation_path(path: &Path, generation: u32) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{generation}"));
    PathBuf::from(value)
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

    /// A `Finalizing` drain that empties the queue but consumes the whole
    /// rotation budget must NOT then run the unbudgeted sink-swap + 2-fsync tail
    /// in the same call. Doing so makes one `drive_audit_rotation` cost
    /// drain(≤budget) + 2·fsync, defeating the
    /// `MAX_AUDIT_ROTATION_BUDGET_MS ≤ MAINTENANCE_STAGE_ABORT_MS/2` clamp
    /// (bug-363) and able to overrun the Maintenance self-watchdog stage →
    /// `process::abort()` of a healthy observer on a slow disk. The tail must
    /// defer to a fresh call where the drain is empty and `call_start` is reset.
    #[test]
    fn rotation_finalizing_defers_tail_when_drain_exhausts_budget() {
        let writes = Arc::new(AtomicUsize::new(0));
        let mut log = synthetic_rotation_log(writes.clone(), Duration::from_millis(10));
        // Enter the FSM directly at the post-rename stage with the sink still on
        // the soon-to-be `.1` inode — the only state the tail hazard lives in.
        log.rotation_progress = RotationProgress::Finalizing;

        log.record_spawn(&crate::audit::SpawnRecord {
            wallclock_ms: 1,
            observer_ns: 1,
            agent_pid: 7,
            child_pid: 107,
            mode: "exec",
            program: "/bin/true",
            source: "inline",
            template_len: 9,
        });
        assert_eq!(log.pending_lines.len(), 1);

        // budget == the single drain write's cost: the drain COMPLETES (queue
        // empties) yet `call_start.elapsed()` reaches the budget, so the atomic
        // tail must defer rather than run on top of an already-spent budget.
        let outcome = log.drive_audit_rotation(Duration::from_millis(10));

        assert_eq!(outcome, RotationOutcome::Deferred);
        assert!(
            log.pending_lines.is_empty(),
            "the drain itself must have completed — the deferral is the tail's, not the drain's"
        );
        assert!(
            matches!(log.rotation_progress, RotationProgress::Finalizing),
            "rotation must stay armed in Finalizing so the next tick runs the tail with a fresh call_start"
        );
        assert!(log.needs_rotation);
        assert_eq!(
            writes.load(Ordering::Relaxed),
            1,
            "only the drain write ran; the swap + header + boot tail must not have executed"
        );
        assert_eq!(log.audit_rotation_budget_exceeded_total, 1);
    }

    /// The `Finalizing` atomic tail must run EXACTLY two fsyncs — the `.1`
    /// durability sync before the swap and the new-generation sync after the
    /// boot anchor — never three. At default `sync_every == 1` the single boot
    /// write reaches the fsync cadence, so without the in-tail suppression
    /// `emit_boot`'s `direct_write_line` fires a third, unbudgeted `fdatasync`
    /// on top of the explicit one that follows it. That extra syscall defeats
    /// the `MAX_AUDIT_ROTATION_BUDGET_MS ≤ MAINTENANCE_STAGE_ABORT_MS/2` clamp
    /// (bug-363/373) and can `process::abort()` a healthy observer on a slow
    /// disk (bug-379). `fsync_durations` records one entry per `flush_and_sync`,
    /// so its length after a rotation from an empty queue is the exact tail
    /// fsync count.
    #[test]
    fn rotation_finalizing_tail_runs_exactly_two_fsyncs() {
        let writes = Arc::new(AtomicUsize::new(0));
        // Zero write delay so the generous budget is never the limiting factor —
        // this isolates fsync COUNT, not timing.
        let mut log = synthetic_rotation_log(writes, Duration::from_millis(0));
        // The tail re-opens `self.path` and swaps the sink to a real `FileSink`
        // before the post-swap fsyncs; point it at a writable temp file so those
        // `sync_data` calls succeed and are recorded (a character device like
        // /dev/null errors `sync_data` on macOS, hiding them).
        let dir = tmpdir("tail-fsync");
        log.path = dir.join("audit.log");
        // Enter directly at the post-rename tail with an empty queue so the
        // drain is a no-op and every recorded fsync belongs to the atomic tail.
        log.rotation_progress = RotationProgress::Finalizing;
        assert_eq!(log.sync_every, 1, "default cadence is the hazard case");
        assert!(log.pending_lines.is_empty());
        assert!(log.fsync_durations.is_empty());

        let outcome = log.drive_audit_rotation(Duration::from_secs(5));

        assert_eq!(outcome, RotationOutcome::Complete);
        assert_eq!(
            log.fsync_durations.len(),
            2,
            "tail must fsync exactly twice (.1 durability + new-generation); a \
             third means emit_boot's cadence fsync was not suppressed (bug-379)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After the `Finalizing` tail, the FSM must pass through `SyncingDir` —
    /// the stage that makes the rename chain and the new live `create_new`
    /// durable (per `fsync(2)`, fsyncing a file does not persist the
    /// directory entry naming it). With the budget already exhausted, the
    /// stage must defer to the next tick rather than stack an unbudgeted
    /// directory fsync on a spent call (the same abort-class hazard as
    /// bug-363/373/379).
    #[test]
    fn syncing_dir_stage_defers_when_budget_exhausted() {
        let dir = tmpdir("syncdir-defer");
        let path = dir.join("audit.log");
        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        log.rotation_progress = RotationProgress::SyncingDir;
        log.needs_rotation = true;

        let outcome = log.drive_audit_rotation(Duration::ZERO);

        assert_eq!(outcome, RotationOutcome::Deferred);
        assert!(
            matches!(log.rotation_progress, RotationProgress::SyncingDir),
            "must stay in SyncingDir so the next tick retries with a fresh budget"
        );
        assert!(log.needs_rotation, "rotation must stay armed");
        assert_eq!(log.audit_rotation_budget_exceeded_total, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `SyncingDir` completes the rotation: the parent-directory fsync makes
    /// the dirent mutations durable, the FSM returns to Idle, and rotation is
    /// disarmed with no error latched.
    #[test]
    fn syncing_dir_stage_completes_and_disarms() {
        let dir = tmpdir("syncdir-ok");
        let path = dir.join("audit.log");
        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        log.rotation_progress = RotationProgress::SyncingDir;
        log.needs_rotation = true;

        let outcome = log.drive_audit_rotation(Duration::from_secs(5));

        assert_eq!(outcome, RotationOutcome::Complete);
        assert!(log.rotation_progress.is_idle());
        assert!(!log.needs_rotation);
        assert!(
            log.pending_err.is_none(),
            "a successful directory fsync must not latch an error"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rotation_preserves_non_utf8_generation_path_identity() {
        use std::os::unix::ffi::OsStringExt;

        let dir = tmpdir("non-utf8");
        let path = dir.join(std::ffi::OsString::from_vec(b"audit-\xff.log".to_vec()));
        let first = generation_path(&path, 1);
        let lossy_first = PathBuf::from(format!("{}.1", path.to_string_lossy()));
        assert_ne!(first, lossy_first, "fixture paths must be distinct");

        let victim = b"unrelated lossy-path file\n";
        std::fs::write(&lossy_first, victim).expect("seed lossy-path victim");
        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        log.rotation_progress = RotationProgress::Renaming { next_gen: 1 };
        log.needs_rotation = true;

        let outcome = log.drive_audit_rotation(Duration::from_secs(5));

        assert_eq!(outcome, RotationOutcome::Complete);
        assert!(
            first.exists(),
            "rotation must append `.1` to the exact Unix pathname bytes"
        );
        assert_eq!(
            std::fs::read(&lossy_first).expect("read lossy-path victim"),
            victim,
            "rotation must not overwrite the distinct lossy UTF-8 pathname"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed parent-directory fsync must latch the error and complete —
    /// never wedge the FSM in `SyncingDir`. The in-memory state is already
    /// past the renames; the error surfaces via `take_pending_err` (same
    /// soft posture as the UDS-bind parent-directory fsync).
    #[test]
    fn syncing_dir_failure_latches_error_and_completes() {
        let writes = Arc::new(AtomicUsize::new(0));
        let mut log = synthetic_rotation_log(writes, Duration::from_millis(0));
        log.path = PathBuf::from("/nonexistent-varta-bug403/audit.log");
        log.rotation_progress = RotationProgress::SyncingDir;

        let outcome = log.drive_audit_rotation(Duration::from_secs(5));

        assert_eq!(outcome, RotationOutcome::Complete);
        assert!(log.rotation_progress.is_idle());
        assert!(!log.needs_rotation);
        assert!(
            log.pending_err.is_some(),
            "directory-fsync failure must be latched for take_pending_err"
        );
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

    /// A v1 file migrates exactly once. `create` preserves the v1 header as
    /// provenance and appends the v2 region below it, so on the NEXT restart the
    /// file still *starts* with the v1 header. The probe must recognise the
    /// embedded v2 region and RESUME — not re-migrate. The unfixed head-only
    /// classifier re-migrated on every restart: a fresh v2 header stacked each
    /// boot, `seq` rolled back to 1, and the SHA-256 chain restarted from zero —
    /// silent destruction of the monotonic-seq + linear-chain Class-C guarantee.
    #[test]
    fn migrated_v1_file_resumes_on_restart_instead_of_remigrating() {
        let dir = tmpdir("v1-resume");
        let path = dir.join("audit.log");
        std::fs::write(
            &path,
            "# varta-watch recovery audit v1\n\
             1700000000000\t42\tspawn\t7\t9001\texec\t/bin/true\tinline\t9\n",
        )
        .expect("write v1");

        // Restart #1: migrates (legacy_v1 boot + v2 header appended).
        let (mut log1, w1) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create 1");
        assert!(w1.legacy_v1, "first open of a v1 file must migrate");
        log1.record_spawn(&crate::audit::SpawnRecord {
            wallclock_ms: 1,
            observer_ns: 1,
            agent_pid: 1,
            child_pid: 100,
            mode: "exec",
            program: "/bin/a",
            source: "inline",
            template_len: 1,
        });
        log1.flush_pending(Duration::from_secs(5));
        drop(log1);

        // Restart #2: file still starts with the v1 header but carries a
        // complete v2 region — must resume, not re-migrate.
        let (mut log2, w2) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create 2");
        assert!(
            !w2.legacy_v1,
            "a migrated file must not re-migrate on restart"
        );
        log2.record_spawn(&crate::audit::SpawnRecord {
            wallclock_ms: 2,
            observer_ns: 2,
            agent_pid: 2,
            child_pid: 200,
            mode: "exec",
            program: "/bin/b",
            source: "inline",
            template_len: 1,
        });
        log2.flush_pending(Duration::from_secs(5));
        drop(log2);

        let body = std::fs::read_to_string(&path).expect("read");

        // (a) Exactly one v2 header — restart #2 must not stack another.
        assert_eq!(
            body.matches(AUDIT_HEADER_V2).count(),
            1,
            "restart must not append a second v2 header:\n{body}"
        );

        // (b) Migration boot then resume boot — not two legacy_v1 boots.
        let boots: Vec<&str> = body.lines().filter(|l| l.contains("\tboot\t")).collect();
        assert_eq!(
            boots.len(),
            2,
            "one migration boot + one resume boot:\n{body}"
        );
        assert!(
            boots[0].contains("\tlegacy_v1"),
            "first boot is the migration"
        );
        assert!(
            boots[1].contains("\tresume"),
            "second boot must resume, got: {}",
            boots[1]
        );

        // (c) seq strictly monotonic across every v2 record — no rollback to 1.
        let v2_start = body.find(AUDIT_HEADER_V2).unwrap() + AUDIT_HEADER_V2.len();
        let mut last_seq = 0u64;
        for line in body[v2_start..].lines().filter(|l| !l.starts_with('#')) {
            let seq = parse_record(line.as_bytes()).expect("v2 record parses").0;
            assert!(
                seq > last_seq,
                "seq must be monotonic: {seq} after {last_seq}\n{body}"
            );
            last_seq = seq;
        }
        assert!(
            last_seq >= 4,
            "boot+spawn+boot+spawn => last seq >= 4, got {last_seq}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Probe-level pin: a hand-built migrated file (v1 header + v1 record, then
    /// a v2 header + two v2 records) must resume from the embedded v2 region's
    /// tail, scanning only the bytes after the last v2 header — never the v1
    /// provenance lines.
    #[test]
    fn probe_tail_treats_embedded_v2_header_as_resume_not_legacy() {
        let dir = tmpdir("embedded-v2");
        let path = dir.join("audit.log");
        let chain: String = if crate::audit::chain_enabled() {
            "a".repeat(64)
        } else {
            "-".to_string()
        };
        let body = format!(
            "# varta-watch recovery audit v1\n\
             1700000000000\t1\tspawn\t7\t9001\texec\t/bin/true\tinline\t9\n\
             # varta-watch recovery audit v2\n\
             1\t1\t1\tboot\t1234\t-\tlegacy_v1\t{chain}\n\
             2\t2\t2\tspawn\t7\t9001\texec\t/bin/x\tinline\t1\t{chain}\n",
        );
        std::fs::write(&path, &body).expect("write migrated");

        let probe = RecoveryAuditLog::probe_tail(&path).expect("probe");
        assert!(
            matches!(probe.reason, BootReason::Resume),
            "embedded v2 header must resume, got {:?}",
            probe.reason
        );
        assert_eq!(probe.last_seq, 2, "must resume from the last v2 record seq");
        assert!(probe.has_v2_header, "must report the v2 header present");
        assert_eq!(
            probe.truncate_to, None,
            "a clean migrated file must not truncate"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression (bug-491, sibling of bug-475): when a file ends with TWO or
    /// more consecutive complete-but-unparseable (drift) records, the clean-tail
    /// look-back fails (the predecessor is also unparseable) and falls through.
    /// That fallthrough returned `last_seq = 0`, so `next_seq` reset to 1 and
    /// reused the retained drift records' sequence numbers — a
    /// strict-monotonic-seq break an offline verifier reads as tampering. The
    /// fallthrough must step past the last drift record's own leading seq.
    #[test]
    fn probe_tail_steps_past_consecutive_unparseable_drift_records() {
        let dir = tmpdir("consec-drift");
        let path = dir.join("audit.log");
        let chain: String = if crate::audit::chain_enabled() {
            "a".repeat(64)
        } else {
            "-".to_string()
        };
        // Two valid v2 records (seq 1, 2), then two complete-but-unparseable
        // drift records (seq 99, 100) whose trailing chain column is malformed
        // (neither "-" nor 64 hex), so `parse_record` rejects them while their
        // leading seq column is still a plain u64.
        let body = format!(
            "# varta-watch recovery audit v2\n\
             1\t1\t1\tboot\t1234\t-\tlegacy_v1\t{chain}\n\
             2\t2\t2\tspawn\t7\t9001\texec\t/bin/x\tinline\t1\t{chain}\n\
             99\t99\t99\tspawn\t7\t9001\texec\t/bin/x\tinline\t1\tBADCHAIN\n\
             100\t100\t100\tspawn\t7\t9001\texec\t/bin/x\tinline\t1\tBADCHAIN\n",
        );
        std::fs::write(&path, &body).expect("write consecutive-drift file");

        let probe = RecoveryAuditLog::probe_tail(&path).expect("probe");
        assert_eq!(
            probe.last_seq, 100,
            "must step past the retained drift records' seq, not reset to 0"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same head-window blind spot afflicts drift-headed files: an
    /// unrecognised header is preserved on migration, so the head stays
    /// non-v2 forever. A migrated drift file must also resume, not re-migrate.
    #[test]
    fn migrated_drift_file_resumes_on_restart() {
        let dir = tmpdir("drift-resume");
        let path = dir.join("audit.log");
        std::fs::write(&path, "garbage not an audit header\n").expect("write drift");

        let (log1, w1) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create 1");
        assert!(w1.schema_drift, "first open of a drift file must migrate");
        drop(log1);

        let (log2, w2) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create 2");
        assert!(
            !w2.schema_drift,
            "a migrated drift file must not re-migrate"
        );
        drop(log2);

        let body = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            body.matches(AUDIT_HEADER_V2).count(),
            1,
            "restart must not append a second v2 header:\n{body}"
        );
        let boots: Vec<&str> = body.lines().filter(|l| l.contains("\tboot\t")).collect();
        assert_eq!(
            boots.len(),
            2,
            "one migration boot + one resume boot:\n{body}"
        );
        assert!(
            boots[0].contains("\tschema_drift"),
            "first boot is migration"
        );
        assert!(
            boots[1].contains("\tresume"),
            "second boot must resume, got: {}",
            boots[1]
        );
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

    /// Regression (bug-475): when `classify_tail`'s clean-unparseable branch
    /// RETAINS the drift record on disk (`truncate_to: None`) and recovers
    /// `last_seq` from the parseable predecessor, the resumed cursor must step
    /// PAST the retained record's own seq. Otherwise the post-drift boot reuses
    /// the drift record's seq (on-disk seqs `[1, 2, 3, 3]`), breaking the
    /// strict-monotonic-seq invariant the gap/loss detector relies on.
    #[test]
    fn clean_unparseable_drift_resume_does_not_reuse_retained_seq() {
        let dir = tmpdir("drift-seq");
        let path = dir.join("audit.log");

        // boot = seq 1, one spawn = seq 2.
        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        log.record_spawn(&crate::audit::SpawnRecord {
            wallclock_ms: 1,
            observer_ns: 1,
            agent_pid: 1,
            child_pid: 100,
            mode: "exec",
            program: "/bin/agent",
            source: "inline",
            template_len: 1,
        });
        log.flush_pending(Duration::from_secs(5));
        drop(log);

        // Append a newline-terminated record with a valid leading seq
        // (3 = last_good + 1) but a trailing column the v2 parser rejects — the
        // newer-schema / trailing-bit-rot "drift" case the clean branch keeps.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open for append");
            f.write_all(b"3\t1\t1\tspawn\t/bin/future\tnope\n")
                .expect("append drift");
            f.flush().expect("flush drift");
        }

        // Resume: SchemaDrift, retains the drift record, emits a post-drift boot.
        let (log2, w) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("re-create");
        assert!(w.schema_drift);
        drop(log2);

        let body = std::fs::read_to_string(&path).expect("read");
        let seqs: Vec<u64> = body
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .filter_map(|l| l.split('\t').next()?.parse::<u64>().ok())
            .collect();

        let mut unique = seqs.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            seqs.len(),
            "duplicate seq after clean-unparseable drift resume: {seqs:?}"
        );
        assert!(
            seqs.contains(&3),
            "the retained drift record (seq 3) must survive: {seqs:?}"
        );
        assert_eq!(
            seqs.iter().max(),
            Some(&4),
            "post-drift boot must resume at seq 4, never reuse 3: {seqs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// On the `EXDEV` rotation fallback, `copy`+`unlink` makes `.1` a fresh
    /// inode distinct from the one `self.sink`'s fd holds. The fallback must
    /// re-point the sink at `.1`; otherwise every record drained during
    /// `Finalizing` lands in the now-unlinked original inode and silently
    /// vanishes (and the post-rotation boot anchor's chain never matches
    /// `.1`'s tail — a hash-chain break across the generation boundary). This
    /// drives `copy_live_to_first` directly because forcing a real `EXDEV` is
    /// not portable across CI filesystems.
    #[test]
    fn cross_device_fallback_repoints_sink_so_drained_records_reach_first() {
        let dir = tmpdir("exdev");
        let path = dir.join("audit.log");

        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        log.record_spawn(&crate::audit::SpawnRecord {
            wallclock_ms: 1,
            observer_ns: 1,
            agent_pid: 1,
            child_pid: 100,
            mode: "exec",
            program: "/bin/before-rotation",
            source: "inline",
            template_len: 1,
        });
        log.flush_pending(Duration::from_secs(5));

        let first = generation_path(&path, 1);
        log.copy_live_to_first(&first)
            .expect("cross-device fallback");

        // The live file was unlinked; the snapshot copy now lives at `.1`.
        assert!(!path.exists(), "original live file must be unlinked");
        assert!(first.exists(), "rotated `.1` generation must exist");
        let first_body = std::fs::read_to_string(&first).expect("read .1");
        assert!(
            first_body.contains("/bin/before-rotation"),
            "pre-rotation records must be carried into `.1`"
        );

        // A record emitted AFTER the fallback must reach `.1` via the
        // re-pointed sink — not the orphaned, now-unlinked original inode.
        log.record_spawn(&crate::audit::SpawnRecord {
            wallclock_ms: 2,
            observer_ns: 2,
            agent_pid: 2,
            child_pid: 200,
            mode: "exec",
            program: "/bin/after-rotation",
            source: "inline",
            template_len: 2,
        });
        log.flush_pending(Duration::from_secs(5));

        let first_body = std::fs::read_to_string(&first).expect("read .1 again");
        assert!(
            first_body.contains("/bin/after-rotation"),
            "records drained after the cross-device fallback must be durable in \
             `.1`, not lost to the unlinked original inode"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_device_fallback_refuses_symlink_destination_without_modifying_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tmpdir("copy-symlink");
        let path = dir.join("audit.log");
        let first = dir.join("audit.log.1");
        let target = dir.join("victim");
        let original = b"must remain unchanged\n";
        std::fs::write(&target, original).expect("write target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("chmod target");

        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create audit");
        log.flush_pending(Duration::MAX);
        symlink(&target, &first).expect("create destination symlink");

        let err = log
            .copy_live_to_first(&first)
            .expect_err("copy fallback must refuse an existing symlink");

        assert!(matches!(
            err.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::InvalidInput
        ));
        assert!(
            std::fs::symlink_metadata(&first)
                .expect("destination symlink remains")
                .file_type()
                .is_symlink(),
            "fallback must not delete a destination it did not create"
        );
        assert_eq!(
            std::fs::read(&target).expect("read target"),
            original,
            "copy fallback must not overwrite the symlink target"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cross_device_fallback_reads_owned_descriptor_after_live_path_swap() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tmpdir("copy-source-swap");
        let path = dir.join("audit.log");
        let displaced = dir.join("displaced-audit.log");
        let first = dir.join("audit.log.1");
        let target = dir.join("victim");
        let original = b"must remain unchanged\n";
        std::fs::write(&target, original).expect("write target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
            .expect("chmod target");

        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create audit");
        log.flush_pending(Duration::MAX);
        std::fs::rename(&path, &displaced).expect("displace live audit path");
        symlink(&target, &path).expect("replace live path with symlink");

        log.copy_live_to_first(&first).expect("copy fallback");

        assert_eq!(
            std::fs::read(&target).expect("read target"),
            original,
            "copy fallback must not read from or write to the replacement target"
        );
        assert_eq!(
            std::fs::read(&first).expect("read rotated audit"),
            std::fs::read(&displaced).expect("read original audit inode"),
            "rotated generation must come from the descriptor owned by the writer"
        );
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

    /// A cleanly-flushed file whose final, fully-durable record is complete
    /// (newline-terminated) but unparseable — bit-rot, or a forward-
    /// incompatible newer-schema record — must resume `seq` and the hash chain
    /// from the last record that *does* parse, not reset them. The unfixed
    /// clean branch returned a seq-0 / zero-chain reset here (no look-back,
    /// unlike the torn branch), rolling `seq` back to 1 and re-anchoring the
    /// chain at genesis mid-file on the next restart — a silent Class-C
    /// integrity break across every prior record, with no crash or truncation
    /// to signal it. The complete unparseable record is preserved (not
    /// truncated): it may be data a newer verifier can read.
    #[test]
    fn clean_unparseable_tail_resumes_not_resets() {
        let dir = tmpdir("clean-drift");
        let path = dir.join("audit.log");

        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
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
        log.flush_pending(Duration::from_secs(5));
        drop(log);

        // Snapshot the last fully-parseable record (the spawn, seq > 1).
        let body = std::fs::read_to_string(&path).expect("read");
        let last_line = body
            .lines()
            .rfind(|l| !l.starts_with('#'))
            .expect("a v2 record");
        let (seq_good, chain_good) = parse_record(last_line.as_bytes()).expect("last parses");
        assert!(seq_good > 1, "precondition: a real record past the boot");

        // Append a COMPLETE (newline-terminated) but unparseable record: a
        // valid leading seq column with a malformed trailing chain column.
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open append");
            f.write_all(format!("{}\tbogus\tnot-a-valid-chain\n", seq_good + 1).as_bytes())
                .expect("clean unparseable write");
        }

        let probe = RecoveryAuditLog::probe_tail(&path).expect("probe");
        assert!(
            matches!(probe.reason, BootReason::SchemaDrift),
            "a complete unparseable tail is drift, got {:?}",
            probe.reason
        );
        // bug-475: the drift record (seq_good + 1) is RETAINED on disk, so the
        // resumed cursor must step PAST it — `last_seq` is `seq_good + 1`, NOT
        // `seq_good`. Resuming at `seq_good` (as this assertion originally
        // demanded) makes the next boot reuse `seq_good + 1` and two records
        // share one seq. Still no reset to 0; the chain still resumes from the
        // parseable predecessor below.
        assert_eq!(
            probe.last_seq,
            seq_good + 1,
            "seq must step past the retained drift record (seq_good+1), not \
             reuse seq_good (collision) and not reset to 0"
        );
        assert_eq!(
            probe.truncate_to, None,
            "a complete record must not be truncated"
        );
        #[cfg(feature = "audit-chain")]
        assert_eq!(
            probe.last_chain, chain_good,
            "chain must continue from the last good record, not genesis"
        );
        let _ = chain_good;
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
        // tail window so the window contains no newline at all. Use a marker
        // outside this fixture's valid record fields; low-entropy digit runs
        // can appear naturally in timestamps or audit-chain hex.
        let torn_marker = "TORN_FRAGMENT_SENTINEL";
        let torn_fragment = torn_marker.repeat((TAIL_SCAN_BYTES as usize / torn_marker.len()) + 2);
        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open append");
            f.write_all(torn_fragment.as_bytes()).expect("torn write");
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
        assert!(
            !body.contains(torn_marker),
            "the torn fragment must be removed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `classify_tail`'s look-back must not trust a record that abuts the buffer
    /// start of a *windowed* read (`scan_start > data_start`): offset 0 is then
    /// wherever the `TAIL_SCAN_BYTES` window cut, so `&buf[0..]` is the leading
    /// fragment of a record the window sliced through, not a real prior record.
    /// On the default build (chain column `-`) `parse_record` accepts such a
    /// fragment with a WRONG `seq`; the unfixed look-back returned
    /// `recovered = true`, suppressing `probe_tail`'s widen-rescan and resuming
    /// the log at a bogus sequence (seq reuse / hash-chain break a Class-C
    /// verifier reads as tampering). The fix forces `recovered = false` so the
    /// caller widens to the full data region, where offset 0 *is* a boundary.
    #[test]
    fn windowed_fragment_at_buffer_start_is_not_trusted_as_a_prior_record() {
        let data_start = AUDIT_HEADER_V2.len() as u64;
        // Simulate a 4096-window that began mid-record: the buffer starts at an
        // absolute offset well past the data region. `frag` is the tail of a
        // record the window sliced — it parses (first token a u64, last `-`)
        // but is NOT a whole record. The window holds exactly one newline, so
        // `prev_start` falls back to 0.
        let frag = b"200\tcol\t-";

        // CLEAN branch: a complete-but-unparseable final line after the fragment.
        let mut clean = Vec::new();
        clean.extend_from_slice(frag);
        clean.push(b'\n');
        clean.extend_from_slice(b"7\tbogus\tnot-a-valid-chain\n");

        // Windowed read (scan_start > data_start): the fragment must be rejected.
        let (probe, recovered) = classify_tail(&clean, data_start + 100, data_start);
        assert!(
            !recovered,
            "clean branch: a fragment at a windowed-read boundary must not be trusted"
        );
        assert_eq!(probe.last_seq, 0, "untrusted look-back resets to seq 0");

        // Whole-region read (scan_start == data_start): offset 0 IS a real
        // boundary, so the legitimate bug-401 look-back is preserved.
        let (probe, recovered) = classify_tail(&clean, data_start, data_start);
        assert!(
            recovered,
            "whole-region read: a record at the true data-region start must be trusted"
        );
        assert_eq!(
            probe.last_seq, 200,
            "look-back resumes from the real prior record"
        );

        // TORN branch: an unterminated fragment after the fragment+newline.
        let mut torn = Vec::new();
        torn.extend_from_slice(frag);
        torn.push(b'\n');
        torn.extend_from_slice(b"99999");

        let (probe, recovered) = classify_tail(&torn, data_start + 100, data_start);
        assert!(
            !recovered,
            "torn branch: a fragment at a windowed-read boundary must not be trusted"
        );
        assert_eq!(probe.last_seq, 0, "untrusted look-back resets to seq 0");

        let (probe, recovered) = classify_tail(&torn, data_start, data_start);
        assert!(
            recovered,
            "whole-region read: torn look-back from the true data-region start is trusted"
        );
        assert_eq!(
            probe.last_seq, 200,
            "look-back resumes from the real prior record"
        );
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
        let (mut log, _) = RecoveryAuditLog::create_unchecked_for_test(&path, c).expect("create");

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

    /// The live-to-`.1` rename/copy (the last sub-step in the `Renaming` stage)
    /// must not run when the rotation budget is already exhausted. On an EXDEV
    /// mount the rename falls back to `copy_live_to_first`, an unbounded
    /// whole-file I/O operation. Running it on top of an already-spent budget
    /// stacks the copy on the Maintenance-stage wall clock and risks overrunning
    /// the 500 ms self-watchdog ceiling → `process::abort()` of a healthy
    /// observer (same abort-class hazard as bug-363/373/379). The rotation must
    /// defer and retry with a fresh `call_start` the next tick.
    #[test]
    fn renaming_live_to_first_defers_before_copy_when_budget_exhausted() {
        let dir = tmpdir("exdev-budget");
        let path = dir.join("audit.log");

        let (mut log, _) = RecoveryAuditLog::create(&path, cfg(None, 1)).expect("create");
        // Jump directly to the last Renaming sub-step so only the live→.1 move
        // remains; the prior generation renames are irrelevant to this hazard.
        log.rotation_progress = RotationProgress::Renaming { next_gen: 1 };
        log.needs_rotation = true;

        // Zero budget: exhausted before the very first check, ensuring the
        // function returns Deferred without touching the live file or creating
        // a partial `.1` generation.
        let outcome = log.drive_audit_rotation(Duration::ZERO);

        assert_eq!(outcome, RotationOutcome::Deferred);
        assert!(
            path.exists(),
            "live file must not be renamed/copied when budget is exhausted"
        );
        assert!(
            !dir.join("audit.log.1").exists(),
            "no `.1` generation must exist — rename/copy must not have started"
        );
        assert_eq!(
            log.audit_rotation_budget_exceeded_total, 1,
            "budget-exceeded counter must be incremented exactly once"
        );
        assert!(
            matches!(
                log.rotation_progress,
                RotationProgress::Renaming { next_gen: 1 }
            ),
            "must stay in Renaming{{next_gen:1}} so the next tick retries with a fresh budget"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
