//! Child reaping: waitpid, kill, drain capture.

use std::io::Read;
use std::time::Instant;

use crate::audit::{CompleteOutcome, CompleteRecord, RecoveryAuditLog};

use super::{Outstanding, Recovery, RecoveryOutcome};

/// Maximum combined stdout+stderr bytes drained from one recovery child per
/// observer tick. The configured capture cap still controls the per-child
/// maximum; this bounds poll-loop work when a completed child has a large
/// pipe backlog.
pub(super) const CAPTURE_DRAIN_BYTES_PER_TICK: usize = 4096;

impl Recovery {
    /// Attempt a non-blocking reap of the outstanding child for `pid`.
    ///
    /// Returns `None` when the child is still running, or when it has exited
    /// but bounded stdio capture still needs later ticks to drain. Returns
    /// `Some(outcome)` on audit-complete exit, reap failure, or any other
    /// terminal condition; the `Outstanding` entry is removed from the table
    /// on all terminal paths.
    pub(super) fn reap_finished_child(
        &mut self,
        pid: u32,
        observer_ns: u64,
    ) -> Option<RecoveryOutcome> {
        let cap = self.capture_cap;
        enum Step {
            Pending,
            Complete {
                child_pid: u32,
            },
            ReapFailed {
                child_pid: u32,
                error: std::io::Error,
            },
        }

        let step = {
            let entry_mut = self.outstanding.get_mut(pid)?;
            Self::drain_outstanding_capture(entry_mut, cap);
            let child_pid = entry_mut.child.id();
            let mut reap_error = None;
            if entry_mut.completed_status.is_none() {
                match entry_mut.child.try_wait() {
                    Ok(Some(status)) => entry_mut.completed_status = Some(status),
                    Ok(None) => return None,
                    Err(error) => reap_error = Some(error),
                }
            }
            if let Some(error) = reap_error {
                Step::ReapFailed { child_pid, error }
            } else if Self::capture_drained(entry_mut) {
                Step::Complete { child_pid }
            } else {
                Step::Pending
            }
        };

        match step {
            Step::Pending => None,
            Step::Complete { child_pid } => {
                let entry = self.outstanding.remove(pid)?;
                let killed = entry.killed;
                let status = entry.completed_status?;
                let duration_ns = Self::recovery_duration_ns(entry.spawned_at);
                self.emit_complete_audit(
                    pid,
                    child_pid,
                    if killed {
                        CompleteOutcome::Killed
                    } else {
                        CompleteOutcome::Reaped
                    },
                    Some(&status),
                    entry.spawned_at,
                    entry.wallclock_at_spawn_ms,
                    entry.stdout_len,
                    entry.stderr_len,
                    entry.truncated,
                    observer_ns,
                );
                Some(RecoveryOutcome::Reaped {
                    child_pid,
                    status,
                    duration_ns,
                })
            }
            Step::ReapFailed { child_pid, error } => {
                Some(self.finish_reap_failed(pid, child_pid, error, observer_ns))
            }
        }
    }

    fn finish_reap_failed(
        &mut self,
        pid: u32,
        child_pid: u32,
        error: std::io::Error,
        observer_ns: u64,
    ) -> RecoveryOutcome {
        if let Some(entry) = self.outstanding.remove(pid) {
            self.emit_complete_audit(
                pid,
                child_pid,
                CompleteOutcome::ReapFailed,
                None,
                entry.spawned_at,
                entry.wallclock_at_spawn_ms,
                entry.stdout_len,
                entry.stderr_len,
                entry.truncated,
                observer_ns,
            );
        }
        RecoveryOutcome::ReapFailed(error)
    }

    /// Non-blocking drain of captured stdout/stderr for one outstanding child.
    ///
    /// Reads a bounded number of bytes the kernel has buffered, up to the
    /// remaining cap, without ever blocking. `WouldBlock` is treated as
    /// "drain again next tick".
    /// Takes the entry by `&mut Outstanding` so it can be called while an
    /// `OccupiedEntry` is held in [`Self::reap_finished_child`] without
    /// re-borrowing the map.
    fn drain_outstanding_capture(entry: &mut Outstanding, cap_cfg: u32) {
        let cap = cap_cfg as usize;
        if cap == 0 {
            return;
        }
        if entry.truncated {
            Self::close_capture_handles(entry);
            return;
        }
        let mut total = entry.stdout_len as usize + entry.stderr_len as usize;
        let mut budget = CAPTURE_DRAIN_BYTES_PER_TICK;
        Self::drain_capture_stream(
            &mut entry.stdout_handle,
            &mut entry.stdout_len,
            &mut total,
            cap,
            &mut budget,
            &mut entry.truncated,
        );
        Self::drain_capture_stream(
            &mut entry.stderr_handle,
            &mut entry.stderr_len,
            &mut total,
            cap,
            &mut budget,
            &mut entry.truncated,
        );
        if entry.truncated {
            Self::close_capture_handles(entry);
        }
    }

    fn drain_capture_stream<R: Read>(
        handle: &mut Option<R>,
        captured_len: &mut u32,
        total: &mut usize,
        cap: usize,
        budget: &mut usize,
        truncated: &mut bool,
    ) {
        let mut buf = [0u8; 1024];
        loop {
            if *truncated || *budget == 0 {
                break;
            }
            if *total >= cap {
                *truncated = true;
                break;
            }
            let Some(reader) = handle.as_mut() else {
                break;
            };
            let want = (cap - *total).min(*budget).min(buf.len());
            match reader.read(&mut buf[..want]) {
                Ok(0) => {
                    *handle = None;
                    break;
                }
                Ok(n) => {
                    *captured_len = captured_len.saturating_add(n as u32);
                    *total = total.saturating_add(n);
                    *budget -= n;
                    if *total >= cap {
                        *truncated = true;
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    *handle = None;
                    break;
                }
            }
        }
    }

    fn capture_drained(entry: &Outstanding) -> bool {
        entry.truncated || (entry.stdout_handle.is_none() && entry.stderr_handle.is_none())
    }

    fn close_capture_handles(entry: &mut Outstanding) {
        entry.stdout_handle = None;
        entry.stderr_handle = None;
    }

    fn recovery_duration_ns(spawned_at: Instant) -> u64 {
        spawned_at.elapsed().as_nanos().min(u64::MAX as u128) as u64
    }

    /// Emit a recovery-complete audit record (if a sink is configured)
    /// from already-extracted fields.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn emit_complete_audit(
        &mut self,
        agent_pid: u32,
        child_pid: u32,
        outcome: CompleteOutcome,
        status: Option<&std::process::ExitStatus>,
        spawned_at: Instant,
        wallclock_at_spawn_ms: u64,
        stdout_len: u32,
        stderr_len: u32,
        truncated: bool,
        observer_ns: u64,
    ) {
        let Some(sink) = self.audit_sink.as_mut() else {
            return;
        };
        use std::os::unix::process::ExitStatusExt;
        let exit_code = status.and_then(|s| s.code());
        let signal = status.and_then(|s| s.signal());
        let duration_ns = Self::recovery_duration_ns(spawned_at);
        let _ = wallclock_at_spawn_ms;
        sink.record_complete(&CompleteRecord {
            wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
            observer_ns,
            agent_pid,
            child_pid,
            outcome,
            exit_code,
            signal,
            duration_ns,
            stdout_len,
            stderr_len,
            truncated,
        });
    }
}
