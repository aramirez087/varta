//! Child reaping: waitpid, kill, drain capture.

use std::io::Read;
use std::time::Instant;

use crate::audit::{CompleteOutcome, CompleteRecord, RecoveryAuditLog};

use super::{Outstanding, Recovery, RecoveryOutcome};

impl Recovery {
    /// Attempt a non-blocking reap of the outstanding child for `pid`.
    ///
    /// Returns `None` when the child is still running (try_wait returned
    /// `Ok(None)`). Returns `Some(outcome)` on exit, reap failure, or
    /// any other terminal condition; the `Outstanding` entry is removed
    /// from the table on all terminal paths.
    pub(super) fn reap_finished_child(&mut self, pid: u32) -> Option<RecoveryOutcome> {
        let cap = self.capture_cap;
        let try_wait_result = {
            let entry_mut = self.outstanding.get_mut(pid)?;
            Self::drain_outstanding_capture(entry_mut, cap);
            let child_pid = entry_mut.child.id();
            let wait = entry_mut.child.try_wait();
            (child_pid, wait)
        };
        let (child_pid, try_wait_result) = try_wait_result;

        match try_wait_result {
            Ok(Some(status)) => {
                if let Some(entry_mut) = self.outstanding.get_mut(pid) {
                    Self::drain_outstanding_capture(entry_mut, cap);
                }
                let entry = self.outstanding.remove(pid)?;
                let killed = entry.killed;
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
                );
                Some(RecoveryOutcome::Reaped { child_pid, status })
            }
            Ok(None) => None,
            Err(e) => {
                let entry = self.outstanding.remove(pid)?;
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
                );
                Some(RecoveryOutcome::ReapFailed(e))
            }
        }
    }

    /// Non-blocking drain of captured stdout/stderr for one outstanding child.
    ///
    /// Reads as many bytes as the kernel has buffered (up to the remaining cap)
    /// without ever blocking. `WouldBlock` is treated as "drain again next tick".
    /// Takes the entry by `&mut Outstanding` so it can be called while an
    /// `OccupiedEntry` is held in [`Self::reap_finished_child`] without
    /// re-borrowing the map.
    fn drain_outstanding_capture(entry: &mut Outstanding, cap_cfg: u32) {
        let cap = cap_cfg as usize;
        if cap == 0 {
            return;
        }
        if entry.truncated {
            return;
        }
        let mut total = entry.stdout_len as usize + entry.stderr_len as usize;
        if let Some(handle) = entry.stdout_handle.as_mut() {
            let mut buf = [0u8; 4096];
            loop {
                if total >= cap {
                    entry.truncated = true;
                    break;
                }
                let want = (cap - total).min(buf.len());
                match handle.read(&mut buf[..want]) {
                    Ok(0) => break,
                    Ok(n) => {
                        entry.stdout_len = entry.stdout_len.saturating_add(n as u32);
                        total = total.saturating_add(n);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        if let Some(handle) = entry.stderr_handle.as_mut() {
            let mut buf = [0u8; 4096];
            loop {
                if total >= cap {
                    entry.truncated = true;
                    break;
                }
                let want = (cap - total).min(buf.len());
                match handle.read(&mut buf[..want]) {
                    Ok(0) => break,
                    Ok(n) => {
                        entry.stderr_len = entry.stderr_len.saturating_add(n as u32);
                        total = total.saturating_add(n);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
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
    ) {
        let Some(sink) = self.audit_sink.as_mut() else {
            return;
        };
        use std::os::unix::process::ExitStatusExt;
        let exit_code = status.and_then(|s| s.code());
        let signal = status.and_then(|s| s.signal());
        let duration_ns = spawned_at.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        let _ = wallclock_at_spawn_ms;
        sink.record_complete(&CompleteRecord {
            wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
            observer_ns: 0,
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
