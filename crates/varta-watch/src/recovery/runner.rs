//! Command spawn, env setup, and child capture.

use std::os::unix::io::AsRawFd;
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::time::Instant;

use crate::audit::SpawnRecord;
use crate::nonblock_fd::set_nonblocking_fd;
use crate::outstanding_table::Reservation as OutstandingReservation;

use super::debounce::LastFiredReservation;
use super::env;
use super::{Recovery, RecoveryMode, RecoveryOutcome};

/// Bookkeeping slot for one outstanding child.
pub(super) struct Outstanding {
    pub(super) child: Child,
    pub(super) spawned_at: Instant,
    pub(super) killed: bool,
    /// Wall-clock ms at spawn time; recorded into the audit log on
    /// completion alongside the monotonic duration.
    pub(super) wallclock_at_spawn_ms: u64,
    /// `Some` iff capture is enabled. Drains accumulate here non-blockingly
    /// across `try_reap` calls; truncation is set when either stream's
    /// captured bytes reach the per-child cap.
    pub(super) stdout_handle: Option<ChildStdout>,
    /// See `stdout_handle`.
    pub(super) stderr_handle: Option<ChildStderr>,
    /// Accumulated captured stdout bytes.
    pub(super) stdout_len: u32,
    /// Accumulated captured stderr bytes.
    pub(super) stderr_len: u32,
    /// True iff either pipe's reads hit the per-child cap and we stopped reading.
    pub(super) truncated: bool,
    /// Exit status captured once `try_wait` reaps the child, while bounded
    /// stdio draining may still need later ticks before audit completion.
    pub(super) completed_status: Option<ExitStatus>,
}

/// Take the piped stdout/stderr handles off `child` (when capture is enabled)
/// and mark them non-blocking. Returns `(None, None)` when capture is disabled.
pub(super) fn take_capture_handles(
    child: &mut Child,
    capture_on: bool,
) -> (Option<ChildStdout>, Option<ChildStderr>) {
    if !capture_on {
        return (None, None);
    }
    let out = child.stdout.take().map(|h| {
        let _ = set_nonblocking_fd(h.as_raw_fd());
        h
    });
    let err = child.stderr.take().map(|h| {
        let _ = set_nonblocking_fd(h.as_raw_fd());
        h
    });
    (out, err)
}

impl Recovery {
    /// Spawn the recovery command for `pid` non-blockingly.
    ///
    /// Extracted from `on_stall`; only called after all safety gates pass.
    /// Handles template substitution, env isolation, capture setup, and
    /// outstanding-table insertion. Emits the spawn audit record on success.
    pub(super) fn spawn_exec_child(
        &mut self,
        pid: u32,
        wallclock_ms: u64,
        now: Instant,
        observer_ns: u64,
        reservation: OutstandingReservation,
        last_fired_reservation: LastFiredReservation,
    ) -> RecoveryOutcome {
        let capture_on = self.capture_cap > 0;
        match &self.mode {
            RecoveryMode::Exec { program, args } => {
                let pid_str = pid.to_string();
                let substituted: Vec<String> = std::iter::once(program.clone())
                    .chain(args.iter().map(|a| a.replace("{pid}", &pid_str)))
                    .collect();
                let mut cmd = Command::new(&substituted[0]);
                env::apply_env(&mut cmd, self.recovery_inherit_env, &self.recovery_env);
                for arg in &substituted[1..] {
                    cmd.arg(arg);
                }
                if capture_on {
                    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
                }
                let template_len: u32 = substituted
                    .iter()
                    .map(|a| a.len() as u32 + 1)
                    .sum::<u32>()
                    .saturating_sub(1);
                match cmd.spawn() {
                    Ok(mut child) => {
                        let child_pid = child.id();
                        let (out_handle, err_handle) = take_capture_handles(&mut child, capture_on);
                        self.outstanding.commit_reserved(
                            reservation,
                            Outstanding {
                                child,
                                spawned_at: now,
                                killed: false,
                                wallclock_at_spawn_ms: wallclock_ms,
                                stdout_handle: out_handle,
                                stderr_handle: err_handle,
                                stdout_len: 0,
                                stderr_len: 0,
                                truncated: false,
                                completed_status: None,
                            },
                        );
                        self.last_fired.commit_reserved(last_fired_reservation);
                        self.emit_spawn_audit(
                            wallclock_ms,
                            observer_ns,
                            pid,
                            child_pid,
                            "exec",
                            substituted[0].as_str(),
                            template_len,
                        );
                        RecoveryOutcome::Spawned { child_pid }
                    }
                    Err(e) => {
                        self.outstanding.release_reservation(reservation);
                        RecoveryOutcome::SpawnFailed(e)
                    }
                }
            }
        }
    }

    /// Emit a recovery-spawn audit record if a sink is configured.
    #[allow(clippy::too_many_arguments)]
    fn emit_spawn_audit(
        &mut self,
        wallclock_ms: u64,
        observer_ns: u64,
        agent_pid: u32,
        child_pid: u32,
        mode: &str,
        program: &str,
        template_len: u32,
    ) {
        let source = self.source.clone();
        let Some(sink) = self.audit_sink.as_mut() else {
            return;
        };
        sink.record_spawn(&SpawnRecord {
            wallclock_ms,
            observer_ns,
            agent_pid,
            child_pid,
            mode,
            program,
            source: &source,
            template_len,
        });
    }
}
