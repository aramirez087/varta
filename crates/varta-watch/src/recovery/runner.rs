//! Command spawn, env setup, and child capture.

use std::io;
use std::os::unix::io::AsRawFd;
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::time::Instant;

use crate::audit::SpawnRecord;
use crate::nonblock_fd::set_nonblocking_fd;
use crate::outstanding_table::Reservation as OutstandingReservation;

use super::debounce::LastFiredReservation;
use super::env;
use super::{Recovery, RecoveryMode, RecoveryOutcome, AUDIT_REASON_SPAWN_FAILED};

/// Bookkeeping slot for one outstanding child.
pub(super) struct Outstanding {
    pub(super) child: Child,
    pub(super) spawned_at: Instant,
    pub(super) killed: bool,
    /// Process-start-time generation token of the stalled agent this child was
    /// spawned for. Pins the slot's *lineage* so a recycled PID (same number,
    /// new process) can be detected in `on_stall` and not silently Debounced.
    /// `None` = generation unknown (non-Linux / `/proc` race) → treated
    /// leniently (bare-PID behaviour), mirroring the debounce ledger.
    pub(super) generation: Option<u64>,
    /// Wall-clock ms at spawn time; recorded into the audit log on
    /// completion alongside the monotonic duration.
    pub(super) wallclock_at_spawn_ms: u64,
    /// `Some` iff capture is enabled and both captured pipes were proven
    /// non-blocking. Drains accumulate here across `try_reap` calls; truncation
    /// is set when setup failed or either stream's captured bytes reach the
    /// per-child cap.
    pub(super) stdout_handle: Option<ChildStdout>,
    /// See `stdout_handle`.
    pub(super) stderr_handle: Option<ChildStderr>,
    /// Accumulated captured stdout bytes.
    pub(super) stdout_len: u32,
    /// Accumulated captured stderr bytes.
    pub(super) stderr_len: u32,
    /// True iff capture setup failed or either pipe's reads hit the per-child
    /// cap and we stopped reading.
    pub(super) truncated: bool,
    /// Exit status captured once `try_wait` reaps the child, while bounded
    /// stdio draining may still need later ticks before audit completion.
    pub(super) completed_status: Option<ExitStatus>,
    /// Monotonic instant the child was first observed exited (stamped with
    /// `completed_status`). Bounds how long post-exit capture draining may
    /// pin this entry when a backgrounded grandchild keeps the pipe
    /// write-end open so the read-end never reaches EOF.
    pub(super) completed_at: Option<Instant>,
    #[cfg(test)]
    pub(super) kill_error_for_test: Option<io::ErrorKind>,
}

pub(super) enum KillForReclaim {
    Killed { child_pid: u32 },
    AlreadyExited,
    AlreadyKilled,
}

impl Outstanding {
    pub(super) fn kill_for_reclaim(&mut self) -> io::Result<KillForReclaim> {
        if self.killed {
            return Ok(KillForReclaim::AlreadyKilled);
        }
        #[cfg(test)]
        if let Some(kind) = self.kill_error_for_test.take() {
            return Err(io::Error::new(kind, "injected reclaim kill failure"));
        }

        let child_pid = self.child.id();
        match self.child.kill() {
            Ok(()) => {
                self.killed = true;
                Ok(KillForReclaim::Killed { child_pid })
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => Ok(KillForReclaim::AlreadyExited),
            Err(e) => Err(e),
        }
    }
}

pub(super) struct CaptureHandles {
    pub(super) stdout: Option<ChildStdout>,
    pub(super) stderr: Option<ChildStderr>,
    pub(super) truncated: bool,
}

impl CaptureHandles {
    fn disabled() -> Self {
        Self {
            stdout: None,
            stderr: None,
            truncated: false,
        }
    }

    fn setup_failed() -> Self {
        Self {
            stdout: None,
            stderr: None,
            truncated: true,
        }
    }
}

/// Take the piped stdout/stderr handles off `child` (when capture is enabled)
/// and mark them non-blocking. Capture is fail-closed: if either expected pipe
/// is missing or cannot be proven non-blocking, both handles are dropped and the
/// child is marked truncated so completion audit records show degraded capture.
pub(super) fn take_capture_handles(child: &mut Child, capture_on: bool) -> CaptureHandles {
    take_capture_handles_with(child, capture_on, set_nonblocking_fd)
}

fn take_capture_handles_with(
    child: &mut Child,
    capture_on: bool,
    mut set_nonblocking: impl FnMut(i32) -> bool,
) -> CaptureHandles {
    if !capture_on {
        return CaptureHandles::disabled();
    }
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return CaptureHandles::setup_failed();
    };

    let out_ok = set_nonblocking(out.as_raw_fd());
    let err_ok = set_nonblocking(err.as_raw_fd());
    if !out_ok || !err_ok {
        return CaptureHandles::setup_failed();
    }

    CaptureHandles {
        stdout: Some(out),
        stderr: Some(err),
        truncated: false,
    }
}

#[cfg(test)]
pub(super) fn take_capture_handles_for_test(
    child: &mut Child,
    capture_on: bool,
    set_nonblocking: impl FnMut(i32) -> bool,
) -> CaptureHandles {
    take_capture_handles_with(child, capture_on, set_nonblocking)
}

impl Recovery {
    /// Spawn the recovery command for `pid` non-blockingly.
    ///
    /// Extracted from `on_stall`; only called after all safety gates pass.
    /// Handles template substitution, env isolation, capture setup, and
    /// outstanding-table insertion. Emits the spawn audit record on success.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn_exec_child(
        &mut self,
        pid: u32,
        generation: Option<u64>,
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
                        let capture = take_capture_handles(&mut child, capture_on);
                        self.outstanding.commit_reserved(
                            reservation,
                            Outstanding {
                                child,
                                spawned_at: now,
                                killed: false,
                                generation,
                                wallclock_at_spawn_ms: wallclock_ms,
                                stdout_handle: capture.stdout,
                                stderr_handle: capture.stderr,
                                stdout_len: 0,
                                stderr_len: 0,
                                truncated: capture.truncated,
                                completed_status: None,
                                completed_at: None,
                                #[cfg(test)]
                                kill_error_for_test: None,
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
                        self.record_refused_audit(pid, observer_ns, AUDIT_REASON_SPAWN_FAILED);
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
