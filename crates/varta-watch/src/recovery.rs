//! Per-pid debounced recovery command runner.
//!
//! Recovery is the daemon's cold path: it fires only when an agent has
//! crossed its silence threshold. The runner substitutes the literal
//! `{pid}` token in a user-supplied template and shells out via
//! `/bin/sh -c <rendered>`. A per-pid debounce window suppresses repeat
//! invocations during a single silence run.
//!
//! ## Async-spawn epic — Session 01 (red phase)
//!
//! The public surface advertised here is the green-phase contract that
//! Sessions 02 and 03 will implement. In this red phase:
//!
//! * `RecoveryOutcome` carries the final six-variant shape, including
//!   `Spawned { child_pid }`, `Reaped { .. }`, `Killed { .. }`, and
//!   `ReapFailed(_)`.
//! * `Recovery::with_timeout` accepts the optional kill-after deadline
//!   but does not yet enforce it. `Recovery::new` delegates to
//!   `with_timeout(.., None)`.
//! * `Recovery::on_stall` STILL BLOCKS. The body uses `Command::spawn`
//!   followed by `Child::wait` so the per-pid `child_pid` is real and
//!   the existing two acceptance tests keep passing on the
//!   `Reaped { .. }` shape. The non-blocking implementation lands in
//!   Session 02.
//! * `Recovery::try_reap` is a stub returning an empty `Vec`. The
//!   four red-phase acceptance tests fail against this stub by design.

use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};

/// Outcome of [`Recovery::on_stall`] or [`Recovery::try_reap`].
///
/// `Spawned`, `SpawnFailed`, and `Debounced` describe the synchronous
/// outcome of `on_stall`. `Reaped`, `Killed`, and `ReapFailed` describe
/// state transitions that `try_reap` will surface for previously-spawned
/// children once the green-phase implementation lands.
#[derive(Debug)]
pub enum RecoveryOutcome {
    /// `/bin/sh -c <rendered>` was forked successfully and the child is
    /// now outstanding. The observer has NOT waited on it; the child
    /// will be reaped on a later tick via [`Recovery::try_reap`].
    Spawned {
        /// OS process id of the freshly-spawned child shell.
        child_pid: u32,
    },
    /// The previous invocation for this pid is still inside the debounce
    /// window; nothing was spawned.
    Debounced,
    /// `Command::spawn` failed before the shell could run (e.g. fork or
    /// `/bin/sh` missing). The error is surfaced verbatim.
    SpawnFailed(std::io::Error),
    /// A previously-spawned child has exited and was reaped on this tick.
    /// The observer never blocks waiting for this transition.
    Reaped {
        /// OS process id of the child that exited.
        child_pid: u32,
        /// `ExitStatus` from `Child::wait` / `Child::try_wait`.
        status: std::process::ExitStatus,
    },
    /// A previously-spawned child exceeded its `recovery_timeout`
    /// deadline and was killed via `kill(2)` on this tick.
    Killed {
        /// OS process id of the child that was killed.
        child_pid: u32,
    },
    /// `try_wait` or `kill` failed for an outstanding child. The pid is
    /// still tracked; the observer will retry on the next tick.
    ReapFailed(std::io::Error),
}

/// Bookkeeping slot for one outstanding child.
///
/// Session 01 only needs the type to exist for the green-phase impl to
/// flesh out; today no field is read because `try_reap` is a stub. The
/// `#[allow(dead_code)]` annotations are a deliberate red-phase signal
/// that Session 02 will activate these fields.
#[allow(dead_code)]
struct Outstanding {
    child: std::process::Child,
    spawned_at: Instant,
}

/// Per-pid debounced runner of a `recovery_cmd` template.
///
/// The `last_fired` map is keyed by pid; recovery is the cold path so
/// the hash-table allocation cost is acceptable per the operator rules.
/// `outstanding` will hold one entry per live child once Session 02
/// lands; today it is reserved but unused.
pub struct Recovery {
    template: String,
    debounce: Duration,
    last_fired: HashMap<u32, Instant>,
    #[allow(dead_code)]
    timeout: Option<Duration>,
    #[allow(dead_code)]
    outstanding: HashMap<u32, Outstanding>,
}

impl Recovery {
    /// Create a new runner with the given `template` and `debounce`
    /// window.
    ///
    /// Equivalent to [`Recovery::with_timeout(template, debounce, None)`].
    /// Children will be reaped on completion but never killed.
    pub fn new(template: String, debounce: Duration) -> Self {
        Self::with_timeout(template, debounce, None)
    }

    /// Create a new runner with an optional kill-after deadline.
    ///
    /// `timeout = None` preserves v0.1.0 semantics: outstanding children
    /// are reaped on completion but are never killed. `timeout = Some(d)`
    /// asks `try_reap` to issue `kill(2)` once a child has been
    /// outstanding longer than `d`.
    ///
    /// The template is taken as-is; the only substitution performed at
    /// fire time is replacing every literal `{pid}` substring with the
    /// stalled pid's decimal representation.
    pub fn with_timeout(
        template: String,
        debounce: Duration,
        timeout: Option<Duration>,
    ) -> Self {
        Recovery {
            template,
            debounce,
            last_fired: HashMap::new(),
            timeout,
            outstanding: HashMap::new(),
        }
    }

    /// Substitute `{pid}` and spawn `/bin/sh -c <rendered>`.
    ///
    /// Returns [`RecoveryOutcome::Debounced`] if the previous invocation
    /// for `pid` is still inside the debounce window. The debounce is
    /// per-pid and monotonic — distinct pids may fire within a single
    /// window without suppressing one another.
    ///
    /// Red-phase note: this body still calls `Child::wait` and therefore
    /// blocks for the child's full duration. The shape of the return
    /// value is the green-phase `Reaped { .. }` so the existing
    /// acceptance tests can match the new variant. Session 02 replaces
    /// the body with a non-blocking spawn that returns `Spawned { .. }`
    /// immediately.
    pub fn on_stall(&mut self, pid: u32) -> RecoveryOutcome {
        let now = Instant::now();
        if let Some(prev) = self.last_fired.get(&pid) {
            if now.duration_since(*prev) < self.debounce {
                return RecoveryOutcome::Debounced;
            }
        }

        let rendered = self.template.replace("{pid}", &pid.to_string());
        self.last_fired.insert(pid, now);

        let mut child = match Command::new("/bin/sh").arg("-c").arg(&rendered).spawn() {
            Ok(c) => c,
            Err(e) => return RecoveryOutcome::SpawnFailed(e),
        };
        let child_pid = child.id();
        match child.wait() {
            Ok(status) => RecoveryOutcome::Reaped { child_pid, status },
            Err(e) => RecoveryOutcome::ReapFailed(e),
        }
    }

    /// Drain completed (or deadline-exceeded) children for one observer
    /// tick.
    ///
    /// Red-phase: returns an empty `Vec`. The four acceptance tests
    /// gating Session 02 fail against this stub by design — they assert
    /// real `Reaped` / `Killed` outcomes that this stub does not produce.
    pub fn try_reap(&mut self) -> Vec<RecoveryOutcome> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debounces_repeat_calls_for_same_pid() {
        let mut rec = Recovery::new("true".to_string(), Duration::from_secs(10));
        let first = rec.on_stall(1);
        let second = rec.on_stall(1);
        assert!(matches!(first, RecoveryOutcome::Reaped { .. }));
        assert!(matches!(second, RecoveryOutcome::Debounced));
    }

    #[test]
    fn debounce_is_per_pid() {
        let mut rec = Recovery::new("true".to_string(), Duration::from_secs(10));
        let a = rec.on_stall(1);
        let b = rec.on_stall(2);
        assert!(matches!(a, RecoveryOutcome::Reaped { .. }));
        assert!(matches!(b, RecoveryOutcome::Reaped { .. }));
    }

    #[test]
    fn template_substitutes_every_pid_token() {
        let mut rec = Recovery::new(
            "test \"{pid}-{pid}\" = \"7-7\"".to_string(),
            Duration::from_secs(0),
        );
        match rec.on_stall(7) {
            RecoveryOutcome::Reaped { status, .. } => assert!(status.success()),
            other => panic!("expected Reaped(success), got {other:?}"),
        }
    }

    #[test]
    fn try_reap_returns_empty_during_red_phase() {
        let mut rec = Recovery::new("true".to_string(), Duration::from_secs(0));
        assert!(rec.try_reap().is_empty());
    }

    #[test]
    fn with_timeout_constructor_accepts_optional_duration() {
        let _none = Recovery::with_timeout("true".to_string(), Duration::ZERO, None);
        let _some = Recovery::with_timeout(
            "true".to_string(),
            Duration::ZERO,
            Some(Duration::from_millis(50)),
        );
    }
}
