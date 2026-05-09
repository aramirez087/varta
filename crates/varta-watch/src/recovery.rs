//! Per-pid debounced recovery command runner.
//!
//! Recovery is the daemon's cold path: it fires only when an agent has
//! crossed its silence threshold. The runner substitutes the literal
//! `{pid}` token in a user-supplied template and shells out via
//! `/bin/sh -c <rendered>`. A per-pid debounce window suppresses repeat
//! invocations during a single silence run; a successful or failed spawn
//! both reset the per-pid clock.

use std::collections::HashMap;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

/// Outcome of [`Recovery::on_stall`].
///
/// `Spawned` and `SpawnFailed` both consume the per-pid debounce slot;
/// `Debounced` indicates the call was suppressed because the previous
/// invocation for this pid is still inside the debounce window.
#[derive(Debug)]
pub enum RecoveryOutcome {
    /// `/bin/sh -c <rendered>` ran to completion. The inner status mirrors
    /// `Command::status()`'s success/failure semantics.
    Spawned(ExitStatus),
    /// The previous invocation for this pid is still inside the debounce
    /// window; nothing was spawned.
    Debounced,
    /// `Command::status()` failed before the shell could run (e.g. fork or
    /// `/bin/sh` missing). The error is surfaced verbatim.
    SpawnFailed(std::io::Error),
}

/// Per-pid debounced runner of a `recovery_cmd` template.
///
/// The `last_fired` map is keyed by pid; recovery is the cold path so the
/// hash-table allocation cost is acceptable per the operator rules.
pub struct Recovery {
    template: String,
    debounce: Duration,
    last_fired: HashMap<u32, Instant>,
}

impl Recovery {
    /// Create a new runner with the given `template` and `debounce` window.
    ///
    /// The template is taken as-is; the only substitution performed at fire
    /// time is replacing every literal `{pid}` substring with the stalled
    /// pid's decimal representation.
    pub fn new(template: String, debounce: Duration) -> Self {
        Recovery {
            template,
            debounce,
            last_fired: HashMap::new(),
        }
    }

    /// Substitute `{pid}` and run the rendered command via `/bin/sh -c`.
    ///
    /// Returns [`RecoveryOutcome::Debounced`] if the previous invocation
    /// for `pid` is still inside the debounce window. The debounce is
    /// per-pid and monotonic — distinct pids may fire within a single
    /// window without suppressing one another.
    pub fn on_stall(&mut self, pid: u32) -> RecoveryOutcome {
        let now = Instant::now();
        if let Some(prev) = self.last_fired.get(&pid) {
            if now.duration_since(*prev) < self.debounce {
                return RecoveryOutcome::Debounced;
            }
        }

        let rendered = self.template.replace("{pid}", &pid.to_string());
        let result = Command::new("/bin/sh").arg("-c").arg(&rendered).status();
        self.last_fired.insert(pid, now);
        match result {
            Ok(status) => RecoveryOutcome::Spawned(status),
            Err(e) => RecoveryOutcome::SpawnFailed(e),
        }
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
        assert!(matches!(first, RecoveryOutcome::Spawned(_)));
        assert!(matches!(second, RecoveryOutcome::Debounced));
    }

    #[test]
    fn debounce_is_per_pid() {
        let mut rec = Recovery::new("true".to_string(), Duration::from_secs(10));
        let a = rec.on_stall(1);
        let b = rec.on_stall(2);
        assert!(matches!(a, RecoveryOutcome::Spawned(_)));
        assert!(matches!(b, RecoveryOutcome::Spawned(_)));
    }

    #[test]
    fn template_substitutes_every_pid_token() {
        let mut rec = Recovery::new(
            "test \"{pid}-{pid}\" = \"7-7\"".to_string(),
            Duration::from_secs(0),
        );
        match rec.on_stall(7) {
            RecoveryOutcome::Spawned(s) => assert!(s.success()),
            other => panic!("expected Spawned(success), got {other:?}"),
        }
    }
}
