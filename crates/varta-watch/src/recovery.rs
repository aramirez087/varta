//! Per-pid debounced recovery command runner (non-blocking).
//!
//! Recovery is the daemon's cold path: it fires only when an agent has
//! crossed its silence threshold. Two execution modes are available:
//!
//! * **Shell mode** ([`RecoveryMode::Shell`]) — `/bin/sh -c <template>`
//!   with the pid passed as positional argument `$1`. The template
//!   body is under full operator control; treat it as a trusted shell
//!   fragment.
//! * **Exec mode** ([`RecoveryMode::Exec`]) — `execvp(argv[0], argv[1..])`
//!   with `{pid}` replaced by the numeric PID in each argument. No shell
//!   is involved, eliminating shell injection risk entirely.
//!
//! A per-pid debounce window suppresses repeat invocations during a single
//! silence run. Children are spawned asynchronously; they never block the
//! observer's poll loop. On each tick, [`Recovery::try_reap`] drains
//! completed or deadline-exceeded children and returns outcomes for
//! logging.
//!
//! # Security
//!
//! In shell mode the pid is always numeric and never string-interpolated
//! into the script body. In exec mode no shell is spawned — arguments are
//! passed directly to `execvp(2)`, so metacharacters have no effect.
//! **The recovery command source is under full operator control** — anyone
//! who can pass `--recovery-cmd` / `--recovery-exec` to `varta-watch`
//! already has arbitrary code execution capability. Treat the template
//! as a trusted fragment and never derive it from an untrusted source
//! (e.g. a network request or environment variable from a less-privileged
//! context). Use `--recovery-cmd-file` / `--recovery-exec-file` with
//! restrictive file permissions for an additional trust check.

use std::collections::HashMap;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// How the recovery command is executed when an agent stalls.
///
/// Two modes are available:
///
/// * [`RecoveryMode::Shell`] — `/bin/sh -c <template>` with the pid
///   passed as `$1`. Backward compatible; the template body is under
///   full operator control.
/// * [`RecoveryMode::Exec`] — `execvp(argv[0], argv[1..])`. `{pid}` in
///   any argument is replaced with the numeric PID. No shell is
///   involved, so shell metacharacters have no effect.
#[derive(Clone, Debug)]
pub enum RecoveryMode {
    /// Execute via `/bin/sh -c <template>`. The stalled pid is passed
    /// as positional argument `$1` (appended after the template and
    /// the `$0` sentinel `"varta-recovery"`).
    Shell(String),
    /// Execute a command directly via `execvp(2)` — no shell is spawned,
    /// so shell injection is structurally impossible. Any argument
    /// containing the literal `{pid}` is substituted with the decimal
    /// representation of the stalled PID.
    Exec {
        /// `argv[0]` — the executable to invoke.
        program: String,
        /// `argv[1..]` — additional arguments. `{pid}` is replaced in
        /// each argument with the stalled PID.
        args: Vec<String>,
    },
}

/// Outcome of [`Recovery::on_stall`] or [`Recovery::try_reap`].
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
    Reaped {
        /// OS process id of the child that exited.
        child_pid: u32,
        /// `ExitStatus` from `Child::try_wait`.
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
struct Outstanding {
    child: Child,
    spawned_at: Instant,
    killed: bool,
}

/// Maximum number of pids tracked in `last_fired`. When the map is full and
/// a new pid stalls, the debounce check is skipped and the recovery command
/// fires. This prevents unbounded memory growth during a large stall burst.
const MAX_LAST_FIRED_CAPACITY: usize = 256;

/// Per-pid debounced runner of a `recovery_cmd` template.
pub struct Recovery {
    mode: RecoveryMode,
    debounce: Duration,
    last_fired: HashMap<u32, Instant>,
    timeout: Option<Duration>,
    outstanding: HashMap<u32, Outstanding>,
    pending_outcomes: Vec<RecoveryOutcome>,
    /// Explicit environment variables for child processes in `KEY=VALUE`
    /// format. When non-empty, the child's environment is cleared to
    /// `PATH=/usr/bin:/bin` plus these variables. When empty, the child
    /// inherits the observer's environment (backward compatible).
    recovery_env: Vec<String>,
}

impl Recovery {
    /// Create a new runner in shell mode with the given `template` and
    /// `debounce` window.
    ///
    /// Equivalent to [`Recovery::with_timeout(template, debounce, None)`].
    pub fn new(template: String, debounce: Duration) -> Self {
        Self::with_timeout(RecoveryMode::Shell(template), debounce, None)
    }

    /// Create a new runner in exec mode.
    ///
    /// `program` is the executable to invoke (`argv[0]`). `args` are
    /// additional arguments. `{pid}` is replaced in each argument with
    /// the stalled PID.
    pub fn new_exec(program: String, args: Vec<String>, debounce: Duration) -> Self {
        Self::with_timeout(RecoveryMode::Exec { program, args }, debounce, None)
    }

    /// Create a new runner with an explicit [`RecoveryMode`].
    pub fn with_mode(mode: RecoveryMode, debounce: Duration) -> Self {
        Self::with_timeout(mode, debounce, None)
    }

    /// Create a new runner with an optional kill-after deadline.
    ///
    /// `timeout = None` preserves v0.1.0 semantics: outstanding children
    /// are reaped on completion but are never killed. `timeout = Some(d)`
    /// asks `try_reap` to issue `kill(2)` once a child has been
    /// outstanding longer than `d`.
    pub fn with_timeout(mode: RecoveryMode, debounce: Duration, timeout: Option<Duration>) -> Self {
        Recovery {
            mode,
            debounce,
            last_fired: HashMap::new(),
            timeout,
            outstanding: HashMap::new(),
            pending_outcomes: Vec::new(),
            recovery_env: Vec::new(),
        }
    }

    /// Set explicit environment variables for child processes.
    ///
    /// Each entry is in `KEY=VALUE` format. When non-empty, the child's
    /// environment is cleared to `PATH=/usr/bin:/bin` plus these variables.
    /// When empty, the child inherits the observer's environment (backward
    /// compatible default).
    pub fn with_recovery_env(mut self, env: Vec<String>) -> Self {
        self.recovery_env = env;
        self
    }

    /// Create a legacy runner from a shell template string.
    ///
    /// Kept for backward compatibility with callers that hold a
    /// `template: String`.
    #[doc(hidden)]
    pub fn with_template_and_timeout(
        template: String,
        debounce: Duration,
        timeout: Option<Duration>,
    ) -> Self {
        Self::with_timeout(RecoveryMode::Shell(template), debounce, timeout)
    }

    fn reap_finished_child(&mut self, pid: u32) -> Option<RecoveryOutcome> {
        let entry = self.outstanding.get_mut(&pid)?;
        match entry.child.try_wait() {
            Ok(Some(status)) => {
                let child_pid = entry.child.id();
                self.outstanding.remove(&pid);
                Some(RecoveryOutcome::Reaped { child_pid, status })
            }
            Ok(None) => None,
            Err(e) => {
                self.outstanding.remove(&pid);
                Some(RecoveryOutcome::ReapFailed(e))
            }
        }
    }

    /// Spawn `/bin/sh -c <template> varta-recovery <pid>` (shell mode) or
    /// `execvp <program> <args...>` (exec mode), both non-blockingly.
    ///
    /// In shell mode the template receives the stalling pid as `$1`. In exec
    /// mode `{pid}` in any argument is replaced with the numeric PID.
    /// A per-pid debounce window suppresses repeat invocations.
    pub fn on_stall(&mut self, pid: u32) -> RecoveryOutcome {
        let now = Instant::now();

        let prune_threshold = self.debounce.saturating_mul(10);
        self.last_fired
            .retain(|_, &mut fired_at| now.duration_since(fired_at) < prune_threshold);

        // If the map is at capacity and this pid is not already tracked,
        // skip the debounce to prevent unbounded memory growth. The
        // outstanding map still prevents double-spawning for the same pid.
        let at_capacity =
            self.last_fired.len() >= MAX_LAST_FIRED_CAPACITY && !self.last_fired.contains_key(&pid);

        if !at_capacity {
            if let Some(prev) = self.last_fired.get(&pid) {
                if now.duration_since(*prev) < self.debounce {
                    return RecoveryOutcome::Debounced;
                }
            }
        }

        if self.outstanding.contains_key(&pid) {
            if let Some(outcome) = self.reap_finished_child(pid) {
                self.pending_outcomes.push(outcome);
            } else {
                return RecoveryOutcome::Debounced;
            }
        }

        if !at_capacity {
            self.last_fired.insert(pid, now);
        }

        match &self.mode {
            RecoveryMode::Shell(template) => {
                let mut cmd = Command::new("/bin/sh");
                self.apply_env(&mut cmd);
                match cmd
                    .arg("-c")
                    .arg(template)
                    .arg("varta-recovery")
                    .arg(pid.to_string())
                    .spawn()
                {
                    Ok(child) => {
                        let child_pid = child.id();
                        self.outstanding.insert(
                            pid,
                            Outstanding {
                                child,
                                spawned_at: now,
                                killed: false,
                            },
                        );
                        RecoveryOutcome::Spawned { child_pid }
                    }
                    Err(e) => RecoveryOutcome::SpawnFailed(e),
                }
            }
            RecoveryMode::Exec { program, args } => {
                let pid_str = pid.to_string();
                let substituted: Vec<String> = std::iter::once(program.clone())
                    .chain(args.iter().map(|a| a.replace("{pid}", &pid_str)))
                    .collect();
                let mut cmd = Command::new(&substituted[0]);
                self.apply_env(&mut cmd);
                for arg in &substituted[1..] {
                    cmd.arg(arg);
                }
                match cmd.spawn() {
                    Ok(child) => {
                        let child_pid = child.id();
                        self.outstanding.insert(
                            pid,
                            Outstanding {
                                child,
                                spawned_at: now,
                                killed: false,
                            },
                        );
                        RecoveryOutcome::Spawned { child_pid }
                    }
                    Err(e) => RecoveryOutcome::SpawnFailed(e),
                }
            }
        }
    }

    /// Apply environment isolation to a child [`Command`].
    ///
    /// When [`Self::recovery_env`] is non-empty, clears the environment to
    /// `PATH=/usr/bin:/bin` plus the explicitly configured variables.  When
    /// empty, does nothing (child inherits the observer's environment,
    /// preserving backward compatibility).
    fn apply_env(&self, cmd: &mut Command) {
        if self.recovery_env.is_empty() {
            return;
        }
        cmd.env_clear();
        cmd.env("PATH", "/usr/bin:/bin");
        for entry in &self.recovery_env {
            if let Some((key, value)) = entry.split_once('=') {
                cmd.env(key, value);
            }
        }
    }

    /// Drain completed (or deadline-exceeded) children for one observer
    /// tick.
    ///
    /// Never blocks; returns an empty vector when no children have
    /// transitioned since the last tick.
    pub fn try_reap(&mut self) -> Vec<RecoveryOutcome> {
        let mut outcomes = Vec::new();
        outcomes.append(&mut self.pending_outcomes);

        // Outstanding recovery children are rare (typically 0–2, bounded by
        // the number of tracked agents).  Use stack storage to avoid a
        // per-tick allocation.
        let mut pids_buf = [0u32; 64];
        let mut pid_count = 0;
        for &pid in self.outstanding.keys() {
            if pid_count >= pids_buf.len() {
                break;
            }
            pids_buf[pid_count] = pid;
            pid_count += 1;
        }
        let pids = &pids_buf[..pid_count];

        for &pid in pids {
            if let Some(outcome) = self.reap_finished_child(pid) {
                outcomes.push(outcome);
                continue;
            }

            let entry = match self.outstanding.get_mut(&pid) {
                Some(e) => e,
                None => continue,
            };

            // Still running — check timeout.
            if let Some(to) = self.timeout {
                if entry.spawned_at.elapsed() >= to {
                    if entry.killed {
                        continue;
                    }

                    let child_pid = entry.child.id();
                    match entry.child.kill() {
                        Ok(()) => {
                            // Do not wait here; the observer poll loop must remain
                            // non-blocking. A later try_wait call will reap the child.
                            entry.killed = true;
                            outcomes.push(RecoveryOutcome::Killed { child_pid });
                        }

                        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                            // Child already exited between our try_wait and kill.
                            // Retry try_wait once to reap.
                            if let Some(outcome) = self.reap_finished_child(pid) {
                                outcomes.push(outcome);
                            }
                        }

                        Err(e) => {
                            self.outstanding.remove(&pid);
                            outcomes.push(RecoveryOutcome::ReapFailed(e));
                        }
                    }
                }
            }
            // No timeout or not yet exceeded — leave in place.
        }

        outcomes
    }
}

impl Drop for Recovery {
    fn drop(&mut self) {
        const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);
        const POLL_INTERVAL: Duration = Duration::from_millis(10);

        // Phase 1: kill all outstanding children immediately (no waiting).
        let mut children: Vec<std::process::Child> = self
            .outstanding
            .drain()
            .map(|(_, mut entry)| {
                let _ = entry.child.kill();
                entry.child
            })
            .collect();

        // Phase 2: wait for all children with a single shared deadline.
        // Previously this was per-child (N × 5s), now it's total 5s max.
        let deadline = Instant::now() + SHUTDOWN_DEADLINE;
        while !children.is_empty() && Instant::now() < deadline {
            children.retain_mut(|child| match child.try_wait() {
                Ok(Some(_)) | Err(_) => false, // reaped or error — remove
                Ok(None) => true,              // still running — keep polling
            });
            if !children.is_empty() {
                std::thread::sleep(POLL_INTERVAL);
            }
        }
        // Any children still alive after the deadline: they will be
        // reparented to PID 1 which will reap them. Child's Drop does
        // not wait, so we do not leak file descriptors.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn debounces_repeat_calls_for_same_pid() {
        let mut rec = Recovery::new("true".to_string(), Duration::from_secs(10));
        let first = rec.on_stall(1);
        let second = rec.on_stall(1);
        assert!(matches!(first, RecoveryOutcome::Spawned { .. }));
        assert!(matches!(second, RecoveryOutcome::Debounced));
    }

    #[test]
    fn debounce_is_per_pid() {
        let mut rec = Recovery::new("true".to_string(), Duration::from_secs(10));
        let a = rec.on_stall(1);
        let b = rec.on_stall(2);
        assert!(matches!(a, RecoveryOutcome::Spawned { .. }));
        assert!(matches!(b, RecoveryOutcome::Spawned { .. }));
    }

    #[test]
    fn does_not_replace_outstanding_child_for_same_pid() {
        let mut rec = Recovery::with_template_and_timeout(
            "sleep 5".to_string(),
            Duration::ZERO,
            Some(Duration::from_millis(50)),
        );
        let first_child_pid = match rec.on_stall(7) {
            RecoveryOutcome::Spawned { child_pid } => child_pid,
            other => panic!("expected first stall to spawn, got {other:?}"),
        };

        let second = rec.on_stall(7);
        assert!(
            matches!(second, RecoveryOutcome::Debounced),
            "same-pid recovery must not replace outstanding child; got {second:?}"
        );

        let deadline = Instant::now() + Duration::from_millis(1_000);
        loop {
            if Instant::now() >= deadline {
                panic!("timed out waiting for original child to be killed");
            }
            let outcomes = rec.try_reap();
            if outcomes.iter().any(
                |o| matches!(o, RecoveryOutcome::Killed { child_pid } if *child_pid == first_child_pid),
            ) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn template_receives_pid_as_dollar_one() {
        let mut rec = Recovery::new(
            "test \"$1-$1\" = \"7-7\"".to_string(),
            Duration::from_secs(0),
        );
        match rec.on_stall(7) {
            RecoveryOutcome::Spawned { child_pid: _ } => {
                // Child should exit quickly; reap it.
                std::thread::sleep(Duration::from_millis(50));
                let outcomes = rec.try_reap();
                let reaped = outcomes.into_iter().find_map(|o| match o {
                    RecoveryOutcome::Reaped { status, .. } => Some(status),
                    _ => None,
                });
                assert!(
                    matches!(reaped, Some(s) if s.success()),
                    "expected Reaped(success) for pid 7; got {:?}",
                    reaped
                );
            }
            other => panic!("expected Spawned, got {other:?}"),
        }
    }

    #[test]
    fn spawn_returns_immediately_for_slow_template() {
        let mut rec = Recovery::new("sleep 1".to_string(), Duration::ZERO);
        let start = Instant::now();
        match rec.on_stall(42) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "spawn blocked for {elapsed:?}; expected non-blocking"
        );
    }

    #[test]
    fn try_reap_surfaces_reaped_for_fast_child() {
        let mut rec = Recovery::new("true".to_string(), Duration::ZERO);
        match rec.on_stall(99) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }

        // Poll try_reap until we see Reaped.
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if Instant::now() >= deadline {
                panic!("timed out waiting for Reaped");
            }
            let outcomes = rec.try_reap();
            if let Some(o) = outcomes.into_iter().find_map(|o| match o {
                RecoveryOutcome::Reaped { status, .. } => Some(status),
                _ => None,
            }) {
                assert!(o.success(), "expected success from 'true'");
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn try_reap_kills_after_timeout() {
        let mut rec = Recovery::with_template_and_timeout(
            "sleep 5".to_string(),
            Duration::ZERO,
            Some(Duration::from_millis(100)),
        );
        match rec.on_stall(7) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }

        let deadline = Instant::now() + Duration::from_millis(1_000);
        loop {
            if Instant::now() >= deadline {
                panic!("timed out waiting for Killed");
            }
            let outcomes = rec.try_reap();
            if outcomes
                .iter()
                .any(|o| matches!(o, RecoveryOutcome::Killed { .. }))
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
    }

    #[test]
    fn drop_kills_and_reaps_still_running_children() {
        // Spawn a long-running child with no timeout — the child will
        // still be alive when `rec` goes out of scope. Drop must kill
        // and wait on it to prevent a zombie.
        let start = Instant::now();
        {
            let mut rec = Recovery::new("sleep 5".to_string(), Duration::ZERO);
            match rec.on_stall(999) {
                RecoveryOutcome::Spawned { .. } => {}
                other => panic!("expected Spawned, got {other:?}"),
            }
            // Drop happens here; kill + wait must run.
        }
        let elapsed = start.elapsed();

        // If Drop properly kills the child, this completes in well under
        // 5 seconds. Without the fix, Drop would only call try_reap (which
        // sees the child is still running and does nothing), and
        // std::process::Child's Drop does not wait — so the child would
        // outlive Recovery but this test would still pass without asserting
        // elapsed time. The timing assert is the proof the child was killed.
        assert!(
            elapsed < Duration::from_secs(1),
            "Drop hung for {elapsed:?}; expected kill+wait to complete quickly"
        );
    }

    #[test]
    fn with_timeout_constructor_accepts_optional_duration() {
        let _none = Recovery::with_template_and_timeout("true".to_string(), Duration::ZERO, None);
        let _some = Recovery::with_template_and_timeout(
            "true".to_string(),
            Duration::ZERO,
            Some(Duration::from_millis(50)),
        );
    }

    #[test]
    fn last_fired_hashmap_is_pruned_after_debounce_times_ten() {
        let debounce = Duration::from_millis(10);
        let mut rec = Recovery::new("true".to_string(), debounce);

        assert!(matches!(rec.on_stall(1), RecoveryOutcome::Spawned { .. }));
        assert!(matches!(rec.on_stall(1), RecoveryOutcome::Debounced));

        let prune_threshold = debounce.saturating_mul(10);
        std::thread::sleep(prune_threshold + Duration::from_millis(40));

        assert!(matches!(rec.on_stall(1), RecoveryOutcome::Spawned { .. }));
    }

    #[test]
    fn exec_mode_spawns_command_via_execvp() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::ZERO,
        );
        match rec.on_stall(42) {
            RecoveryOutcome::Spawned { .. } => {
                std::thread::sleep(Duration::from_millis(50));
                let outcomes = rec.try_reap();
                let reaped = outcomes.into_iter().find_map(|o| match o {
                    RecoveryOutcome::Reaped { status, .. } => Some(status),
                    _ => None,
                });
                assert!(
                    matches!(reaped, Some(s) if s.success()),
                    "expected exec mode to spawn and reap true; got {reaped:?}"
                );
            }
            other => panic!("expected Spawned in exec mode, got {other:?}"),
        }
    }

    #[test]
    fn exec_mode_substitutes_pid_in_args() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "test \"$1\" = \"42\"".to_string(),
                    "varta-recovery".to_string(),
                    "{pid}".to_string(),
                ],
            },
            Duration::ZERO,
        );
        match rec.on_stall(42) {
            RecoveryOutcome::Spawned { .. } => {
                std::thread::sleep(Duration::from_millis(100));
                let outcomes = rec.try_reap();
                let reaped = outcomes.into_iter().find_map(|o| match o {
                    RecoveryOutcome::Reaped { status, .. } => Some(status),
                    _ => None,
                });
                assert!(
                    matches!(reaped, Some(s) if s.success()),
                    "expected {{pid}} substitution in exec mode; got {reaped:?}"
                );
            }
            other => panic!("expected Spawned, got {other:?}"),
        }
    }

    #[test]
    fn exec_mode_no_shell_injection_via_pid_substitution() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec!["{pid}".to_string()],
            },
            Duration::ZERO,
        );
        match rec.on_stall(42) {
            RecoveryOutcome::Spawned { .. } => {
                std::thread::sleep(Duration::from_millis(50));
                let outcomes = rec.try_reap();
                assert!(
                    outcomes.iter().any(
                        |o| matches!(o, RecoveryOutcome::Reaped { status, .. } if status.success())
                    ),
                    "exec mode with {{pid}} in args should succeed: {outcomes:?}"
                );
            }
            other => panic!("expected Spawned, got {other:?}"),
        }
    }

    #[test]
    fn env_isolation_clears_inherited_environment() {
        let mut rec = Recovery::with_timeout(
            RecoveryMode::Shell("test -z \"$HOME\"".to_string()),
            Duration::ZERO,
            None,
        )
        .with_recovery_env(vec!["FOO=bar".to_string()]);
        match rec.on_stall(1) {
            RecoveryOutcome::Spawned { .. } => {
                std::thread::sleep(Duration::from_millis(100));
                let outcomes = rec.try_reap();
                let reaped = outcomes.into_iter().find_map(|o| match o {
                    RecoveryOutcome::Reaped { status, .. } => Some(status),
                    _ => None,
                });
                assert!(
                    matches!(reaped, Some(s) if s.success()),
                    "HOME should not be set when recovery_env is non-empty; got {reaped:?}"
                );
            }
            other => panic!("expected Spawned, got {other:?}"),
        }
    }

    #[test]
    fn env_isolation_passes_explicit_variables() {
        let mut rec = Recovery::with_timeout(
            RecoveryMode::Shell(
                "test \"$MYVAR\" = \"hello\" && test \"$OTHER\" = \"world\"".to_string(),
            ),
            Duration::ZERO,
            None,
        )
        .with_recovery_env(vec!["MYVAR=hello".to_string(), "OTHER=world".to_string()]);
        match rec.on_stall(1) {
            RecoveryOutcome::Spawned { .. } => {
                std::thread::sleep(Duration::from_millis(100));
                let outcomes = rec.try_reap();
                let reaped = outcomes.into_iter().find_map(|o| match o {
                    RecoveryOutcome::Reaped { status, .. } => Some(status),
                    _ => None,
                });
                assert!(
                    matches!(reaped, Some(s) if s.success()),
                    "explicit env vars should be visible to child; got {reaped:?}"
                );
            }
            other => panic!("expected Spawned, got {other:?}"),
        }
    }

    #[test]
    fn no_env_isolation_preserves_inherited_env() {
        let mut rec = Recovery::with_timeout(
            RecoveryMode::Shell("test -n \"$HOME\"".to_string()),
            Duration::ZERO,
            None,
        );
        // Default: recovery_env is empty → inherits observer's environment.
        match rec.on_stall(1) {
            RecoveryOutcome::Spawned { .. } => {
                std::thread::sleep(Duration::from_millis(100));
                let outcomes = rec.try_reap();
                let reaped = outcomes.into_iter().find_map(|o| match o {
                    RecoveryOutcome::Reaped { status, .. } => Some(status),
                    _ => None,
                });
                assert!(
                    matches!(reaped, Some(s) if s.success()),
                    "HOME should be inherited when recovery_env is empty; got {reaped:?}"
                );
            }
            other => panic!("expected Spawned, got {other:?}"),
        }
    }

    #[test]
    fn exec_mode_env_isolation_clears_environment() {
        let mut rec = Recovery::with_timeout(
            RecoveryMode::Exec {
                program: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "test -z \"$HOME\" && test \"$E1\" = \"a\" && test \"$E2\" = \"b\"".to_string(),
                ],
            },
            Duration::ZERO,
            None,
        )
        .with_recovery_env(vec!["E1=a".to_string(), "E2=b".to_string()]);
        match rec.on_stall(1) {
            RecoveryOutcome::Spawned { .. } => {
                std::thread::sleep(Duration::from_millis(100));
                let outcomes = rec.try_reap();
                let reaped = outcomes.into_iter().find_map(|o| match o {
                    RecoveryOutcome::Reaped { status, .. } => Some(status),
                    _ => None,
                });
                assert!(
                    matches!(reaped, Some(s) if s.success()),
                    "exec mode env isolation failed; got {reaped:?}"
                );
            }
            other => panic!("expected Spawned, got {other:?}"),
        }
    }
}
