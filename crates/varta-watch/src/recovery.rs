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
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use crate::audit::{CompleteOutcome, CompleteRecord, RecoveryAuditLog, RefusedRecord, SpawnRecord};
use crate::peer_cred::BeatOrigin;

// fcntl(2) flags. Hand-rolled to avoid pulling `libc` into a production crate.
#[cfg(target_os = "linux")]
const O_NONBLOCK_FCNTL: i32 = 0x800;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
const O_NONBLOCK_FCNTL: i32 = 0x0004;

#[cfg(any(target_os = "solaris", target_os = "illumos"))]
const O_NONBLOCK_FCNTL: i32 = 0x80;

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos",
)))]
compile_error!("O_NONBLOCK_FCNTL value is unknown for this target — add it to the cfg gates above");

// F_GETFL = 3, F_SETFL = 4: IEEE Std 1003.1-2017 §<fcntl.h>. These values
// are historically stable across every Unix in the wild; no cfg gating needed.
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;

extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

/// Best-effort set `O_NONBLOCK` on a raw fd. Failure is logged-only — the
/// drain loop checks `WouldBlock` and falls back to a single bounded
/// `read` if the flag could not be set, so a failing fcntl never blocks
/// the observer.
fn set_nonblocking_fd(fd: i32) -> bool {
    // SAFETY: F_GETFL/F_SETFL are standard fcntl commands. The fd is owned
    // by the ChildStdout/ChildStderr handle for the duration of this call.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 {
        return false;
    }
    let rc = unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK_FCNTL) };
    rc >= 0
}

/// Take the piped stdout/stderr handles off `child` (when capture is
/// enabled) and mark them non-blocking. Returns `(None, None)` when
/// capture is disabled or the handles were never piped.
fn take_capture_handles(
    child: &mut Child,
    capture_on: bool,
) -> (Option<ChildStdout>, Option<ChildStderr>) {
    if !capture_on {
        return (None, None);
    }
    let out = child.stdout.take().inspect(|h| {
        let _ = set_nonblocking_fd(h.as_raw_fd());
    });
    let err = child.stderr.take().inspect(|h| {
        let _ = set_nonblocking_fd(h.as_raw_fd());
    });
    (out, err)
}

/// How the recovery command is executed when an agent stalls.
///
/// Two modes are available:
///
/// * [`RecoveryMode::Shell`] — `/bin/sh -c <template>` with the pid
///   passed as `$1`. Backward compatible; the template body is under
///   full operator control. Requires the `unsafe-shell-recovery` Cargo
///   feature.
/// * [`RecoveryMode::Exec`] — `execvp(argv[0], argv[1..])`. `{pid}` in
///   any argument is replaced with the numeric PID. No shell is
///   involved, so shell metacharacters have no effect.
#[derive(Clone, Debug)]
pub enum RecoveryMode {
    /// Execute via `/bin/sh -c <template>`. The stalled pid is passed
    /// as positional argument `$1` (appended after the template and
    /// the `$0` sentinel `"varta-recovery"`).
    ///
    /// Requires the `unsafe-shell-recovery` Cargo feature. Even with
    /// the feature enabled, `--i-accept-shell-risk` is required at
    /// runtime.
    #[cfg(feature = "unsafe-shell-recovery")]
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
    /// A recovery child was forked successfully and is now outstanding.
    /// The observer has NOT waited on it; the child will be reaped on a
    /// later tick via [`Recovery::try_reap`].
    Spawned {
        /// OS process id of the freshly-spawned child shell.
        child_pid: u32,
    },
    /// The previous invocation for this pid is still inside the debounce
    /// window; nothing was spawned.
    Debounced,
    /// `Command::spawn` failed before the child could run (e.g. fork
    /// failure or missing executable). The error is surfaced verbatim.
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
    /// Recovery was structurally declined because the stalled pid's beat
    /// lifetime included a non-kernel-attested transport (any UDP variant),
    /// and the operator did not pass
    /// `--i-accept-recovery-on-unauthenticated-transport`. No child was
    /// spawned. The refusal is logged to the audit sink and counted in
    /// Prometheus so operators can detect both legitimate misconfiguration
    /// and active spoofing attempts.
    RefusedUnauthenticatedSource {
        /// Agent pid whose stall was refused.
        pid: u32,
    },
    /// Recovery was structurally declined because the stalled agent's
    /// kernel-attested PID namespace differs from the observer's. The
    /// numeric pid in this namespace would target a different (or no)
    /// process, so spawning `kill(2)` / `systemctl restart` against it is
    /// unsafe. The refusal is logged to the audit sink and counted in
    /// Prometheus. The operator can opt out via
    /// `--allow-cross-namespace-agents`.
    RefusedCrossNamespace {
        /// Agent pid whose stall was refused.
        pid: u32,
    },
}

/// Bookkeeping slot for one outstanding child.
struct Outstanding {
    child: Child,
    spawned_at: Instant,
    killed: bool,
    /// Wall-clock ms at spawn time; recorded into the audit log on
    /// completion alongside the monotonic duration.
    wallclock_at_spawn_ms: u64,
    /// `Some` iff capture is enabled. Drains accumulate here non-blockingly
    /// across `try_reap` calls; truncation is set when either stream's
    /// captured bytes reach the per-child cap.
    stdout_handle: Option<ChildStdout>,
    /// See `stdout_handle`.
    stderr_handle: Option<ChildStderr>,
    /// Accumulated captured stdout bytes (length only — content is held
    /// briefly in `_stdout_buf` and discarded after the cap is reached).
    stdout_len: u32,
    /// Accumulated captured stderr bytes.
    stderr_len: u32,
    /// True iff either pipe's reads hit the per-child cap and we
    /// stopped reading.
    truncated: bool,
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
    /// Maximum wall-clock time the [`Drop`] impl will block waiting for
    /// outstanding children to exit after issuing `kill(2)`. Children that
    /// outlive the grace are abandoned to PID 1 (init) for reaping.  Tuned
    /// via `--shutdown-grace-ms` in the observer CLI.
    shutdown_grace: Duration,
    /// Optional audit sink. Spawn and complete records are emitted here
    /// when set; when `None`, audit is effectively disabled.
    audit_sink: Option<RecoveryAuditLog>,
    /// Per-child combined byte cap for stdout+stderr capture. `0` disables
    /// capture entirely (default behavior). Set via
    /// [`Recovery::with_capture`].
    capture_cap: u32,
    /// Source descriptor recorded into the spawn audit row: either
    /// `"inline"` or the operator-supplied template-file path.
    source: String,
    /// If `true`, [`on_stall`] will spawn the recovery command even when the
    /// stalled slot's pinned origin is [`BeatOrigin::NetworkUnverified`].
    /// Controlled by `--i-accept-recovery-on-unauthenticated-transport`.
    ///
    /// Default `false`: refuse recovery for any non-kernel-attested origin
    /// and emit a structured audit entry instead. This is the safety-critical
    /// default — see `docs/architecture/peer-authentication.md` for the
    /// trust model.
    ///
    /// [`on_stall`]: Recovery::on_stall
    allow_unauthenticated_source: bool,
    /// Per-pid count of refused recoveries since the last call to
    /// [`Recovery::take_refused_unauthenticated_source`]. Surfaced as
    /// `varta_recovery_refused_total{reason="unauthenticated_transport"}`.
    refused_unauthenticated_source: u64,
    /// If `true`, [`on_stall`] will spawn the recovery command even when the
    /// stalled agent's PID namespace differs from the observer's. Controlled
    /// by `--allow-cross-namespace-agents`. Default `false` — refuse and
    /// audit-log.
    ///
    /// [`on_stall`]: Recovery::on_stall
    allow_cross_namespace: bool,
    /// Per-pid count of refused recoveries that fired because the stalled
    /// agent's PID namespace differed from the observer's. Surfaced as
    /// `varta_recovery_refused_cross_namespace_total`.
    refused_cross_namespace: u64,
}

impl Recovery {
    /// Create a new runner in shell mode with the given `template` and
    /// `debounce` window.
    ///
    /// Equivalent to [`Recovery::with_timeout(template, debounce, None)`].
    ///
    /// Requires the `unsafe-shell-recovery` Cargo feature.
    #[cfg(feature = "unsafe-shell-recovery")]
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
    ///
    /// The [`Drop`] grace defaults to [`crate::config::DEFAULT_SHUTDOWN_GRACE_MS`].
    /// Use [`Self::with_shutdown_grace`] to override.
    pub fn with_timeout(mode: RecoveryMode, debounce: Duration, timeout: Option<Duration>) -> Self {
        Recovery {
            mode,
            debounce,
            last_fired: HashMap::new(),
            timeout,
            outstanding: HashMap::new(),
            pending_outcomes: Vec::new(),
            recovery_env: Vec::new(),
            shutdown_grace: Duration::from_millis(crate::config::DEFAULT_SHUTDOWN_GRACE_MS),
            audit_sink: None,
            capture_cap: 0,
            source: "inline".to_string(),
            allow_unauthenticated_source: false,
            refused_unauthenticated_source: 0,
            allow_cross_namespace: false,
            refused_cross_namespace: 0,
        }
    }

    /// Permit recovery to fire for agents whose kernel-attested PID namespace
    /// differs from the observer's. Default `false`. Wired from the
    /// `--allow-cross-namespace-agents` CLI flag. Use only when the operator
    /// can guarantee a meaningful PID translation (e.g. agents launched with
    /// `--pid=host`, or an out-of-band translator in the recovery template).
    pub fn with_allow_cross_namespace(mut self, allow: bool) -> Self {
        self.allow_cross_namespace = allow;
        self
    }

    /// Take and reset the count of recovery refusals that fired because the
    /// stalled agent's PID namespace differed from the observer's.
    pub fn take_refused_cross_namespace(&mut self) -> u64 {
        let n = self.refused_cross_namespace;
        self.refused_cross_namespace = 0;
        n
    }

    /// Enable spawning the recovery command even when the stalled slot's
    /// pinned transport origin is [`BeatOrigin::NetworkUnverified`] (any UDP
    /// variant). Default `false` — recovery refuses non-kernel-attested
    /// sources, treats them as audit-only stalls.
    ///
    /// Wired from `--i-accept-recovery-on-unauthenticated-transport`. The
    /// flag is intentionally verbose: an operator who types it is making an
    /// explicit statement that this build is not for safety-critical use.
    pub fn with_allow_unauthenticated_source(mut self, allow: bool) -> Self {
        self.allow_unauthenticated_source = allow;
        self
    }

    /// Take and reset the count of recovery refusals that fired because the
    /// stalled slot's origin was [`BeatOrigin::NetworkUnverified`] and the
    /// operator did not pass
    /// `--i-accept-recovery-on-unauthenticated-transport`.
    pub fn take_refused_unauthenticated_source(&mut self) -> u64 {
        let n = self.refused_unauthenticated_source;
        self.refused_unauthenticated_source = 0;
        n
    }

    /// Attach a recovery audit sink. Every spawn and completion will be
    /// appended as a TSV record. Passing `None` (the default) disables
    /// audit emission without altering the recovery behavior.
    pub fn with_audit_sink(mut self, sink: Option<RecoveryAuditLog>) -> Self {
        self.audit_sink = sink;
        self
    }

    /// Enable bounded stdout/stderr capture for child processes. `cap` is
    /// the combined per-child byte cap (stdout + stderr); a value of `0`
    /// disables capture. Pipes are read non-blockingly each tick to
    /// prevent the observer poll loop from stalling on a slow child.
    pub fn with_capture(mut self, cap: u32) -> Self {
        self.capture_cap = cap;
        self
    }

    /// Set the audit-row `source` field. Use `"inline"` (default) for
    /// `--recovery-cmd` / `--recovery-exec`, or the path string for the
    /// `*-file` variants — provides operator visibility into which
    /// template body was loaded into memory.
    pub fn with_source(mut self, source: String) -> Self {
        self.source = source;
        self
    }

    /// Override the Drop-time shutdown grace.  See
    /// [`crate::config::DEFAULT_SHUTDOWN_GRACE_MS`] and
    /// [`crate::config::MIN_SHUTDOWN_GRACE_MS`] for the bounds; values
    /// shorter than the minimum are clamped on the way in.
    pub fn with_shutdown_grace(mut self, grace: Duration) -> Self {
        let min = Duration::from_millis(crate::config::MIN_SHUTDOWN_GRACE_MS);
        self.shutdown_grace = grace.max(min);
        self
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
    ///
    /// Requires the `unsafe-shell-recovery` Cargo feature.
    #[cfg(feature = "unsafe-shell-recovery")]
    #[doc(hidden)]
    pub fn with_template_and_timeout(
        template: String,
        debounce: Duration,
        timeout: Option<Duration>,
    ) -> Self {
        Self::with_timeout(RecoveryMode::Shell(template), debounce, timeout)
    }

    fn reap_finished_child(&mut self, pid: u32) -> Option<RecoveryOutcome> {
        // Drain piped stdio (if any) before checking exit; the child may
        // have written its last bytes after our previous tick's drain.
        self.drain_capture(pid);

        let entry = self.outstanding.get_mut(&pid)?;
        match entry.child.try_wait() {
            Ok(Some(status)) => {
                let child_pid = entry.child.id();
                let killed = entry.killed;
                let spawned_at = entry.spawned_at;
                let wallclock_ms = entry.wallclock_at_spawn_ms;
                let stdout_len = entry.stdout_len;
                let stderr_len = entry.stderr_len;
                let truncated = entry.truncated;
                // Final drain pass after exit: the child may have flushed
                // its tail buffer between our last drain and try_wait.
                self.drain_capture(pid);
                let outstanding_entry = self.outstanding.remove(&pid).unwrap();
                self.emit_complete_audit(
                    pid,
                    child_pid,
                    if killed {
                        CompleteOutcome::Killed
                    } else {
                        CompleteOutcome::Reaped
                    },
                    Some(&status),
                    spawned_at,
                    wallclock_ms,
                    outstanding_entry.stdout_len,
                    outstanding_entry.stderr_len,
                    outstanding_entry.truncated,
                );
                // suppress unused variable warning when capture is disabled
                let _ = (stdout_len, stderr_len, truncated);
                Some(RecoveryOutcome::Reaped { child_pid, status })
            }
            Ok(None) => None,
            Err(e) => {
                let child_pid = entry.child.id();
                let spawned_at = entry.spawned_at;
                let wallclock_ms = entry.wallclock_at_spawn_ms;
                let entry = self.outstanding.remove(&pid).unwrap();
                self.emit_complete_audit(
                    pid,
                    child_pid,
                    CompleteOutcome::ReapFailed,
                    None,
                    spawned_at,
                    wallclock_ms,
                    entry.stdout_len,
                    entry.stderr_len,
                    entry.truncated,
                );
                Some(RecoveryOutcome::ReapFailed(e))
            }
        }
    }

    /// Non-blocking drain of captured stdout/stderr for one outstanding
    /// child. Reads as many bytes as the kernel has buffered (up to the
    /// remaining cap) without ever blocking. WouldBlock is treated as
    /// "drain again next tick".
    fn drain_capture(&mut self, pid: u32) {
        let cap = self.capture_cap as usize;
        if cap == 0 {
            return;
        }
        let Some(entry) = self.outstanding.get_mut(&pid) else {
            return;
        };
        if entry.truncated {
            return;
        }
        let mut total = entry.stdout_len as usize + entry.stderr_len as usize;
        // Drain stdout.
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
        // Drain stderr.
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
    fn emit_complete_audit(
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
        let _ = wallclock_at_spawn_ms; // reserved for future "spawn→complete" wallclock pair
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

    /// Spawn `/bin/sh -c <template> varta-recovery <pid>` (shell mode) or
    /// `execvp <program> <args...>` (exec mode), both non-blockingly.
    ///
    /// In shell mode the template receives the stalling pid as `$1`. In exec
    /// mode `{pid}` in any argument is replaced with the numeric PID.
    /// A per-pid debounce window suppresses repeat invocations.
    ///
    /// `origin` is the transport-class classification of the slot whose
    /// stall is being reported. When `origin == NetworkUnverified` and the
    /// operator has not opted in via
    /// [`Recovery::with_allow_unauthenticated_source`], the recovery
    /// command is **not** spawned and [`RecoveryOutcome::RefusedUnauthenticatedSource`]
    /// is returned (and audit-logged) — see the H2 mitigation in
    /// `docs/architecture/peer-authentication.md`.
    ///
    /// `cross_namespace_agent` is `true` iff the caller has determined that
    /// the stalled agent's kernel-attested PID namespace differs from the
    /// observer's (Linux only). When true and the operator has not opted in
    /// via [`Recovery::with_allow_cross_namespace`], recovery is **not**
    /// spawned and [`RecoveryOutcome::RefusedCrossNamespace`] is returned
    /// (and audit-logged with `reason="cross_namespace_agent"`). The
    /// cross-namespace check fires before the unauthenticated-transport check
    /// because both gates can be satisfied at once (an attacker on UDP **and**
    /// in a different namespace), and the cross-namespace signal is the more
    /// specific one when present.
    pub fn on_stall(
        &mut self,
        pid: u32,
        origin: BeatOrigin,
        cross_namespace_agent: bool,
    ) -> RecoveryOutcome {
        // Cross-namespace gate. Default-safe: refuse recovery when the agent's
        // PID namespace differs from the observer's. The pid in the frame is
        // meaningful only inside the agent's namespace; `kill(2)` against it
        // in the observer's namespace would target the wrong process.
        if cross_namespace_agent && !self.allow_cross_namespace {
            self.refused_cross_namespace = self.refused_cross_namespace.saturating_add(1);
            if let Some(sink) = self.audit_sink.as_mut() {
                sink.record_refused(&RefusedRecord {
                    wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
                    observer_ns: 0,
                    agent_pid: pid,
                    reason: "cross_namespace_agent",
                });
            }
            return RecoveryOutcome::RefusedCrossNamespace { pid };
        }

        // Structural origin gate. Default-safe: refuse recovery when the
        // stalled pid's beat lifetime included a non-kernel-attested
        // transport. The operator can opt out (e.g. for development /
        // testing) via `--i-accept-recovery-on-unauthenticated-transport`.
        if origin == BeatOrigin::NetworkUnverified && !self.allow_unauthenticated_source {
            self.refused_unauthenticated_source =
                self.refused_unauthenticated_source.saturating_add(1);
            if let Some(sink) = self.audit_sink.as_mut() {
                sink.record_refused(&RefusedRecord {
                    wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
                    observer_ns: 0,
                    agent_pid: pid,
                    reason: "unauthenticated_transport",
                });
            }
            return RecoveryOutcome::RefusedUnauthenticatedSource { pid };
        }

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

        let capture_on = self.capture_cap > 0;
        let wallclock_ms = RecoveryAuditLog::wallclock_ms_now();

        match &self.mode {
            #[cfg(feature = "unsafe-shell-recovery")]
            RecoveryMode::Shell(template) => {
                let template_len = template.len() as u32;
                let mut cmd = Command::new("/bin/sh");
                self.apply_env(&mut cmd);
                cmd.arg("-c")
                    .arg(template)
                    .arg("varta-recovery")
                    .arg(pid.to_string());
                if capture_on {
                    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
                }
                match cmd.spawn() {
                    Ok(mut child) => {
                        let child_pid = child.id();
                        let (out_handle, err_handle) = take_capture_handles(&mut child, capture_on);
                        self.emit_spawn_audit(
                            wallclock_ms,
                            pid,
                            child_pid,
                            "shell",
                            "/bin/sh",
                            template_len,
                        );
                        self.outstanding.insert(
                            pid,
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
                        self.emit_spawn_audit(
                            wallclock_ms,
                            pid,
                            child_pid,
                            "exec",
                            substituted[0].as_str(),
                            template_len,
                        );
                        self.outstanding.insert(
                            pid,
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
                            },
                        );
                        RecoveryOutcome::Spawned { child_pid }
                    }
                    Err(e) => RecoveryOutcome::SpawnFailed(e),
                }
            }
        }
    }

    /// Emit a recovery-spawn audit record if a sink is configured.
    fn emit_spawn_audit(
        &mut self,
        wallclock_ms: u64,
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
            observer_ns: 0,
            agent_pid,
            child_pid,
            mode,
            program,
            source: &source,
            template_len,
        });
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
                            let entry = self.outstanding.remove(&pid).unwrap();
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

        // Phase 2: wait for all children with a single shared deadline
        // (configured via `--shutdown-grace-ms`).  This is total wall-clock
        // time across all outstanding children, not per-child, so a noisy
        // recovery template cannot stretch shutdown beyond the operator's
        // budget.  systemd's `TimeoutStopSec` should be at least
        // `shutdown_grace_ms` + a small reap margin (~2 s) — see
        // `docs/architecture/peer-authentication.md`.
        let deadline = Instant::now() + self.shutdown_grace;
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

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn debounces_repeat_calls_for_same_pid() {
        let mut rec = Recovery::new("true".to_string(), Duration::from_secs(10));
        let first = rec.on_stall(1, BeatOrigin::KernelAttested, false);
        let second = rec.on_stall(1, BeatOrigin::KernelAttested, false);
        assert!(matches!(first, RecoveryOutcome::Spawned { .. }));
        assert!(matches!(second, RecoveryOutcome::Debounced));
    }

    /// The configurable Drop grace must bound wall-clock shutdown time
    /// even when outstanding children are still running.  We spawn a child
    /// that sleeps far longer than the grace, then drop the Recovery and
    /// time the unwind.  The deadline gives SIGKILL ample headroom over
    /// the grace itself; the test fails if Drop blocked for the full
    /// 30-second sleep.
    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn drop_returns_within_configured_grace() {
        let mut rec = Recovery::new("sleep 30".to_string(), Duration::ZERO)
            .with_shutdown_grace(Duration::from_millis(200));
        match rec.on_stall(99, BeatOrigin::KernelAttested, false) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected first stall to spawn, got {other:?}"),
        }
        let start = Instant::now();
        drop(rec);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(1_500),
            "Drop took {elapsed:?}; must respect --shutdown-grace-ms (~200 ms here)"
        );
    }

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn debounce_is_per_pid() {
        let mut rec = Recovery::new("true".to_string(), Duration::from_secs(10));
        let a = rec.on_stall(1, BeatOrigin::KernelAttested, false);
        let b = rec.on_stall(2, BeatOrigin::KernelAttested, false);
        assert!(matches!(a, RecoveryOutcome::Spawned { .. }));
        assert!(matches!(b, RecoveryOutcome::Spawned { .. }));
    }

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn does_not_replace_outstanding_child_for_same_pid() {
        let mut rec = Recovery::with_template_and_timeout(
            "sleep 5".to_string(),
            Duration::ZERO,
            Some(Duration::from_millis(50)),
        );
        let first_child_pid = match rec.on_stall(7, BeatOrigin::KernelAttested, false) {
            RecoveryOutcome::Spawned { child_pid } => child_pid,
            other => panic!("expected first stall to spawn, got {other:?}"),
        };

        let second = rec.on_stall(7, BeatOrigin::KernelAttested, false);
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

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn template_receives_pid_as_dollar_one() {
        let mut rec = Recovery::new(
            "test \"$1-$1\" = \"7-7\"".to_string(),
            Duration::from_secs(0),
        );
        match rec.on_stall(7, BeatOrigin::KernelAttested, false) {
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

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn spawn_returns_immediately_for_slow_template() {
        let mut rec = Recovery::new("sleep 1".to_string(), Duration::ZERO);
        let start = Instant::now();
        match rec.on_stall(42, BeatOrigin::KernelAttested, false) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(50),
            "spawn blocked for {elapsed:?}; expected non-blocking"
        );
    }

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn try_reap_surfaces_reaped_for_fast_child() {
        let mut rec = Recovery::new("true".to_string(), Duration::ZERO);
        match rec.on_stall(99, BeatOrigin::KernelAttested, false) {
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

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn try_reap_kills_after_timeout() {
        let mut rec = Recovery::with_template_and_timeout(
            "sleep 5".to_string(),
            Duration::ZERO,
            Some(Duration::from_millis(100)),
        );
        match rec.on_stall(7, BeatOrigin::KernelAttested, false) {
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

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn drop_kills_and_reaps_still_running_children() {
        // Spawn a long-running child with no timeout — the child will
        // still be alive when `rec` goes out of scope. Drop must kill
        // and wait on it to prevent a zombie.
        let start = Instant::now();
        {
            let mut rec = Recovery::new("sleep 5".to_string(), Duration::ZERO);
            match rec.on_stall(999, BeatOrigin::KernelAttested, false) {
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

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn with_timeout_constructor_accepts_optional_duration() {
        let _none = Recovery::with_template_and_timeout("true".to_string(), Duration::ZERO, None);
        let _some = Recovery::with_template_and_timeout(
            "true".to_string(),
            Duration::ZERO,
            Some(Duration::from_millis(50)),
        );
    }

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn last_fired_hashmap_is_pruned_after_debounce_times_ten() {
        let debounce = Duration::from_millis(10);
        let mut rec = Recovery::new("true".to_string(), debounce);

        assert!(matches!(
            rec.on_stall(1, BeatOrigin::KernelAttested, false),
            RecoveryOutcome::Spawned { .. }
        ));
        assert!(matches!(
            rec.on_stall(1, BeatOrigin::KernelAttested, false),
            RecoveryOutcome::Debounced
        ));

        let prune_threshold = debounce.saturating_mul(10);
        std::thread::sleep(prune_threshold + Duration::from_millis(40));

        assert!(matches!(
            rec.on_stall(1, BeatOrigin::KernelAttested, false),
            RecoveryOutcome::Spawned { .. }
        ));
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
        match rec.on_stall(42, BeatOrigin::KernelAttested, false) {
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
        match rec.on_stall(42, BeatOrigin::KernelAttested, false) {
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
        match rec.on_stall(42, BeatOrigin::KernelAttested, false) {
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

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn env_isolation_clears_inherited_environment() {
        let mut rec = Recovery::with_timeout(
            RecoveryMode::Shell("test -z \"$HOME\"".to_string()),
            Duration::ZERO,
            None,
        )
        .with_recovery_env(vec!["FOO=bar".to_string()]);
        match rec.on_stall(1, BeatOrigin::KernelAttested, false) {
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

    #[cfg(feature = "unsafe-shell-recovery")]
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
        match rec.on_stall(1, BeatOrigin::KernelAttested, false) {
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

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn no_env_isolation_preserves_inherited_env() {
        let mut rec = Recovery::with_timeout(
            RecoveryMode::Shell("test -n \"$HOME\"".to_string()),
            Duration::ZERO,
            None,
        );
        // Default: recovery_env is empty → inherits observer's environment.
        match rec.on_stall(1, BeatOrigin::KernelAttested, false) {
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
        match rec.on_stall(1, BeatOrigin::KernelAttested, false) {
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

    // ----- M1: audit log + capture tests -----

    fn audit_tmpdir(tag: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "varta-rec-audit-{tag}-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir(&dir).expect("create tempdir");
        // Restore execute bit on the dir explicitly. A parallel
        // `UnixDatagram::bind` in another test installs a 0o177 umask
        // that masks out the `x` bit from new directories, which would
        // make every subsequent open() inside this dir return EACCES.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod tempdir");
        dir
    }

    #[test]
    fn audit_sink_records_spawn_and_complete_for_exec_mode() {
        let dir = audit_tmpdir("audit-rt");
        let path = dir.join("audit.log");
        let sink = RecoveryAuditLog::create(&path, None).expect("create audit");

        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::ZERO,
        )
        .with_audit_sink(Some(sink));

        match rec.on_stall(123, BeatOrigin::KernelAttested, false) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }
        // Spin try_reap until we observe Reaped, then drop to flush.
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if Instant::now() >= deadline {
                panic!("timed out waiting for Reaped");
            }
            let outcomes = rec.try_reap();
            if outcomes
                .iter()
                .any(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(rec);

        let body = std::fs::read_to_string(&path).expect("read audit");
        let lines: Vec<&str> = body.lines().collect();
        assert!(lines[0].starts_with("# varta-watch recovery audit v1"));
        assert!(
            lines.iter().any(|l| l.contains("\tspawn\t123\t")),
            "expected spawn line for pid 123: {body}"
        );
        assert!(
            lines.iter().any(|l| l.contains("\tcomplete\t123\t")),
            "expected complete line for pid 123: {body}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn capture_records_nonzero_length_for_chatty_child() {
        let dir = audit_tmpdir("capture");
        let path = dir.join("audit.log");
        let sink = RecoveryAuditLog::create(&path, None).expect("create audit");

        // Print exactly 64 bytes to stdout, then exit.
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "sh".to_string(),
                args: vec!["-c".to_string(), "printf '%64s' '' | tr ' ' X".to_string()],
            },
            Duration::ZERO,
        )
        .with_capture(4096)
        .with_audit_sink(Some(sink));

        match rec.on_stall(77, BeatOrigin::KernelAttested, false) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            if Instant::now() >= deadline {
                panic!("timed out waiting for Reaped");
            }
            let outcomes = rec.try_reap();
            if outcomes
                .iter()
                .any(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(rec);

        let body = std::fs::read_to_string(&path).expect("read audit");
        let complete = body
            .lines()
            .find(|l| l.contains("\tcomplete\t77\t"))
            .expect("complete line");
        // stdout_len appears in the 10th tab-separated column (index 9).
        let cols: Vec<&str> = complete.split('\t').collect();
        let stdout_len: u32 = cols[9].parse().expect("stdout_len");
        assert!(
            stdout_len >= 64,
            "expected stdout_len ≥ 64, got {stdout_len}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn capture_truncates_at_per_child_cap() {
        let dir = audit_tmpdir("truncate");
        let path = dir.join("audit.log");
        let sink = RecoveryAuditLog::create(&path, None).expect("create audit");

        // Print ~10 KB to stdout; cap at 64 bytes.
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "head -c 10000 /dev/zero | tr '\\0' X".to_string(),
                ],
            },
            Duration::ZERO,
        )
        .with_capture(64)
        .with_audit_sink(Some(sink));

        match rec.on_stall(8, BeatOrigin::KernelAttested, false) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }
        let deadline = Instant::now() + Duration::from_millis(2_000);
        loop {
            if Instant::now() >= deadline {
                panic!("timed out waiting for Reaped");
            }
            let outcomes = rec.try_reap();
            if outcomes
                .iter()
                .any(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(rec);

        let body = std::fs::read_to_string(&path).expect("read audit");
        let complete = body
            .lines()
            .find(|l| l.contains("\tcomplete\t8\t"))
            .expect("complete line");
        let cols: Vec<&str> = complete.split('\t').collect();
        let truncated = cols[11];
        assert_eq!(
            truncated, "true",
            "expected truncated=true, got: {complete}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_disabled_does_not_create_audit_file() {
        // Sanity: audit is opt-in; without a sink we never touch any path.
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::ZERO,
        );
        match rec.on_stall(1, BeatOrigin::KernelAttested, false) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }
        // No audit_sink configured → nothing to assert beyond "still works".
    }

    /// H2 default-safe gate: a `NetworkUnverified` stall must NOT spawn the
    /// recovery command. The counter increments and the outcome is the new
    /// `RefusedUnauthenticatedSource` variant.
    #[test]
    fn refuses_recovery_on_unauthenticated_origin_by_default() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::ZERO,
        );

        match rec.on_stall(42, BeatOrigin::NetworkUnverified, false) {
            RecoveryOutcome::RefusedUnauthenticatedSource { pid } => assert_eq!(pid, 42),
            other => panic!("expected RefusedUnauthenticatedSource, got {other:?}"),
        }
        assert_eq!(rec.take_refused_unauthenticated_source(), 1);
        // Counter resets after take.
        assert_eq!(rec.take_refused_unauthenticated_source(), 0);
    }

    /// `--i-accept-recovery-on-unauthenticated-transport` flips the gate
    /// off — `NetworkUnverified` stalls spawn like UDS ones.
    #[test]
    fn accept_flag_allows_unauthenticated_recovery() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::ZERO,
        )
        .with_allow_unauthenticated_source(true);

        match rec.on_stall(42, BeatOrigin::NetworkUnverified, false) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }
        assert_eq!(rec.take_refused_unauthenticated_source(), 0);
    }

    /// The refusal path must NOT mutate debounce state — a second stall for
    /// the same pid (regardless of origin) is still allowed to advance to
    /// the legitimate gate.
    #[test]
    fn refusal_does_not_burn_debounce_window() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::from_secs(60),
        );

        // First call refused → no debounce entry recorded.
        let _ = rec.on_stall(7, BeatOrigin::NetworkUnverified, false);

        // A genuine kernel-attested stall for the same pid still spawns —
        // the previous (refused) call did not consume the debounce window.
        match rec.on_stall(7, BeatOrigin::KernelAttested, false) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }
    }

    /// M8 default-safe gate: a kernel-attested stall whose agent runs in a
    /// different PID namespace from the observer must NOT spawn recovery —
    /// `kill(2)` in the observer's namespace would target the wrong process.
    #[test]
    fn refuses_recovery_on_cross_namespace_agent() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::ZERO,
        );

        match rec.on_stall(42, BeatOrigin::KernelAttested, /* cross_ns */ true) {
            RecoveryOutcome::RefusedCrossNamespace { pid } => assert_eq!(pid, 42),
            other => panic!("expected RefusedCrossNamespace, got {other:?}"),
        }
        assert_eq!(rec.take_refused_cross_namespace(), 1);
        assert_eq!(rec.take_refused_cross_namespace(), 0);
    }

    /// `--allow-cross-namespace-agents` flips the gate off; cross-namespace
    /// stalls reach the spawn path like same-namespace ones.
    #[test]
    fn opt_in_allows_recovery_on_cross_namespace_agent() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::ZERO,
        )
        .with_allow_cross_namespace(true);

        match rec.on_stall(42, BeatOrigin::KernelAttested, true) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned with opt-in, got {other:?}"),
        }
        assert_eq!(rec.take_refused_cross_namespace(), 0);
    }

    /// Cross-namespace gate takes precedence over the unauthenticated-transport
    /// gate when both conditions are satisfied — the cross-namespace signal
    /// is more specific.
    #[test]
    fn cross_namespace_gate_precedes_unauth_gate() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::ZERO,
        );

        match rec.on_stall(42, BeatOrigin::NetworkUnverified, true) {
            RecoveryOutcome::RefusedCrossNamespace { pid } => assert_eq!(pid, 42),
            other => panic!("expected RefusedCrossNamespace, got {other:?}"),
        }
        assert_eq!(rec.take_refused_cross_namespace(), 1);
        // The unauth counter must NOT have been bumped — first match wins.
        assert_eq!(rec.take_refused_unauthenticated_source(), 0);
    }
}
