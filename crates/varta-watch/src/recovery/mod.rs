//! Per-pid debounced recovery command runner (non-blocking).
//!
//! Recovery is the daemon's cold path: it fires only when an agent has
//! crossed its silence threshold. One execution mode is available:
//!
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
//! No shell is spawned — arguments are passed directly to `execvp(2)`,
//! so shell metacharacters have no effect.
//! **The recovery command source is under full operator control** — anyone
//! who can pass `--recovery-exec` to `varta-watch`
//! already has arbitrary code execution capability. Treat the command
//! as a trusted invocation and never derive it from an untrusted source
//! (e.g. a network request or environment variable from a less-privileged
//! context). Use `--recovery-exec-file` with
//! restrictive file permissions for an additional trust check.

use std::time::{Duration, Instant};

use crate::audit::{RecoveryAuditLog, RefusedRecord};
use crate::outstanding_table::OutstandingTable;
use crate::peer_cred::BeatOrigin;

mod debounce;
mod env;
mod reaper;
mod runner;

use debounce::{InsertOutcome, LastFiredTable};
use runner::Outstanding;

/// Maximum number of outstanding pids visited per [`Recovery::try_reap`] call.
///
/// Bounds the `waitpid(2, WNOHANG)` + optional `kill(2)` syscall budget to at
/// most 64 per poll tick, preventing a large outstanding-child fan from
/// blowing the `recovery_reap` phase budget. A rotating cursor ensures
/// fairness: pids not visited this tick are visited first next tick.
const REAP_MAX_PER_TICK: usize = 64;

/// How the recovery command is executed when an agent stalls.
///
/// One mode is available:
///
/// * [`RecoveryMode::Exec`] — `execvp(argv[0], argv[1..])`. `{pid}` in
///   any argument is replaced with the numeric PID. No shell is
///   involved, so shell metacharacters have no effect.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum RecoveryMode {
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
    /// Recovery was structurally declined because the stalled pid's beat
    /// arrived on a Unix Domain Socket on a platform without per-datagram
    /// kernel credential passing (`BeatOrigin::SocketModeOnly`). The only
    /// defence is `--socket-mode 0600`; any process under the same UID can
    /// forge `frame.pid`, so spawning a recovery command against it is
    /// unsafe. The refusal is logged to the audit sink and counted in
    /// Prometheus.
    RefusedSocketModeOnly {
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
    /// Recovery was structurally declined because the per-pid debounce
    /// ledger ([`LastFiredTable`]) was at capacity AND no entry's age
    /// exceeded `debounce` — i.e. firing would either evict a fresh
    /// entry (silently violating its debounce window) or skip
    /// insertion (leaving the new pid unbounded).  The refusal is
    /// logged to the audit sink and counted in Prometheus so operators
    /// can detect both legitimate scale-out and the M8 adversarial
    /// stall-burst pattern.
    RefusedDebounceCapacity {
        /// Agent pid whose stall was refused.
        pid: u32,
    },
    /// Recovery was structurally declined because the
    /// [`crate::outstanding_table::OutstandingTable`] was at capacity —
    /// one outstanding child per tracked agent already in flight.  This
    /// only fires when the operator's `--tracker-capacity` worth of
    /// agents are simultaneously in mid-recovery, which is itself an
    /// emergency condition.  The refusal is logged to the audit sink and
    /// counted in Prometheus.
    RefusedOutstandingCapacity {
        /// Agent pid whose stall was refused.
        pid: u32,
    },
}

/// Per-pid debounced runner of a `recovery_cmd` template.
pub struct Recovery {
    pub(crate) mode: RecoveryMode,
    pub(crate) debounce: Duration,
    last_fired: LastFiredTable,
    pub(crate) timeout: Option<Duration>,
    pub(in crate::recovery) outstanding: OutstandingTable<Outstanding>,
    /// Count of recoveries refused because [`OutstandingTable`] was at capacity.
    pub(crate) refused_outstanding_capacity: u64,
    pub(crate) pending_outcomes: Vec<RecoveryOutcome>,
    /// Explicit environment variables for child processes in `KEY=VALUE` format.
    pub(crate) recovery_env: Vec<String>,
    /// When `true`, recovery child processes inherit the observer's full environment.
    pub(crate) recovery_inherit_env: bool,
    /// Maximum wall-clock time the [`Drop`] impl will block waiting for outstanding children.
    pub(crate) shutdown_grace: Duration,
    /// Optional audit sink.
    pub(crate) audit_sink: Option<RecoveryAuditLog>,
    /// Per-child combined byte cap for stdout+stderr capture.
    pub(crate) capture_cap: u32,
    /// Source descriptor recorded into the spawn audit row.
    pub(crate) source: String,
    pub(crate) refused_unauthenticated_source: u64,
    pub(crate) refused_socket_mode_only: u64,
    pub(crate) allow_cross_namespace: bool,
    pub(crate) refused_cross_namespace: u64,
    pub(crate) refused_debounce_capacity: u64,
    /// Scratch buffer reused across [`Recovery::try_reap`] calls.
    pub(crate) reap_scratch: Vec<u32>,
    /// Rotating index into `reap_scratch` used to ensure fairness across ticks.
    pub(crate) reap_cursor: usize,
    pub(crate) reap_truncated_total: u64,
    /// Per-tick reap cap.
    pub(crate) reap_max: usize,
}

impl Recovery {
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
            last_fired: LastFiredTable::new(),
            timeout,
            outstanding: OutstandingTable::with_capacity(crate::tracker::MAX_CAPACITY),
            refused_outstanding_capacity: 0,
            pending_outcomes: Vec::new(),
            recovery_env: Vec::new(),
            recovery_inherit_env: false,
            shutdown_grace: Duration::from_millis(crate::config::DEFAULT_SHUTDOWN_GRACE_MS),
            audit_sink: None,
            capture_cap: 0,
            source: "inline".to_string(),
            refused_unauthenticated_source: 0,
            refused_socket_mode_only: 0,
            allow_cross_namespace: false,
            refused_cross_namespace: 0,
            refused_debounce_capacity: 0,
            reap_scratch: Vec::new(),
            reap_cursor: 0,
            reap_truncated_total: 0,
            reap_max: REAP_MAX_PER_TICK,
        }
    }

    /// Pre-size the scratch buffer used by [`Recovery::try_reap`] to the
    /// observer's `tracker_capacity`. Optional — the buffer grows on first
    /// use if not pre-sized.
    pub fn with_reap_scratch_capacity(mut self, capacity: usize) -> Self {
        self.reap_scratch.reserve_exact(capacity);
        self
    }

    /// Bound the outstanding-child table to `capacity` slots.
    pub fn with_outstanding_capacity(mut self, capacity: usize) -> Self {
        let cap = capacity.max(1);
        self.outstanding = OutstandingTable::with_capacity(cap);
        self
    }

    /// Take and reset the count of recoveries refused because the
    /// outstanding-child table was at capacity.
    pub fn take_refused_outstanding_capacity(&mut self) -> u64 {
        let n = self.refused_outstanding_capacity;
        self.refused_outstanding_capacity = 0;
        n
    }

    /// Take and reset the [`OutstandingTable`] probe-exhausted counter.
    ///
    /// Surfaced as `varta_recovery_outstanding_probe_exhausted_total`.
    pub fn take_outstanding_probe_exhausted(&mut self) -> u64 {
        self.outstanding.take_probe_exhausted()
    }

    /// Permit recovery to fire for agents whose kernel-attested PID namespace
    /// differs from the observer's.
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

    /// Take and reset the count of recovery refusals that fired because the
    /// stalled slot's origin was [`BeatOrigin::NetworkUnverified`].
    pub fn take_refused_unauthenticated_source(&mut self) -> u64 {
        let n = self.refused_unauthenticated_source;
        self.refused_unauthenticated_source = 0;
        n
    }

    /// Take and reset the count of recoveries refused because the stalled
    /// agent's beat origin was [`crate::peer_cred::BeatOrigin::SocketModeOnly`].
    pub fn take_refused_socket_mode_only(&mut self) -> u64 {
        let n = self.refused_socket_mode_only;
        self.refused_socket_mode_only = 0;
        n
    }

    /// Take and reset the count of recoveries refused because
    /// [`LastFiredTable`] was at capacity and no entry's debounce
    /// window had elapsed.
    pub fn take_refused_debounce_capacity(&mut self) -> u64 {
        let n = self.refused_debounce_capacity;
        self.refused_debounce_capacity = 0;
        n
    }

    /// Take and reset the count of [`try_reap`] calls that were truncated
    /// because the outstanding-child count exceeded [`REAP_MAX_PER_TICK`].
    ///
    /// [`try_reap`]: Recovery::try_reap
    pub fn take_reap_truncated(&mut self) -> u64 {
        let n = self.reap_truncated_total;
        self.reap_truncated_total = 0;
        n
    }

    /// Take and reset the count of [`LastFiredTable`] evictions.
    pub fn take_last_fired_evictions(&mut self) -> u64 {
        self.last_fired.take_evictions()
    }

    /// Take and reset the count of [`LastFiredTable`] invariant violations.
    pub fn take_last_fired_invariant_violations(&mut self) -> u64 {
        self.last_fired.take_invariant_violations()
    }

    /// Test-only: shrink the [`LastFiredTable`] to `cap` slots.
    #[cfg(test)]
    pub(crate) fn shrink_last_fired_for_test(&mut self, cap: usize) {
        self.last_fired = LastFiredTable::with_capacity(cap);
    }

    /// Test-only: lower the per-tick reap cap.
    #[cfg(test)]
    pub(crate) fn shrink_reap_max_for_test(&mut self, max: usize) {
        self.reap_max = max.max(1);
    }

    /// Attach a recovery audit sink.
    pub fn with_audit_sink(mut self, sink: Option<RecoveryAuditLog>) -> Self {
        self.audit_sink = sink;
        self
    }

    /// Drain any IO error latched by the audit sink since the previous call.
    pub fn drain_audit_err(&mut self) -> Option<std::io::Error> {
        self.audit_sink.as_mut().and_then(|s| s.take_pending_err())
    }

    /// Flush buffered audit lines to the BufWriter, bounded by `budget`.
    pub fn flush_audit_pending(&mut self, budget: std::time::Duration) {
        if let Some(s) = self.audit_sink.as_mut() {
            s.flush_pending(budget);
        }
    }

    /// Take and reset the count of audit lines dropped due to ring-full.
    pub fn take_audit_dropped(&mut self) -> u64 {
        self.audit_sink
            .as_mut()
            .map(|s| s.take_audit_dropped())
            .unwrap_or(0)
    }

    /// Take and reset the count of ticks where audit flush exceeded its budget.
    pub fn take_audit_flush_budget_exceeded(&mut self) -> u64 {
        self.audit_sink
            .as_mut()
            .map(|s| s.take_audit_flush_budget_exceeded())
            .unwrap_or(0)
    }

    /// Drain (and clear) buffered `fdatasync` durations from the audit sink.
    pub fn take_audit_fsync_durations(&mut self) -> Vec<std::time::Duration> {
        self.audit_sink
            .as_mut()
            .map(|s| s.take_audit_fsync_durations())
            .unwrap_or_default()
    }

    /// Take and reset the count of `fdatasync(2)` calls that exceeded budget.
    pub fn take_audit_fsync_budget_exceeded(&mut self) -> u64 {
        self.audit_sink
            .as_mut()
            .map(|s| s.take_audit_fsync_budget_exceeded())
            .unwrap_or(0)
    }

    /// Take and reset the count of `drive_audit_rotation` calls that exceeded budget.
    pub fn take_audit_rotation_budget_exceeded(&mut self) -> u64 {
        self.audit_sink
            .as_mut()
            .map(|s| s.take_audit_rotation_budget_exceeded())
            .unwrap_or(0)
    }

    /// Take and reset the rising-edge ring-warn watermark counter.
    pub fn take_audit_ring_watermark_warn(&mut self) -> u64 {
        self.audit_sink
            .as_mut()
            .map(|s| s.take_audit_ring_watermark_warn())
            .unwrap_or(0)
    }

    /// Take and reset the rising-edge ring-critical watermark counter.
    pub fn take_audit_ring_watermark_critical(&mut self) -> u64 {
        self.audit_sink
            .as_mut()
            .map(|s| s.take_audit_ring_watermark_critical())
            .unwrap_or(0)
    }

    /// Returns `true` while an audit-log rotation is in progress.
    pub fn audit_rotation_pending(&self) -> bool {
        self.audit_sink
            .as_ref()
            .map(|s| s.audit_rotation_pending())
            .unwrap_or(false)
    }

    /// Returns `true` when the audit file has crossed its `max_bytes` cap.
    pub fn audit_rotation_due(&self) -> bool {
        self.audit_sink
            .as_ref()
            .map(|s| s.audit_rotation_due())
            .unwrap_or(false)
    }

    /// Advance the audit-log rotation state machine.
    pub fn drive_audit_rotation(
        &mut self,
        budget: std::time::Duration,
    ) -> Option<crate::audit::RotationOutcome> {
        self.audit_sink
            .as_mut()
            .map(|s| s.drive_audit_rotation(budget))
    }

    /// Enable bounded stdout/stderr capture for child processes.
    pub fn with_capture(mut self, cap: u32) -> Self {
        self.capture_cap = cap;
        self
    }

    /// Set the audit-row `source` field.
    pub fn with_source(mut self, source: String) -> Self {
        self.source = source;
        self
    }

    /// Override the Drop-time shutdown grace.
    pub fn with_shutdown_grace(mut self, grace: Duration) -> Self {
        let min = Duration::from_millis(crate::config::MIN_SHUTDOWN_GRACE_MS);
        self.shutdown_grace = grace.max(min);
        self
    }

    /// Set explicit environment variables for child processes.
    ///
    /// Each entry is in `KEY=VALUE` format.
    pub fn with_recovery_env(mut self, env: Vec<String>) -> Self {
        self.recovery_env = env;
        self
    }

    /// Opt in to inheriting the observer's full environment for recovery children.
    ///
    /// Default: `false`. The secure default clears the child's environment
    /// to `PATH=/usr/bin:/bin` plus any [`Self::with_recovery_env`] overrides.
    pub fn with_recovery_inherit_env(mut self, inherit: bool) -> Self {
        self.recovery_inherit_env = inherit;
        self
    }

    /// Spawn `execvp <program> <args...> <pid>` non-blockingly.
    ///
    /// `{pid}` in any argument is replaced with the numeric PID.
    /// A per-pid debounce window suppresses repeat invocations.
    ///
    /// # Safety gate
    ///
    /// `origin` is the transport-class classification of the slot whose
    /// stall is being reported. `NetworkUnverified` and `SocketModeOnly`
    /// origins are **always refused**; `KernelAttested` and
    /// `OperatorAttestedTransport` flow through to the spawn path.
    ///
    /// `cross_namespace_agent` is `true` iff the stalled agent's
    /// kernel-attested PID namespace differs from the observer's. When
    /// true and `allow_cross_namespace` is false, recovery is refused.
    pub fn on_stall(
        &mut self,
        pid: u32,
        origin: BeatOrigin,
        cross_namespace_agent: bool,
        observer_ns: u64,
    ) -> RecoveryOutcome {
        // --- SAFETY GATE START ---
        // Cross-namespace gate. Default-safe: refuse recovery when the agent's
        // PID namespace differs from the observer's.
        if cross_namespace_agent && !self.allow_cross_namespace {
            self.refused_cross_namespace = self.refused_cross_namespace.saturating_add(1);
            if let Some(sink) = self.audit_sink.as_mut() {
                sink.record_refused(&RefusedRecord {
                    wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
                    observer_ns,
                    agent_pid: pid,
                    reason: "cross_namespace_agent",
                });
            }
            return RecoveryOutcome::RefusedCrossNamespace { pid };
        }

        // Structural origin gate. Default-deny by exhaustive match: any new
        // `BeatOrigin` variant added without an explicit arm here is a
        // compile error. CLAUDE.md hard constraint #8 — do not add a
        // `_ =>` fallthrough; recovery must default to refused for every
        // future variant.
        match origin {
            BeatOrigin::KernelAttested | BeatOrigin::OperatorAttestedTransport => {}
            BeatOrigin::NetworkUnverified => {
                self.refused_unauthenticated_source =
                    self.refused_unauthenticated_source.saturating_add(1);
                if let Some(sink) = self.audit_sink.as_mut() {
                    sink.record_refused(&RefusedRecord {
                        wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
                        observer_ns,
                        agent_pid: pid,
                        reason: "unauthenticated_transport",
                    });
                }
                return RecoveryOutcome::RefusedUnauthenticatedSource { pid };
            }
            BeatOrigin::SocketModeOnly => {
                self.refused_socket_mode_only = self.refused_socket_mode_only.saturating_add(1);
                if let Some(sink) = self.audit_sink.as_mut() {
                    sink.record_refused(&RefusedRecord {
                        wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
                        observer_ns,
                        agent_pid: pid,
                        reason: "socket_mode_only",
                    });
                }
                return RecoveryOutcome::RefusedSocketModeOnly { pid };
            }
        }
        // --- SAFETY GATE END ---

        let now = Instant::now();

        let prune_threshold = self.debounce.saturating_mul(10);
        self.last_fired.prune_expired(now, prune_threshold);

        if let Some(prev) = self.last_fired.get(pid) {
            if now.saturating_duration_since(prev) < self.debounce {
                return RecoveryOutcome::Debounced;
            }
        }

        if self.outstanding.contains(pid) {
            if let Some(outcome) = self.reap_finished_child(pid, observer_ns) {
                self.pending_outcomes.push(outcome);
            } else {
                return RecoveryOutcome::Debounced;
            }
        }

        let reservation = match self.outstanding.try_reserve(pid) {
            Ok(reservation) => reservation,
            Err(_) => {
                self.refused_outstanding_capacity =
                    self.refused_outstanding_capacity.saturating_add(1);
                if let Some(sink) = self.audit_sink.as_mut() {
                    sink.record_refused(&RefusedRecord {
                        wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
                        observer_ns,
                        agent_pid: pid,
                        reason: "outstanding_capacity",
                    });
                }
                return RecoveryOutcome::RefusedOutstandingCapacity { pid };
            }
        };

        match self.last_fired.try_insert(pid, now, self.debounce) {
            InsertOutcome::Inserted | InsertOutcome::EvictedOldest { .. } => {}
            InsertOutcome::RefusedCapacity => {
                self.outstanding.release_reservation(reservation);
                self.refused_debounce_capacity = self.refused_debounce_capacity.saturating_add(1);
                if let Some(sink) = self.audit_sink.as_mut() {
                    sink.record_refused(&RefusedRecord {
                        wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
                        observer_ns,
                        agent_pid: pid,
                        reason: "debounce_capacity",
                    });
                }
                return RecoveryOutcome::RefusedDebounceCapacity { pid };
            }
        }

        let wallclock_ms = RecoveryAuditLog::wallclock_ms_now();
        self.spawn_exec_child(pid, wallclock_ms, now, observer_ns, reservation)
    }

    /// Drain completed or timeout-exceeded children.
    ///
    /// Never blocks; returns an empty vector when no children have
    /// transitioned since the last tick.
    ///
    /// `observer_ns` is the observer-local monotonic timestamp of the current
    /// poll tick (`Observer::now_ns()`); it is stamped into every `complete`
    /// audit record so completions land on the same timeline as the event
    /// stream (see `CompleteRecord::observer_ns`).
    pub fn try_reap(&mut self, observer_ns: u64) -> Vec<RecoveryOutcome> {
        let mut outcomes = Vec::new();
        outcomes.append(&mut self.pending_outcomes);

        self.reap_scratch.clear();
        self.reap_scratch.extend(self.outstanding.iter_pids());
        debug_assert!(
            self.reap_scratch.len() == self.outstanding.len(),
            "reap_scratch must mirror outstanding exactly"
        );
        let n = self.reap_scratch.len();
        if n == 0 {
            return outcomes;
        }

        let limit = self.reap_max.min(n);
        let start = self.reap_cursor % n;
        if limit < n {
            self.reap_truncated_total = self.reap_truncated_total.saturating_add(1);
        }
        self.reap_cursor = (start + limit) % n;

        for offset in 0..limit {
            let idx = (start + offset) % n;
            let pid = self.reap_scratch[idx];
            if let Some(outcome) = self.reap_finished_child(pid, observer_ns) {
                outcomes.push(outcome);
                continue;
            }

            let kill_step = {
                let Some(entry_mut) = self.outstanding.get_mut(pid) else {
                    continue;
                };
                let Some(to) = self.timeout else { continue };
                if entry_mut.spawned_at.elapsed() < to {
                    continue;
                }
                if entry_mut.killed {
                    continue;
                }
                let child_pid = entry_mut.child.id();
                let kill_result = entry_mut.child.kill();
                (child_pid, kill_result)
            };
            let (child_pid, kill_result) = kill_step;

            let mut needs_reap_retry = false;
            match kill_result {
                Ok(()) => {
                    if let Some(entry_mut) = self.outstanding.get_mut(pid) {
                        entry_mut.killed = true;
                    }
                    outcomes.push(RecoveryOutcome::Killed { child_pid });
                }

                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                    needs_reap_retry = true;
                }

                Err(e) => {
                    if let Some(entry) = self.outstanding.remove(pid) {
                        self.emit_complete_audit(
                            pid,
                            child_pid,
                            crate::audit::CompleteOutcome::ReapFailed,
                            None,
                            entry.spawned_at,
                            entry.wallclock_at_spawn_ms,
                            entry.stdout_len,
                            entry.stderr_len,
                            entry.truncated,
                            observer_ns,
                        );
                    }
                    outcomes.push(RecoveryOutcome::ReapFailed(e));
                }
            }
            if needs_reap_retry {
                if let Some(outcome) = self.reap_finished_child(pid, observer_ns) {
                    outcomes.push(outcome);
                }
            }
        }

        outcomes
    }
}

impl Drop for Recovery {
    fn drop(&mut self) {
        const POLL_INTERVAL: Duration = Duration::from_millis(10);

        let mut children: Vec<std::process::Child> = self
            .outstanding
            .drain()
            .map(|mut entry| {
                let _ = entry.child.kill();
                entry.child
            })
            .collect();

        let deadline = Instant::now() + self.shutdown_grace;
        while !children.is_empty() && Instant::now() < deadline {
            children.retain_mut(|child| match child.try_wait() {
                Ok(Some(_)) | Err(_) => false,
                Ok(None) => true,
            });
            if !children.is_empty() {
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

#[cfg(test)]
mod tests;
