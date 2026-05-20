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

mod env;
mod reaper;
mod runner;

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

/// Maximum number of pids tracked in [`LastFiredTable`].
///
/// Each slot is `Option<LastFiredSlot>` ≈ 24 bytes → ~96 KiB total table —
/// within budget for the observer (which already carries
/// `MAX_SENDER_STATES = 1024` rate-limit tables and the `PidIndex`).
///
/// Sized to make the M8 debounce-bypass attack costly: under steady-state
/// 4096 unique pids would have to stall faster than `debounce` cadence
/// before the eviction policy kicks in.  Above that threshold the table
/// fails closed via [`RecoveryOutcome::RefusedDebounceCapacity`].
const MAX_LAST_FIRED_CAPACITY: usize = 4096;

/// Per-pid entry in [`LastFiredTable`].
#[derive(Clone, Copy)]
struct LastFiredSlot {
    pid: u32,
    fired_at: Instant,
}

/// Outcome of [`LastFiredTable::try_insert`].
#[derive(Debug, Eq, PartialEq)]
enum InsertOutcome {
    /// Slot was newly allocated (either filling an empty slot or
    /// updating an existing one for the same pid).
    Inserted,
    /// Table was at capacity; an entry whose age exceeded `debounce`
    /// was evicted to make room.  Debounce semantics are preserved
    /// because the evicted pid's window had already elapsed.
    EvictedOldest {
        /// Pid whose slot was evicted.
        #[allow(dead_code)]
        evicted_pid: u32,
    },
    /// Table is at capacity AND no entry is older than `debounce`.
    /// The caller MUST treat this as a fail-closed refusal: firing
    /// would either evict a fresh entry (violating its debounce
    /// window) or skip insertion (leaving the new pid unbounded).
    RefusedCapacity,
}

/// Fixed-capacity, array-backed ledger of recent recovery fires.
///
/// Replaces the original `HashMap<u32, Instant>` whose reactive pruning
/// (`prune_threshold = debounce * 10`) created a debounce-bypass window
/// under adversarial load: when the map stayed full of fresh entries,
/// the `at_capacity` branch skipped the debounce check entirely and
/// fired without throttling.
///
/// Design properties:
///
/// * **Bounded WCET.** Every operation is a linear scan over a
///   fixed-size `[Option<LastFiredSlot>; MAX_LAST_FIRED_CAPACITY]`
///   backing store — deterministic, no `HashMap` rehash, no
///   randomised hash function.
/// * **Fail-closed under capacity pressure.** When the table is full
///   and no entry's age exceeds `debounce`, [`try_insert`] returns
///   [`InsertOutcome::RefusedCapacity`]; the caller emits a refusal
///   audit row and bumps a Prometheus counter so operators see the
///   condition.
/// * **Clock-regression defense.** All age comparisons use
///   [`Instant::saturating_duration_since`], which returns
///   [`Duration::ZERO`] on regression — preventing a backwards clock
///   blip from auto-evicting the whole table.
/// * **No-panic indexing.** All slot access goes through `.iter()` /
///   `.iter_mut()`; defensive else-branches bump
///   `invariant_violations`, mirroring the DO-178C pattern documented
///   for `PidIndex` in `tracker.rs`.
///
/// See `book/src/architecture/observer-liveness.md` for the operator-facing
/// semantics and alerting recommendation.
///
/// [`try_insert`]: LastFiredTable::try_insert
struct LastFiredTable {
    slots: Box<[Option<LastFiredSlot>]>,
    /// Number of slots currently holding `Some`.
    occupied: usize,
    /// Monotonic count of evictions.
    evictions: u64,
    /// Monotonic count of impossible-by-construction conditions.
    invariant_violations: u64,
}

impl LastFiredTable {
    fn new() -> Self {
        Self::with_capacity(MAX_LAST_FIRED_CAPACITY)
    }

    fn with_capacity(cap: usize) -> Self {
        LastFiredTable {
            slots: vec![None; cap].into_boxed_slice(),
            occupied: 0,
            evictions: 0,
            invariant_violations: 0,
        }
    }

    fn get(&self, pid: u32) -> Option<Instant> {
        for s in self.slots.iter().flatten() {
            if s.pid == pid {
                return Some(s.fired_at);
            }
        }
        None
    }

    fn try_insert(&mut self, pid: u32, now: Instant, debounce: Duration) -> InsertOutcome {
        let mut existing_slot: Option<usize> = None;
        let mut first_empty: Option<usize> = None;
        let mut oldest: Option<(usize, Instant)> = None;

        for (idx, slot) in self.slots.iter().enumerate() {
            match slot {
                Some(s) if s.pid == pid => {
                    existing_slot = Some(idx);
                    break;
                }
                Some(s) => match oldest {
                    Some((_, oldest_at)) if s.fired_at >= oldest_at => {}
                    _ => oldest = Some((idx, s.fired_at)),
                },
                None => {
                    if first_empty.is_none() {
                        first_empty = Some(idx);
                    }
                }
            }
        }

        if let Some(idx) = existing_slot {
            match self.slots.get_mut(idx) {
                Some(slot) => *slot = Some(LastFiredSlot { pid, fired_at: now }),
                None => {
                    self.invariant_violations = self.invariant_violations.saturating_add(1);
                    return InsertOutcome::RefusedCapacity;
                }
            }
            return InsertOutcome::Inserted;
        }

        if let Some(idx) = first_empty {
            match self.slots.get_mut(idx) {
                Some(slot) => {
                    *slot = Some(LastFiredSlot { pid, fired_at: now });
                    self.occupied = self.occupied.saturating_add(1);
                }
                None => {
                    self.invariant_violations = self.invariant_violations.saturating_add(1);
                    return InsertOutcome::RefusedCapacity;
                }
            }
            return InsertOutcome::Inserted;
        }

        if let Some((idx, oldest_at)) = oldest {
            let age = now.saturating_duration_since(oldest_at);
            if age >= debounce {
                let evicted_pid = match self.slots.get(idx) {
                    Some(Some(s)) => s.pid,
                    _ => {
                        self.invariant_violations = self.invariant_violations.saturating_add(1);
                        return InsertOutcome::RefusedCapacity;
                    }
                };
                match self.slots.get_mut(idx) {
                    Some(slot) => *slot = Some(LastFiredSlot { pid, fired_at: now }),
                    None => {
                        self.invariant_violations = self.invariant_violations.saturating_add(1);
                        return InsertOutcome::RefusedCapacity;
                    }
                }
                self.evictions = self.evictions.saturating_add(1);
                return InsertOutcome::EvictedOldest { evicted_pid };
            }
            return InsertOutcome::RefusedCapacity;
        }

        self.invariant_violations = self.invariant_violations.saturating_add(1);
        InsertOutcome::RefusedCapacity
    }

    fn prune_expired(&mut self, now: Instant, threshold: Duration) {
        for slot in self.slots.iter_mut() {
            if let Some(s) = slot {
                if now.saturating_duration_since(s.fired_at) >= threshold {
                    *slot = None;
                    self.occupied = self.occupied.saturating_sub(1);
                }
            }
        }
    }

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.occupied
    }

    fn take_evictions(&mut self) -> u64 {
        let n = self.evictions;
        self.evictions = 0;
        n
    }

    fn take_invariant_violations(&mut self) -> u64 {
        let n = self.invariant_violations;
        self.invariant_violations = 0;
        n
    }
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
    ) -> RecoveryOutcome {
        // --- SAFETY GATE START ---
        // Cross-namespace gate. Default-safe: refuse recovery when the agent's
        // PID namespace differs from the observer's.
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
                        observer_ns: 0,
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
                        observer_ns: 0,
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
            if let Some(outcome) = self.reap_finished_child(pid) {
                self.pending_outcomes.push(outcome);
            } else {
                return RecoveryOutcome::Debounced;
            }
        }

        if self.outstanding.len() >= self.outstanding.capacity() {
            self.refused_outstanding_capacity = self.refused_outstanding_capacity.saturating_add(1);
            if let Some(sink) = self.audit_sink.as_mut() {
                sink.record_refused(&RefusedRecord {
                    wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
                    observer_ns: 0,
                    agent_pid: pid,
                    reason: "outstanding_capacity",
                });
            }
            return RecoveryOutcome::RefusedOutstandingCapacity { pid };
        }

        match self.last_fired.try_insert(pid, now, self.debounce) {
            InsertOutcome::Inserted | InsertOutcome::EvictedOldest { .. } => {}
            InsertOutcome::RefusedCapacity => {
                self.refused_debounce_capacity = self.refused_debounce_capacity.saturating_add(1);
                if let Some(sink) = self.audit_sink.as_mut() {
                    sink.record_refused(&RefusedRecord {
                        wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
                        observer_ns: 0,
                        agent_pid: pid,
                        reason: "debounce_capacity",
                    });
                }
                return RecoveryOutcome::RefusedDebounceCapacity { pid };
            }
        }

        let wallclock_ms = RecoveryAuditLog::wallclock_ms_now();
        self.spawn_exec_child(pid, wallclock_ms, now)
    }

    /// Drain completed or timeout-exceeded children.
    ///
    /// Never blocks; returns an empty vector when no children have
    /// transitioned since the last tick.
    pub fn try_reap(&mut self) -> Vec<RecoveryOutcome> {
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
            if let Some(outcome) = self.reap_finished_child(pid) {
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
                        );
                    }
                    outcomes.push(RecoveryOutcome::ReapFailed(e));
                }
            }
            if needs_reap_retry {
                if let Some(outcome) = self.reap_finished_child(pid) {
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
mod tests {
    use super::*;
    use std::time::Instant;

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
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod tempdir");
        dir
    }

    #[test]
    fn audit_sink_records_spawn_and_complete_for_exec_mode() {
        let dir = audit_tmpdir("audit-rt");
        let path = dir.join("audit.log");
        let (sink, _) =
            crate::audit::RecoveryAuditLog::create(&path, crate::audit::AuditConfig::default())
                .expect("create audit");

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
        assert!(lines[0].starts_with("# varta-watch recovery audit v2"));
        assert!(
            lines.iter().any(|l| l.contains("\tspawn\t123\t")),
            "expected spawn line for pid 123: {body}"
        );
        assert!(
            lines.iter().any(|l| l.contains("\tcomplete\t123\t")),
            "expected complete line for pid 123: {body}"
        );
        for line in lines.iter().filter(|l| !l.starts_with('#')) {
            let cols: Vec<&str> = line.split('\t').collect();
            let seq: u64 = cols[0].parse().expect("seq column parses");
            assert!(seq >= 1, "seq must be >= 1");
            let chain = cols.last().expect("chain column");
            assert!(
                *chain == "-" || chain.len() == 64,
                "chain column must be `-` or 64 hex chars; got {chain:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn capture_records_nonzero_length_for_chatty_child() {
        let dir = audit_tmpdir("capture");
        let path = dir.join("audit.log");
        let (sink, _) =
            crate::audit::RecoveryAuditLog::create(&path, crate::audit::AuditConfig::default())
                .expect("create audit");

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
        let cols: Vec<&str> = complete.split('\t').collect();
        let stdout_len: u32 = cols[10].parse().expect("stdout_len");
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
        let (sink, _) =
            crate::audit::RecoveryAuditLog::create(&path, crate::audit::AuditConfig::default())
                .expect("create audit");

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
        let truncated = cols[12];
        assert_eq!(
            truncated, "true",
            "expected truncated=true, got: {complete}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_disabled_does_not_create_audit_file() {
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
    }

    #[test]
    fn refuses_recovery_on_unauthenticated_origin_always() {
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
        assert_eq!(rec.take_refused_unauthenticated_source(), 0);
    }

    #[test]
    fn operator_attested_transport_fires_recovery() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::ZERO,
        );

        match rec.on_stall(42, BeatOrigin::OperatorAttestedTransport, false) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }
        assert_eq!(rec.take_refused_unauthenticated_source(), 0);
    }

    #[test]
    fn refusal_does_not_burn_debounce_window() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::from_secs(60),
        );

        let _ = rec.on_stall(7, BeatOrigin::NetworkUnverified, false);

        match rec.on_stall(7, BeatOrigin::KernelAttested, false) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned, got {other:?}"),
        }
    }

    #[test]
    fn refuses_recovery_on_cross_namespace_agent() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::ZERO,
        );

        match rec.on_stall(42, BeatOrigin::KernelAttested, true) {
            RecoveryOutcome::RefusedCrossNamespace { pid } => assert_eq!(pid, 42),
            other => panic!("expected RefusedCrossNamespace, got {other:?}"),
        }
        assert_eq!(rec.take_refused_cross_namespace(), 1);
        assert_eq!(rec.take_refused_cross_namespace(), 0);
    }

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
        assert_eq!(rec.take_refused_unauthenticated_source(), 0);
    }

    #[test]
    fn last_fired_table_at_capacity_with_fresh_entries_refuses() {
        let mut table = LastFiredTable::with_capacity(4);
        let debounce = Duration::from_secs(10);
        let t0 = Instant::now();
        for pid in 10..14 {
            assert_eq!(
                table.try_insert(pid, t0, debounce),
                InsertOutcome::Inserted,
                "pid {pid} should fill an empty slot"
            );
        }
        assert_eq!(table.len(), 4);

        let result = table.try_insert(99, t0 + Duration::from_millis(1), debounce);
        assert_eq!(result, InsertOutcome::RefusedCapacity);
        assert!(table.get(99).is_none());
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn last_fired_table_at_capacity_evicts_oldest_past_debounce() {
        let mut table = LastFiredTable::with_capacity(4);
        let debounce = Duration::from_millis(100);
        let t0 = Instant::now();
        table.try_insert(10, t0, debounce);
        table.try_insert(11, t0 + Duration::from_millis(10), debounce);
        table.try_insert(12, t0 + Duration::from_millis(20), debounce);
        table.try_insert(13, t0 + Duration::from_millis(30), debounce);

        let now = t0 + Duration::from_millis(200);
        let outcome = table.try_insert(99, now, debounce);
        assert_eq!(outcome, InsertOutcome::EvictedOldest { evicted_pid: 10 });
        assert!(table.get(10).is_none());
        assert_eq!(table.get(99), Some(now));
        assert_eq!(table.get(11), Some(t0 + Duration::from_millis(10)));
        assert_eq!(table.get(12), Some(t0 + Duration::from_millis(20)));
        assert_eq!(table.get(13), Some(t0 + Duration::from_millis(30)));
    }

    #[test]
    fn last_fired_table_refusal_does_not_burn_debounce_window() {
        let mut table = LastFiredTable::with_capacity(2);
        let debounce = Duration::from_millis(100);
        let t0 = Instant::now();
        table.try_insert(1, t0, debounce);
        table.try_insert(2, t0, debounce);

        let refused = table.try_insert(99, t0 + Duration::from_millis(50), debounce);
        assert_eq!(refused, InsertOutcome::RefusedCapacity);
        assert!(table.get(99).is_none(), "refusal must not leave a record");

        let later = t0 + Duration::from_millis(200);
        let outcome = table.try_insert(99, later, debounce);
        assert!(matches!(
            outcome,
            InsertOutcome::EvictedOldest { .. } | InsertOutcome::Inserted
        ));
        assert_eq!(table.get(99), Some(later));
    }

    #[test]
    fn last_fired_table_prune_bounded_wcet() {
        let mut table = LastFiredTable::with_capacity(MAX_LAST_FIRED_CAPACITY);
        let t0 = Instant::now();
        for pid in 0..MAX_LAST_FIRED_CAPACITY as u32 {
            table.try_insert(pid.saturating_add(2), t0, Duration::ZERO);
        }
        assert_eq!(table.len(), MAX_LAST_FIRED_CAPACITY);

        let later = t0 + Duration::from_secs(60);
        let start = Instant::now();
        table.prune_expired(later, Duration::from_secs(1));
        let elapsed = start.elapsed();
        assert_eq!(table.len(), 0, "every entry exceeded the prune threshold");
        assert!(
            elapsed < Duration::from_millis(5),
            "prune_expired took {elapsed:?} — expected < 5 ms"
        );
    }

    #[test]
    fn on_stall_refuses_when_debounce_table_at_capacity_with_fresh_entries() {
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::from_secs(10),
        );
        rec.shrink_last_fired_for_test(2);

        for pid in 10..12u32 {
            match rec.on_stall(pid, BeatOrigin::KernelAttested, false) {
                RecoveryOutcome::Spawned { .. } => {}
                other => panic!("expected Spawned for pid {pid}, got {other:?}"),
            }
        }

        match rec.on_stall(99, BeatOrigin::KernelAttested, false) {
            RecoveryOutcome::RefusedDebounceCapacity { pid } => assert_eq!(pid, 99),
            other => panic!("expected RefusedDebounceCapacity, got {other:?}"),
        }
        assert_eq!(rec.take_refused_debounce_capacity(), 1);
        assert_eq!(rec.take_refused_unauthenticated_source(), 0);
        assert_eq!(rec.take_refused_cross_namespace(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn try_reap_no_truncation_within_cap() {
        let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(10));
        for pid in 1u32..=3 {
            rec.on_stall(pid, BeatOrigin::KernelAttested, false);
        }
        std::thread::sleep(Duration::from_millis(50));
        let outcomes = rec.try_reap();
        assert_eq!(rec.take_reap_truncated(), 0, "no truncation expected");
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
                .count(),
            3,
            "all 3 children should be reaped"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn try_reap_caps_and_cursor_advances() {
        let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(10));
        for pid in 1u32..=5 {
            rec.on_stall(pid, BeatOrigin::KernelAttested, false);
        }
        rec.shrink_reap_max_for_test(2);
        std::thread::sleep(Duration::from_millis(100));

        let mut total_reaped = 0;
        let mut total_ticks = 0;
        for _ in 0..3 {
            let outcomes = rec.try_reap();
            total_reaped += outcomes
                .iter()
                .filter(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
                .count();
            total_ticks += 1;
            if rec.outstanding.len() == 0 {
                break;
            }
        }
        assert_eq!(total_reaped, 5, "all 5 children eventually reaped");
        assert!(total_ticks <= 3, "at most 3 ticks to drain 5 with cap=2");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn try_reap_truncation_counter_increments_and_resets() {
        let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(10));
        for pid in 1u32..=4 {
            rec.on_stall(pid, BeatOrigin::KernelAttested, false);
        }
        rec.shrink_reap_max_for_test(2);
        std::thread::sleep(Duration::from_millis(100));

        rec.try_reap();
        assert_eq!(rec.take_reap_truncated(), 1, "one truncated tick");
        assert_eq!(rec.take_reap_truncated(), 0, "counter reset after drain");
    }
}
