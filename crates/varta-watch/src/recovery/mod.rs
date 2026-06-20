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

use debounce::LastFiredTable;
use runner::{KillForReclaim, Outstanding};

/// Maximum number of outstanding pids visited per [`Recovery::try_reap`] call.
///
/// Bounds the `waitpid(2, WNOHANG)` + optional `kill(2)` syscall budget to at
/// most 64 per poll tick, preventing a large outstanding-child fan from
/// blowing the `recovery_reap` phase budget. A rotating cursor ensures
/// fairness: pids not visited this tick are visited first next tick.
const REAP_MAX_PER_TICK: usize = 64;

/// Maximum recovery children `fork(2)`+`exec`'d in one observer poll tick.
///
/// The sibling of [`REAP_MAX_PER_TICK`] for the *spawn* side. A mass
/// simultaneous stall (a shared dependency dies and the whole fleet stops
/// beating at once, or a VM live-migration / suspend-resume forward clock jump
/// trips every tracked slot's threshold in a single pass) queues up to
/// `tracker_capacity` stall events. Without this cap the `DrainPending` stage
/// would `fork`+`exec` all of them back-to-back — head-of-line-blocking the
/// single-threaded poll loop and, at a few ms per spawn, overrunning the 2 s
/// `STAGE_ABORT_NS[DrainPending]` ceiling into a spurious `process::abort()`
/// (and a host reboot under `--hw-watchdog`) at the exact moment the fleet is
/// in trouble. The remainder stays queued (the `stall_queue`/`stall_cursor`
/// cursor resumes next tick) and recovery is staggered across ticks — which
/// also defuses the thundering-herd of simultaneous recovery commands.
/// Smaller than [`REAP_MAX_PER_TICK`] because `fork`+`exec` is far costlier
/// than the non-blocking `waitpid(WNOHANG)` the reap side performs.
pub const RECOVERY_SPAWN_MAX_PER_TICK: usize = 16;

/// Maximum queued stalls *evaluated* in one observer poll tick, regardless of
/// outcome.
///
/// [`RECOVERY_SPAWN_MAX_PER_TICK`] bounds only the stalls that `fork`+`exec` a
/// recovery child; it leaves the *non-spawning* outcomes — `Debounced` and
/// every `Refused*` — uncapped. But evaluating a stall is not free even when it
/// never spawns: [`Recovery::on_stall`] runs an O(`tracker_capacity`) scan of
/// the debounce ledger (`prune_expired` + `get`) on every call, and the
/// `DrainPending` freshness re-check adds a `/proc/<pid>/stat` start-time read
/// per stall. A mass simultaneous stall queues up to `tracker_capacity` events
/// (the same trigger that motivates the spawn cap), and a flapping fleet whose
/// stalls all land inside their debounce window resolves every one of them to
/// `Debounced`. Without this cap the loop would drain the whole queue in a
/// single `DrainPending` stage — `O(N·tracker_capacity)` slot touches plus up
/// to `N` `/proc` reads — head-of-line-blocking the single-threaded poll loop
/// and, under `--prometheus-exporter`, overrunning `STAGE_ABORT_NS[DrainPending]`
/// into a spurious `process::abort()` (host reboot under `--hw-watchdog`). This
/// is the *evaluation*-side sibling of the spawn and reap per-tick budgets — the
/// last unbounded per-tick walk on the poll loop. The remainder stays queued
/// (the `stall_queue`/`stall_cursor` cursor resumes next tick), exactly as the
/// spawn budget defers its overflow. Kept comfortably above
/// [`RECOVERY_SPAWN_MAX_PER_TICK`] so it never throttles genuine spawn
/// throughput: in a stall batch that *does* spawn, the spawn cap trips first;
/// this cap bites only the non-spawning flood it exists to bound.
pub const RECOVERY_STALL_EVAL_MAX_PER_TICK: usize = 256;

/// Maximum ingress datagrams consumed by the `DrainPending` pre-drain in one
/// observer poll tick, before any deferred stall is allowed to fire.
///
/// The fire-time freshness gate (`Observer::stall_freshness`) can only see
/// resumptions the tracker has *recorded*, and the tracker only learns of a
/// resumption when `Observer::poll()` consumes the agent's beat. But `poll()`
/// returns on the first exported `Event` — at most one returnable beat per
/// listener per tick — while the `DrainPending` stage fires up to
/// [`RECOVERY_SPAWN_MAX_PER_TICK`] deferred recoveries per tick. Under a mass
/// simultaneous stall whose agents have since resumed (a transient
/// system-wide pause: cgroup freeze, hypervisor pause, suspend/resume on a
/// suspend-advancing `--clock-source`), deferred kills would outrun the
/// resume-beats that prove them wrong ~16:1 and the freshness gate would read
/// stale `stall_emitted` state — spuriously killing most of a healthy,
/// already-recovered fleet. The pre-drain consumes queued ingress until the
/// sockets report `WouldBlock` (genuinely stalled agents are silent and
/// contribute nothing), so every queued stall is judged against all evidence
/// already received. This budget is the runaway guard for the one case the
/// sockets never empty — a hostile datagram flood: set to
/// [`crate::tracker::MAX_CAPACITY`] so a single tick can observe a resume
/// beat from every trackable agent, while bounding the stage to
/// `MAX_CAPACITY` recv+decode+record steps (microseconds each — two orders
/// of magnitude inside the 2 s `STAGE_ABORT_NS[DrainPending]` ceiling).
pub const RECOVERY_PREDRAIN_INGRESS_MAX_PER_TICK: usize = crate::tracker::MAX_CAPACITY;

/// Maximum stale-lineage children retained for later orphan reaping.
///
/// Recovery can hold at most one outstanding child per tracked agent, but PID
/// recycle handling moves the old lineage's child out of that pid-keyed table
/// before spawning for the new lineage. Without a sibling cap, an unreapable
/// stale child plus repeated recycle churn can grow `reaping_orphans` without
/// bound and allocate inside the observer loop. Keep the orphan backlog under
/// the same structural capacity discipline as [`OutstandingTable`].
const DEFAULT_ORPHAN_CAPACITY: usize = crate::tracker::MAX_CAPACITY;

const AUDIT_REASON_CROSS_NAMESPACE_AGENT: &str = "cross_namespace_agent";
const AUDIT_REASON_UNAUTHENTICATED_TRANSPORT: &str = "unauthenticated_transport";
const AUDIT_REASON_SOCKET_MODE_ONLY: &str = "socket_mode_only";
const AUDIT_REASON_DEBOUNCED: &str = "debounced";
const AUDIT_REASON_OUTSTANDING_IN_FLIGHT: &str = "outstanding_in_flight";
const AUDIT_REASON_DEBOUNCE_CAPACITY: &str = "debounce_capacity";
const AUDIT_REASON_OUTSTANDING_CAPACITY: &str = "outstanding_capacity";
const AUDIT_REASON_ORPHAN_REAP_CAPACITY: &str = "orphan_reap_capacity";
const AUDIT_REASON_STALE_CHILD_KILL_FAILED: &str = "stale_child_kill_failed";
const AUDIT_REASON_SPAWN_FAILED: &str = "spawn_failed";
const AUDIT_REASON_SKIPPED_AGENT_RESUMED: &str = "skipped_agent_resumed";
const AUDIT_REASON_SKIPPED_PID_RECYCLED: &str = "skipped_pid_recycled";
const AUDIT_REASON_SKIPPED_STALL_UNVERIFIABLE: &str = "skipped_stall_unverifiable";

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
    /// window, or a same-lineage child is still in flight; nothing was spawned.
    /// The non-spawn decision is logged to the audit sink.
    Debounced,
    /// `Command::spawn` failed before the child could run (e.g. fork
    /// failure or missing executable). The error is surfaced verbatim and the
    /// failed recovery decision is logged to the audit sink.
    SpawnFailed(std::io::Error),
    /// A previously-spawned child has exited and was reaped on this tick.
    Reaped {
        /// OS process id of the child that exited.
        child_pid: u32,
        /// `ExitStatus` from `Child::try_wait`.
        status: std::process::ExitStatus,
        /// Wall-clock time from successful spawn to final reap.
        duration_ns: u64,
    },
    /// A previously-spawned child was killed via `kill(2)` on this tick.
    /// This can happen after a recovery timeout, or when a recycled PID's
    /// stale-lineage recovery child is stopped before freeing the bare-pid
    /// outstanding slot for the new lineage.
    Killed {
        /// OS process id of the child that was killed.
        child_pid: u32,
    },
    /// `try_wait` or `kill` failed for an outstanding child. The pid is
    /// still tracked; the observer will retry on the next tick.
    ReapFailed(std::io::Error),
    /// Recovery was structurally declined because the stalled pid's beat
    /// lifetime included a non-kernel-attested transport (any UDP variant),
    /// and the operator did not pass the listener's transport-qualified
    /// `--{secure,plaintext}-udp-i-accept-recovery-on-unauthenticated-transport`
    /// accept flag. No child was
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
    /// Recovery was structurally declined because a recycled PID's previous
    /// recovery child could not be killed. Freeing the bare-pid outstanding
    /// slot in that state would allow two recovery children to operate against
    /// the same numeric PID lineage, so the observer fails closed and leaves
    /// the original child tracked.
    RefusedStaleChildKillFailed {
        /// Agent pid whose recycled-lineage stall was refused.
        pid: u32,
        /// Error returned by `kill(2)` while trying to stop the stale child.
        error: std::io::Error,
    },
    /// Recovery was skipped because the agent resumed beating before its
    /// stall fired. A mass simultaneous stall queues more events than the
    /// per-tick spawn budget ([`RECOVERY_SPAWN_MAX_PER_TICK`]) can fire, so
    /// the remainder is deferred across ticks. If the agent emits an accepted
    /// beat in that window its tracker slot clears `stall_emitted`; firing the
    /// stale, deferred stall now would `kill(2)`/restart a healthy process.
    /// This is a benign self-heal, not a safety refusal — it is synthesized by
    /// the observer's freshness re-check (never returned by
    /// [`Recovery::on_stall`]), logged to the audit sink, and counted in
    /// Prometheus as
    /// `varta_recovery_outcomes_total{outcome="skipped_agent_resumed"}`.
    SkippedAgentResumed {
        /// Agent pid whose deferred stall was skipped after it resumed beating.
        pid: u32,
    },
    /// Recovery was skipped because the stalled PID was recycled to a
    /// *different* process before its deferred stall fired. As with
    /// [`Self::SkippedAgentResumed`], a mass simultaneous stall defers events
    /// across ticks; if the OS recycles a stalled agent's PID inside that
    /// window and the new occupant has not beaten, the tracker slot stays
    /// silence-latched but its pinned start-time generation no longer matches
    /// the live process. Firing the `{pid}`-substituted `kill(2)`/restart now
    /// would target an innocent bystander. This is a safety skip — synthesized
    /// by the observer's freshness re-check (never returned by
    /// [`Recovery::on_stall`]), logged to the audit sink, and counted in
    /// Prometheus as
    /// `varta_recovery_outcomes_total{outcome="skipped_pid_recycled"}`.
    SkippedPidRecycled {
        /// Agent pid whose deferred stall was skipped after PID recycle.
        pid: u32,
    },
    /// Recovery was skipped because a recovery-eligible (`KernelAttested`)
    /// deferred stall could not prove PID freshness at fire time. Either the
    /// queued stall carries no start-time generation, or the pinned generation
    /// could not be re-read before recovery fired, so a PID recycle inside the
    /// deferral window cannot be ruled out. This is the unverifiable sibling of
    /// [`Self::SkippedPidRecycled`]. Rather than risk `kill(2)`/restart against
    /// a possibly-recycled bystander, the observer skips. A non-zero count means
    /// kernel-attested recovery is operating in a degraded
    /// (recycle-unverifiable) mode. Synthesized by the observer's freshness
    /// re-check (never returned by [`Recovery::on_stall`]), logged to the
    /// audit sink, and counted as
    /// `varta_recovery_outcomes_total{outcome="skipped_stall_unverifiable"}`.
    SkippedStallUnverifiable {
        /// Agent pid whose deferred stall was skipped as recycle-unverifiable.
        pid: u32,
    },
}

impl RecoveryOutcome {
    /// Wall-clock recovery duration for terminal child-completion outcomes.
    pub fn duration_ns(&self) -> Option<u64> {
        match self {
            Self::Reaped { duration_ns, .. } => Some(*duration_ns),
            _ => None,
        }
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
    /// Stale-lineage recovery children whose pid slot was reclaimed after a
    /// PID recycle (see [`Self::on_stall`]). They were `kill(2)`'d and moved
    /// off the pid-keyed [`OutstandingTable`] so the recycled pid's new
    /// occupant can be recovered immediately; they are reaped non-blockingly
    /// here across later ticks (mirrors the timeout-kill → later-reap split).
    pub(in crate::recovery) reaping_orphans: Vec<(u32, Outstanding)>,
    /// Structural cap for [`Self::reaping_orphans`].
    pub(in crate::recovery) orphan_capacity: usize,
    /// Rotating index into `reaping_orphans`, the orphan-side analogue of
    /// `reap_cursor`. Caps the per-tick `try_wait(2)` budget for the orphan
    /// reaper at [`REAP_MAX_PER_TICK`] so a large reclaimed-orphan fan cannot
    /// blow the `RecoveryReap` stage budget; the cursor guarantees every orphan
    /// is eventually examined (no reap starvation under churn).
    pub(in crate::recovery) orphan_reap_cursor: usize,
    /// Count of outstanding slots reclaimed because a slot's pinned generation
    /// proved its PID had been recycled to a new process while the previous
    /// lineage's recovery child was still in flight. Surfaced as
    /// `varta_recovery_outstanding_recycle_resets_total`; a non-zero value
    /// means recovery was correctly *not* suppressed for the recycled PID.
    pub(crate) outstanding_recycle_resets: u64,
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
            reaping_orphans: Vec::with_capacity(DEFAULT_ORPHAN_CAPACITY),
            orphan_capacity: DEFAULT_ORPHAN_CAPACITY,
            orphan_reap_cursor: 0,
            outstanding_recycle_resets: 0,
        }
    }

    /// Pre-size the scratch buffer used by [`Recovery::try_reap`] to the
    /// observer's `tracker_capacity`. Optional — the buffer grows on first
    /// use if not pre-sized.
    pub fn with_reap_scratch_capacity(mut self, capacity: usize) -> Self {
        self.reap_scratch
            .reserve_exact(capacity.min(crate::tracker::MAX_CAPACITY));
        self
    }

    /// Bound the outstanding-child table to `capacity` slots.
    pub fn with_outstanding_capacity(mut self, capacity: usize) -> Self {
        let cap = capacity
            .clamp(1, crate::tracker::MAX_CAPACITY)
            .max(self.reaping_orphans.len());
        self.outstanding = OutstandingTable::with_capacity(cap);
        self.orphan_capacity = cap;
        if self.reaping_orphans.is_empty() {
            self.reaping_orphans = Vec::with_capacity(cap);
        } else if self.reaping_orphans.capacity() < cap {
            self.reaping_orphans
                .reserve_exact(cap - self.reaping_orphans.capacity());
        }
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

    /// Take and reset the count of stale debounce windows dropped because a
    /// slot's pinned generation proved its PID had been recycled. Surfaced as
    /// `varta_recovery_debounce_recycle_resets_total`.
    pub fn take_last_fired_recycle_resets(&mut self) -> u64 {
        self.last_fired.take_recycle_resets()
    }

    /// Take and reset the count of outstanding-child slots reclaimed because a
    /// slot's pinned generation proved its PID had been recycled while the
    /// previous lineage's recovery child was still in flight. Surfaced as
    /// `varta_recovery_outstanding_recycle_resets_total`.
    pub fn take_outstanding_recycle_resets(&mut self) -> u64 {
        let n = self.outstanding_recycle_resets;
        self.outstanding_recycle_resets = 0;
        n
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

    /// Test-only: push a real reclaimed orphan onto [`Self::reaping_orphans`]
    /// without the full recycle dance, so the per-tick orphan-drain bound can be
    /// exercised cheaply. `program`/`args` choose whether the child exits
    /// immediately (`true`) or stays running (`sleep 30`).
    #[cfg(test)]
    pub(crate) fn push_orphan_for_test(&mut self, pid: u32, program: &str, args: &[&str]) {
        let child = std::process::Command::new(program)
            .args(args)
            .spawn()
            .expect("spawn test orphan child");
        self.reaping_orphans.push((
            pid,
            runner::Outstanding {
                child,
                spawned_at: Instant::now(),
                killed: true,
                generation: None,
                wallclock_at_spawn_ms: 0,
                stdout_handle: None,
                stderr_handle: None,
                stdout_len: 0,
                stderr_len: 0,
                truncated: false,
                completed_status: None,
                completed_at: None,
                kill_error_for_test: None,
            },
        ));
    }

    /// Attach a recovery audit sink.
    pub fn with_audit_sink(mut self, sink: Option<RecoveryAuditLog>) -> Self {
        self.audit_sink = sink;
        self
    }

    fn record_refused_audit(&mut self, pid: u32, observer_ns: u64, reason: &'static str) {
        if let Some(sink) = self.audit_sink.as_mut() {
            sink.record_refused(&RefusedRecord {
                wallclock_ms: RecoveryAuditLog::wallclock_ms_now(),
                observer_ns,
                agent_pid: pid,
                reason,
            });
        }
    }

    /// Audit a deferred-stall skip synthesized by the observer freshness gate.
    ///
    /// These outcomes are not returned by [`Recovery::on_stall`], but they are
    /// still recovery decisions: a queued stall reached the recovery stage and
    /// the daemon deliberately did not spawn a child. Record them in the same
    /// `refused` schema as the other non-spawning decisions so the audit log
    /// remains the complete forensic stream for recovery handling.
    pub fn record_deferred_skip_audit(&mut self, outcome: &RecoveryOutcome, observer_ns: u64) {
        match outcome {
            RecoveryOutcome::SkippedAgentResumed { pid } => {
                self.record_refused_audit(*pid, observer_ns, AUDIT_REASON_SKIPPED_AGENT_RESUMED);
            }
            RecoveryOutcome::SkippedPidRecycled { pid } => {
                self.record_refused_audit(*pid, observer_ns, AUDIT_REASON_SKIPPED_PID_RECYCLED);
            }
            RecoveryOutcome::SkippedStallUnverifiable { pid } => {
                self.record_refused_audit(
                    *pid,
                    observer_ns,
                    AUDIT_REASON_SKIPPED_STALL_UNVERIFIABLE,
                );
            }
            _ => {}
        }
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
    ///
    /// `generation` is the kernel-attested start-time token pinned by the
    /// stalled slot (`Some` only for `KernelAttested` Linux agents; `None`
    /// otherwise). The per-pid debounce ledger is keyed by `(pid, generation)`
    /// so a PID recycled to a new process within a previous fire's debounce
    /// window is **not** suppressed — the new process gets its own recovery.
    /// `None` generation preserves the prior bare-PID debounce behaviour.
    pub fn on_stall(
        &mut self,
        pid: u32,
        origin: BeatOrigin,
        cross_namespace_agent: bool,
        generation: Option<u64>,
        observer_ns: u64,
    ) -> RecoveryOutcome {
        // --- SAFETY GATE START ---
        // Cross-namespace gate. Default-safe: refuse recovery when the agent's
        // PID namespace differs from the observer's.
        if cross_namespace_agent && !self.allow_cross_namespace {
            self.refused_cross_namespace = self.refused_cross_namespace.saturating_add(1);
            self.record_refused_audit(pid, observer_ns, AUDIT_REASON_CROSS_NAMESPACE_AGENT);
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
                self.record_refused_audit(pid, observer_ns, AUDIT_REASON_UNAUTHENTICATED_TRANSPORT);
                return RecoveryOutcome::RefusedUnauthenticatedSource { pid };
            }
            BeatOrigin::SocketModeOnly => {
                self.refused_socket_mode_only = self.refused_socket_mode_only.saturating_add(1);
                self.record_refused_audit(pid, observer_ns, AUDIT_REASON_SOCKET_MODE_ONLY);
                return RecoveryOutcome::RefusedSocketModeOnly { pid };
            }
        }
        // --- SAFETY GATE END ---

        let now = Instant::now();

        let prune_threshold = self.debounce.saturating_mul(10);
        self.last_fired.prune_expired(now, prune_threshold);

        if let Some(prev) = self.last_fired.get(pid, generation) {
            if now.saturating_duration_since(prev) < self.debounce {
                self.record_refused_audit(pid, observer_ns, AUDIT_REASON_DEBOUNCED);
                return RecoveryOutcome::Debounced;
            }
        }

        if self.outstanding.contains(pid) {
            let stored_generation = self.outstanding.get(pid).and_then(|o| o.generation);
            if !debounce::same_lineage(stored_generation, generation) {
                // The OS recycled this PID to a new process while the previous
                // lineage's recovery child is still tracked. That child belongs
                // to a now-dead process; without reclaiming its slot, the
                // genuinely-stalled new occupant `B` would be silently
                // Debounced and never recovered — the same user-visible failure
                // bug-346 fixed for the debounce ledger, via the sibling path
                // the OutstandingTable left open. Reclaim the stale slot and
                // fall through to spawn recovery for the new lineage.
                if let Some(refusal) = self.reclaim_recycled_outstanding(pid, observer_ns) {
                    return refusal;
                }
            } else if let Some(outcome) = self.reap_finished_child(pid, observer_ns) {
                self.pending_outcomes.push(outcome);
            } else {
                self.record_refused_audit(pid, observer_ns, AUDIT_REASON_OUTSTANDING_IN_FLIGHT);
                return RecoveryOutcome::Debounced;
            }
        }

        let reservation = match self.outstanding.try_reserve(pid) {
            Ok(reservation) => reservation,
            Err(_) => {
                self.refused_outstanding_capacity =
                    self.refused_outstanding_capacity.saturating_add(1);
                self.record_refused_audit(pid, observer_ns, AUDIT_REASON_OUTSTANDING_CAPACITY);
                return RecoveryOutcome::RefusedOutstandingCapacity { pid };
            }
        };

        let Some(last_fired_reservation) =
            self.last_fired
                .try_reserve(pid, generation, now, self.debounce)
        else {
            self.outstanding.release_reservation(reservation);
            self.refused_debounce_capacity = self.refused_debounce_capacity.saturating_add(1);
            self.record_refused_audit(pid, observer_ns, AUDIT_REASON_DEBOUNCE_CAPACITY);
            return RecoveryOutcome::RefusedDebounceCapacity { pid };
        };

        let wallclock_ms = RecoveryAuditLog::wallclock_ms_now();
        self.spawn_exec_child(
            pid,
            generation,
            wallclock_ms,
            now,
            observer_ns,
            reservation,
            last_fired_reservation,
        )
    }

    /// Reclaim the outstanding slot for a recycled PID.
    ///
    /// The tracked child belongs to a process that has exited (its PID was
    /// recycled). We `kill(2)` it — leaving it running would let a recovery
    /// template that substitutes `{pid}` act on the *new* occupant of the
    /// recycled PID — then move it off the pid-keyed [`OutstandingTable`] into
    /// [`Self::reaping_orphans`] so the slot is free for the new lineage
    /// immediately. The killed child is reaped non-blockingly on later ticks
    /// (its terminal `complete` audit row is emitted then), exactly like the
    /// timeout-kill path; we never block the poll loop on `wait(2)` here.
    fn reclaim_recycled_outstanding(
        &mut self,
        pid: u32,
        observer_ns: u64,
    ) -> Option<RecoveryOutcome> {
        if self.reaping_orphans.len() >= self.orphan_capacity {
            if let Some(entry) = self.outstanding.get_mut(pid) {
                let _ = entry.kill_for_reclaim();
            }
            self.refused_outstanding_capacity = self.refused_outstanding_capacity.saturating_add(1);
            self.record_refused_audit(pid, observer_ns, AUDIT_REASON_ORPHAN_REAP_CAPACITY);
            return Some(RecoveryOutcome::RefusedOutstandingCapacity { pid });
        }

        let kill_outcome = {
            let entry = self.outstanding.get_mut(pid)?;
            match entry.kill_for_reclaim() {
                Ok(outcome) => outcome,
                Err(error) => {
                    self.record_refused_audit(
                        pid,
                        observer_ns,
                        AUDIT_REASON_STALE_CHILD_KILL_FAILED,
                    );
                    return Some(RecoveryOutcome::RefusedStaleChildKillFailed { pid, error });
                }
            }
        };

        self.outstanding_recycle_resets = self.outstanding_recycle_resets.saturating_add(1);
        if let Some(entry) = self.outstanding.remove(pid) {
            self.reaping_orphans.push((pid, entry));
        }
        if let KillForReclaim::Killed { child_pid } = kill_outcome {
            self.pending_outcomes
                .push(RecoveryOutcome::Killed { child_pid });
        }
        None
    }

    /// Non-blocking reap of [`Self::reaping_orphans`] — children reclaimed from
    /// recycled PID slots. Emits each one's terminal `complete` audit row on
    /// exit (mirroring [`Self::reap_finished_child`]) and drops it; still-running
    /// orphans are retained for a later tick. Runs every [`Self::try_reap`].
    ///
    /// Bounded to [`Self::reap_max`] `try_wait(2)` calls per tick (the orphan-side
    /// analogue of the outstanding-table reap budget): `reclaim_recycled_outstanding`
    /// can push orphans onto this list faster than killed children become reapable
    /// (a stale child wedged in uninterruptible sleep ignores `SIGKILL` until its
    /// syscall returns), so an unbounded full-vector walk here is the one remaining
    /// per-tick loop that could overrun `STAGE_ABORT_NS[RecoveryReap]` and
    /// `process::abort()` a healthy observer (a host reboot under `--hw-watchdog`)
    /// at the exact moment a PID-recycle churn storm is in progress. The rotating
    /// [`Self::orphan_reap_cursor`] guarantees every orphan is eventually examined,
    /// so the bound staggers rather than starves reaping.
    fn drain_orphan_reaps(&mut self, observer_ns: u64) {
        let mut visited = 0;
        while visited < self.reap_max {
            let len = self.reaping_orphans.len();
            if len == 0 {
                break;
            }
            if self.orphan_reap_cursor >= len {
                self.orphan_reap_cursor = 0;
            }
            let i = self.orphan_reap_cursor;
            visited += 1;

            // Orphans are still recovery children with audit-visible capture
            // state. Preserve the normal reap path's bounded drain semantics
            // before emitting their terminal complete record.
            let remove_now = {
                let entry = &mut self.reaping_orphans[i].1;
                Self::drain_outstanding_capture(entry, self.capture_cap);

                if entry.completed_status.is_none() {
                    match entry.child.try_wait() {
                        Ok(Some(status)) => {
                            entry.completed_status = Some(status);
                            entry.completed_at = Some(Instant::now());
                            Self::capture_drained(entry)
                        }
                        Ok(None) => {
                            self.orphan_reap_cursor += 1;
                            continue;
                        }
                        Err(_) => true,
                    }
                } else {
                    Self::capture_drained(entry)
                }
            };

            if !remove_now {
                self.orphan_reap_cursor += 1;
                continue;
            }

            // `swap_remove` moves the tail entry into slot `i`; leave the cursor
            // on `i` so that swapped-in entry is examined next (it wraps to 0 via
            // the `>= len` guard when `i` was the final slot).
            let (orphan_pid, entry) = self.reaping_orphans.swap_remove(i);
            let child_pid = entry.child.id();
            self.emit_complete_audit(
                orphan_pid,
                child_pid,
                crate::audit::CompleteOutcome::Killed,
                entry.completed_status.as_ref(),
                entry.spawned_at,
                entry.wallclock_at_spawn_ms,
                entry.stdout_len,
                entry.stderr_len,
                entry.truncated,
                observer_ns,
            );
        }
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

        // Reap stale-lineage children reclaimed from recycled PID slots.
        self.drain_orphan_reaps(observer_ns);

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
                if entry_mut.completed_status.is_some() {
                    continue;
                }
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
        // Stale-lineage orphans (already killed in reclaim) must also be reaped
        // before Drop returns so no recovery child is leaked at shutdown.
        for (_, mut entry) in self.reaping_orphans.drain(..) {
            let _ = entry.child.kill();
            children.push(entry.child);
        }

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
