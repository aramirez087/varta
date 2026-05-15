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

use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use crate::audit::{CompleteOutcome, CompleteRecord, RecoveryAuditLog, RefusedRecord, SpawnRecord};
use crate::outstanding_table::{InsertError as OutstandingInsertError, OutstandingTable};
use crate::peer_cred::BeatOrigin;

/// Maximum number of outstanding pids visited per [`Recovery::try_reap`] call.
///
/// Bounds the `waitpid(2, WNOHANG)` + optional `kill(2)` syscall budget to at
/// most 64 per poll tick, preventing a large outstanding-child fan from
/// blowing the `recovery_reap` phase budget. A rotating cursor ensures
/// fairness: pids not visited this tick are visited first next tick.
const REAP_MAX_PER_TICK: usize = 64;

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
///
/// `pid` is the agent pid (always ≥ 2 because [`crate::varta_vlp::Frame::decode`]
/// rejects 0 and 1 with `BadPid`).  `fired_at` is a monotonic instant from
/// [`Instant::now`] at the moment recovery fired for this pid.
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
        #[allow(dead_code)] // Reserved for future audit emission.
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
    /// Number of slots currently holding `Some`.  Tracked separately so
    /// `len()` and the capacity check are O(1).  Kept in sync with the
    /// `Some` count by every mutation; a divergence bumps
    /// `invariant_violations`.
    occupied: usize,
    /// Monotonic count of evictions that occurred because the table was
    /// at capacity and a slot's debounce window had elapsed.  Drained
    /// by [`take_evictions`] for Prometheus exposition.
    ///
    /// [`take_evictions`]: LastFiredTable::take_evictions
    evictions: u64,
    /// Monotonic count of impossible-by-construction conditions
    /// encountered at runtime — should stay at 0 forever.  Operators
    /// alert on any non-zero value.
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

    /// Return the most recent fire instant for `pid`, if any.
    fn get(&self, pid: u32) -> Option<Instant> {
        for s in self.slots.iter().flatten() {
            if s.pid == pid {
                return Some(s.fired_at);
            }
        }
        None
    }

    /// Insert or update the entry for `pid` at `now`.
    ///
    /// Three-pass strategy in a single linear scan:
    ///
    /// 1. If a slot for `pid` already exists, update its `fired_at` in
    ///    place.
    /// 2. Otherwise, if there is an empty slot, fill it.
    /// 3. Otherwise, if the oldest slot's age is at least `debounce`,
    ///    evict it and take its place.  This preserves the per-pid
    ///    debounce invariant because the evicted pid's window has
    ///    elapsed.
    /// 4. Otherwise, return [`InsertOutcome::RefusedCapacity`].
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

        // Table is full.  Check the oldest entry's age against debounce.
        // `saturating_duration_since` returns ZERO on clock regression,
        // which is treated as "not eligible for eviction" — preventing
        // a backwards clock blip from auto-evicting the whole table.
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

        // Unreachable in correct operation: occupied == capacity but no
        // oldest candidate was found.  Surface defensively rather than
        // panicking.
        self.invariant_violations = self.invariant_violations.saturating_add(1);
        InsertOutcome::RefusedCapacity
    }

    /// Drop any entry whose age exceeds `threshold`.  Cheap quiet-period
    /// optimisation: under steady-state the table self-trims so the
    /// eviction policy is never engaged.
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

    /// Number of slots currently holding `Some`.
    #[allow(dead_code)] // Useful for diagnostics / tests; not load-bearing.
    fn len(&self) -> usize {
        self.occupied
    }

    /// Drain the eviction counter for Prometheus exposition.
    fn take_evictions(&mut self) -> u64 {
        let n = self.evictions;
        self.evictions = 0;
        n
    }

    /// Drain the invariant-violation counter for Prometheus exposition.
    fn take_invariant_violations(&mut self) -> u64 {
        let n = self.invariant_violations;
        self.invariant_violations = 0;
        n
    }
}

/// Per-pid debounced runner of a `recovery_cmd` template.
pub struct Recovery {
    mode: RecoveryMode,
    debounce: Duration,
    last_fired: LastFiredTable,
    timeout: Option<Duration>,
    outstanding: OutstandingTable<Outstanding>,
    /// Count of recoveries refused because [`OutstandingTable`] was at
    /// capacity (one outstanding child per tracked agent already in
    /// flight). Surfaced as
    /// `varta_recovery_refused_total{reason="outstanding_capacity"}`.
    refused_outstanding_capacity: u64,
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
    /// Per-pid count of refused recoveries since the last call to
    /// [`Recovery::take_refused_unauthenticated_source`]. Surfaced as
    /// `varta_recovery_refused_total{reason="unauthenticated_transport"}`.
    refused_unauthenticated_source: u64,
    /// Per-pid count of refused recoveries since the last call to
    /// [`Recovery::take_refused_socket_mode_only`]. Surfaced as
    /// `varta_recovery_refused_total{reason="socket_mode_only"}`.
    refused_socket_mode_only: u64,
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
    /// Count of recoveries refused because [`LastFiredTable`] was at
    /// capacity AND no entry's debounce window had elapsed.  Surfaced
    /// as `varta_recovery_refused_total{reason="debounce_capacity"}`.
    /// See [`RecoveryOutcome::RefusedDebounceCapacity`].
    refused_debounce_capacity: u64,
    /// Scratch buffer reused across [`Recovery::try_reap`] calls to snapshot
    /// the keys of `outstanding` without per-tick allocation. Bounded by
    /// `outstanding.len()`, which is in turn bounded by the observer's
    /// `tracker_capacity`. Pre-sized via
    /// [`Recovery::with_reap_scratch_capacity`] from the observer's
    /// configured tracker capacity; otherwise grows on first use.
    reap_scratch: Vec<u32>,
    /// Rotating index into `reap_scratch` used to ensure fairness across
    /// ticks. When [`REAP_MAX_PER_TICK`] is less than the current
    /// outstanding count, the cursor advances by the number of pids visited
    /// so pids deferred this tick are visited first next tick.
    reap_cursor: usize,
    /// Count of [`try_reap`] calls that were truncated because the outstanding
    /// count exceeded [`REAP_MAX_PER_TICK`]. Surfaced as
    /// `varta_recovery_reap_truncated_total`.
    ///
    /// [`try_reap`]: Recovery::try_reap
    reap_truncated_total: u64,
    /// Per-tick reap cap. Always [`REAP_MAX_PER_TICK`] in production;
    /// lowerable in tests via [`Self::shrink_reap_max_for_test`] to exercise
    /// the truncation path without spawning 65+ child processes.
    reap_max: usize,
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
            last_fired: LastFiredTable::new(),
            timeout,
            outstanding: OutstandingTable::with_capacity(crate::tracker::MAX_CAPACITY),
            refused_outstanding_capacity: 0,
            pending_outcomes: Vec::new(),
            recovery_env: Vec::new(),
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
    /// use if not pre-sized. Sizing here makes the first stall storm
    /// allocation-free.
    pub fn with_reap_scratch_capacity(mut self, capacity: usize) -> Self {
        self.reap_scratch.reserve_exact(capacity);
        self
    }

    /// Bound the outstanding-child table to `capacity` slots. By default
    /// the table is sized at [`crate::tracker::MAX_CAPACITY`]; threading
    /// the observer's actual `tracker_capacity` through tightens the
    /// bound so a capacity-exhaustion attempt against `Recovery` fails
    /// closed at the same threshold the tracker itself enforces.
    pub fn with_outstanding_capacity(mut self, capacity: usize) -> Self {
        let cap = capacity.max(1);
        self.outstanding = OutstandingTable::with_capacity(cap);
        self
    }

    /// Take and reset the count of recoveries refused because the
    /// outstanding-child table was at capacity.  Distinct from
    /// [`Self::take_refused_debounce_capacity`]: a debounce-capacity
    /// refusal means we cannot record that recovery fired; an
    /// outstanding-capacity refusal means we cannot track the child
    /// process after it spawns. Both are surfaced under
    /// `varta_recovery_refused_total` with distinct `reason` labels.
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

    /// Take and reset the count of recovery refusals that fired because the
    /// stalled slot's origin was [`BeatOrigin::NetworkUnverified`].
    ///
    /// With C3, this counter only increments for `NetworkUnverified` origins.
    /// `OperatorAttestedTransport` beats are allowed to fire recovery and do
    /// not increment this counter.
    pub fn take_refused_unauthenticated_source(&mut self) -> u64 {
        let n = self.refused_unauthenticated_source;
        self.refused_unauthenticated_source = 0;
        n
    }

    /// Take and reset the count of recoveries refused because the stalled
    /// agent's beat origin was [`crate::peer_cred::BeatOrigin::SocketModeOnly`]
    /// — the observer is running on a platform without per-datagram kernel
    /// credential passing. Surfaced as
    /// `varta_recovery_refused_total{reason="socket_mode_only"}`.
    pub fn take_refused_socket_mode_only(&mut self) -> u64 {
        let n = self.refused_socket_mode_only;
        self.refused_socket_mode_only = 0;
        n
    }

    /// Take and reset the count of recoveries refused because
    /// [`LastFiredTable`] was at capacity and no entry's debounce
    /// window had elapsed.  See [`RecoveryOutcome::RefusedDebounceCapacity`].
    pub fn take_refused_debounce_capacity(&mut self) -> u64 {
        let n = self.refused_debounce_capacity;
        self.refused_debounce_capacity = 0;
        n
    }

    /// Take and reset the count of [`try_reap`] calls that were truncated
    /// because the outstanding-child count exceeded [`REAP_MAX_PER_TICK`].
    /// Surfaced as `varta_recovery_reap_truncated_total`.
    ///
    /// A sustained non-zero rate indicates that the outstanding fan-out
    /// exceeds 64 children per tick. Operators should alert and investigate
    /// whether recovery templates are hung or the debounce window is too
    /// short.
    ///
    /// [`try_reap`]: Recovery::try_reap
    pub fn take_reap_truncated(&mut self) -> u64 {
        let n = self.reap_truncated_total;
        self.reap_truncated_total = 0;
        n
    }

    /// Take and reset the count of [`LastFiredTable`] evictions —
    /// stale entries dropped to make room for a new pid when the table
    /// is at capacity and the evicted entry's debounce window had
    /// elapsed.  Distinct from
    /// [`Self::take_refused_debounce_capacity`]: an eviction is
    /// debounce-respecting churn; a refusal is suppression.
    pub fn take_last_fired_evictions(&mut self) -> u64 {
        self.last_fired.take_evictions()
    }

    /// Take and reset the count of [`LastFiredTable`] invariant
    /// violations — should be `0` forever in correct operation.
    /// Operators alert on any non-zero value.
    pub fn take_last_fired_invariant_violations(&mut self) -> u64 {
        self.last_fired.take_invariant_violations()
    }

    /// Test-only: shrink the [`LastFiredTable`] to `cap` slots so unit
    /// tests can exercise the capacity-pressure branches without
    /// spawning [`MAX_LAST_FIRED_CAPACITY`] child processes.  The
    /// production code path constructs the table at full capacity via
    /// [`LastFiredTable::new`].
    #[cfg(test)]
    pub(crate) fn shrink_last_fired_for_test(&mut self, cap: usize) {
        self.last_fired = LastFiredTable::with_capacity(cap);
    }

    /// Test-only: lower the per-tick reap cap so tests can exercise the
    /// truncation path without spawning [`REAP_MAX_PER_TICK`] child processes.
    #[cfg(test)]
    pub(crate) fn shrink_reap_max_for_test(&mut self, max: usize) {
        self.reap_max = max.max(1); // 0 would loop forever
    }

    /// Attach a recovery audit sink. Every spawn and completion will be
    /// appended as a TSV record. Passing `None` (the default) disables
    /// audit emission without altering the recovery behavior.
    pub fn with_audit_sink(mut self, sink: Option<RecoveryAuditLog>) -> Self {
        self.audit_sink = sink;
        self
    }

    /// Drain any IO error latched by the audit sink since the previous call.
    ///
    /// The audit log latches failed writes / rotations / fsync calls
    /// internally so the recovery hot path never blocks on disk I/O. For
    /// IEC 62304 Class C compliance the daemon must surface those latched
    /// errors — silently dropping audit failures is itself a Class C
    /// violation. The main loop polls this once per tick and routes any
    /// `Some(err)` through its existing `varta_warn!` / json-log emit path.
    ///
    /// Returns `None` if no sink is configured or no error is pending.
    pub fn drain_audit_err(&mut self) -> Option<std::io::Error> {
        self.audit_sink.as_mut().and_then(|s| s.take_pending_err())
    }

    /// Flush buffered audit lines to the BufWriter, bounded by `budget`.
    /// Call once per maintenance phase tick.
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

    /// Drain (and clear) buffered `fdatasync` durations from the audit
    /// sink for the exporter to fold into the
    /// `varta_audit_fsync_seconds` histogram.
    pub fn take_audit_fsync_durations(&mut self) -> Vec<std::time::Duration> {
        self.audit_sink
            .as_mut()
            .map(|s| s.take_audit_fsync_durations())
            .unwrap_or_default()
    }

    /// Take and reset the count of `fdatasync(2)` calls on the audit
    /// sink that exceeded `--audit-fsync-budget-ms`.
    pub fn take_audit_fsync_budget_exceeded(&mut self) -> u64 {
        self.audit_sink
            .as_mut()
            .map(|s| s.take_audit_fsync_budget_exceeded())
            .unwrap_or(0)
    }

    /// Take and reset the count of `drive_audit_rotation` calls that
    /// exceeded `--audit-rotation-budget-ms`.
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

    /// Returns `true` while an audit-log rotation is in progress across
    /// ticks (state machine is past the kick-off).
    pub fn audit_rotation_pending(&self) -> bool {
        self.audit_sink
            .as_ref()
            .map(|s| s.audit_rotation_pending())
            .unwrap_or(false)
    }

    /// Returns `true` when the audit file has crossed its `max_bytes`
    /// cap and the next maintenance tick should drive rotation.
    pub fn audit_rotation_due(&self) -> bool {
        self.audit_sink
            .as_ref()
            .map(|s| s.audit_rotation_due())
            .unwrap_or(false)
    }

    /// Advance the audit-log rotation state machine by at most one
    /// per-sub-step unit of work; the call is bounded by `budget`.
    /// Called once per maintenance tick when `audit_rotation_pending`
    /// or `audit_rotation_due` is true.
    pub fn drive_audit_rotation(
        &mut self,
        budget: std::time::Duration,
    ) -> Option<crate::audit::RotationOutcome> {
        self.audit_sink
            .as_mut()
            .map(|s| s.drive_audit_rotation(budget))
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
        // Acquire the entry once via the Entry API. `OccupiedEntry::remove`
        // returns the owned value with no second map lookup, so the
        // formerly-unreachable `remove(&pid).unwrap()` paths cannot be
        // constructed at all — the unreachable branch is gone, not just
        // better-annotated. Mirrors the DO-178C "no unproven panics" stance
        // already enforced in tracker.rs (cerebrum 2026-05-13).
        let cap = self.capture_cap;
        // Step 1: drain capture and call `try_wait` while holding the
        // mutable borrow.  The borrow ends with the inner scope so the
        // ownership-taking arms below can call `&mut self` methods
        // without conflict.
        let try_wait_result = {
            let entry_mut = self.outstanding.get_mut(pid)?;
            // Drain piped stdio (if any) before checking exit; the child
            // may have written its last bytes after our previous tick's
            // drain.
            Self::drain_outstanding_capture(entry_mut, cap);
            let child_pid = entry_mut.child.id();
            let wait = entry_mut.child.try_wait();
            (child_pid, wait)
        };
        let (child_pid, try_wait_result) = try_wait_result;

        match try_wait_result {
            Ok(Some(status)) => {
                // Final drain pass after exit: the child may have flushed
                // its tail buffer between our last drain and try_wait.
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

    /// Non-blocking drain of captured stdout/stderr for one outstanding
    /// child. Reads as many bytes as the kernel has buffered (up to the
    /// remaining cap) without ever blocking. WouldBlock is treated as
    /// "drain again next tick".
    ///
    /// Takes the entry by `&mut Outstanding` rather than by `pid`+`&mut self`
    /// so it can be called while an `OccupiedEntry` is held in
    /// [`Self::reap_finished_child`] without re-borrowing the map.
    fn drain_outstanding_capture(entry: &mut Outstanding, cap_cfg: u32) {
        let cap = cap_cfg as usize;
        if cap == 0 {
            return;
        }
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
    /// `book/src/architecture/peer-authentication.md`.
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

        // Structural origin gate. Refuse recovery when the stalled pid's
        // beat lifetime was on a transport the operator did not declare
        // recovery-eligible at bind time. `NetworkUnverified` and
        // `SocketModeOnly` are always refused; `OperatorAttestedTransport`
        // and `KernelAttested` flow through. Trust is per-listener, not
        // daemon-wide.
        if origin == BeatOrigin::NetworkUnverified {
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
        if origin == BeatOrigin::SocketModeOnly {
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

        let now = Instant::now();

        // Quiet-period optimisation: drop entries past `debounce * 10`
        // so the table self-trims under steady-state load and the
        // eviction policy is rarely engaged.  Bounded WCET: linear
        // scan over a fixed-size `[Option<LastFiredSlot>; 4096]`.
        let prune_threshold = self.debounce.saturating_mul(10);
        self.last_fired.prune_expired(now, prune_threshold);

        // Per-pid debounce check — ALWAYS honoured.  The pre-M8
        // HashMap implementation skipped this branch when the map was
        // at capacity, creating a silent debounce-bypass window under
        // adversarial stall bursts.  `LastFiredTable::get` is a
        // bounded linear scan; capacity has no effect on whether the
        // check runs.
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

        // Pre-spawn capacity check.  If every tracked-agent slot already
        // has an outstanding recovery in flight, fail closed before
        // burning a LastFiredTable slot so the debounce window for this
        // pid is preserved for the next attempt.
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

        // Capacity-aware insertion.  Three outcomes:
        //   - `Inserted` / `EvictedOldest`: proceed to spawn.  The
        //     eviction path only fires when the oldest entry's
        //     debounce window has already elapsed, so per-pid debounce
        //     semantics are preserved.
        //   - `RefusedCapacity`: table is full AND every entry is
        //     fresh.  Fail closed — emit audit, bump Prometheus
        //     counter, return `RefusedDebounceCapacity`.  See M8 in
        //     `book/src/architecture/observer-liveness.md`.
        match self.last_fired.try_insert(pid, now, self.debounce) {
            InsertOutcome::Inserted | InsertOutcome::EvictedOldest { .. } => {
                // fall through to spawn
            }
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
                        match self.outstanding.try_insert(
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
                        ) {
                            Ok(()) => RecoveryOutcome::Spawned { child_pid },
                            Err(OutstandingInsertError::AlreadyPresent) => {
                                debug_assert!(
                                    false,
                                    "OutstandingTable::try_insert returned AlreadyPresent \
                                     after the `contains` guard above",
                                );
                                RecoveryOutcome::Spawned { child_pid }
                            }
                            Err(OutstandingInsertError::Full) => {
                                // The pre-spawn capacity check should make
                                // this unreachable, but probe-budget
                                // exhaustion is a theoretical residual.
                                // Fail closed: surface the refusal and let
                                // the kernel reap the orphaned child.
                                self.refused_outstanding_capacity =
                                    self.refused_outstanding_capacity.saturating_add(1);
                                RecoveryOutcome::RefusedOutstandingCapacity { pid }
                            }
                        }
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
                        match self.outstanding.try_insert(
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
                        ) {
                            Ok(()) => RecoveryOutcome::Spawned { child_pid },
                            Err(OutstandingInsertError::AlreadyPresent) => {
                                debug_assert!(
                                    false,
                                    "OutstandingTable::try_insert returned AlreadyPresent \
                                     after the `contains` guard above",
                                );
                                RecoveryOutcome::Spawned { child_pid }
                            }
                            Err(OutstandingInsertError::Full) => {
                                self.refused_outstanding_capacity =
                                    self.refused_outstanding_capacity.saturating_add(1);
                                RecoveryOutcome::RefusedOutstandingCapacity { pid }
                            }
                        }
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
    /// Drain completed or timeout-exceeded children.
    ///
    /// At most [`REAP_MAX_PER_TICK`] outstanding pids are visited per call,
    /// bounding `waitpid(2, WNOHANG)` syscall budget per poll tick. A
    /// rotating `reap_cursor` advances past the visited window so pids
    /// deferred this tick are visited first on the next call. When the full
    /// outstanding set exceeds the cap, `varta_recovery_reap_truncated_total`
    /// is incremented; drain the value via [`take_reap_truncated`].
    ///
    /// [`take_reap_truncated`]: Recovery::take_reap_truncated
    pub fn try_reap(&mut self) -> Vec<RecoveryOutcome> {
        let mut outcomes = Vec::new();
        outcomes.append(&mut self.pending_outcomes);

        // Snapshot the outstanding keys into a reusable scratch buffer.
        // `clear()` keeps the backing allocation; `extend` grows it the
        // first time it must (and never thereafter in steady state).
        // Bounded by `outstanding.len()`, which is itself bounded by
        // `tracker_capacity`.
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

        // Clamp work to the per-tick cap and advance the rotating cursor.
        let limit = self.reap_max.min(n);
        let start = self.reap_cursor % n;
        if limit < n {
            self.reap_truncated_total = self.reap_truncated_total.saturating_add(1);
        }
        // Advance cursor so the window slides forward each tick.
        self.reap_cursor = (start + limit) % n;

        // Iterate by index so we don't hold an immutable borrow on
        // `self.reap_scratch` across the `&mut self` method calls below.
        // The buffer is never mutated inside the loop, so indices remain
        // stable.
        for offset in 0..limit {
            let idx = (start + offset) % n;
            let pid = self.reap_scratch[idx];
            if let Some(outcome) = self.reap_finished_child(pid) {
                outcomes.push(outcome);
                continue;
            }

            // Capture metadata and run `kill` inside a borrow scope so
            // the mutable borrow ends before the `Err(e)` arm needs to
            // call back into `&mut self` to take ownership.  The pattern
            // is the same one used by `reap_finished_child`.
            let kill_step = {
                let Some(entry_mut) = self.outstanding.get_mut(pid) else {
                    continue;
                };
                let Some(to) = self.timeout else { continue };
                if entry_mut.spawned_at.elapsed() < to {
                    // No timeout exceeded — leave in place.
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
                    // Do not wait here; the observer poll loop must
                    // remain non-blocking. A later try_wait call will
                    // reap the child.
                    if let Some(entry_mut) = self.outstanding.get_mut(pid) {
                        entry_mut.killed = true;
                    }
                    outcomes.push(RecoveryOutcome::Killed { child_pid });
                }

                Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
                    // Child already exited between our try_wait and kill.
                    // Retry try_wait once.
                    needs_reap_retry = true;
                }

                Err(e) => {
                    if let Some(entry) = self.outstanding.remove(pid) {
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

        // Phase 1: kill all outstanding children immediately (no waiting).
        let mut children: Vec<std::process::Child> = self
            .outstanding
            .drain()
            .map(|mut entry| {
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
        // `book/src/architecture/peer-authentication.md`.
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
        let (sink, _) = RecoveryAuditLog::create(&path, crate::audit::AuditConfig::default())
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
        assert!(lines[0].starts_with("# varta-watch recovery audit v2"));
        assert!(
            lines.iter().any(|l| l.contains("\tspawn\t123\t")),
            "expected spawn line for pid 123: {body}"
        );
        assert!(
            lines.iter().any(|l| l.contains("\tcomplete\t123\t")),
            "expected complete line for pid 123: {body}"
        );
        // v2 schema: every record line carries a seq (first column) and
        // chain (last column).
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
        let (sink, _) = RecoveryAuditLog::create(&path, crate::audit::AuditConfig::default())
            .expect("create audit");

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
        // v2 layout (seq prepended): stdout_len is at column index 10.
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
        let (sink, _) = RecoveryAuditLog::create(&path, crate::audit::AuditConfig::default())
            .expect("create audit");

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
        // v2 layout (seq prepended): truncated is at column index 12.
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
    /// recovery command. The counter increments and the outcome is the
    /// `RefusedUnauthenticatedSource` variant.
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
        // Counter resets after take.
        assert_eq!(rec.take_refused_unauthenticated_source(), 0);
    }

    /// `OperatorAttestedTransport` beats fire recovery just like UDS ones.
    /// The per-listener trust promotion is what enables this path — no
    /// daemon-wide flag required.
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
        // NetworkUnverified counter must not have been bumped.
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
        // The unauth counter must NOT have been bumped — cross-namespace is checked first.
        assert_eq!(rec.take_refused_unauthenticated_source(), 0);
    }

    // ----------------------------------------------------------------
    // M8 — `LastFiredTable` capacity-pressure semantics
    //
    // These tests prove that the fail-closed eviction policy preserves
    // the per-pid debounce invariant under adversarial stall bursts,
    // closing the silent-bypass gap documented in the M8 finding.
    // The first four tests exercise `LastFiredTable` directly so they
    // run in microseconds; the fifth wires through `Recovery::on_stall`
    // to confirm the audit + counter + outcome plumbing.
    // ----------------------------------------------------------------

    #[test]
    fn last_fired_table_at_capacity_with_fresh_entries_refuses() {
        // Capacity=4 keeps the test trivially exhaustive.  The
        // production table uses MAX_LAST_FIRED_CAPACITY=4096 but the
        // logic under test is identical.
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

        // Table is full and every entry is fresh (age 0 < debounce).
        // The insert MUST be refused — preserving the debounce window
        // of all four existing entries.
        let result = table.try_insert(99, t0 + Duration::from_millis(1), debounce);
        assert_eq!(result, InsertOutcome::RefusedCapacity);
        // Refusal does not insert: pid 99 is absent and the table is
        // still full of the original four pids.
        assert!(table.get(99).is_none());
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn last_fired_table_at_capacity_evicts_oldest_past_debounce() {
        let mut table = LastFiredTable::with_capacity(4);
        let debounce = Duration::from_millis(100);
        let t0 = Instant::now();
        // pid 10 is the oldest entry.
        table.try_insert(10, t0, debounce);
        table.try_insert(11, t0 + Duration::from_millis(10), debounce);
        table.try_insert(12, t0 + Duration::from_millis(20), debounce);
        table.try_insert(13, t0 + Duration::from_millis(30), debounce);

        // 200 ms later, pid 10's debounce window (100 ms) has elapsed —
        // it is safe to evict.  pids 11/12/13 must remain in the table.
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
        // A capacity-refused pid must remain *absent* from the table
        // so that, once capacity drains, the next legitimate stall for
        // that pid fires immediately rather than being held back by a
        // stale entry that was never actually granted.
        let mut table = LastFiredTable::with_capacity(2);
        let debounce = Duration::from_millis(100);
        let t0 = Instant::now();
        table.try_insert(1, t0, debounce);
        table.try_insert(2, t0, debounce);

        let refused = table.try_insert(99, t0 + Duration::from_millis(50), debounce);
        assert_eq!(refused, InsertOutcome::RefusedCapacity);
        assert!(table.get(99).is_none(), "refusal must not leave a record");

        // Capacity drains: both slots age past debounce.  pid 99 now
        // inserts cleanly (evicting one of the older entries).
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
        // Fill the production-sized table with entries older than the
        // prune threshold; the prune must complete in well under 5 ms
        // in debug builds.  Detects a future refactor that
        // reintroduces O(n²) behaviour disguised as "cleanup."
        let mut table = LastFiredTable::with_capacity(MAX_LAST_FIRED_CAPACITY);
        let t0 = Instant::now();
        for pid in 0..MAX_LAST_FIRED_CAPACITY as u32 {
            // pid 0/1 are normally rejected at the wire by
            // Frame::decode, but LastFiredTable itself accepts any u32.
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
            "prune_expired took {elapsed:?} — expected < 5 ms; \
             O(n) linear scan over {MAX_LAST_FIRED_CAPACITY} slots"
        );
    }

    #[test]
    fn on_stall_refuses_when_debounce_table_at_capacity_with_fresh_entries() {
        // E2E wiring check: shrink the table to a tiny capacity, fill
        // it via real `on_stall` calls (each spawning `/bin/true`),
        // then assert that the next distinct pid surfaces as
        // `RefusedDebounceCapacity` AND increments the dedicated
        // refusal counter.  The audit path is exercised structurally
        // (no sink attached — the call itself must not panic).
        let mut rec = Recovery::with_mode(
            RecoveryMode::Exec {
                program: "true".to_string(),
                args: vec![],
            },
            Duration::from_secs(10),
        );
        rec.shrink_last_fired_for_test(2);

        // Slot 1, slot 2 — both spawn and fill the table.
        for pid in 10..12u32 {
            match rec.on_stall(pid, BeatOrigin::KernelAttested, false) {
                RecoveryOutcome::Spawned { .. } => {}
                other => panic!("expected Spawned for pid {pid}, got {other:?}"),
            }
        }

        // Third distinct pid arrives while both slots are still fresh
        // (debounce = 10 s).  Must be refused with the new outcome
        // variant + dedicated counter bump.
        match rec.on_stall(99, BeatOrigin::KernelAttested, false) {
            RecoveryOutcome::RefusedDebounceCapacity { pid } => assert_eq!(pid, 99),
            other => panic!("expected RefusedDebounceCapacity, got {other:?}"),
        }
        assert_eq!(rec.take_refused_debounce_capacity(), 1);
        // Other refusal counters must be untouched — this is a
        // distinct refusal class.
        assert_eq!(rec.take_refused_unauthenticated_source(), 0);
        assert_eq!(rec.take_refused_cross_namespace(), 0);
    }

    /// When the outstanding count is within the per-tick cap, no truncation
    /// occurs and all children are visited.
    #[test]
    #[cfg_attr(miri, ignore)] // JUSTIFY: spawns real child processes via Command
    fn try_reap_no_truncation_within_cap() {
        let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(10));
        // Spawn 3 children — well within the default cap of 64.
        for pid in 1u32..=3 {
            rec.on_stall(pid, BeatOrigin::KernelAttested, false);
        }
        // Give children time to exit.
        std::thread::sleep(Duration::from_millis(50));
        // First try_reap should collect all 3 with no truncation.
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

    /// When outstanding children exceed the test-reduced cap, exactly `cap`
    /// pids are visited per tick, the truncation counter is incremented, and
    /// the cursor advances so the next tick visits the remaining pids.
    #[test]
    #[cfg_attr(miri, ignore)] // JUSTIFY: spawns real child processes via Command
    fn try_reap_caps_and_cursor_advances() {
        let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(10));
        // Spawn 5 children and lower the cap to 2 so truncation triggers.
        for pid in 1u32..=5 {
            rec.on_stall(pid, BeatOrigin::KernelAttested, false);
        }
        rec.shrink_reap_max_for_test(2);
        // Give all children time to exit.
        std::thread::sleep(Duration::from_millis(100));

        let mut total_reaped = 0;
        let mut total_ticks = 0;
        // 3 ticks of 2 should drain all 5 (ceil(5/2) = 3).
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

    /// The truncation counter increments once per truncated tick and resets
    /// on drain.
    #[test]
    #[cfg_attr(miri, ignore)] // JUSTIFY: spawns real child processes via Command
    fn try_reap_truncation_counter_increments_and_resets() {
        let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(10));
        for pid in 1u32..=4 {
            rec.on_stall(pid, BeatOrigin::KernelAttested, false);
        }
        rec.shrink_reap_max_for_test(2);
        std::thread::sleep(Duration::from_millis(100));

        rec.try_reap(); // tick 1: visits 2 of 4 → truncated
        assert_eq!(rec.take_reap_truncated(), 1, "one truncated tick");
        assert_eq!(rec.take_reap_truncated(), 0, "counter reset after drain");
    }
}
