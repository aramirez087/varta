//! Single-threaded observer: bind one or more transport listeners, decode
//! incoming VLP frames, surface beats / stalls / decode errors via [`Event`].
//!
//! The observer never spawns threads, never allocates after setup,
//! and surfaces at most one [`Event`] per call to [`Observer::poll`]. The
//! caller drives the loop — see `main.rs` for the daemon entrypoint.
//!
//! Multiple listeners (e.g. UDS + UDP) are polled round-robin. Each call to
//! [`Observer::poll`] starts at the rotating cursor and stops as soon as one
//! returnable event is selected, so later datagrams stay queued for later
//! calls instead of being consumed without an exported event. If all listeners
//! return `WouldBlock`, stalls are drained and `None` is returned.

use std::io;
use std::path::Path;
use std::time::Duration;

use varta_vlp::{DecodeError, Frame, Status, NONCE_TERMINAL};

use crate::clock::{Clock, ClockSource};
use crate::listener::{BeatListener, PreThreadAttestation, UdsListener};
use crate::peer_cred::{BeatOrigin, RecvResult};
use crate::tracker::{EvictionPolicy, StallFreshness, Tracker, Update};

/// Reason a beat was dropped by the rate limiter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RateLimitReason {
    PerPid = 0,
    Global = 1,
}

pub(crate) const RATE_LIMIT_N: usize = 2;

/// Forward-jump sentinel: a single poll-tick advance exceeding this threshold
/// is counted as an anomalous forward jump (sleep/wake, VM live migration,
/// hypervisor pause). 5 s is far above worst-case poll-tick latency on a
/// loaded host and far below any plausible sleep or migration interval.
const CLOCK_JUMP_FORWARD_THRESHOLD_NS: u64 = 5_000_000_000;

/// Re-read `/proc/sys/kernel/pid_max` at most every 60 s. Bounded so that an
/// operator-driven `sysctl -w kernel.pid_max=...` change is picked up without
/// daemon restart; coarse enough that the `/proc` read never appears on any
/// latency profile (the refresh runs in the maintenance phase, not on the
/// poll hot path). Hardcoded — no CLI knob, matching the self-watchdog
/// cadence convention.
const PID_MAX_REFRESH_INTERVAL_NS: u64 = 60_000_000_000;

/// Global per-observer token bucket — one shared across all senders.
///
/// Guards against per-pid rotation attacks where an attacker cycles through
/// fake pids to keep every per-pid bucket empty.
///
/// Disabled when `capacity_milli == 0`.  All arithmetic is integer-only
/// (milli-tokens) to stay allocation-free on the hot path.
pub(crate) struct GlobalRateLimit {
    /// Current token count in milli-tokens (1000 milli-tokens = 1 frame allowed).
    tokens_milli: u64,
    /// Maximum token count (= burst × 1000).
    capacity_milli: u64,
    /// Milli-tokens added per second.
    refill_milli_per_sec: u64,
    /// Fractional refill carried between calls, in milli-token-nanoseconds.
    refill_remainder: u64,
    /// Nanosecond timestamp of last refill.
    last_refill_ns: u64,
}

impl GlobalRateLimit {
    /// Construct a new token bucket.  `rate_per_sec = 0` or `burst = 0`
    /// produces a disabled bucket (always allows).
    pub(crate) fn new(rate_per_sec: u32, burst: u32) -> Self {
        if rate_per_sec == 0 || burst == 0 {
            return GlobalRateLimit {
                tokens_milli: 0,
                capacity_milli: 0,
                refill_milli_per_sec: 0,
                refill_remainder: 0,
                last_refill_ns: 0,
            };
        }
        let capacity_milli = (burst as u64).saturating_mul(1_000);
        GlobalRateLimit {
            tokens_milli: capacity_milli,
            capacity_milli,
            refill_milli_per_sec: (rate_per_sec as u64).saturating_mul(1_000),
            refill_remainder: 0,
            last_refill_ns: 0,
        }
    }

    /// Disabled when capacity is 0 — all frames pass.
    #[inline]
    pub(crate) fn is_disabled(&self) -> bool {
        self.capacity_milli == 0
    }

    /// Try to consume one token.  Returns `true` if the frame is allowed,
    /// `false` if the global bucket is exhausted.
    #[inline]
    pub(crate) fn try_consume(&mut self, now_ns: u64) -> bool {
        if self.is_disabled() {
            return true;
        }
        // Lazy refill: add tokens proportional to elapsed time since last refill.
        let elapsed_ns = now_ns.saturating_sub(self.last_refill_ns);
        if elapsed_ns > 0 {
            let refill_units = (elapsed_ns as u128) * (self.refill_milli_per_sec as u128)
                + (self.refill_remainder as u128);
            let added = refill_units / 1_000_000_000u128;
            self.refill_remainder = (refill_units % 1_000_000_000u128) as u64;
            let added_milli = added.min(self.capacity_milli as u128) as u64;
            self.tokens_milli = self
                .tokens_milli
                .saturating_add(added_milli)
                .min(self.capacity_milli);
            if self.tokens_milli == self.capacity_milli {
                self.refill_remainder = 0;
            }
            self.last_refill_ns = now_ns;
        }
        // Consume 1000 milli-tokens (= 1 frame).
        if self.tokens_milli >= 1_000 {
            self.tokens_milli -= 1_000;
            true
        } else {
            false
        }
    }
}

/// Event surfaced by [`Observer::poll`].
///
/// Each call to `poll` returns at most one event. Unknown-pid overflow and
/// out-of-order beats are silently dropped at this layer; the bench / metrics
/// sessions can layer counters on top without changing this enum.
#[derive(Debug)]
pub enum Event {
    /// A well-formed beat was accepted for a tracked pid.
    Beat {
        /// OS process id of the emitting agent.
        pid: u32,
        /// Decoded health status of the beat.
        status: Status,
        /// Application-defined payload carried by the beat.
        payload: u32,
        /// Monotonic nonce of the beat.
        nonce: u64,
        /// Transport-class classification of the beat (see [`BeatOrigin`]).
        /// Recovery commands consult this to refuse firing on non-kernel-attested origins.
        origin: BeatOrigin,
        /// Kernel-attested PID-namespace inode of the sender (Linux only).
        /// `None` for non-Linux platforms, UDP transports, or when the peer's
        /// `/proc/<pid>/ns/pid` was unreadable.
        pid_ns_inode: Option<u64>,
        /// Observer-local timestamp (ns since [`Observer`] start) when this
        /// event was produced.
        observer_ns: u64,
    },
    /// A tracked pid has not beaten within the configured threshold and the
    /// observer has not yet surfaced a stall event for this silence run.
    Stall {
        /// OS process id of the silent agent.
        pid: u32,
        /// Last nonce observed for this pid.
        last_nonce: u64,
        /// Observer-local timestamp (ns since [`Observer`] start) of the
        /// last accepted beat for this pid.
        last_ns: u64,
        /// Transport origin pinned by the slot's first beat. Recovery
        /// refuses to spawn for `NetworkUnverified` unless the operator has
        /// explicitly opted in via
        /// `--i-accept-recovery-on-unauthenticated-transport`.
        origin: BeatOrigin,
        /// PID-namespace inode pinned by the slot's first beat (Linux only).
        /// Used by main.rs to construct the recovery `StallSource`: a
        /// `Some(_)` value that differs from the observer's namespace inode
        /// indicates a cross-namespace agent and gates recovery refusal.
        pid_ns_inode: Option<u64>,
        /// Process *generation* (start-time) token pinned by the slot's first
        /// beat. `Some` only for Linux slots whose `/proc/<pid>/stat`
        /// start-time was pinned; `None` for non-Linux, non-attested, and
        /// generation-unpinned slots. Threaded into `Recovery::on_stall` so the
        /// debounce ledger can tell a recycled PID from the original process.
        generation: Option<u64>,
        /// Observer-local timestamp (ns since [`Observer`] start) when this
        /// stall event was produced.
        observer_ns: u64,
    },
    /// A 32-byte payload arrived but failed VLP decoding.
    Decode(DecodeError, u64),
    /// Frame decoded but the `frame.pid` does not match the kernel-verified
    /// peer PID of the sender. The claimed pid is preserved so exporters can
    /// record what the frame *claimed* to be.
    AuthFailure {
        /// The pid the frame on the wire claimed to be.
        claimed_pid: u32,
        /// Observer-local timestamp (ns since [`Observer`] start) when this
        /// event was produced.
        observer_ns: u64,
    },
    /// A beat arrived for an already-tracked pid, but its transport origin
    /// was weaker than the origin pinned by the slot. The slot was not
    /// mutated; the beat was dropped.
    OriginConflict {
        /// The pid claimed by the dropped beat (same as the existing slot's pid).
        claimed_pid: u32,
        /// Transport origin observed on this datagram.
        observed_origin: BeatOrigin,
        /// Origin pinned by the slot (the one that "won" the conflict).
        slot_origin: BeatOrigin,
        /// Observer-local timestamp (ns since [`Observer`] start) when this
        /// event was produced.
        observer_ns: u64,
    },
    /// A kernel-attested beat arrived whose peer PID-namespace inode differs
    /// from the observer's namespace (Linux only). Recovery for the
    /// associated pid cannot safely fire because the pid is in a different
    /// namespace — `kill(2)` and `systemctl` would target the wrong process.
    /// The beat was dropped at receive; the tracker was not modified.
    NamespaceConflict {
        /// The pid claimed by the dropped beat.
        claimed_pid: u32,
        /// PID-namespace inode of the sender (Linux only; `None` when
        /// `/proc/<peer_pid>/ns/pid` was unreadable).
        observed_ns_inode: Option<u64>,
        /// The observer's own PID-namespace inode (cached at startup; `None`
        /// when `/proc/self/ns/pid` is unreadable, which usually means the
        /// platform isn't Linux).
        observer_ns_inode: Option<u64>,
        /// Observer-local timestamp (ns since [`Observer`] start) when this
        /// event was produced.
        observer_ns: u64,
    },
    /// Receiving from a listener failed with an error other than
    /// `WouldBlock` / `TimedOut`.
    Io(io::Error, u64),
    /// Ancillary data truncated by the kernel (`MSG_CTRUNC` on Linux).
    /// Indicates the kernel's ancillary-data buffer was too small for the
    /// per-message metadata — a kernel-level buffer sizing issue.
    CtrlTruncated(io::Error, u64),
}

/// Observer bound to one or more transport listeners.
///
/// The observer owns all listeners; cleanup (e.g. socket file unlink) happens
/// when the [`Observer`] is dropped.
pub struct Observer {
    listeners: Vec<Box<dyn BeatListener>>,
    tracker: Tracker,
    threshold_ns: u64,
    clock: Clock,
    stall_queue: Vec<Option<Event>>,
    stall_cursor: usize,
    /// Next index to start polling from for fair round-robin across listeners.
    next_listener_start: usize,
    /// Whether the most recent [`Observer::poll`] dequeued at least one
    /// datagram from any listener — including datagrams that were dropped
    /// (rate-limited, short, cross-namespace, above `pid_max`) without
    /// producing a returnable [`Event`]. The main loop reads this via
    /// [`Observer::last_poll_consumed`] to decide whether the socket may
    /// still hold queued beats. A consumed-but-dropped datagram must NOT be
    /// mistaken for an idle tick: otherwise a burst of dropped traffic (e.g.
    /// one agent beating above its per-pid limit) head-of-line-blocks
    /// legitimate beats behind a 10 ms idle sleep per drained datagram,
    /// capping drain at ~100 datagrams/s and triggering false stalls.
    /// Overwritten at the end of every `poll()`.
    last_poll_consumed: bool,
    /// Minimum inter-beat interval applied per pid, in nanoseconds.
    /// `None` means no rate limiting (the default).
    rate_limit_interval_ns: Option<u64>,
    /// Beats dropped by the per-pid and global rate limiters since the last drain.
    /// Index 0 = per-pid (`RateLimitReason::PerPid`), 1 = global (`RateLimitReason::Global`).
    rate_limited_total: [u64; RATE_LIMIT_N],
    /// Global per-observer token bucket for defeating per-pid rotation attacks.
    global_rl: GlobalRateLimit,
    /// Monotonicity guard — last `now_ns()` value, clamped forward-only to
    /// survive TSC drift and VM live migration.
    last_now_ns: u64,
    /// Count of times the underlying monotonic clock returned a value
    /// strictly less than `last_now_ns` and the clamp absorbed the
    /// regression. Surfaced as `varta_observer_clock_regression_total` so
    /// operators can alert on TSC drift / VM-live-migration events that
    /// would otherwise be invisible. Drained via
    /// [`Observer::drain_clock_regressions`].
    clock_regressions: u64,
    /// Count of times consecutive `now_ns()` readings advanced by more than
    /// [`CLOCK_JUMP_FORWARD_THRESHOLD_NS`] in a single poll tick. This
    /// captures sleep/wake on `monotonic-raw`/`boottime`, VM live migration,
    /// and hypervisor pauses that are invisible to the regression counter.
    /// Surfaced as `varta_observer_clock_jump_forward_total`. Drained via
    /// [`Observer::drain_clock_jumps_forward`].
    clock_jumps_forward: u64,
    /// When true, beats from agents whose kernel-attested PID namespace
    /// differs from the observer's are admitted into the tracker (and may
    /// later be passed to recovery). Set by `--allow-cross-namespace-agents`.
    /// Default `false` — beats from cross-namespace agents are dropped at
    /// ingress and counted via [`Observer::drain_cross_namespace_drops`].
    allow_cross_namespace: bool,
    /// Count of beats dropped at ingress because the kernel-attested peer's
    /// PID namespace inode differs from the observer's. Linux-only signal;
    /// 0 on other platforms.
    cross_namespace_drops: u64,
    /// Maximum PID accepted on the wire — cached from
    /// `/proc/sys/kernel/pid_max` on Linux at observer startup. On non-Linux
    /// targets and when `/proc` is unreadable, this is `u32::MAX` (gate
    /// effectively disabled). See [`crate::pid_max::read_pid_max`].
    pid_max: u32,
    /// Count of beats dropped at ingress because `frame.pid > pid_max`.
    /// Surfaced as `varta_frame_rejected_pid_above_max_total`.
    pid_above_max_drops: u64,
    /// Monotonic-clock timestamp (ns) of the most recent `pid_max` refresh
    /// from `/proc/sys/kernel/pid_max`. `0` until the first periodic refresh
    /// fires from [`Observer::maybe_refresh_pid_max`]; the value cached at
    /// `Observer::new` covers the startup window until then. Compared against
    /// `self.now_ns()` with [`PID_MAX_REFRESH_INTERVAL_NS`].
    last_pid_max_refresh_ns: u64,
    /// Effective `SO_RCVBUF` size granted by the kernel for the observer UDS,
    /// in bytes.  `0` if `--uds-rcvbuf-bytes 0` was used or tuning failed.
    /// Set by [`Observer::bind`] from the [`UdsListener::rcvbuf_bytes`] accessor.
    pub uds_rcvbuf_bytes: u32,
}

impl Observer {
    /// Create an empty observer with no listeners. Use
    /// [`Observer::add_listener`] to attach transports, or call
    /// [`Observer::bind`] for the common single-UDS case.
    ///
    /// `tracker_capacity` sets the maximum number of distinct agent pids
    /// tracked concurrently. Beats for new pids beyond this limit are
    /// dropped with [`Update::CapacityExceeded`] (the counter is surfaced
    /// via `varta_tracker_capacity_exceeded_total`).
    ///
    /// `eviction_policy` controls which slot to reclaim when the tracker
    /// is full and a new pid arrives ([`EvictionPolicy::Strict`] only
    /// evicts confirmed-stalled agents; [`EvictionPolicy::Balanced`] also
    /// evicts the oldest active slot to prevent capacity exhaustion).
    ///
    /// `max_beat_rate` is an optional per-pid rate limit in beats per
    /// second.  When set, beats arriving faster than this rate from the
    /// same pid are dropped and counted via [`Observer::drain_rate_limited`].
    /// `None` (the default) disables rate limiting.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        threshold: Duration,
        tracker_capacity: usize,
        eviction_policy: EvictionPolicy,
        eviction_scan_window: usize,
        max_beat_rate: Option<u32>,
        global_beat_rate: u32,
        global_beat_burst: u32,
        clock_source: ClockSource,
    ) -> io::Result<Self> {
        let tracker_capacity = tracker_capacity.min(crate::tracker::MAX_CAPACITY);
        let threshold_ns = threshold.as_nanos().min(u64::MAX as u128) as u64;
        let rate_limit_interval_ns = max_beat_rate.and_then(|rps| {
            if rps == 0 {
                None
            } else {
                // Convert beats/sec to nanosecond interval.
                // Saturate at 1 ns (1 GHz rate) to avoid overflow.
                let interval_ns = 1_000_000_000u64.checked_div(rps as u64).unwrap_or(1);
                Some(interval_ns)
            }
        });
        let clock = Clock::new(clock_source).map_err(io::Error::from)?;
        Ok(Observer {
            listeners: Vec::new(),
            tracker: Tracker::new(tracker_capacity, eviction_policy, eviction_scan_window),
            threshold_ns,
            clock,
            stall_queue: Vec::with_capacity(tracker_capacity),
            stall_cursor: 0,
            next_listener_start: 0,
            last_poll_consumed: false,
            rate_limit_interval_ns,
            rate_limited_total: [0; RATE_LIMIT_N],
            global_rl: GlobalRateLimit::new(global_beat_rate, global_beat_burst),
            last_now_ns: 0,
            clock_regressions: 0,
            clock_jumps_forward: 0,
            allow_cross_namespace: false,
            cross_namespace_drops: 0,
            pid_max: crate::pid_max::read_pid_max(),
            pid_above_max_drops: 0,
            last_pid_max_refresh_ns: 0,
            uds_rcvbuf_bytes: 0,
        })
    }

    /// Allow beats from agents whose kernel-attested PID namespace differs
    /// from the observer's own namespace. Default `false`. Wired from the
    /// `--allow-cross-namespace-agents` CLI flag.
    pub fn with_allow_cross_namespace(mut self, allow: bool) -> Self {
        self.allow_cross_namespace = allow;
        self
    }

    /// Create an observer from a single already-configured listener.
    #[allow(clippy::too_many_arguments)]
    pub fn from_listener<L: BeatListener + 'static>(
        listener: L,
        threshold: Duration,
        tracker_capacity: usize,
        eviction_policy: EvictionPolicy,
        eviction_scan_window: usize,
        max_beat_rate: Option<u32>,
        global_beat_rate: u32,
        global_beat_burst: u32,
        clock_source: ClockSource,
    ) -> io::Result<Self> {
        let mut obs = Self::new(
            threshold,
            tracker_capacity,
            eviction_policy,
            eviction_scan_window,
            max_beat_rate,
            global_beat_rate,
            global_beat_burst,
            clock_source,
        )?;
        obs.add_listener(Box::new(listener));
        Ok(obs)
    }

    /// Bind a Unix datagram socket at `path` and return an [`Observer`]
    /// with that single UDS listener.
    ///
    /// This is the backward-compatible convenience constructor for the common
    /// single-UDS case. For multi-transport setups, use [`Observer::new`]
    /// followed by [`Observer::add_listener`].
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        path: impl AsRef<Path>,
        threshold: Duration,
        socket_mode: u32,
        read_timeout: Duration,
        uds_rcvbuf_bytes: u32,
        tracker_capacity: usize,
        eviction_policy: EvictionPolicy,
        eviction_scan_window: usize,
        max_beat_rate: Option<u32>,
        global_beat_rate: u32,
        global_beat_burst: u32,
        clock_source: ClockSource,
        pre_thread: &PreThreadAttestation,
    ) -> io::Result<Self> {
        let listener = UdsListener::bind(
            path,
            socket_mode,
            read_timeout,
            uds_rcvbuf_bytes,
            pre_thread,
        )?;
        let rcvbuf = listener.rcvbuf_bytes();
        let mut obs = Self::from_listener(
            listener,
            threshold,
            tracker_capacity,
            eviction_policy,
            eviction_scan_window,
            max_beat_rate,
            global_beat_rate,
            global_beat_burst,
            clock_source,
        )?;
        obs.uds_rcvbuf_bytes = rcvbuf;
        Ok(obs)
    }

    /// Add a listener to the observer. The listener is polled in round-robin
    /// order alongside any existing listeners.
    pub fn add_listener(&mut self, listener: Box<dyn BeatListener>) {
        self.listeners.push(listener);
    }

    /// Poll listeners round-robin and return the first [`Event`] found.
    /// Each listener is tried at most once per call, and polling stops as
    /// soon as a returnable event is selected. This preserves the one-event
    /// return contract: later listener datagrams remain queued for later
    /// `poll()` calls instead of being consumed without an exported event.
    /// A busy listener cannot starve others because the round-robin cursor
    /// (`next_listener_start`) advances past the listener that produced the
    /// returned event.
    ///
    /// **Latency bound:** worst-case per-call work is
    /// `N_listeners × per-listener-recv-cost + eviction_scan_window`.
    /// Under the canonical stress profile (3 listeners, 4096 tracker
    /// capacity, 256-slot eviction window) the p99 iteration time is
    /// ≤ 5 ms — see `book/src/architecture/observer-liveness.md` and the
    /// `tick-distribution` bench (`cargo run -p varta-bench --release --
    /// tick-distribution`) which asserts this bound under sustained load.
    ///
    /// This method never returns [`Event::Stall`] — queued stall events must
    /// be retrieved via [`Observer::poll_pending`].
    pub fn poll(&mut self) -> Option<Event> {
        let len = self.listeners.len();
        let start = self.next_listener_start;
        let mut first_event: Option<Event> = None;
        let mut consumed = false;
        let mut round = 0;
        while round < len {
            let i = (start + round) % len;
            round += 1;
            let result = self.listeners[i].recv();
            // Any result other than `WouldBlock` means a datagram was pulled
            // off the socket queue this pass — including the drop paths below
            // that `continue` without yielding an `Event`. Record it so the
            // main loop keeps draining instead of treating a dropped beat as
            // an idle tick (see `last_poll_consumed`).
            if !matches!(result, RecvResult::WouldBlock) {
                consumed = true;
            }
            match result {
                RecvResult::Authenticated {
                    peer_pid,
                    peer_uid: _,
                    peer_pid_ns_inode,
                    peer_pidfd,
                    origin,
                    data,
                } => {
                    let now_ns = self.now_ns();
                    if first_event.is_none() {
                        self.next_listener_start = (i + 1) % len;
                    }
                    match Frame::decode(&data) {
                        Ok(frame) => {
                            // Observer-side PID range gate. VLP rejects 0/1
                            // as wire-format `BadPid`; here we additionally
                            // reject any pid above the kernel's configured
                            // `pid_max` (Linux) — no live process can hold
                            // that id, so the frame is either corrupted or
                            // forged. Non-Linux: `pid_max == u32::MAX`,
                            // gate is a no-op.
                            if frame.pid > self.pid_max {
                                self.pid_above_max_drops =
                                    self.pid_above_max_drops.saturating_add(1);
                                continue;
                            }
                            // Per-datagram PID verification — works on Linux
                            // (SCM_CREDENTIALS via SO_PASSCRED) and macOS
                            // (LOCAL_PEERTOKEN via getsockopt). For transports
                            // without kernel credential support, peer_pid is 0
                            // and this check is a no-op.
                            if peer_pid != 0 && frame.pid != peer_pid {
                                if first_event.is_none() {
                                    first_event = Some(Event::AuthFailure {
                                        claimed_pid: frame.pid,
                                        observer_ns: now_ns,
                                    });
                                }
                                break;
                            }
                            // Capture the slot's pre-record pinned origin (if
                            // any) so an OriginConflict event can report what
                            // the slot was pinned to without an extra lookup
                            // afterwards. Also let higher-trust origins repair
                            // lower-trust preemption before the per-pid limiter
                            // can drop the corrective beat.
                            let slot_origin_before = self.tracker.origin_of(frame.pid);
                            #[cfg(target_os = "linux")]
                            let slot_generation_before = self.tracker.generation_of(frame.pid);
                            let origin_upgrade = match slot_origin_before {
                                Some(pinned) => origin.can_replace(pinned),
                                None => false,
                            };

                            // A panic hook's terminal frame
                            // (`NONCE_TERMINAL`, decode-enforced ⇒ `Critical`)
                            // is the agent's single dying gasp. It almost
                            // always arrives within the per-pid interval of the
                            // last regular beat (the process was beating
                            // normally, then panicked), so the per-pid limiter
                            // below would shed exactly the one beat the tracker
                            // is built never to drop (see
                            // `tracker::record_with_generation`, which records a
                            // terminal frame even when its namespace inode has
                            // already read back `None`). Exempt it from the
                            // per-pid limiter, mirroring `origin_upgrade`.
                            let is_terminal = frame.nonce == NONCE_TERMINAL;
                            let terminal_global_bypass = is_terminal
                                && peer_pid != 0
                                && frame.pid == peer_pid
                                && matches!(
                                    self.tracker.last_observed_nonce_of(frame.pid),
                                    Some(nonce) if nonce != NONCE_TERMINAL
                                );
                            // Per-pid rate limiting is an O(1) tracker lookup
                            // and must run before the global bucket. A
                            // same-pid burst that is already being dropped
                            // must not spend shared global tokens and starve
                            // unrelated agents. Unknown pids fall through to
                            // the global limiter below, preserving the
                            // rotation-attack guard before namespace reads or
                            // tracker insertion.
                            if !origin_upgrade && !is_terminal {
                                if let Some(interval_ns) = self.rate_limit_interval_ns {
                                    if let Some(last_ns) = self.tracker.last_ns_of(frame.pid) {
                                        if now_ns.saturating_sub(last_ns) < interval_ns {
                                            self.rate_limited_total
                                                [RateLimitReason::PerPid as usize] = self
                                                .rate_limited_total
                                                [RateLimitReason::PerPid as usize]
                                                .saturating_add(1);
                                            continue;
                                        }
                                    }
                                }
                            }
                            // Global token bucket: drop BEFORE namespace /
                            // tracker classification so a rotation attack
                            // cannot exhaust namespace reads or insertion
                            // work. One narrow exception is the first
                            // kernel-attested terminal frame after a tracked
                            // non-terminal beat: an unrelated burst must not
                            // erase a dying agent's only Critical signal, but
                            // untracked / UDP terminal traffic and repeated
                            // terminal frames still pay the global bucket.
                            if !terminal_global_bypass && !self.global_rl.try_consume(now_ns) {
                                self.rate_limited_total[RateLimitReason::Global as usize] =
                                    self.rate_limited_total[RateLimitReason::Global as usize]
                                        .saturating_add(1);
                                continue;
                            }
                            // Resolve the peer's PID-namespace inode now —
                            // only AFTER the global rate limiter has admitted
                            // the frame. Resolving it eagerly at recv time
                            // would let a datagram flood force one
                            // readlink(/proc/<pid>/ns/pid) syscall per packet
                            // regardless of the limiter, defeating its stated
                            // purpose of shedding namespace classification work
                            // under a rotation attack. Mirrors the prior
                            // recv-time condition: kernel-attested peers
                            // (`peer_pid != 0`) only; non-UDS transports keep
                            // their `None` (they report `peer_pid == 0`).
                            let (peer_pid_ns_inode, peer_generation) = if peer_pid != 0 {
                                crate::peer_cred::read_peer_identity(peer_pid, peer_pidfd.as_ref())
                            } else {
                                (peer_pid_ns_inode, None)
                            };
                            // Linux recovery safety needs a process-generation
                            // token before a first-contact UDS beat may pin a
                            // recovery-eligible origin. If the sender exits
                            // between recvmsg(2) and the /proc start-time
                            // read, the kernel still attested the numeric PID,
                            // but the tracker cannot distinguish the original
                            // process from a later PID recycle. Keep the beat
                            // observable by tracking it as SocketModeOnly until
                            // a later accepted beat can pin Some(generation)
                            // and upgrade to KernelAttested. Existing pinned
                            // slots are left alone so terminal dying-gasp frames
                            // do not lose their Critical signal when /proc has
                            // already vanished.
                            #[cfg(target_os = "linux")]
                            let origin = if origin == BeatOrigin::KernelAttested
                                && peer_generation.is_none()
                                && slot_generation_before.flatten().is_none()
                            {
                                BeatOrigin::SocketModeOnly
                            } else {
                                origin
                            };
                            // Resolve the peer's process identity
                            // (PID-namespace inode + start-time generation)
                            // alongside the same kernel-attested `peer_pid`.
                            // On Linux 6.5+ the recv layer also supplies a
                            // pidfd; `read_peer_identity` then trusts /proc
                            // only if that pidfd proves the original sender
                            // is still live before and after the reads. This
                            // prevents a fast PID recycle from pinning
                            // namespace/generation metadata from the new
                            // process to a datagram sent by the old one.
                            // Cross-namespace gate (Linux only). When the
                            // kernel-attested peer's PID namespace inode
                            // differs from the observer's, the frame.pid
                            // cannot safely be used to target recovery
                            // commands. The check is a no-op on non-Linux
                            // (both inodes are `None`), for UDP transports
                            // (peer inode is `None`), and when the operator
                            // has opted in via --allow-cross-namespace-agents.
                            let observer_ns_inode =
                                crate::peer_cred::observer_pid_namespace_inode();
                            let cross_ns = matches!(
                                (observer_ns_inode, peer_pid_ns_inode),
                                (Some(a), Some(b)) if a != b
                            );
                            if cross_ns && !self.allow_cross_namespace {
                                self.cross_namespace_drops =
                                    self.cross_namespace_drops.saturating_add(1);
                                if first_event.is_none() {
                                    first_event = Some(Event::NamespaceConflict {
                                        claimed_pid: frame.pid,
                                        observed_ns_inode: peer_pid_ns_inode,
                                        observer_ns_inode,
                                        observer_ns: now_ns,
                                    });
                                }
                                break;
                            }
                            match self.tracker.record_with_generation(
                                &frame,
                                now_ns,
                                self.threshold_ns,
                                origin,
                                peer_pid_ns_inode,
                                peer_generation,
                            ) {
                                Update::Inserted | Update::Refreshed => {
                                    if first_event.is_none() {
                                        first_event = Some(Event::Beat {
                                            pid: frame.pid,
                                            status: frame.status,
                                            payload: frame.payload,
                                            nonce: frame.nonce,
                                            origin,
                                            pid_ns_inode: peer_pid_ns_inode,
                                            observer_ns: now_ns,
                                        });
                                    }
                                }
                                Update::OriginConflict => {
                                    if first_event.is_none() {
                                        first_event = Some(Event::OriginConflict {
                                            claimed_pid: frame.pid,
                                            observed_origin: origin,
                                            slot_origin: slot_origin_before.unwrap_or(origin),
                                            observer_ns: now_ns,
                                        });
                                    }
                                }
                                Update::NamespaceConflict => {
                                    if first_event.is_none() {
                                        first_event = Some(Event::NamespaceConflict {
                                            claimed_pid: frame.pid,
                                            observed_ns_inode: peer_pid_ns_inode,
                                            observer_ns_inode,
                                            observer_ns: now_ns,
                                        });
                                    }
                                }
                                Update::OutOfOrder | Update::CapacityExceeded => {}
                            }
                        }
                        Err(e) => {
                            if first_event.is_none() {
                                first_event = Some(Event::Decode(e, now_ns));
                            }
                        }
                    }
                }
                RecvResult::WouldBlock => continue,
                RecvResult::ShortRead => continue,
                RecvResult::CtrlTruncated(e) => {
                    if first_event.is_none() {
                        self.next_listener_start = (i + 1) % len;
                        first_event = Some(Event::CtrlTruncated(e, self.now_ns()));
                    }
                }
                RecvResult::IoError(e) => {
                    if first_event.is_none() {
                        self.next_listener_start = (i + 1) % len;
                        first_event = Some(Event::Io(e, self.now_ns()));
                    }
                }
            }
            if first_event.is_some() {
                break;
            }
        }
        self.last_poll_consumed = consumed;
        self.drain_stalls();
        first_event
    }

    /// Return the next queued [`Event::Stall`], if any.
    pub fn poll_pending(&mut self) -> Option<Event> {
        if self.stall_cursor < self.stall_queue.len() {
            let stall = self.stall_queue[self.stall_cursor].take();
            self.stall_cursor += 1;
            return stall;
        }
        None
    }

    /// Whether the stall queue has unconsumed [`Event::Stall`] entries.
    pub fn has_pending_stalls(&self) -> bool {
        self.stall_cursor < self.stall_queue.len()
    }

    /// Re-validate the queued stall for `pid` immediately before recovery
    /// fires. A stall deferred across ticks by the per-tick spawn budget (a
    /// mass simultaneous stall exceeding `RECOVERY_SPAWN_MAX_PER_TICK`) must
    /// not fire if, inside the deferral window, the agent resumed beating
    /// ([`StallFreshness::AgentResumed`]) or its PID was recycled to a
    /// different process ([`StallFreshness::PidRecycled`]) — either would
    /// kill/restart an innocent process. `generation` is the start-time token
    /// carried on the queued `Event::Stall`.
    pub fn stall_freshness(&self, pid: u32, generation: Option<u64>) -> StallFreshness {
        self.tracker.stall_freshness(pid, generation)
    }

    /// Whether the most recent [`Observer::poll`] dequeued at least one
    /// datagram (see the `last_poll_consumed` field). Returns `true` even
    /// when every dequeued datagram was dropped without yielding an `Event`
    /// (rate-limited, short, cross-namespace, above `pid_max`). The main loop
    /// uses this to skip the idle throttle sleep while the socket may still
    /// hold queued beats, so a flood of dropped traffic cannot starve real
    /// beats one 10 ms sleep at a time.
    pub fn last_poll_consumed(&self) -> bool {
        self.last_poll_consumed
    }

    /// Observer-local nanosecond timestamp (ns since [`Observer`] start).
    ///
    /// Clamped to never decrease — on some platforms (VMs with TSC drift,
    /// live-migration pause-and-resume), the underlying clock can produce
    /// values that appear to go backwards. Without clamping, a forward clock
    /// jump after a backward excursion can cause false stall detections.
    ///
    /// The kernel clock backing this reading is selected via
    /// [`crate::clock::ClockSource`] (`--clock-source` CLI flag); see
    /// `book/src/architecture/safety-profiles.md` for the SRE vs. medical
    /// deployment matrix.
    pub fn now_ns(&mut self) -> u64 {
        let raw = self.clock.now_ns();
        self.apply_raw_clock(raw)
    }

    fn apply_raw_clock(&mut self, raw: u64) -> u64 {
        if raw < self.last_now_ns {
            self.clock_regressions = self.clock_regressions.saturating_add(1);
        } else if self.last_now_ns > 0
            && raw.saturating_sub(self.last_now_ns) > CLOCK_JUMP_FORWARD_THRESHOLD_NS
        {
            self.clock_jumps_forward = self.clock_jumps_forward.saturating_add(1);
        }
        self.last_now_ns = self.last_now_ns.max(raw);
        self.last_now_ns
    }

    /// Feed a synthetic raw clock value directly, bypassing `self.clock`.
    /// Only available in tests; allows forward-jump and regression scenarios
    /// without waiting for real time to advance.
    #[cfg(test)]
    pub(crate) fn apply_raw_clock_test(&mut self, raw: u64) -> u64 {
        self.apply_raw_clock(raw)
    }

    /// Drain and reset the clock-regression counter — number of times the
    /// kernel monotonic clock returned a value strictly less than the
    /// previously observed one and the forward clamp absorbed the
    /// regression. Non-zero values surface TSC drift, VM live migration,
    /// or other anomalous clock behavior that would otherwise be invisible.
    /// Surfaced as `varta_observer_clock_regression_total`.
    pub fn drain_clock_regressions(&mut self) -> u64 {
        let n = self.clock_regressions;
        self.clock_regressions = 0;
        n
    }

    /// Drain and reset the forward-jump counter — number of times the kernel
    /// monotonic clock advanced by more than [`CLOCK_JUMP_FORWARD_THRESHOLD_NS`]
    /// between adjacent poll ticks. Non-zero values indicate sleep/wake on
    /// `monotonic-raw`/`boottime`, VM live migration, or a hypervisor pause.
    /// Surfaced as `varta_observer_clock_jump_forward_total`.
    pub fn drain_clock_jumps_forward(&mut self) -> u64 {
        let n = self.clock_jumps_forward;
        self.clock_jumps_forward = 0;
        n
    }

    /// Inspect the kernel clock backing this observer's stall accounting.
    pub fn clock_source(&self) -> ClockSource {
        self.clock.source()
    }

    fn drain_stalls(&mut self) {
        if self.stall_cursor < self.stall_queue.len() {
            return;
        }
        let now_ns = self.now_ns();
        self.stall_queue.clear();
        self.stall_cursor = 0;
        self.tracker.drain_stalled_slots(
            now_ns,
            self.threshold_ns,
            |pid, last_nonce, last_ns, origin, pid_ns_inode, generation| {
                self.stall_queue.push(Some(Event::Stall {
                    pid,
                    last_nonce,
                    last_ns,
                    origin,
                    pid_ns_inode,
                    generation,
                    observer_ns: now_ns,
                }));
            },
        );
    }

    /// Drain and reset the eviction counter.
    pub fn drain_evictions(&mut self) -> u64 {
        self.tracker.take_evictions()
    }

    /// Drain one pid whose tracker slot was removed, if any.
    ///
    /// Covers capacity evictions and generation-mismatch retirements. The
    /// main loop drains this to remove stale per-pid exporter rows.
    pub fn drain_evicted_pid(&mut self) -> Option<u32> {
        self.tracker.take_evicted_pid()
    }

    /// Drain and reset the capacity-exceeded counter.
    pub fn drain_capacity_exceeded(&mut self) -> u64 {
        self.tracker.take_capacity_exceeded()
    }

    /// Drain and reset the nonce-wrap counter.
    pub fn drain_nonce_wraps(&mut self) -> u64 {
        self.tracker.take_nonce_wraps()
    }

    /// Drain and reset the count of bounded eviction-scan calls that ran
    /// the full [`crate::tracker::EVICTION_SCAN_WINDOW`] without finding a
    /// victim. Non-zero values prove the per-frame work cap engaged — i.e.
    /// the tracker was full and an attacker would otherwise have forced
    /// O(n) work per arriving frame.
    pub fn drain_eviction_scan_truncated(&mut self) -> u64 {
        self.tracker.take_eviction_scan_truncated()
    }

    /// Drain and reset the per-tracker origin-conflict counter — number of
    /// beats dropped because their transport origin was weaker than the
    /// slot's pinned origin. Surfaced as
    /// `varta_origin_conflict_total` in the Prometheus exporter.
    pub fn drain_origin_conflicts(&mut self) -> u64 {
        self.tracker.take_origin_conflicts()
    }

    /// Drain and reset the count of beats dropped at ingress because the
    /// peer's PID-namespace inode differs from the observer's. Surfaced as
    /// `varta_frame_namespace_mismatch_total` in the Prometheus exporter.
    pub fn drain_cross_namespace_drops(&mut self) -> u64 {
        let n = self.cross_namespace_drops;
        self.cross_namespace_drops = 0;
        n
    }

    /// Drain and reset the count of beats dropped at ingress because
    /// `frame.pid` exceeded the kernel's configured `pid_max`. Surfaced as
    /// `varta_frame_rejected_pid_above_max_total` in the Prometheus
    /// exporter. Linux-only signal; 0 on platforms where the gate defaults
    /// to `u32::MAX`.
    pub fn drain_pid_above_max_drops(&mut self) -> u64 {
        let n = self.pid_above_max_drops;
        self.pid_above_max_drops = 0;
        n
    }

    /// Observer's cached `pid_max`. Linux-only meaningful value; otherwise
    /// `u32::MAX`. Exposed for tests and for the Prometheus exporter's
    /// gauge.
    pub fn pid_max(&self) -> u32 {
        self.pid_max
    }

    /// Re-read `/proc/sys/kernel/pid_max` if at least
    /// [`PID_MAX_REFRESH_INTERVAL_NS`] has elapsed since the last refresh.
    /// Cheap no-op otherwise (single `u64` compare).
    ///
    /// Intended to be called from the daemon's maintenance phase — *not*
    /// from `poll()` — so the I/O hot path stays untouched. Picks up
    /// runtime `sysctl -w kernel.pid_max=...` changes within one interval.
    /// On non-Linux targets, [`crate::pid_max::read_pid_max`] returns
    /// `u32::MAX` so the gate stays effectively disabled and this method
    /// is a steady no-op.
    ///
    /// Returns `true` when a refresh actually ran this call (regardless of
    /// whether the read value changed), `false` when gated by the interval.
    pub fn maybe_refresh_pid_max(&mut self) -> bool {
        let now_ns = self.now_ns();
        if now_ns.saturating_sub(self.last_pid_max_refresh_ns) < PID_MAX_REFRESH_INTERVAL_NS {
            return false;
        }
        self.pid_max = crate::pid_max::read_pid_max();
        self.last_pid_max_refresh_ns = now_ns;
        true
    }

    /// Drain and reset the per-tracker namespace-conflict counter — beats
    /// dropped because the beat's namespace inode disagreed with the slot's
    /// pinned namespace inode (first-namespace-wins). Surfaced as
    /// `varta_tracker_namespace_conflict_total`.
    pub fn drain_namespace_conflicts(&mut self) -> u64 {
        self.tracker.take_namespace_conflicts()
    }

    /// Drain and reset the per-tracker PID-recycle counter — stale slot
    /// identities reset or retired because a kernel-attested process
    /// generation (start-time) mismatch proved the pid had been recycled to a
    /// new process. Surfaced as `varta_tracker_pid_recycle_total`.
    pub fn drain_pid_recycles(&mut self) -> u64 {
        self.tracker.take_pid_recycles()
    }

    /// Observer's own PID-namespace inode (Linux only; cached). Used by
    /// `main.rs` to construct recovery `StallSource` values that include
    /// the observer's namespace for the audit record.
    pub fn observer_pid_namespace_inode(&self) -> Option<u64> {
        crate::peer_cred::observer_pid_namespace_inode()
    }

    /// Drain and reset the tracker invariant-violation counter. Non-zero
    /// values surface that a defensive fall-through in the hot path
    /// triggered (e.g. a stale `PidIndex` entry pointed at an out-of-range
    /// slot). Exposed as `varta_tracker_invariant_violations_total`.
    pub fn drain_invariant_violations(&mut self) -> u64 {
        self.tracker.take_invariant_violations()
    }

    /// Drain and reset the `PidIndex` probe-exhaustion counter — number of
    /// times a pid lookup ran the full `MAX_PROBE` budget without finding
    /// a match. Surfaced as `varta_tracker_pid_index_probe_exhausted_total`.
    pub fn drain_pid_index_probe_exhausted(&mut self) -> u64 {
        self.tracker.take_probe_exhausted()
    }

    /// Drain and reset the per-pid rate-limited counter.
    pub fn drain_per_pid_rate_limited(&mut self) -> u64 {
        let n = self.rate_limited_total[RateLimitReason::PerPid as usize];
        self.rate_limited_total[RateLimitReason::PerPid as usize] = 0;
        n
    }

    /// Drain and reset the global rate-limited counter.
    pub fn drain_global_rate_limited(&mut self) -> u64 {
        let n = self.rate_limited_total[RateLimitReason::Global as usize];
        self.rate_limited_total[RateLimitReason::Global as usize] = 0;
        n
    }

    /// Effective `SO_RCVBUF` size granted by the kernel for the observer UDS.
    pub fn uds_rcvbuf_bytes(&self) -> u32 {
        self.uds_rcvbuf_bytes
    }

    /// Drain and reset the AEAD decryption failure counter across all
    /// listeners.
    pub fn drain_decrypt_failures(&mut self) -> u64 {
        self.listeners
            .iter_mut()
            .map(|l| l.drain_decrypt_failures())
            .sum()
    }

    /// Drain and reset the truncated-datagram counter across all listeners.
    pub fn drain_truncated(&mut self) -> u64 {
        self.listeners.iter_mut().map(|l| l.drain_truncated()).sum()
    }

    /// Drain and reset the sender-state-full counter across all listeners.
    pub fn drain_sender_state_full(&mut self) -> u64 {
        self.listeners
            .iter_mut()
            .map(|l| l.drain_sender_state_full())
            .sum()
    }

    /// Drain and reset the AEAD-decryption-attempt counter across all
    /// listeners. In steady state this equals
    /// `frames_received * (keys.len() + master_key_configured as u64)` for
    /// the secure-UDP listener — every loaded key is tried per frame to
    /// remove the key-rotation timing side-channel.
    pub fn drain_aead_attempts(&mut self) -> u64 {
        self.listeners
            .iter_mut()
            .map(|l| l.drain_aead_attempts())
            .sum()
    }

    /// Drain and reset the parent-directory fsync failure counter for UDS
    /// bind.  Non-zero only when the OS returned an error from `fsync(2)` on
    /// the socket's parent directory during startup.  Surfaced as
    /// `varta_socket_bind_dir_fsync_failed_total`.
    pub fn drain_bind_dir_fsync_failures() -> u64 {
        crate::listener::drain_bind_dir_fsync_failures()
    }
}

#[cfg(test)]
mod tests;
