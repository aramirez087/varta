//! Per-pid liveness tracker backed by a pre-allocated `Vec<Slot>` plus a
//! fixed-size, open-addressed [`PidIndex`] for O(1) pid lookup.
//!
//! The tracker is the in-memory ledger the observer consults each time a
//! frame arrives or the read timeout expires. It never reallocates: capacity
//! is fixed at construction, the pid-index table is sized for load factor
//! ≤ 0.5 with a bounded probe budget ([`PidIndex::MAX_PROBE`]), and an
//! exhausted tracker yields [`Update::CapacityExceeded`] rather than growing.
//!
//! The custom pid index replaces `std::collections::HashMap` for two
//! DO-178C-style reasons: (1) `HashMap` uses SipHash randomized per process,
//! producing a non-constant memory access pattern that defeats WCET
//! analysis, and (2) it can rehash on collision-driven growth. `PidIndex`
//! uses a deterministic integer mixer (Murmur3 finalizer) and linear
//! probing with a fixed budget, so every operation has a tight WCET bound.

use varta_vlp::{Frame, Status, NONCE_TERMINAL};

use crate::peer_cred::BeatOrigin;

/// Maximum number of distinct agents the observer can track concurrently.
///
/// v0.2.0 raises this from 64 to 256. Override via `--tracker-capacity`.
pub const DEFAULT_CAPACITY: usize = 256;

/// Hard upper bound for `--tracker-capacity`. The tracker uses a linear scan
/// over active slots; at capacities exceeding this value the scan becomes a
/// latency spike risk in the observer poll loop.
pub const MAX_CAPACITY: usize = 4096;

/// Multiplier applied to the stall threshold when choosing eviction victims.
///
/// A slot is only evictable if (a) the observer has already surfaced a stall
/// event for its pid (`stall_emitted == true`) **and** (b) the silence duration
/// exceeds `threshold * EVICTION_MULTIPLIER`. The 10× multiplier ensures that
/// only agents which have been silent for **significantly** longer than the
/// stall threshold are evicted — a slow-beating but alive agent (e.g. every
/// 40 s with a 5 s threshold) will not be evicted because it resets
/// `stall_emitted` on every beat.
const EVICTION_MULTIPLIER: u32 = 10;

/// Default maximum number of slots scanned per [`Tracker::find_evictable_slot`] call.
///
/// The eviction scan used to be O(`len`) — at [`MAX_CAPACITY`] = 4096 that
/// meant up to 4096 slot reads on **every** new-pid frame once the table was
/// full. An attacker who could send beats from many unique pids could
/// therefore force O(n) work per arriving frame on the single-threaded
/// observer poll loop.
///
/// The scan is now bounded to `Tracker::eviction_scan_window` (configurable
/// via `--eviction-scan-window`, defaulting to this constant), with a rotating
/// cursor ([`Tracker::eviction_scan_cursor`]) that resumes where the previous
/// call left off. A full sweep takes `ceil(capacity / eviction_scan_window)`
/// consecutive calls. First-fit eviction inside the window is correct under
/// capacity pressure (any slot whose silence exceeds
/// `threshold * EVICTION_MULTIPLIER` is a valid victim — they are by
/// definition not actively beating).
///
/// 256 was chosen as a compromise: large enough that a single call typically
/// finds a victim on tables of 1–2 k pids, small enough that the per-frame
/// upper bound stays well under the existing observer-tick budget.
pub const DEFAULT_EVICTION_SCAN_WINDOW: usize = 256;

/// Minimum allowed value for `--eviction-scan-window`. Window = 1 is
/// degenerate but correct; only window = 0 breaks the algorithm.
pub const MIN_EVICTION_SCAN_WINDOW: usize = 1;

/// Maximum allowed value for `--eviction-scan-window`. Capped at
/// [`MAX_CAPACITY`] so a table scan in one call is bounded by the maximum
/// tracker size.
pub const MAX_EVICTION_SCAN_WINDOW: usize = MAX_CAPACITY;

/// Threshold for nonce wrap detection. When the tracker's `last_nonce` for a
/// pid is within this distance of `u64::MAX` and an incoming frame carries a
/// nonce below this threshold, the tracker treats the gap as a nonce-space
/// wrap (agent exhausted u64 nonces and looped to 0) rather than an
/// out-of-order beat. The threshold is 2^20 (~1M); at 1M beats/sec the agent
/// would take days to exhaust the nonce space, so a genuine gap this large
/// can only be a wrap.
const NONCE_WRAP_THRESHOLD: u64 = 1_048_576;

mod pid_index;
pub(crate) use pid_index::PidIndex;

/// Controls which slot to reclaim when the tracker is at capacity and a
/// new pid arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictionPolicy {
    /// Only evict slots that have already been surfaced as stalled and
    /// have been silent for > `threshold * EVICTION_MULTIPLIER`. This is
    /// the safest choice — a correctly-beating agent is never evicted,
    /// but a capacity-exhaustion attack can cause `CapacityExceeded`.
    Strict,
    /// Like `Strict`, but when no strictly-evictable slot exists, falls
    /// back to evicting the oldest active slot (by `last_ns`) whose
    /// silence exceeds `threshold * EVICTION_MULTIPLIER`. This prevents
    /// `CapacityExceeded` completely at the expense of potentially
    /// evicting a slow-but-alive agent during a flood.
    Balanced,
}

/// Liveness slot for a single agent pid.
///
/// `Slot` is internal to the observer and never crosses the wire, so it uses
/// the default Rust repr (lets the compiler tighten field order). The
/// `stall_emitted` latch is private: it tracks whether the observer has
/// already surfaced an [`crate::observer::Event::Stall`] for the current
/// silence run, so a stalled pid raises the event exactly once and then stays
/// silent until a fresh beat resets it.
#[derive(Clone, Copy, Debug)]
pub struct Slot {
    /// OS process id of the tracked agent.
    pub(crate) pid: u32,
    /// Most recent non-terminal nonce accepted from this pid.
    ///
    /// Panic-hook terminal frames carry `NONCE_TERMINAL`; storing that
    /// sentinel here would poison the regular nonce high-water mark and make
    /// later healthy beats look out-of-order. `has_regular_nonce` marks
    /// whether this field is initialized for slots first created by a
    /// terminal frame.
    pub(crate) last_nonce: u64,
    /// True iff `last_nonce` contains an accepted regular-beat nonce.
    pub(crate) has_regular_nonce: bool,
    /// Most recent accepted wire nonce, including `NONCE_TERMINAL`.
    ///
    /// Used only for stall telemetry. Regular monotonicity checks use
    /// `last_nonce` + `has_regular_nonce`.
    pub(crate) last_observed_nonce: u64,
    /// Highest accepted timestamp for a terminal panic frame.
    ///
    /// Terminal frames all use the same nonce sentinel, so timestamp is the
    /// only frame-local ordering signal available to reject terminal replays
    /// without blocking later regular beats.
    pub(crate) last_terminal_timestamp: Option<u64>,
    /// Observer-local timestamp (nanoseconds since [`crate::observer::Observer`]
    /// start) of the last accepted beat for this pid.
    pub(crate) last_ns: u64,
    /// Most recent [`Status`] reported by this pid.
    pub(crate) status: Status,
    /// Strongest transport origin accepted for this pid. Used to gate
    /// recovery-eligibility. Weaker conflicting origins are rejected as
    /// [`Update::OriginConflict`]; stronger origins replace weaker preemption
    /// attempts. See [`BeatOrigin`] for the trust model.
    pub(crate) origin: BeatOrigin,
    /// PID-namespace inode pinned at the slot's first beat (Linux only).
    ///
    /// `None` on non-Linux platforms, for UDP transports (no kernel attestation),
    /// or when `/proc/<peer_pid>/ns/pid` was unreadable at first contact. A
    /// later beat carrying a different `Some(_)` namespace inode for the same
    /// pid is rejected as [`Update::NamespaceConflict`] without mutating the
    /// slot. A `None → Some(_)` upgrade is permitted exactly once — it
    /// represents a peer whose namespace became readable after a transient
    /// failure (e.g. peer died briefly between `recvmsg` and `readlink`).
    pub(crate) pid_ns_inode: Option<u64>,
    /// Process *generation* token pinned at the slot's first beat — the
    /// kernel-attested process start-time (Linux `/proc/<pid>/stat` field 22;
    /// see [`crate::peer_cred::read_pid_start_time`]).
    ///
    /// `None` on non-Linux, for UDP transports (no kernel attestation), or
    /// when `/proc/<peer_pid>/stat` was unreadable. A later beat carrying a
    /// **different** `Some(_)` generation for the same pid means the OS
    /// recycled the PID to a new process: the slot is reset to a fresh agent
    /// rather than inheriting the dead process's nonce baseline / origin /
    /// silence timer. `None` on either side is "generation unknown" and is
    /// treated leniently (first-wins, never a recycle signal) — mirroring
    /// [`Slot::pid_ns_inode`].
    pub(crate) generation: Option<u64>,
    /// False iff this slot has never been written; observers treat the
    /// slot's other fields as undefined when `used == false`.
    pub(crate) used: bool,
    /// True iff the observer has already emitted a stall event for the
    /// current silence run. Cleared when a fresh beat arrives.
    pub(crate) stall_emitted: bool,
}

impl Slot {
    fn from_frame(
        frame: &Frame,
        now_ns: u64,
        status: Status,
        origin: BeatOrigin,
        peer_pid_ns_inode: Option<u64>,
        peer_generation: Option<u64>,
    ) -> Self {
        let is_terminal = frame.nonce == NONCE_TERMINAL;
        Slot {
            pid: frame.pid,
            last_nonce: if is_terminal { 0 } else { frame.nonce },
            has_regular_nonce: !is_terminal,
            last_observed_nonce: frame.nonce,
            last_terminal_timestamp: if is_terminal {
                Some(frame.timestamp)
            } else {
                None
            },
            last_ns: now_ns,
            status,
            origin,
            pid_ns_inode: peer_pid_ns_inode,
            generation: peer_generation,
            used: true,
            stall_emitted: false,
        }
    }

    fn clear_stall_emitted(&mut self) -> bool {
        if self.stall_emitted {
            self.stall_emitted = false;
            true
        } else {
            false
        }
    }

    fn refresh_terminal(&mut self, frame: &Frame, now_ns: u64, status: Status) -> bool {
        match self.last_terminal_timestamp {
            Some(last) if frame.timestamp <= last => return false,
            _ => {}
        }
        self.last_terminal_timestamp = Some(frame.timestamp);
        self.last_observed_nonce = frame.nonce;
        self.last_ns = now_ns;
        self.status = status;
        true
    }

    fn refresh_regular(&mut self, frame: &Frame, now_ns: u64, status: Status) -> RegularRefresh {
        if self.has_regular_nonce && frame.nonce <= self.last_nonce {
            // Detect nonce wrap: agent exhausted u64 nonce space and looped
            // to 0. last_nonce is near u64::MAX and the incoming nonce is
            // near 0, a gap too large to be a genuine out-of-order beat.
            let wrap_lo = NONCE_WRAP_THRESHOLD;
            let wrap_hi = u64::MAX.saturating_sub(NONCE_WRAP_THRESHOLD);
            if self.last_nonce >= wrap_hi && frame.nonce <= wrap_lo {
                self.last_nonce = frame.nonce;
                self.has_regular_nonce = true;
                self.last_observed_nonce = frame.nonce;
                self.last_ns = now_ns;
                self.status = status;
                return RegularRefresh::Wrapped;
            }
            return RegularRefresh::OutOfOrder;
        }
        self.last_nonce = frame.nonce;
        self.has_regular_nonce = true;
        self.last_observed_nonce = frame.nonce;
        self.last_ns = now_ns;
        self.status = status;
        RegularRefresh::Accepted
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegularRefresh {
    Accepted,
    Wrapped,
    OutOfOrder,
}

/// Result of [`Tracker::record`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Update {
    /// The frame's pid was new and a fresh slot was allocated for it.
    Inserted,
    /// An existing slot was updated with the new nonce / timestamp / status.
    Refreshed,
    /// The frame's nonce was not strictly greater than the slot's last
    /// observed nonce; the slot was left untouched.
    OutOfOrder,
    /// The tracker is full and the frame's pid is not yet known. The slot
    /// table was not modified.
    CapacityExceeded,
    /// A beat arrived for a pid that is already tracked, but the beat's
    /// transport origin is weaker than the origin pinned by the slot. The
    /// slot is **not** mutated and the beat is dropped.
    OriginConflict,
    /// A beat arrived for a pid that is already tracked, but the beat's
    /// kernel-attested PID-namespace inode disagrees with the inode pinned
    /// by the slot's first beat (Linux only — see
    /// [`crate::peer_cred::read_pid_namespace_inode`]). First-namespace-wins:
    /// the slot is **not** mutated and the beat is dropped. Catches the
    /// PID-collision case where two containers happen to share a numeric pid
    /// value (e.g. PID 1 in container A vs PID 1 in container B); the
    /// existing `frame.pid == peer_pid` gate at the observer fires first for
    /// most cross-namespace traffic, but a same-pid-different-namespace
    /// collision is invisible to that gate.
    NamespaceConflict,
}

/// Verdict from the deferred-stall fire-time freshness re-check.
///
/// A stall queued by `drain_stalled_slots` may sit on the recovery queue
/// across several ticks: a mass simultaneous stall enqueues more events than
/// `RECOVERY_SPAWN_MAX_PER_TICK` can fire in one `DrainPending` stage, so the
/// remainder is deferred. The observer re-checks each stall at fire time —
/// *both* failure modes below mean "do not fire", but they are operationally
/// distinct and counted under separate metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StallFreshness {
    /// The slot is present, used, still silence-latched, and the PID still
    /// names the same process. Fire recovery.
    Warranted,
    /// The agent resumed beating (any accepted beat clears `stall_emitted`) or
    /// the slot was evicted/retired since the stall was queued. A benign
    /// self-heal — firing now would kill/restart a process that recovered
    /// inside the deferral window.
    AgentResumed,
    /// The PID was recycled to a *different* process inside the deferral
    /// window. The new occupant never beat (else `stall_emitted` would have
    /// cleared), so the slot is still silence-latched yet its pinned start-time
    /// generation no longer matches the live process — the numeric PID now
    /// names an innocent bystander. Firing recovery's `{pid}`-substituted
    /// `kill(2)`/`systemctl restart` would target it.
    PidRecycled,
    /// The slot is recovery-eligible (`KernelAttested`) and still
    /// silence-latched, but it carries **no** start-time generation, so a PID
    /// recycle inside the deferral window cannot be ruled out. This happens on
    /// credential-passing platforms without `/proc` —
    /// FreeBSD/DragonFly/NetBSD/illumos/Solaris — where the kernel attests the
    /// sender PID (minting `KernelAttested`) but [`crate::peer_cred::read_pid_start_time`]
    /// always returns `None`. On Linux a `KernelAttested` slot always carries a
    /// generation (recovery authority requires complete identity), so this arm
    /// is unreachable there. Treated as a safety skip — firing a deferred
    /// recovery we cannot prove fresh risks killing a recycled bystander, the
    /// same harm [`Self::PidRecycled`] guards against, only here the recycle is
    /// *unverifiable* rather than *confirmed*.
    UnverifiableGeneration,
}

/// Bounded per-pid liveness ledger.
///
/// The slot table is a `Vec<Slot>` pre-allocated at construction to the
/// configured capacity; subsequent inserts push into that pre-allocated
/// space without reallocation.  Lookups use a fixed-size [`PidIndex`] for
/// O(1) pid-to-index mapping — replaces the original `HashMap` so the hot
/// path is WCET-bounded (deterministic hash, bounded probe budget, no
/// rehashing on growth).
pub struct Tracker {
    entries: Vec<Slot>,
    len: usize,
    pid_to_index: PidIndex,
    evictions: u64,
    capacity_exceeded: u64,
    nonce_wraps: u64,
    removed_pids: Vec<u32>,
    eviction_policy: EvictionPolicy,
    /// Cached count of slots whose `stall_emitted` flag is currently set.
    ///
    /// Allows [`Tracker::find_evictable_slot`] to skip the strict scan
    /// entirely when no slots have surfaced a stall yet — defangs the most
    /// realistic DoS profile where an attacker fills the tracker faster
    /// than the stall threshold can elapse.
    stall_emitted_count: usize,
    /// Maximum slots inspected per [`Tracker::scan_window`] call.
    /// Configurable via `--eviction-scan-window`; defaults to
    /// [`DEFAULT_EVICTION_SCAN_WINDOW`]. A full table sweep takes
    /// `ceil(len / eviction_scan_window)` consecutive calls.
    eviction_scan_window: usize,
    /// Round-robin cursor into `entries` for the bounded eviction scan.
    /// Persists across `find_evictable_slot` calls so a sequence of N
    /// failed evictions covers the whole table in
    /// `ceil(len / eviction_scan_window)` calls without ever scanning more
    /// than `eviction_scan_window` slots in a single call.
    eviction_scan_cursor: usize,
    /// Number of times the bounded eviction scan reached its window cap
    /// without finding a victim while the table was full. Surfaced via
    /// [`Tracker::take_eviction_scan_truncated`] for Prometheus.
    eviction_scan_truncated: u64,
    /// Count of beats dropped because their transport origin was weaker than
    /// the slot's pinned origin. Surfaced via
    /// [`Tracker::take_origin_conflicts`] for Prometheus.
    origin_conflicts: u64,
    /// Count of beats dropped because their kernel-attested PID-namespace
    /// inode disagreed with the slot's pinned namespace (first-namespace-wins).
    /// Surfaced via [`Tracker::take_namespace_conflicts`] for Prometheus.
    namespace_conflicts: u64,
    /// Count of stale slot identities retired or reset because a
    /// kernel-attested process generation (start-time) mismatch proved the
    /// slot's PID had been recycled to a new process. Surfaced via
    /// [`Tracker::take_pid_recycles`] for Prometheus; a non-zero value is the
    /// operator's signal that PID reuse is occurring and that stale slot state
    /// did not drive recovery against the recycled process.
    pid_recycles: u64,
    /// Count of internal invariant violations encountered on the hot path —
    /// e.g. a [`PidIndex`] entry pointed at a slot index outside `entries`,
    /// or `find_evictable_slot` returned a stale index. Each violation is
    /// recovered defensively (the operation behaves as a miss or as
    /// [`Update::CapacityExceeded`]) rather than panicking. Surfaced via
    /// [`Tracker::take_invariant_violations`] for Prometheus so operators
    /// can alert on a non-zero value — in correctly-operating code this
    /// counter stays at 0 forever.
    invariant_violations: u64,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new(
            DEFAULT_CAPACITY,
            EvictionPolicy::Strict,
            DEFAULT_EVICTION_SCAN_WINDOW,
        )
    }
}

impl Tracker {
    /// Create an empty tracker with capacity for `capacity` pids.
    ///
    /// The slot table is pre-allocated to `capacity` entries; pushing
    /// beyond that boundary yields [`Update::CapacityExceeded`] rather
    /// than reallocating.
    ///
    /// `eviction_scan_window` caps the number of slots inspected per
    /// eviction attempt. Values outside
    /// `[MIN_EVICTION_SCAN_WINDOW, MAX_EVICTION_SCAN_WINDOW]` are clamped
    /// as defense in depth; the config layer rejects out-of-range values
    /// loudly at startup.
    pub fn new(
        capacity: usize,
        eviction_policy: EvictionPolicy,
        eviction_scan_window: usize,
    ) -> Self {
        let cap = capacity.min(MAX_CAPACITY);
        let window = eviction_scan_window.clamp(MIN_EVICTION_SCAN_WINDOW, MAX_EVICTION_SCAN_WINDOW);
        Tracker {
            entries: Vec::with_capacity(cap),
            len: 0,
            pid_to_index: PidIndex::new(cap),
            evictions: 0,
            capacity_exceeded: 0,
            nonce_wraps: 0,
            removed_pids: Vec::with_capacity(cap),
            eviction_policy,
            stall_emitted_count: 0,
            eviction_scan_window: window,
            eviction_scan_cursor: 0,
            eviction_scan_truncated: 0,
            origin_conflicts: 0,
            namespace_conflicts: 0,
            pid_recycles: 0,
            invariant_violations: 0,
        }
    }

    /// Record a frame against the tracker.
    ///
    /// Uses bounded `PidIndex` lookup to find the slot for `frame.pid`.
    /// Returns [`Update::Inserted`] for a brand-new pid, [`Update::Refreshed`]
    /// for an existing pid whose nonce moved forward, [`Update::OutOfOrder`]
    /// if the nonce did not strictly increase, [`Update::CapacityExceeded`]
    /// if the slot table is full (and no stale slot could be reclaimed) and
    /// the pid is not yet tracked, or [`Update::OriginConflict`] if the
    /// frame's transport origin disagrees with the slot's pinned origin.
    ///
    /// `origin` is the transport-class classification surfaced by the
    /// receiving listener (`KernelAttested` for UDS, `NetworkUnverified` for
    /// any UDP variant). The first beat for a pid pins the slot's origin;
    /// subsequent beats from a different origin are dropped without
    /// mutating the slot.
    ///
    /// `peer_pid_ns_inode` is the kernel-attested PID-namespace inode of the
    /// sending process (Linux only; `None` on non-Linux or when
    /// `/proc/<peer_pid>/ns/pid` was unreadable). The first beat pins the
    /// slot's namespace inode; a later beat carrying a different `Some(_)`
    /// inode for the same pid is rejected as [`Update::NamespaceConflict`].
    /// A `None → Some(_)` upgrade is permitted (peer became readable after a
    /// transient failure); a `Some(_) → None` regression is treated as a
    /// conflict.
    pub fn record(
        &mut self,
        frame: &Frame,
        now_ns: u64,
        threshold_ns: u64,
        origin: BeatOrigin,
        peer_pid_ns_inode: Option<u64>,
    ) -> Update {
        // Back-compat shim: callers without a kernel-attested process
        // generation (tests, non-UDS paths) get the prior PID-only identity
        // (`peer_generation = None` disables recycle detection).
        self.record_with_generation(frame, now_ns, threshold_ns, origin, peer_pid_ns_inode, None)
    }

    /// Like [`Tracker::record`], but with the sending process's
    /// kernel-attested *generation* token (start-time; see
    /// [`crate::peer_cred::read_pid_start_time`]).
    ///
    /// When a beat arrives for an already-tracked pid whose pinned generation
    /// is `Some(a)` and the incoming generation is `Some(b)` with `a != b`,
    /// the OS has recycled the PID to a new process. The slot is reset to a
    /// fresh agent (new nonce baseline, origin, namespace, silence timer) and
    /// [`Update::Inserted`] is returned — rather than letting the new
    /// process's low nonce be rejected as [`Update::OutOfOrder`], which would
    /// freeze the slot's `last_ns`, false-stall the healthy new process, and
    /// misdirect recovery against it. A `None` on either side is treated
    /// leniently — "generation unknown", never a recycle signal — so
    /// non-Linux and non-attested transports keep their prior behaviour.
    pub fn record_with_generation(
        &mut self,
        frame: &Frame,
        now_ns: u64,
        threshold_ns: u64,
        origin: BeatOrigin,
        peer_pid_ns_inode: Option<u64>,
        peer_generation: Option<u64>,
    ) -> Update {
        let status = frame.status;

        if let Some(idx) = self.pid_to_index.get(frame.pid) {
            // Defensive: the index promised this slot exists. If it doesn't,
            // we treat the lookup as a miss and bump the invariant counter
            // so ops can alert; the code then falls through to the insert
            // path. Never panics.
            let Some(slot) = self.entries.get_mut(idx) else {
                self.invariant_violations = self.invariant_violations.saturating_add(1);
                // Drop the stale index entry so the next lookup is a clean miss.
                let _ = self.pid_to_index.remove(frame.pid);
                self.capacity_exceeded = self.capacity_exceeded.saturating_add(1);
                return Update::CapacityExceeded;
            };
            if slot.used {
                // PID-recycle gate. A kernel-attested generation mismatch
                // means this pid now belongs to a different process. Reset the
                // slot to the new agent BEFORE the origin / namespace / nonce
                // checks below — every one of them assumes a slot-identity
                // continuity that no longer holds. `None` on either side is
                // "generation unknown" and falls through to the existing
                // same-process logic (first-wins leniency, like `pid_ns_inode`).
                if let (Some(pinned), Some(current)) = (slot.generation, peer_generation) {
                    if pinned != current {
                        if slot.stall_emitted {
                            self.stall_emitted_count = self.stall_emitted_count.saturating_sub(1);
                        }
                        *slot = Slot::from_frame(
                            frame,
                            now_ns,
                            status,
                            origin,
                            peer_pid_ns_inode,
                            peer_generation,
                        );
                        self.pid_recycles = self.pid_recycles.saturating_add(1);
                        return Update::Inserted;
                    }
                }
                // Generation-less network-transport recycle gate. UDP-class
                // transports (secure or plaintext) carry no kernel start-time
                // generation, so the `Some`/`Some` gate above can never reset
                // them. A fresh process that recycles the PID restarts its
                // monotonic VLP nonce low; without this gate its first beat is
                // rejected as `OutOfOrder` below, freezing the dead
                // predecessor's slot and false-stalling — or, under
                // `OperatorAttestedTransport`, recovery-KILLING — the healthy
                // newcomer. Treat a non-advancing regular nonce as a recycle
                // only once the slot has been silent past the stall threshold:
                // a live sender advances its nonce, and an aged-out replay is
                // filtered by the secure listener's per-sender high-water
                // before it ever reaches the tracker. Restricted to network
                // origins so kernel-attested / socket-mode UDS slots keep their
                // existing generation / `UnverifiableGeneration` semantics
                // byte-for-byte.
                if peer_generation.is_none()
                    && slot.generation.is_none()
                    && slot.origin == origin
                    && matches!(
                        origin,
                        BeatOrigin::OperatorAttestedTransport | BeatOrigin::NetworkUnverified
                    )
                    && frame.nonce != NONCE_TERMINAL
                    && slot.has_regular_nonce
                    && frame.nonce <= slot.last_nonce
                    && now_ns.saturating_sub(slot.last_ns) >= threshold_ns
                {
                    if slot.stall_emitted {
                        self.stall_emitted_count = self.stall_emitted_count.saturating_sub(1);
                    }
                    *slot = Slot::from_frame(
                        frame,
                        now_ns,
                        status,
                        origin,
                        peer_pid_ns_inode,
                        peer_generation,
                    );
                    self.pid_recycles = self.pid_recycles.saturating_add(1);
                    return Update::Inserted;
                }
                if slot.origin != origin {
                    if origin.can_replace(slot.origin) {
                        if slot.stall_emitted {
                            self.stall_emitted_count = self.stall_emitted_count.saturating_sub(1);
                        }
                        *slot = Slot::from_frame(
                            frame,
                            now_ns,
                            status,
                            origin,
                            peer_pid_ns_inode,
                            peer_generation,
                        );
                        return Update::Refreshed;
                    } else {
                        self.origin_conflicts = self.origin_conflicts.saturating_add(1);
                        return Update::OriginConflict;
                    }
                }
                // First-namespace-wins. Same precedence as origin: an actively
                // disagreeing inode is a conflict. A `None → Some` upgrade is
                // valid only if the frame's nonce is accepted; rejected
                // out-of-order frames must not mutate slot identity.
                let namespace_upgrade = match (slot.pid_ns_inode, peer_pid_ns_inode) {
                    (Some(a), Some(b)) if a != b => {
                        self.namespace_conflicts = self.namespace_conflicts.saturating_add(1);
                        return Update::NamespaceConflict;
                    }
                    // A pinned-then-lost inode is normally a tampering signal.
                    // Exception: a panic hook's terminal frame (`NONCE_TERMINAL`)
                    // is the agent's dying gasp. The process is already exiting,
                    // so by the time the single-threaded observer reads
                    // `/proc/<pid>/ns/pid` the link is gone and the inode reads
                    // back `None`. That is benign process death, not a namespace
                    // swap — the terminal beat must still be recorded (and its
                    // `Critical` status surfaced) rather than dropped as a
                    // conflict. The `_ => false` fall-through keeps the slot's
                    // pinned inode (`Some`) intact. Regular frames keep the
                    // strict pinned-then-lost semantics. A genuine cross-ns
                    // swap `(Some(a), Some(b)) a != b` is still refused above,
                    // terminal or not.
                    (Some(_), None) if frame.nonce != NONCE_TERMINAL => {
                        self.namespace_conflicts = self.namespace_conflicts.saturating_add(1);
                        return Update::NamespaceConflict;
                    }
                    (None, Some(_)) => true,
                    _ => false,
                };
                // First-generation-wins mirrors namespace: pin the start-time
                // token once `/proc` becomes readable, but only on an accepted
                // nonce — out-of-order frames must not mutate slot identity.
                let generation_upgrade =
                    matches!((slot.generation, peer_generation), (None, Some(_)));
                if frame.nonce == NONCE_TERMINAL {
                    if !slot.refresh_terminal(frame, now_ns, status) {
                        return Update::OutOfOrder;
                    }
                    if namespace_upgrade {
                        slot.pid_ns_inode = peer_pid_ns_inode;
                    }
                    if generation_upgrade {
                        slot.generation = peer_generation;
                    }
                    if slot.clear_stall_emitted() {
                        self.stall_emitted_count = self.stall_emitted_count.saturating_sub(1);
                    }
                    return Update::Refreshed;
                }

                match slot.refresh_regular(frame, now_ns, status) {
                    RegularRefresh::Accepted => {}
                    RegularRefresh::Wrapped => {
                        self.nonce_wraps = self.nonce_wraps.saturating_add(1);
                    }
                    RegularRefresh::OutOfOrder => return Update::OutOfOrder,
                }
                if namespace_upgrade {
                    slot.pid_ns_inode = peer_pid_ns_inode;
                }
                if generation_upgrade {
                    slot.generation = peer_generation;
                }
                if slot.clear_stall_emitted() {
                    self.stall_emitted_count = self.stall_emitted_count.saturating_sub(1);
                }
                return Update::Refreshed;
            }
        }

        if self.len >= self.entries.capacity() {
            if let Some(evict_idx) = self.find_evictable_slot(now_ns, threshold_ns) {
                // Snapshot the slot we're evicting. If `find_evictable_slot`
                // ever returned an OOB index (invariant break), defensively
                // surface CapacityExceeded instead of panicking.
                let Some(&evicted_slot) = self.entries.get(evict_idx) else {
                    self.invariant_violations = self.invariant_violations.saturating_add(1);
                    self.capacity_exceeded = self.capacity_exceeded.saturating_add(1);
                    return Update::CapacityExceeded;
                };
                let _ = self.pid_to_index.remove(evicted_slot.pid);
                let Some(slot_mut) = self.entries.get_mut(evict_idx) else {
                    self.invariant_violations = self.invariant_violations.saturating_add(1);
                    self.capacity_exceeded = self.capacity_exceeded.saturating_add(1);
                    return Update::CapacityExceeded;
                };
                *slot_mut = Slot::from_frame(
                    frame,
                    now_ns,
                    status,
                    origin,
                    peer_pid_ns_inode,
                    peer_generation,
                );
                if self.pid_to_index.insert(frame.pid, evict_idx).is_err() {
                    // Probe budget exhausted — roll back the slot write so
                    // the table stays internally consistent and surface
                    // CapacityExceeded to the caller. The `stall_emitted_count`
                    // decrement is deferred to the commit point below, so no
                    // rollback of the counter is needed here.
                    if let Some(slot_mut) = self.entries.get_mut(evict_idx) {
                        *slot_mut = evicted_slot;
                    }
                    // Best-effort re-pin of the old pid. If even this insert
                    // fails (probe budget exhausted twice), the slot data
                    // remains (`used = true`) but `pid_to_index` no longer
                    // maps `evicted_slot.pid` to it — the slot is reachable
                    // only via a future eviction sweep, which silently loses
                    // the original agent's `last_nonce`/`stall_emitted`
                    // identity. Tick `invariant_violations` so ops can alert.
                    if self
                        .pid_to_index
                        .insert(evicted_slot.pid, evict_idx)
                        .is_err()
                    {
                        self.invariant_violations = self.invariant_violations.saturating_add(1);
                    }
                    self.capacity_exceeded = self.capacity_exceeded.saturating_add(1);
                    return Update::CapacityExceeded;
                }
                // Commit-on-success: `stall_emitted_count` is decremented only
                // after the new pid is pinned in the index. If the index insert
                // had failed above, the slot rollback would have restored the
                // old `stall_emitted = true` flag — decrementing the counter
                // before the insert (the pre-commit-on-success layout) caused
                // an `observed > tracked` divergence, surfaced by the
                // `tracker_record` fuzz target. Pattern mirrors cerebrum
                // 2026-05-15 (AEAD nonce state mutation).
                if evicted_slot.stall_emitted {
                    self.stall_emitted_count = self.stall_emitted_count.saturating_sub(1);
                }
                self.evictions = self.evictions.saturating_add(1);
                self.remember_removed_pid(evicted_slot.pid);
                return Update::Inserted;
            }
            self.capacity_exceeded = self.capacity_exceeded.saturating_add(1);
            return Update::CapacityExceeded;
        }
        let idx = self.len;
        // Reserve the index in the pid map *before* pushing — on probe
        // exhaustion we surface CapacityExceeded and leave entries unchanged.
        if self.pid_to_index.insert(frame.pid, idx).is_err() {
            self.capacity_exceeded = self.capacity_exceeded.saturating_add(1);
            return Update::CapacityExceeded;
        }
        self.entries.push(Slot::from_frame(
            frame,
            now_ns,
            status,
            origin,
            peer_pid_ns_inode,
            peer_generation,
        ));
        self.len += 1;
        Update::Inserted
    }

    /// Find a slot that can be evicted to make room for a new pid.
    ///
    /// A slot is evictable when both conditions hold:
    /// 1. The observer has already surfaced a stall event for this pid
    ///    (`stall_emitted == true`).
    /// 2. Silence duration exceeds `threshold_ns * EVICTION_MULTIPLIER`.
    ///
    /// **Bounded-work guarantee.** The scan visits at most
    /// [`EVICTION_SCAN_WINDOW`] slots per call, starting at
    /// `self.eviction_scan_cursor` and wrapping mod `self.len`. The cursor
    /// is advanced regardless of outcome so back-to-back failed evictions
    /// eventually cover the whole table without ever performing more than
    /// `WINDOW` slot reads in a single call. This trades strict
    /// global-oldest LRU for an O(1) per-frame upper bound — the right
    /// tradeoff under capacity pressure, because every slot satisfying the
    /// threshold criterion is by definition a safe victim.
    ///
    /// **Fast-bail for Strict policy.** When no slots have surfaced a stall
    /// yet (`stall_emitted_count == 0`), the strict pass is skipped
    /// entirely. This is the common DoS profile: an attacker can fill the
    /// tracker faster than the threshold can elapse, so no slot has a
    /// `stall_emitted` flag set, and the previous code wasted O(n) work
    /// looking for one anyway.
    ///
    /// When the policy is [`EvictionPolicy::Balanced`] and no
    /// strictly-evictable slot is found in the window, a second windowed
    /// pass picks the first slot whose silence exceeds the threshold
    /// (disregarding `stall_emitted`). This prevents capacity-exhaustion
    /// attacks at the cost of possibly evicting a slow-but-alive agent.
    fn find_evictable_slot(&mut self, now_ns: u64, threshold_ns: u64) -> Option<usize> {
        let evict_threshold = threshold_ns.saturating_mul(EVICTION_MULTIPLIER as u64);

        // Track whether any windowed scan actually engaged. The
        // `eviction_scan_truncated` counter exists to tell operators that the
        // window cap was the limiting factor; ticking it on a fast-bail (no
        // stalled slots → strict pass skipped) conflates two distinct failure
        // modes and makes the metric useless for tuning
        // `--eviction-scan-window`.
        let mut scanned = false;

        // Strict pass — cheap bail when no slots have stalled yet.
        if self.stall_emitted_count > 0 {
            scanned = true;
            if let Some(idx) = self.scan_window(now_ns, evict_threshold, true) {
                return Some(idx);
            }
        }
        if self.eviction_policy == EvictionPolicy::Balanced {
            scanned = true;
            if let Some(idx) = self.scan_window(now_ns, evict_threshold, false) {
                return Some(idx);
            }
        }
        if scanned {
            self.eviction_scan_truncated = self.eviction_scan_truncated.saturating_add(1);
        }
        None
    }

    /// Bounded windowed scan helper for [`Tracker::find_evictable_slot`].
    ///
    /// Examines at most [`EVICTION_SCAN_WINDOW`] slots starting at
    /// `eviction_scan_cursor` (mod `self.len`). Returns the index of the
    /// first slot whose silence exceeds `evict_threshold` and, if
    /// `require_stall`, whose `stall_emitted` flag is set. The cursor is
    /// advanced past the inspected window (or just past the hit) so
    /// subsequent calls progress around the ring.
    fn scan_window(
        &mut self,
        now_ns: u64,
        evict_threshold: u64,
        require_stall: bool,
    ) -> Option<usize> {
        let n = self.len.min(self.entries.len());
        if n == 0 {
            return None;
        }
        let window = self.eviction_scan_window.min(n);
        let start = self.eviction_scan_cursor % n;
        for i in 0..window {
            let idx = (start + i) % n;
            // Defensive: if `n` ever exceeded `entries.len()` this would
            // be unreachable under invariant `n = len.min(entries.len())`,
            // but treat OOB as "skip" rather than panic.
            let Some(slot) = self.entries.get(idx) else {
                self.invariant_violations = self.invariant_violations.saturating_add(1);
                continue;
            };
            let stale = now_ns.saturating_sub(slot.last_ns) > evict_threshold;
            let qualifies = stale && (!require_stall || slot.stall_emitted);
            if qualifies {
                self.eviction_scan_cursor = (idx + 1) % n;
                return Some(idx);
            }
        }
        self.eviction_scan_cursor = (start + window) % n;
        None
    }

    /// Remove a stale slot from the dense slot table and repair the pid index.
    ///
    /// Used when stall-time generation revalidation proves the PID now belongs
    /// to a different process. The stale slot must disappear before recovery
    /// sees it; otherwise a dead agent's old `KernelAttested` origin can fire
    /// against a healthy recycled PID.
    fn retire_slot_at(&mut self, idx: usize) {
        if idx >= self.len || idx >= self.entries.len() {
            self.invariant_violations = self.invariant_violations.saturating_add(1);
            return;
        }

        let removed = self.entries[idx];
        let removed_pid = removed.pid;
        let _ = self.pid_to_index.remove(removed.pid);
        if removed.stall_emitted {
            self.stall_emitted_count = self.stall_emitted_count.saturating_sub(1);
        }

        let Some(last_idx) = self.len.checked_sub(1) else {
            self.invariant_violations = self.invariant_violations.saturating_add(1);
            return;
        };
        if idx != last_idx {
            let Some(&moved) = self.entries.get(last_idx) else {
                self.invariant_violations = self.invariant_violations.saturating_add(1);
                return;
            };
            self.entries[idx] = moved;
            if self.pid_to_index.insert(moved.pid, idx).is_err() {
                self.invariant_violations = self.invariant_violations.saturating_add(1);
            }
        }
        let _ = self.entries.pop();
        self.len = self.len.saturating_sub(1);
        if self.len == 0 {
            self.eviction_scan_cursor = 0;
        } else {
            self.eviction_scan_cursor %= self.len;
        }
        self.remember_removed_pid(removed_pid);
    }

    fn remember_removed_pid(&mut self, pid: u32) {
        if self.removed_pids.len() < self.removed_pids.capacity() {
            self.removed_pids.push(pid);
        }
    }

    /// Take and reset the eviction counter. Returns the number of slots
    /// reclaimed since the last call.
    pub fn take_evictions(&mut self) -> u64 {
        let count = self.evictions;
        self.evictions = 0;
        count
    }

    /// Return one pending pid removed from the tracker, if any.
    ///
    /// Covers both capacity evictions and generation-mismatch retirements.
    /// Consumers use this to drop per-pid exporter rows after the slot is no
    /// longer tracked. Repeated calls drain all pending removals.
    pub fn take_evicted_pid(&mut self) -> Option<u32> {
        self.removed_pids.pop()
    }

    /// Take and reset the nonce-wrap counter. Returns the number of
    /// nonce-space wraps detected since the last call.
    pub fn take_nonce_wraps(&mut self) -> u64 {
        let count = self.nonce_wraps;
        self.nonce_wraps = 0;
        count
    }

    /// Take and reset the capacity-exceeded counter. Returns the number of
    /// beats dropped due to a full tracker since the last call.
    pub fn take_capacity_exceeded(&mut self) -> u64 {
        let count = self.capacity_exceeded;
        self.capacity_exceeded = 0;
        count
    }

    /// Number of pids currently tracked.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return the `last_ns` timestamp for a tracked pid, if present.
    /// Used by the observer for per-pid rate limiting without exposing
    /// internal slot layout.
    pub fn last_ns_of(&self, pid: u32) -> Option<u64> {
        self.pid_to_index
            .get(pid)
            .and_then(|idx| self.entries.get(idx).map(|s| s.last_ns))
    }

    /// Return the most recent accepted wire nonce for a tracked pid, if
    /// present. Used by the observer to admit one authenticated terminal
    /// panic frame after a regular beat without creating an unlimited
    /// terminal-frame bypass around the global rate limiter.
    pub fn last_observed_nonce_of(&self, pid: u32) -> Option<u64> {
        self.pid_to_index
            .get(pid)
            .and_then(|idx| self.entries.get(idx))
            .filter(|s| s.used)
            .map(|s| s.last_observed_nonce)
    }

    /// Return the pinned transport origin of a tracked pid, if present.
    /// Used by the observer to populate `Event::OriginConflict::slot_origin`
    /// before calling `record` (which may produce the conflict).
    pub fn origin_of(&self, pid: u32) -> Option<BeatOrigin> {
        self.pid_to_index
            .get(pid)
            .and_then(|idx| self.entries.get(idx))
            .filter(|s| s.used)
            .map(|s| s.origin)
    }

    /// Return the pinned PID-namespace inode of a tracked pid, if present.
    ///
    /// The outer `Option` is `Some` when the pid is tracked at all; the inner
    /// `Option` is the inode (or `None` for non-Linux / unreadable). Used by
    /// the observer to populate `Event::NamespaceConflict::slot_ns_inode`
    /// without an extra slot lookup.
    pub fn pid_ns_inode_of(&self, pid: u32) -> Option<Option<u64>> {
        self.pid_to_index
            .get(pid)
            .and_then(|idx| self.entries.get(idx))
            .filter(|s| s.used)
            .map(|s| s.pid_ns_inode)
    }

    /// Return the pinned process start-time generation of a tracked pid, if
    /// present.
    ///
    /// The outer `Option` is `Some` when the pid is tracked at all; the inner
    /// `Option` is the Linux `/proc/<pid>/stat` start-time token. The observer
    /// uses this before recording a beat to avoid promoting first-contact
    /// Linux UDS frames to recovery-eligible status when generation pinning
    /// failed.
    pub fn generation_of(&self, pid: u32) -> Option<Option<u64>> {
        self.pid_to_index
            .get(pid)
            .and_then(|idx| self.entries.get(idx))
            .filter(|s| s.used)
            .map(|s| s.generation)
    }

    /// True iff no pids are tracked.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Re-validate a deferred stall immediately before recovery fires.
    ///
    /// Returns [`StallFreshness::Warranted`] only while the slot stays present,
    /// used, and silence-latched (`stall_emitted`) AND — for a kernel-attested
    /// slot with a pinned start-time `generation` — the live process still
    /// matches that generation. This is the fire-time mirror of the recycle
    /// check `drain_stalled_slots` already runs at *enqueue* time: a PID
    /// recycle that lands inside the spawn-budget deferral window leaves the
    /// stall-latched slot untouched (the new occupant never beat), so without
    /// this re-check `on_stall` would fire `{pid}` recovery against the
    /// innocent recycled process.
    ///
    /// `generation` is the token carried on the queued `Event::Stall`; pass
    /// `None` for non-kernel-attested / non-Linux slots, which skips the
    /// recycle check and degrades to the silence-latch test alone.
    pub fn stall_freshness(&self, pid: u32, generation: Option<u64>) -> StallFreshness {
        self.stall_freshness_with_recycle_check(pid, generation, |pid, pinned_generation| {
            matches!(
                crate::peer_cred::read_pid_start_time(pid),
                Some(current_generation) if current_generation != pinned_generation
            )
        })
    }

    fn stall_freshness_with_recycle_check(
        &self,
        pid: u32,
        generation: Option<u64>,
        mut generation_recycled: impl FnMut(u32, u64) -> bool,
    ) -> StallFreshness {
        let Some(slot) = self
            .pid_to_index
            .get(pid)
            .and_then(|idx| self.entries.get(idx))
            .filter(|s| s.used)
        else {
            return StallFreshness::AgentResumed;
        };
        if !slot.stall_emitted {
            return StallFreshness::AgentResumed;
        }
        match generation {
            Some(pinned_generation) => {
                if generation_recycled(pid, pinned_generation) {
                    StallFreshness::PidRecycled
                } else {
                    StallFreshness::Warranted
                }
            }
            None => {
                // No generation token to verify freshness against. A
                // `KernelAttested` slot is recovery-eligible, but on
                // credential-only platforms without `/proc`
                // (FreeBSD/DragonFly/NetBSD/illumos/Solaris) the kernel attests
                // the sender PID — minting `KernelAttested` — while
                // `read_pid_start_time` always returns `None`, so the recycle
                // gate is structurally blind. Refuse to fire a recovery-eligible
                // deferred stall we cannot prove fresh rather than risk
                // `kill(2)`/restart against an innocent recycled PID. On Linux a
                // `KernelAttested` slot always carries a generation (recovery
                // authority requires complete identity), so this arm is reached
                // only on those platforms. Non-eligible origins keep the
                // silence-latch verdict: `on_stall` refuses them regardless of
                // freshness, so the label they already produce is unchanged.
                if slot.origin == BeatOrigin::KernelAttested {
                    StallFreshness::UnverifiableGeneration
                } else {
                    StallFreshness::Warranted
                }
            }
        }
    }

    /// Find newly-stalled slots and mark them emitted in one atomic pass.
    ///
    /// A slot is "newly stalled" when its silence duration exceeds
    /// `threshold_ns` **and** the observer has not yet surfaced a stall
    /// event for the current silence run (`stall_emitted == false`).
    /// Qualifying slots are marked `stall_emitted = true` and the callback
    /// is invoked with
    /// `(pid, last_nonce, last_ns, origin, pid_ns_inode, generation)` — all
    /// within the same mutable borrow, closing the TOCTOU window that existed
    /// between the former `iter_stalled` / `mark_stall_emitted` pair. The
    /// trailing `generation` is the slot's pinned start-time token, carried so
    /// the recovery debounce ledger can distinguish a recycled PID.
    pub fn drain_stalled_slots(
        &mut self,
        now_ns: u64,
        threshold_ns: u64,
        mut cb: impl FnMut(u32, u64, u64, BeatOrigin, Option<u64>, Option<u64>),
    ) {
        self.drain_stalled_slots_with_generation_check(
            now_ns,
            threshold_ns,
            |pid, pinned_generation| {
                matches!(
                    crate::peer_cred::read_pid_start_time(pid),
                    Some(current_generation) if current_generation != pinned_generation
                )
            },
            &mut cb,
        );
    }

    fn drain_stalled_slots_with_generation_check(
        &mut self,
        now_ns: u64,
        threshold_ns: u64,
        mut generation_recycled: impl FnMut(u32, u64) -> bool,
        mut cb: impl FnMut(u32, u64, u64, BeatOrigin, Option<u64>, Option<u64>),
    ) {
        if self.len > self.entries.len() {
            self.invariant_violations = self.invariant_violations.saturating_add(1);
        }

        let mut idx = 0usize;
        while idx < self.len {
            let Some(slot) = self.entries.get(idx) else {
                self.invariant_violations = self.invariant_violations.saturating_add(1);
                break;
            };
            if !slot.used || slot.stall_emitted {
                idx += 1;
                continue;
            }
            if now_ns.saturating_sub(slot.last_ns) < threshold_ns {
                idx += 1;
                continue;
            }

            if slot.origin == BeatOrigin::KernelAttested {
                if let Some(pinned_generation) = slot.generation {
                    if generation_recycled(slot.pid, pinned_generation) {
                        self.retire_slot_at(idx);
                        self.pid_recycles = self.pid_recycles.saturating_add(1);
                        continue;
                    }
                }
            }

            let Some(slot) = self.entries.get_mut(idx) else {
                self.invariant_violations = self.invariant_violations.saturating_add(1);
                break;
            };
            slot.stall_emitted = true;
            self.stall_emitted_count = self.stall_emitted_count.saturating_add(1);
            let event = (
                slot.pid,
                slot.last_observed_nonce,
                slot.last_ns,
                slot.origin,
                slot.pid_ns_inode,
                slot.generation,
            );
            cb(event.0, event.1, event.2, event.3, event.4, event.5);
            idx += 1;
        }
        #[cfg(debug_assertions)]
        self.debug_assert_stall_count();
    }

    /// Take and reset the origin-conflict counter.
    ///
    /// Surfaced as `varta_origin_conflict_total` by the Prometheus exporter;
    /// non-zero values indicate that beats for a tracked pid arrived from a
    /// transport other than the one that first claimed the pid — either a
    /// misconfigured agent or an active spoofing attempt.
    pub fn take_origin_conflicts(&mut self) -> u64 {
        let count = self.origin_conflicts;
        self.origin_conflicts = 0;
        count
    }

    /// Take and reset the namespace-conflict counter.
    ///
    /// Surfaced as `varta_tracker_namespace_conflict_total` by the Prometheus
    /// exporter; non-zero values mean beats for a tracked pid arrived from a
    /// different PID namespace than the one pinned by the slot's first beat.
    /// Linux-only signal; on non-Linux platforms this counter stays at 0.
    pub fn take_namespace_conflicts(&mut self) -> u64 {
        let count = self.namespace_conflicts;
        self.namespace_conflicts = 0;
        count
    }

    /// Take and reset the PID-recycle counter.
    ///
    /// Surfaced as `varta_tracker_pid_recycle_total` by the Prometheus
    /// exporter. A non-zero value means a tracked pid was reused by a new
    /// process (kernel-attested start-time changed) and stale slot identity
    /// was reset or retired before it could false-stall the new process.
    /// Linux-only signal; on non-Linux platforms this counter stays at 0.
    pub fn take_pid_recycles(&mut self) -> u64 {
        let count = self.pid_recycles;
        self.pid_recycles = 0;
        count
    }

    /// Take and reset the bounded-window truncated-scan counter.
    ///
    /// Surfaced as `varta_tracker_eviction_scan_truncated_total` by the
    /// Prometheus exporter; non-zero values prove the window cap actually
    /// engaged (i.e. the table was full and no victim was found within
    /// `EVICTION_SCAN_WINDOW` slots).
    pub fn take_eviction_scan_truncated(&mut self) -> u64 {
        let count = self.eviction_scan_truncated;
        self.eviction_scan_truncated = 0;
        count
    }

    /// Take and reset the invariant-violation counter.
    ///
    /// Surfaced as `varta_tracker_invariant_violations_total` by the
    /// Prometheus exporter. In correctly-operating code this counter stays
    /// at 0 forever — non-zero values mean one of the defensive `.get()`
    /// fall-throughs in the hot path triggered (e.g. a stale `PidIndex`
    /// entry pointed at an out-of-range slot). The tracker recovers
    /// without panicking; ops should still treat any non-zero value as a
    /// bug worth investigating.
    pub fn take_invariant_violations(&mut self) -> u64 {
        let count = self.invariant_violations;
        self.invariant_violations = 0;
        count
    }

    /// Take and reset the [`PidIndex`] probe-exhaustion counter.
    ///
    /// Surfaced as `varta_tracker_pid_index_probe_exhausted_total` by the
    /// Prometheus exporter. Non-zero values mean a pid lookup walked
    /// [`PidIndex::MAX_PROBE`] slots without resolving — at load factor
    /// ≤ 0.5 this is effectively unreachable, so any non-zero value is a
    /// red flag (pathological pid distribution, or an attempt to fill the
    /// index past its safe load factor).
    pub fn take_probe_exhausted(&mut self) -> u64 {
        self.pid_to_index.take_probe_exhausted()
    }

    /// Recompute `stall_emitted_count` from scratch and assert it matches
    /// the maintained counter. Cheap (single linear pass over `len` slots),
    /// gated to debug builds to keep the release-mode hot path untouched.
    #[cfg(debug_assertions)]
    fn debug_assert_stall_count(&self) {
        let upper = self.len.min(self.entries.len());
        let observed = self
            .entries
            .get(..upper)
            .unwrap_or(&[])
            .iter()
            .filter(|s| s.stall_emitted)
            .count();
        debug_assert_eq!(
            observed, self.stall_emitted_count,
            "stall_emitted_count out of sync: observed {}, tracked {}",
            observed, self.stall_emitted_count
        );
    }
}

#[cfg(test)]
mod tests;
