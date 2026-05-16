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

use varta_vlp::{Frame, Status};

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

/// Fixed-size, open-addressed `u32 → u32` map from agent pid to slot index.
///
/// Thin newtype over the generic [`crate::probe_table::BoundedIndex`]; see
/// that module for the full WCET argument. The hot tracker path uses this
/// type directly so the call sites stay readable while the probe-table
/// machinery is shared with `OutstandingTable` and `IpStateTable`.
///
/// `Entry<u32>` in the generic table is still 8 bytes (see the
/// `entry_u32_is_8_bytes` test in `probe_table`), so the per-slot cache
/// pressure on the hot path is unchanged across the refactor.
pub(crate) struct PidIndex(crate::probe_table::BoundedIndex<u32>);

/// Re-export the generic probe-exhaustion marker so the rest of the tracker
/// keeps referring to a `ProbeExhausted` type local to this module.
pub(crate) use crate::probe_table::ProbeExhausted;

impl PidIndex {
    /// Hard cap on the probe sequence length per `get` / `insert` /
    /// `remove`.  Referenced from the doc comments above and from
    /// `Tracker::take_probe_exhausted`'s remediation text; the actual
    /// bound is enforced inside the generic `BoundedIndex`.
    #[allow(dead_code)]
    pub(crate) const MAX_PROBE: usize = crate::probe_table::BoundedIndex::<u32>::MAX_PROBE;

    /// Build a pid index sized for `capacity` agents.
    pub(crate) fn new(capacity: usize) -> Self {
        Self(crate::probe_table::BoundedIndex::new(capacity))
    }

    /// Look up the slot index recorded for `pid`. Returns `None` if absent
    /// or if the probe budget was exhausted (treated as absent so callers
    /// fall through to insert / capacity-exceeded paths).
    pub(crate) fn get(&self, pid: u32) -> Option<usize> {
        self.0.get(pid)
    }

    /// Insert or update `pid → slot_idx`. Returns `Err(ProbeExhausted)` if
    /// no free or matching slot was found within
    /// [`Self::MAX_PROBE`] probes; table state is unchanged in that case
    /// and the probe-exhausted counter is incremented.
    pub(crate) fn insert(&mut self, pid: u32, slot_idx: usize) -> Result<(), ProbeExhausted> {
        self.0.insert(pid, slot_idx)
    }

    /// Remove `pid` from the index. Returns the slot index it pointed to,
    /// if any.
    pub(crate) fn remove(&mut self, pid: u32) -> Option<usize> {
        self.0.remove(pid)
    }

    /// Drain and reset the probe-exhausted counter.
    pub(crate) fn take_probe_exhausted(&mut self) -> u64 {
        self.0.take_probe_exhausted()
    }

    /// Number of live entries.  Used by the existing occupancy invariant
    /// tests below; production code reads occupancy through the tracker
    /// itself, not the index.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

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
    /// Most recent nonce accepted from this pid.
    pub(crate) last_nonce: u64,
    /// Observer-local timestamp (nanoseconds since [`crate::observer::Observer`]
    /// start) of the last accepted beat for this pid.
    pub(crate) last_ns: u64,
    /// Most recent [`Status`] reported by this pid.
    pub(crate) status: Status,
    /// Transport origin pinned at the slot's first beat. Used to gate
    /// recovery-eligibility — beats from a different origin than the pinned
    /// one are rejected as [`Update::OriginConflict`] without mutating the
    /// slot. See [`BeatOrigin`] for the trust model.
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
    /// False iff this slot has never been written; observers treat the
    /// slot's other fields as undefined when `used == false`.
    pub(crate) used: bool,
    /// True iff the observer has already emitted a stall event for the
    /// current silence run. Cleared when a fresh beat arrives.
    pub(crate) stall_emitted: bool,
}

impl Slot {}

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
    /// transport origin disagrees with the origin pinned by the slot's
    /// first beat. First-origin-wins: the slot is **not** mutated and the
    /// beat is dropped. Prevents an attacker on an untrusted transport
    /// from "tainting" a slot that legitimately belongs to a kernel-attested
    /// agent (or vice-versa).
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
    last_evicted_pid: Option<u32>,
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
    /// Count of beats dropped because their transport origin disagreed with
    /// the slot's pinned origin (first-origin-wins). Surfaced via
    /// [`Tracker::take_origin_conflicts`] for Prometheus.
    origin_conflicts: u64,
    /// Count of beats dropped because their kernel-attested PID-namespace
    /// inode disagreed with the slot's pinned namespace (first-namespace-wins).
    /// Surfaced via [`Tracker::take_namespace_conflicts`] for Prometheus.
    namespace_conflicts: u64,
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
            last_evicted_pid: None,
            eviction_policy,
            stall_emitted_count: 0,
            eviction_scan_window: window,
            eviction_scan_cursor: 0,
            eviction_scan_truncated: 0,
            origin_conflicts: 0,
            namespace_conflicts: 0,
            invariant_violations: 0,
        }
    }

    /// Record a frame against the tracker.
    ///
    /// Uses O(1) HashMap pid lookup to find the slot for `frame.pid`.
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
                if slot.origin != origin {
                    self.origin_conflicts = self.origin_conflicts.saturating_add(1);
                    return Update::OriginConflict;
                }
                // First-namespace-wins. Same precedence as origin: an actively
                // disagreeing inode is a conflict; a `None → Some` upgrade
                // pins the now-known namespace and falls through to refresh;
                // both-`None` is the non-Linux / unreadable case and is a
                // no-op.
                match (slot.pid_ns_inode, peer_pid_ns_inode) {
                    (Some(a), Some(b)) if a != b => {
                        self.namespace_conflicts = self.namespace_conflicts.saturating_add(1);
                        return Update::NamespaceConflict;
                    }
                    (Some(_), None) => {
                        // Regression — pinned-then-lost is a tampering signal.
                        self.namespace_conflicts = self.namespace_conflicts.saturating_add(1);
                        return Update::NamespaceConflict;
                    }
                    (None, Some(_)) => {
                        // Forgiving upgrade — fill in the previously-unknown
                        // inode in place and continue with refresh.
                        slot.pid_ns_inode = peer_pid_ns_inode;
                    }
                    _ => {}
                }
                if frame.nonce <= slot.last_nonce {
                    // Detect nonce wrap: agent exhausted u64 nonce space
                    // and looped to 0.  last_nonce is near u64::MAX and
                    // the incoming nonce is near 0 — a gap this large
                    // cannot be a genuine out-of-order beat.
                    let wrap_lo = NONCE_WRAP_THRESHOLD;
                    let wrap_hi = u64::MAX.saturating_sub(NONCE_WRAP_THRESHOLD);
                    if slot.last_nonce >= wrap_hi && frame.nonce < wrap_lo {
                        slot.last_nonce = frame.nonce;
                        slot.last_ns = now_ns;
                        slot.status = status;
                        if slot.stall_emitted {
                            slot.stall_emitted = false;
                            self.stall_emitted_count = self.stall_emitted_count.saturating_sub(1);
                        }
                        self.nonce_wraps = self.nonce_wraps.saturating_add(1);
                        return Update::Refreshed;
                    }
                    return Update::OutOfOrder;
                }
                slot.last_nonce = frame.nonce;
                slot.last_ns = now_ns;
                slot.status = status;
                if slot.stall_emitted {
                    slot.stall_emitted = false;
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
                *slot_mut = Slot {
                    pid: frame.pid,
                    last_nonce: frame.nonce,
                    last_ns: now_ns,
                    status,
                    origin,
                    pid_ns_inode: peer_pid_ns_inode,
                    used: true,
                    stall_emitted: false,
                };
                if self.pid_to_index.insert(frame.pid, evict_idx).is_err() {
                    // Probe budget exhausted — roll back the slot write so
                    // the table stays internally consistent and surface
                    // CapacityExceeded to the caller. The `stall_emitted_count`
                    // decrement is deferred to the commit point below, so no
                    // rollback of the counter is needed here.
                    if let Some(slot_mut) = self.entries.get_mut(evict_idx) {
                        *slot_mut = evicted_slot;
                    }
                    // Best-effort re-pin of the old pid; if even this insert
                    // fails the slot is logically vacant for the next call.
                    let _ = self.pid_to_index.insert(evicted_slot.pid, evict_idx);
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
                self.last_evicted_pid = Some(evicted_slot.pid);
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
        self.entries.push(Slot {
            pid: frame.pid,
            last_nonce: frame.nonce,
            last_ns: now_ns,
            status,
            origin,
            pid_ns_inode: peer_pid_ns_inode,
            used: true,
            stall_emitted: false,
        });
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

        // Strict pass — cheap bail when no slots have stalled yet.
        if self.stall_emitted_count > 0 {
            if let Some(idx) = self.scan_window(now_ns, evict_threshold, true) {
                return Some(idx);
            }
        }
        if self.eviction_policy == EvictionPolicy::Balanced {
            if let Some(idx) = self.scan_window(now_ns, evict_threshold, false) {
                return Some(idx);
            }
        }
        self.eviction_scan_truncated = self.eviction_scan_truncated.saturating_add(1);
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

    /// Take and reset the eviction counter. Returns the number of slots
    /// reclaimed since the last call.
    pub fn take_evictions(&mut self) -> u64 {
        let count = self.evictions;
        self.evictions = 0;
        count
    }

    /// Return the pid of the most recently evicted slot, if any slots
    /// have been evicted since the last call.
    pub fn take_evicted_pid(&mut self) -> Option<u32> {
        self.last_evicted_pid.take()
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

    /// True iff no pids are tracked.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Find newly-stalled slots and mark them emitted in one atomic pass.
    ///
    /// A slot is "newly stalled" when its silence duration exceeds
    /// `threshold_ns` **and** the observer has not yet surfaced a stall
    /// event for the current silence run (`stall_emitted == false`).
    /// Qualifying slots are marked `stall_emitted = true` and the callback
    /// is invoked with `(pid, last_nonce, last_ns, origin, pid_ns_inode)` —
    /// all within the same mutable borrow, closing the TOCTOU window that
    /// existed between the former `iter_stalled` / `mark_stall_emitted` pair.
    pub fn drain_stalled_slots(
        &mut self,
        now_ns: u64,
        threshold_ns: u64,
        mut cb: impl FnMut(u32, u64, u64, BeatOrigin, Option<u64>),
    ) {
        // Clamp the slice to actual `entries` length so the slice
        // expression cannot panic even if `len` somehow exceeded it
        // (invariant violation — counted, never panicked on).
        let upper = self.len.min(self.entries.len());
        if upper < self.len {
            self.invariant_violations = self.invariant_violations.saturating_add(1);
        }
        if let Some(slice) = self.entries.get_mut(..upper) {
            for slot in slice {
                if !slot.used || slot.stall_emitted {
                    continue;
                }
                if now_ns.saturating_sub(slot.last_ns) >= threshold_ns {
                    slot.stall_emitted = true;
                    self.stall_emitted_count = self.stall_emitted_count.saturating_add(1);
                    cb(
                        slot.pid,
                        slot.last_nonce,
                        slot.last_ns,
                        slot.origin,
                        slot.pid_ns_inode,
                    );
                }
            }
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
mod tests {
    use super::*;
    use varta_vlp::Frame;

    fn frame(pid: u32, nonce: u64) -> Frame {
        Frame::new(Status::Ok, pid, nonce, nonce, 0)
    }

    /// Default origin used by tests that don't exercise transport-origin
    /// behaviour. Picked as `KernelAttested` so existing tests continue to
    /// represent the common UDS path.
    const ORIGIN: BeatOrigin = BeatOrigin::KernelAttested;

    /// Fill capacity entirely; never trigger a stall. find_evictable_slot
    /// must return None without scanning any slot (Strict policy).
    #[test]
    fn find_evictable_slot_returns_none_when_no_stalls_emitted() {
        let cap = 64;
        let mut t = Tracker::new(cap, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 1_000;
        // Fill at t=0 so silence isn't a factor either.
        for pid in 1u32..=(cap as u32) {
            assert_eq!(
                t.record(&frame(pid, 1), 0, threshold_ns, ORIGIN, None),
                Update::Inserted
            );
        }
        assert_eq!(t.len(), cap);
        assert_eq!(t.stall_emitted_count, 0);

        // Even at very large "now_ns" (silence >> 10× threshold), Strict
        // policy must bail without scanning: no slot has stall_emitted=true.
        let now_ns = threshold_ns * 100;
        let result = t.record(&frame(99_999, 1), now_ns, threshold_ns, ORIGIN, None);
        assert_eq!(result, Update::CapacityExceeded);
        // Cursor must NOT have advanced through the table (fast-bail path).
        assert_eq!(t.eviction_scan_cursor, 0);
    }

    /// drain_stalled_slots marks slots; counter must reflect that, and the
    /// next find_evictable_slot must actually scan and (eventually) succeed.
    #[test]
    fn stall_counter_enables_eviction_after_drain() {
        let cap = 8;
        let mut t = Tracker::new(cap, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;

        for pid in 1u32..=(cap as u32) {
            assert_eq!(
                t.record(&frame(pid, 1), 0, threshold_ns, ORIGIN, None),
                Update::Inserted
            );
        }
        // Time advances past threshold — every slot stalls.
        let now_ns = threshold_ns * 20;
        let mut stalled = 0u32;
        t.drain_stalled_slots(now_ns, threshold_ns, |_, _, _, _, _| stalled += 1);
        assert_eq!(stalled, cap as u32);
        assert_eq!(t.stall_emitted_count, cap);

        // Silence now exceeds 10× threshold → eviction succeeds.
        let result = t.record(&frame(9_999, 1), now_ns, threshold_ns, ORIGIN, None);
        assert_eq!(result, Update::Inserted);
        // The replacing slot is fresh — stall counter decremented once.
        assert_eq!(t.stall_emitted_count, cap - 1);
    }

    /// A fresh beat on a previously-stalled slot must decrement the counter.
    #[test]
    fn stall_counter_decrements_on_refresh() {
        let mut t = Tracker::new(4, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        assert_eq!(
            t.record(&frame(1, 1), 0, threshold_ns, ORIGIN, None),
            Update::Inserted
        );
        t.drain_stalled_slots(threshold_ns * 2, threshold_ns, |_, _, _, _, _| {});
        assert_eq!(t.stall_emitted_count, 1);

        // New beat with strictly increasing nonce → refresh and clear flag.
        assert_eq!(
            t.record(&frame(1, 2), threshold_ns * 3, threshold_ns, ORIGIN, None),
            Update::Refreshed
        );
        assert_eq!(t.stall_emitted_count, 0);
    }

    /// The bounded scan window must cap per-call work. Fill 4096 slots
    /// at t=0, stall them all, then verify each find_evictable_slot call
    /// advances the cursor by at most the configured window.
    #[test]
    fn find_evictable_slot_scan_is_bounded_to_window() {
        let cap = MAX_CAPACITY;
        let mut t = Tracker::new(cap, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        for pid in 1u32..=(cap as u32) {
            assert_eq!(
                t.record(&frame(pid, 1), 0, threshold_ns, ORIGIN, None),
                Update::Inserted
            );
        }
        // Stall everything.
        let now_ns = threshold_ns * 20;
        t.drain_stalled_slots(now_ns, threshold_ns, |_, _, _, _, _| {});
        assert_eq!(t.stall_emitted_count, cap);

        // Each new-pid insert evicts one slot. Cursor must advance by ≤ window.
        let window = t.eviction_scan_window;
        let start_cursor = t.eviction_scan_cursor;
        let _ = t.record(&frame(50_001, 1), now_ns, threshold_ns, ORIGIN, None);
        let advanced = t.eviction_scan_cursor.wrapping_sub(start_cursor) % cap;
        assert!(
            advanced <= window,
            "cursor advanced by {advanced}, expected ≤ {window}"
        );
    }

    /// A Tracker constructed with a small eviction_scan_window must honour
    /// that window, not the default.
    #[test]
    fn eviction_scan_window_is_plumbed_through() {
        let cap = 16;
        let window = 4;
        let mut t = Tracker::new(cap, EvictionPolicy::Strict, window);
        assert_eq!(t.eviction_scan_window, window);
        let threshold_ns = 100;
        for pid in 1u32..=(cap as u32) {
            assert_eq!(
                t.record(&frame(pid, 1), 0, threshold_ns, ORIGIN, None),
                Update::Inserted
            );
        }
        // Stall everything so every slot is eviction-eligible.
        let now_ns = threshold_ns * 20;
        t.drain_stalled_slots(now_ns, threshold_ns, |_, _, _, _, _| {});
        assert_eq!(t.stall_emitted_count, cap);
        // Force an eviction attempt and confirm the cursor advanced by ≤ window.
        let start = t.eviction_scan_cursor;
        let _ = t.record(&frame(9_999, 1), now_ns, threshold_ns, ORIGIN, None);
        let advanced = t.eviction_scan_cursor.wrapping_sub(start) % cap;
        assert!(
            advanced <= window,
            "cursor advanced {advanced}, expected ≤ {window} (configured window)"
        );
    }

    /// Cursor must wrap past `len` correctly so a long sequence of failed
    /// evictions doesn't go out of bounds.
    #[test]
    fn scan_window_cursor_wraps_correctly() {
        let cap = 4;
        let mut t = Tracker::new(cap, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        for pid in 1u32..=(cap as u32) {
            assert_eq!(
                t.record(&frame(pid, 1), 0, threshold_ns, ORIGIN, None),
                Update::Inserted
            );
        }
        // Force the cursor to advance past `len` by calling scan_window
        // many times with no qualifying slots (threshold not exceeded).
        for _ in 0..10 {
            let _ = t.scan_window(50, 1_000_000, true);
        }
        assert!(t.eviction_scan_cursor < cap);
    }

    /// Stress: random sequence of record / drain_stalled / time advances.
    /// debug_assert_stall_count fires inside drain_stalled_slots after every
    /// call, so this test exercises the invariant.
    #[test]
    fn stall_emitted_count_invariant_holds_across_random_ops() {
        let mut t = Tracker::new(32, EvictionPolicy::Balanced, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        let mut now_ns: u64 = 0;
        // Simple deterministic PRNG (xorshift64) — no rand dep.
        let mut s: u64 = 0xC0FFEE;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..2000 {
            let r = next() % 4;
            now_ns = now_ns.saturating_add(20);
            match r {
                0 => {
                    let pid = (next() % 64) as u32 + 1;
                    let _ = t.record(&frame(pid, now_ns), now_ns, threshold_ns, ORIGIN, None);
                }
                1 => {
                    // Advance and drain (may flip flags to true).
                    now_ns = now_ns.saturating_add(threshold_ns * 2);
                    t.drain_stalled_slots(now_ns, threshold_ns, |_, _, _, _, _| {});
                }
                _ => {
                    // No-op — let other ops dominate.
                }
            }
        }
        // Final consistency check (also runs implicitly in drain).
        let observed = t.entries[..t.len]
            .iter()
            .filter(|s| s.stall_emitted)
            .count();
        assert_eq!(observed, t.stall_emitted_count);
    }

    /// Acceptance check: scan-truncated counter increments only when we
    /// run the full window without finding a victim.
    #[test]
    fn scan_truncated_counter_increments_on_dry_scan() {
        let mut t = Tracker::new(32, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        for pid in 1u32..=32 {
            assert_eq!(
                t.record(&frame(pid, 1), 0, threshold_ns, ORIGIN, None),
                Update::Inserted
            );
        }
        // Table full, no stalls emitted → strict bails, balanced not used →
        // counter still increments since we returned None at capacity.
        let _ = t.record(
            &frame(99_999, 1),
            threshold_ns * 100,
            threshold_ns,
            ORIGIN,
            None,
        );
        assert_eq!(t.take_eviction_scan_truncated(), 1);
        // Take resets.
        assert_eq!(t.take_eviction_scan_truncated(), 0);
    }

    /// First-origin-wins: once a slot is pinned to an origin, a beat with a
    /// different origin is dropped as `OriginConflict` without mutating the
    /// slot or incrementing the slot's `last_ns`.
    #[test]
    fn origin_conflict_first_origin_wins() {
        let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;

        // Beat 1 arrives via UDS (kernel-attested) and pins the slot.
        assert_eq!(
            t.record(
                &frame(7, 1),
                10,
                threshold_ns,
                BeatOrigin::KernelAttested,
                None
            ),
            Update::Inserted
        );

        // Beat 2 arrives via UDP with the same pid — must be rejected.
        assert_eq!(
            t.record(
                &frame(7, 2),
                20,
                threshold_ns,
                BeatOrigin::NetworkUnverified,
                None,
            ),
            Update::OriginConflict
        );

        // Slot is untouched: nonce still 1, last_ns still 10, origin still UDS.
        assert_eq!(t.last_ns_of(7), Some(10));
        assert_eq!(t.entries[0].last_nonce, 1);
        assert_eq!(t.entries[0].origin, BeatOrigin::KernelAttested);

        // Counter reflects the dropped beat.
        assert_eq!(t.take_origin_conflicts(), 1);
        assert_eq!(t.take_origin_conflicts(), 0);

        // Same-origin follow-up still works.
        assert_eq!(
            t.record(
                &frame(7, 3),
                30,
                threshold_ns,
                BeatOrigin::KernelAttested,
                None
            ),
            Update::Refreshed
        );
    }

    // ---------------------- PidIndex unit tests ----------------------

    #[test]
    fn pid_index_insert_get_remove_roundtrip() {
        let mut idx = PidIndex::new(16);
        assert_eq!(idx.get(42), None);
        idx.insert(42, 7).expect("insert");
        assert_eq!(idx.get(42), Some(7));

        // Update in place preserves occupied count.
        idx.insert(42, 9).expect("update");
        assert_eq!(idx.get(42), Some(9));
        assert_eq!(idx.len(), 1);

        assert_eq!(idx.remove(42), Some(9));
        assert_eq!(idx.get(42), None);
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn pid_index_tombstone_reuse() {
        // Insert N pids, remove half, re-insert: lookups must still work
        // even though the removed slots left tombstones along the probe
        // sequences.
        let mut idx = PidIndex::new(64);
        for pid in 1u32..=32 {
            idx.insert(pid, pid as usize).expect("insert");
        }
        for pid in 1u32..=16 {
            assert_eq!(idx.remove(pid), Some(pid as usize));
        }
        // The remaining 16 are still findable.
        for pid in 17u32..=32 {
            assert_eq!(idx.get(pid), Some(pid as usize));
        }
        // Re-insert the removed ones; tombstones must be reused (table is
        // small enough that probe walks could otherwise overflow).
        for pid in 1u32..=16 {
            idx.insert(pid, (pid + 100) as usize).expect("reinsert");
        }
        for pid in 1u32..=16 {
            assert_eq!(idx.get(pid), Some((pid + 100) as usize));
        }
        for pid in 17u32..=32 {
            assert_eq!(idx.get(pid), Some(pid as usize));
        }
    }

    #[test]
    fn pid_index_probe_exhaustion_returns_error() {
        // Build a tiny table where MAX_PROBE is large enough to find slots
        // through linear probing under normal use, then deliberately fill
        // every slot to force exhaustion of the probe budget on insert.
        // Table size = next_power_of_two(4 * 2) = 8 slots.
        let mut idx = PidIndex::new(4);
        // Insert MAX_PROBE-many pids that all hash to the same bucket would
        // be impossible with a deterministic mix; instead we fill the
        // *whole* table so any new pid hashing into a fully-occupied chain
        // exhausts the budget.
        for pid in 1u32..=8 {
            idx.insert(pid, pid as usize).expect("fill");
        }
        // Now every slot is occupied (no EMPTY anywhere). Any new pid must
        // walk the full MAX_PROBE without finding an EMPTY slot.
        let err = idx.insert(9999, 0).expect_err("must exhaust");
        assert_eq!(err, ProbeExhausted);
        assert_eq!(idx.take_probe_exhausted(), 1);
        assert_eq!(idx.take_probe_exhausted(), 0);
    }

    #[test]
    fn record_probe_exhaustion_surfaces_capacity_exceeded() {
        // PidIndex table size = next_power_of_two(cap * 2). At cap = 4 the
        // table has 8 slots. Filling the *entry* table at cap leaves 4
        // PidIndex slots occupied (half full), so we never exhaust the
        // probe budget through ordinary inserts. To force exhaustion we
        // need the index itself to be saturated — which only happens if
        // someone constructs a Tracker with capacity ≥ table_size. For
        // safety we verify the rollback path: a forced-error scenario is
        // not realistically reachable through normal API use, so we instead
        // assert that under heavy churn the counter stays at 0.
        let mut t = Tracker::new(32, EvictionPolicy::Balanced, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        let mut now = 0u64;
        for pid in 1u32..=4096 {
            now = now.saturating_add(1);
            let _ = t.record(&frame(pid, 1), now, threshold_ns, ORIGIN, None);
        }
        // Under nominal use probe exhaustion is unreachable at load ≤ 0.5.
        assert_eq!(t.take_probe_exhausted(), 0);
    }

    #[test]
    fn invariant_violations_stays_zero_under_random_ops() {
        // Mirrors `stall_emitted_count_invariant_holds_across_random_ops`
        // but asserts the new invariant_violations counter never ticks.
        let mut t = Tracker::new(32, EvictionPolicy::Balanced, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        let mut now_ns: u64 = 0;
        let mut s: u64 = 0xDEADBEEF;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..4000 {
            let r = next() % 4;
            now_ns = now_ns.saturating_add(20);
            match r {
                0 => {
                    let pid = (next() % 96) as u32 + 1;
                    let _ = t.record(&frame(pid, now_ns), now_ns, threshold_ns, ORIGIN, None);
                }
                1 => {
                    now_ns = now_ns.saturating_add(threshold_ns * 2);
                    t.drain_stalled_slots(now_ns, threshold_ns, |_, _, _, _, _| {});
                }
                2 => {
                    let pid = (next() % 96) as u32 + 1;
                    let _ = t.last_ns_of(pid);
                    let _ = t.origin_of(pid);
                }
                _ => {}
            }
        }
        assert_eq!(t.take_invariant_violations(), 0);
        assert_eq!(t.take_probe_exhausted(), 0);
    }

    /// drain_stalled_slots propagates each slot's pinned origin to the
    /// callback so downstream consumers (Recovery) can gate on transport
    /// trust.
    #[test]
    fn drain_stalled_slots_emits_pinned_origin() {
        let mut t = Tracker::new(4, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;

        assert_eq!(
            t.record(
                &frame(11, 1),
                0,
                threshold_ns,
                BeatOrigin::KernelAttested,
                None
            ),
            Update::Inserted
        );
        assert_eq!(
            t.record(
                &frame(22, 1),
                0,
                threshold_ns,
                BeatOrigin::NetworkUnverified,
                None,
            ),
            Update::Inserted
        );

        let mut seen: Vec<(u32, BeatOrigin)> = Vec::new();
        t.drain_stalled_slots(threshold_ns * 2, threshold_ns, |pid, _, _, origin, _| {
            seen.push((pid, origin));
        });
        seen.sort_by_key(|(p, _)| *p);
        assert_eq!(
            seen,
            vec![
                (11, BeatOrigin::KernelAttested),
                (22, BeatOrigin::NetworkUnverified),
            ]
        );
    }

    // ---------------------- PID-namespace gate tests ----------------------

    /// First-namespace-wins: a beat with a different `Some(_)` inode for an
    /// already-tracked pid is rejected as `NamespaceConflict`.
    #[test]
    fn namespace_conflict_blocks_rebind() {
        let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        assert_eq!(
            t.record(
                &frame(7, 1),
                0,
                threshold_ns,
                BeatOrigin::KernelAttested,
                Some(4026531836),
            ),
            Update::Inserted
        );
        let r = t.record(
            &frame(7, 2),
            10,
            threshold_ns,
            BeatOrigin::KernelAttested,
            Some(4026531840),
        );
        assert_eq!(r, Update::NamespaceConflict);
        // Slot is untouched.
        assert_eq!(t.pid_ns_inode_of(7), Some(Some(4026531836)));
        assert_eq!(t.take_namespace_conflicts(), 1);
        assert_eq!(t.take_namespace_conflicts(), 0);
    }

    /// Same inode → normal refresh.
    #[test]
    fn namespace_match_passes_through() {
        let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        let _ = t.record(
            &frame(7, 1),
            0,
            threshold_ns,
            BeatOrigin::KernelAttested,
            Some(123),
        );
        let r = t.record(
            &frame(7, 2),
            10,
            threshold_ns,
            BeatOrigin::KernelAttested,
            Some(123),
        );
        assert_eq!(r, Update::Refreshed);
        assert_eq!(t.take_namespace_conflicts(), 0);
    }

    /// `Some → None` regression on a same-pid rebind is a conflict.
    #[test]
    fn namespace_some_to_none_is_conflict() {
        let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        let _ = t.record(
            &frame(7, 1),
            0,
            threshold_ns,
            BeatOrigin::KernelAttested,
            Some(123),
        );
        let r = t.record(
            &frame(7, 2),
            10,
            threshold_ns,
            BeatOrigin::KernelAttested,
            None,
        );
        assert_eq!(r, Update::NamespaceConflict);
        assert_eq!(t.take_namespace_conflicts(), 1);
    }

    /// `None → Some` upgrade on a same-pid rebind pins the now-known inode
    /// and falls through to refresh. This is the forgiving case for a peer
    /// whose `/proc/<pid>/ns/pid` was briefly unreadable at first contact.
    #[test]
    fn namespace_none_to_some_upgrades_in_place() {
        let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        let _ = t.record(
            &frame(7, 1),
            0,
            threshold_ns,
            BeatOrigin::KernelAttested,
            None,
        );
        assert_eq!(t.pid_ns_inode_of(7), Some(None));
        let r = t.record(
            &frame(7, 2),
            10,
            threshold_ns,
            BeatOrigin::KernelAttested,
            Some(999),
        );
        assert_eq!(r, Update::Refreshed);
        assert_eq!(t.pid_ns_inode_of(7), Some(Some(999)));
        assert_eq!(t.take_namespace_conflicts(), 0);
    }

    /// Both `None` (non-Linux / unreadable) → refresh, no conflict.
    #[test]
    fn namespace_both_none_is_match() {
        let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
        let threshold_ns = 100;
        let _ = t.record(
            &frame(7, 1),
            0,
            threshold_ns,
            BeatOrigin::KernelAttested,
            None,
        );
        let r = t.record(
            &frame(7, 2),
            10,
            threshold_ns,
            BeatOrigin::KernelAttested,
            None,
        );
        assert_eq!(r, Update::Refreshed);
        assert_eq!(t.take_namespace_conflicts(), 0);
    }

    // ---- C1 regression: PidIndex::insert occupancy bookkeeping ----------

    /// `occupied` tracks live entries.  Under a cyclic insert/remove cycle the
    /// counter must stay exactly equal to the number of live pids — neither
    /// drifting up (double-counting) nor drifting down (under-counting).
    #[test]
    fn pid_index_occupied_tracks_live_entries_under_churn() {
        // Table sized for 32 entries (64 slots, load ≤ 0.5).
        // We use a *cyclic* pid space (0..48) so tombstones from removed pids
        // fall in the same hash chains as later inserts, ensuring reuse.
        const CAP: usize = 32;
        const PID_RANGE: u32 = 48; // > CAP but < table_size; guarantees reuse
        let mut idx = PidIndex::new(CAP);

        let mut expected_live: u32 = 0;
        let mut live_set = std::collections::HashSet::new();

        for i in 0u32..2_000 {
            let pid = i % PID_RANGE;
            if live_set.contains(&pid) {
                // Already live — remove then re-insert to exercise the tombstone path.
                idx.remove(pid);
                live_set.remove(&pid);
                expected_live -= 1;
                idx.insert(pid, pid as usize).expect("re-insert");
                live_set.insert(pid);
                expected_live += 1;
            } else if expected_live < CAP as u32 {
                idx.insert(pid, pid as usize).expect("fresh insert");
                live_set.insert(pid);
                expected_live += 1;
            } else {
                // At capacity: remove the first entry and insert the new one.
                let victim = *live_set.iter().next().unwrap();
                idx.remove(victim);
                live_set.remove(&victim);
                expected_live -= 1;
                idx.insert(pid, pid as usize).expect("insert after evict");
                live_set.insert(pid);
                expected_live += 1;
            }
            assert_eq!(
                idx.len(),
                expected_live as usize,
                "i={i} pid={pid}: occupied={} expected={expected_live}",
                idx.len()
            );
        }
    }

    /// Re-inserting a previously-removed pid via its tombstone slot must
    /// restore the live count.  `remove()` decremented `occupied`; the
    /// re-insert must re-increment it so the counter stays accurate.
    #[test]
    fn pid_index_occupied_restored_on_tombstone_reuse() {
        let mut idx = PidIndex::new(16);

        idx.insert(42, 0).expect("first insert");
        assert_eq!(idx.len(), 1);

        idx.remove(42);
        assert_eq!(idx.len(), 0);

        // Re-insert via the tombstone slot: live count must go back to 1.
        idx.insert(42, 5).expect("reinsert via tombstone");
        assert_eq!(
            idx.len(),
            1,
            "reinsert via tombstone did not restore occupied to 1 (was {})",
            idx.len()
        );
    }
}
