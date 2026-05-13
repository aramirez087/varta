//! Per-pid liveness tracker backed by a fixed `[Slot; 64]` array with
//! O(1) pid lookup via `HashMap<u32, usize>`.
//!
//! The tracker is the in-memory ledger the observer consults each time a
//! frame arrives or the read timeout expires. It never reallocates: capacity
//! is a compile-time constant and an exhausted tracker yields
//! [`Update::CapacityExceeded`] rather than growing.

use std::collections::HashMap;

use varta_vlp::{Frame, Status};

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

/// Threshold for nonce wrap detection. When the tracker's `last_nonce` for a
/// pid is within this distance of `u64::MAX` and an incoming frame carries a
/// nonce below this threshold, the tracker treats the gap as a nonce-space
/// wrap (agent exhausted u64 nonces and looped to 0) rather than an
/// out-of-order beat. The threshold is 2^20 (~1M); at 1M beats/sec the agent
/// would take days to exhaust the nonce space, so a genuine gap this large
/// can only be a wrap.
const NONCE_WRAP_THRESHOLD: u64 = 1_048_576;

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
    pub pid: u32,
    /// Most recent nonce accepted from this pid.
    pub last_nonce: u64,
    /// Observer-local timestamp (nanoseconds since [`crate::observer::Observer`]
    /// start) of the last accepted beat for this pid.
    pub last_ns: u64,
    /// Most recent [`Status`] reported by this pid.
    pub status: Status,
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
}

/// Bounded per-pid liveness ledger.
///
/// The slot table is a `Vec<Slot>` pre-allocated at construction to the
/// configured capacity; subsequent inserts push into that pre-allocated
/// space without reallocation.  Lookups use a `HashMap<u32, usize>` for
/// O(1) pid-to-index mapping — the linear scan was replaced because at
/// MAX_CAPACITY (4096) every frame arrival triggered a scan of up to
/// 4096 slots, competing with I/O polling and Prometheus serving.
pub struct Tracker {
    entries: Vec<Slot>,
    len: usize,
    pid_to_index: HashMap<u32, usize>,
    evictions: u64,
    capacity_exceeded: u64,
    nonce_wraps: u64,
    last_evicted_pid: Option<u32>,
    eviction_policy: EvictionPolicy,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY, EvictionPolicy::Strict)
    }
}

impl Tracker {
    /// Create an empty tracker with capacity for `capacity` pids.
    ///
    /// The slot table is pre-allocated to `capacity` entries; pushing
    /// beyond that boundary yields [`Update::CapacityExceeded`] rather
    /// than reallocating.
    pub fn new(capacity: usize, eviction_policy: EvictionPolicy) -> Self {
        let cap = capacity.min(MAX_CAPACITY);
        let map_cap = cap
            .saturating_mul(8)
            .saturating_div(7)
            .saturating_add(1)
            .min(MAX_CAPACITY * 2);
        Tracker {
            entries: Vec::with_capacity(cap),
            len: 0,
            pid_to_index: HashMap::with_capacity(map_cap),
            evictions: 0,
            capacity_exceeded: 0,
            nonce_wraps: 0,
            last_evicted_pid: None,
            eviction_policy,
        }
    }

    /// Record a frame against the tracker.
    ///
    /// Uses O(1) HashMap pid lookup to find the slot for `frame.pid`.
    /// Returns [`Update::Inserted`] for a brand-new pid, [`Update::Refreshed`]
    /// for an existing pid whose nonce moved forward, [`Update::OutOfOrder`]
    /// if the nonce did not strictly increase, or [`Update::CapacityExceeded`]
    /// if the slot table is full (and no stale slot could be reclaimed) and
    /// the pid is not yet tracked.
    pub fn record(&mut self, frame: &Frame, now_ns: u64, threshold_ns: u64) -> Update {
        let status = frame.status;

        if let Some(&idx) = self.pid_to_index.get(&frame.pid) {
            let slot = &mut self.entries[idx];
            if slot.used {
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
                        slot.stall_emitted = false;
                        self.nonce_wraps = self.nonce_wraps.saturating_add(1);
                        return Update::Refreshed;
                    }
                    return Update::OutOfOrder;
                }
                slot.last_nonce = frame.nonce;
                slot.last_ns = now_ns;
                slot.status = status;
                slot.stall_emitted = false;
                return Update::Refreshed;
            }
        }

        if self.len >= self.entries.capacity() {
            if let Some(evict_idx) = self.find_evictable_slot(now_ns, threshold_ns) {
                let evicted_pid = self.entries[evict_idx].pid;
                self.pid_to_index.remove(&evicted_pid);
                self.entries[evict_idx] = Slot {
                    pid: frame.pid,
                    last_nonce: frame.nonce,
                    last_ns: now_ns,
                    status,
                    used: true,
                    stall_emitted: false,
                };
                self.pid_to_index.insert(frame.pid, evict_idx);
                self.evictions = self.evictions.saturating_add(1);
                self.last_evicted_pid = Some(evicted_pid);
                return Update::Inserted;
            }
            self.capacity_exceeded = self.capacity_exceeded.saturating_add(1);
            return Update::CapacityExceeded;
        }
        let idx = self.len;
        self.entries.push(Slot {
            pid: frame.pid,
            last_nonce: frame.nonce,
            last_ns: now_ns,
            status,
            used: true,
            stall_emitted: false,
        });
        self.pid_to_index.insert(frame.pid, idx);
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
    /// Among eligible slots the one with the oldest `last_ns` is chosen
    /// (oldest-dead-first). If no slot satisfies both criteria and the
    /// policy is [`EvictionPolicy::Strict`], returns `None` and the caller
    /// receives [`Update::CapacityExceeded`].
    ///
    /// When the policy is [`EvictionPolicy::Balanced`] and no
    /// strictly-evictable slot exists, a second pass picks the oldest slot
    /// by `last_ns` whose silence exceeds the same threshold — disregarding
    /// `stall_emitted`. This prevents capacity-exhaustion attacks at the
    /// expense of potentially evicting a slow-but-alive agent.
    fn find_evictable_slot(&self, now_ns: u64, threshold_ns: u64) -> Option<usize> {
        let evict_threshold = threshold_ns.saturating_mul(EVICTION_MULTIPLIER as u64);
        let mut best_idx: Option<usize> = None;
        let mut best_last_ns: u64 = u64::MAX;

        for (idx, slot) in self.entries[..self.len].iter().enumerate() {
            if slot.stall_emitted
                && now_ns.saturating_sub(slot.last_ns) > evict_threshold
                && slot.last_ns < best_last_ns
            {
                best_last_ns = slot.last_ns;
                best_idx = Some(idx);
            }
        }
        if best_idx.is_some() {
            return best_idx;
        }
        if self.eviction_policy == EvictionPolicy::Balanced {
            best_last_ns = u64::MAX;
            for (idx, slot) in self.entries[..self.len].iter().enumerate() {
                if now_ns.saturating_sub(slot.last_ns) > evict_threshold
                    && slot.last_ns < best_last_ns
                {
                    best_last_ns = slot.last_ns;
                    best_idx = Some(idx);
                }
            }
        }
        best_idx
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
            .get(&pid)
            .map(|&idx| self.entries[idx].last_ns)
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
    /// is invoked with `(pid, last_nonce, last_ns)` — all within the same
    /// mutable borrow, closing the TOCTOU window that existed between the
    /// former `iter_stalled` / `mark_stall_emitted` pair.
    pub fn drain_stalled_slots(
        &mut self,
        now_ns: u64,
        threshold_ns: u64,
        mut cb: impl FnMut(u32, u64, u64),
    ) {
        for slot in &mut self.entries[..self.len] {
            if !slot.used || slot.stall_emitted {
                continue;
            }
            if now_ns.saturating_sub(slot.last_ns) >= threshold_ns {
                slot.stall_emitted = true;
                cb(slot.pid, slot.last_nonce, slot.last_ns);
            }
        }
    }
}
