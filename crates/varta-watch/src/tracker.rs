//! Per-pid liveness tracker backed by a fixed `[Slot; 64]` array.
//!
//! The tracker is the in-memory ledger the observer consults each time a
//! frame arrives or the read timeout expires. It never reallocates: capacity
//! is a compile-time constant and an exhausted tracker yields
//! [`Update::CapacityExceeded`] rather than growing.

use varta_vlp::{Frame, Status};

/// Maximum number of distinct agents the observer can track concurrently.
///
/// v0.1.0 ships with a fixed budget; the bench session pins this number in
/// the CPU target (50 agents × 1 Hz). Override via `--tracker-capacity`.
pub const DEFAULT_CAPACITY: usize = 64;

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
/// space without reallocation. Lookups are linear scans. At typical
/// capacities (≤ 256 entries) the linear scan beats hashing on branch
/// predictability and zero allocation overhead after setup.
pub struct Tracker {
    entries: Vec<Slot>,
    len: usize,
    evictions: u64,
    capacity_exceeded: u64,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl Tracker {
    /// Create an empty tracker with capacity for `capacity` pids.
    ///
    /// The slot table is pre-allocated to `capacity` entries; pushing
    /// beyond that boundary yields [`Update::CapacityExceeded`] rather
    /// than reallocating.
    pub fn new(capacity: usize) -> Self {
        Tracker {
            entries: Vec::with_capacity(capacity),
            len: 0,
            evictions: 0,
            capacity_exceeded: 0,
        }
    }

    /// Record a frame against the tracker.
    ///
    /// Returns [`Update::Inserted`] for a brand-new pid, [`Update::Refreshed`]
    /// for an existing pid whose nonce moved forward, [`Update::OutOfOrder`]
    /// if the nonce did not strictly increase, or [`Update::CapacityExceeded`]
    /// if the slot table is full (and no stale slot could be reclaimed) and
    /// the pid is not yet tracked.
    pub fn record(&mut self, frame: &Frame, now_ns: u64, threshold_ns: u64) -> Update {
        let status = frame.status;

        for slot in &mut self.entries[..self.len] {
            if !slot.used {
                continue;
            }
            if slot.pid == frame.pid {
                if frame.nonce <= slot.last_nonce {
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
                self.entries[evict_idx] = Slot {
                    pid: frame.pid,
                    last_nonce: frame.nonce,
                    last_ns: now_ns,
                    status,
                    used: true,
                    stall_emitted: false,
                };
                self.evictions = self.evictions.saturating_add(1);
                return Update::Inserted;
            }
            self.capacity_exceeded = self.capacity_exceeded.saturating_add(1);
            return Update::CapacityExceeded;
        }
        self.entries.push(Slot {
            pid: frame.pid,
            last_nonce: frame.nonce,
            last_ns: now_ns,
            status,
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
    /// Among eligible slots the one with the oldest `last_ns` is chosen
    /// (oldest-dead-first). If no slot satisfies both criteria, returns
    /// `None` and the caller receives [`Update::CapacityExceeded`].
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
        best_idx
    }

    /// Take and reset the eviction counter. Returns the number of slots
    /// reclaimed since the last call.
    pub fn take_evictions(&mut self) -> u64 {
        let count = self.evictions;
        self.evictions = 0;
        count
    }

    /// Take and reset the capacity-exceeded counter. Returns the number of
    /// beats dropped due to a full tracker since the last call.
    pub fn take_capacity_exceeded(&mut self) -> u64 {
        let count = self.capacity_exceeded;
        self.capacity_exceeded = 0;
        count
    }

    /// Iterator over every slot whose silence (relative to `now_ns`) has
    /// crossed `threshold_ns`, regardless of whether the observer has already
    /// surfaced a stall event for it.
    pub fn iter_stalled(&self, now_ns: u64, threshold_ns: u64) -> impl Iterator<Item = &Slot> + '_ {
        self.entries[..self.len]
            .iter()
            .filter(move |slot| now_ns.saturating_sub(slot.last_ns) >= threshold_ns)
    }

    /// Number of pids currently tracked.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True iff no pids are tracked.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Mark a pid's slot as having had its stall event surfaced. The latch is
    /// cleared automatically on the next [`Tracker::record`] call for the
    /// same pid. No-op if the pid is unknown.
    pub(crate) fn mark_stall_emitted(&mut self, pid: u32) {
        for slot in &mut self.entries[..self.len] {
            if slot.used && slot.pid == pid {
                slot.stall_emitted = true;
                return;
            }
        }
    }
}
