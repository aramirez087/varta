//! Per-pid liveness tracker backed by a fixed `[Slot; 64]` array with
//! O(1) pid lookup via `HashMap<u32, usize>`.
//!
//! The tracker is the in-memory ledger the observer consults each time a
//! frame arrives or the read timeout expires. It never reallocates: capacity
//! is a compile-time constant and an exhausted tracker yields
//! [`Update::CapacityExceeded`] rather than growing.

use std::collections::HashMap;

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

/// Maximum number of slots scanned per [`Tracker::find_evictable_slot`] call.
///
/// The eviction scan used to be O(`len`) — at [`MAX_CAPACITY`] = 4096 that
/// meant up to 4096 slot reads on **every** new-pid frame once the table was
/// full. An attacker who could send beats from many unique pids could
/// therefore force O(n) work per arriving frame on the single-threaded
/// observer poll loop.
///
/// The scan is now bounded to this window, with a rotating cursor
/// ([`Tracker::eviction_scan_cursor`]) that resumes where the previous call
/// left off. First-fit eviction inside the window is correct under capacity
/// pressure (any slot whose silence exceeds `threshold * EVICTION_MULTIPLIER`
/// is a valid victim — they are by definition not actively beating).
///
/// 256 was chosen as a compromise: large enough that a single call typically
/// finds a victim on tables of 1–2 k pids, small enough that the per-frame
/// upper bound stays well under the existing observer-tick budget.
const EVICTION_SCAN_WINDOW: usize = 256;

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
    /// Transport origin pinned at the slot's first beat. Used to gate
    /// recovery-eligibility — beats from a different origin than the pinned
    /// one are rejected as [`Update::OriginConflict`] without mutating the
    /// slot. See [`BeatOrigin`] for the trust model.
    pub origin: BeatOrigin,
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
    /// Cached count of slots whose `stall_emitted` flag is currently set.
    ///
    /// Allows [`Tracker::find_evictable_slot`] to skip the strict scan
    /// entirely when no slots have surfaced a stall yet — defangs the most
    /// realistic DoS profile where an attacker fills the tracker faster
    /// than the stall threshold can elapse.
    stall_emitted_count: usize,
    /// Round-robin cursor into `entries` for the bounded eviction scan.
    /// Persists across `find_evictable_slot` calls so a sequence of N
    /// failed evictions covers the whole table in `ceil(len / WINDOW)`
    /// calls without ever scanning more than [`EVICTION_SCAN_WINDOW`]
    /// slots in a single call.
    eviction_scan_cursor: usize,
    /// Number of times the bounded eviction scan reached its window cap
    /// without finding a victim while the table was full. Surfaced via
    /// [`Tracker::take_eviction_scan_truncated`] for Prometheus.
    eviction_scan_truncated: u64,
    /// Count of beats dropped because their transport origin disagreed with
    /// the slot's pinned origin (first-origin-wins). Surfaced via
    /// [`Tracker::take_origin_conflicts`] for Prometheus.
    origin_conflicts: u64,
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
            stall_emitted_count: 0,
            eviction_scan_cursor: 0,
            eviction_scan_truncated: 0,
            origin_conflicts: 0,
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
    pub fn record(
        &mut self,
        frame: &Frame,
        now_ns: u64,
        threshold_ns: u64,
        origin: BeatOrigin,
    ) -> Update {
        let status = frame.status;

        if let Some(&idx) = self.pid_to_index.get(&frame.pid) {
            let slot = &mut self.entries[idx];
            if slot.used {
                if slot.origin != origin {
                    self.origin_conflicts = self.origin_conflicts.saturating_add(1);
                    return Update::OriginConflict;
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
                let evicted_slot = self.entries[evict_idx];
                if evicted_slot.stall_emitted {
                    self.stall_emitted_count = self.stall_emitted_count.saturating_sub(1);
                }
                self.pid_to_index.remove(&evicted_slot.pid);
                self.entries[evict_idx] = Slot {
                    pid: frame.pid,
                    last_nonce: frame.nonce,
                    last_ns: now_ns,
                    status,
                    origin,
                    used: true,
                    stall_emitted: false,
                };
                self.pid_to_index.insert(frame.pid, evict_idx);
                self.evictions = self.evictions.saturating_add(1);
                self.last_evicted_pid = Some(evicted_slot.pid);
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
            origin,
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
        let window = EVICTION_SCAN_WINDOW.min(n);
        let start = self.eviction_scan_cursor % n;
        for i in 0..window {
            let idx = (start + i) % n;
            let slot = &self.entries[idx];
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
            .get(&pid)
            .map(|&idx| self.entries[idx].last_ns)
    }

    /// Return the pinned transport origin of a tracked pid, if present.
    /// Used by the observer to populate `Event::OriginConflict::slot_origin`
    /// before calling `record` (which may produce the conflict).
    pub fn origin_of(&self, pid: u32) -> Option<BeatOrigin> {
        self.pid_to_index.get(&pid).and_then(|&idx| {
            let slot = &self.entries[idx];
            if slot.used {
                Some(slot.origin)
            } else {
                None
            }
        })
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
    /// is invoked with `(pid, last_nonce, last_ns, origin)` — all within the
    /// same mutable borrow, closing the TOCTOU window that existed between
    /// the former `iter_stalled` / `mark_stall_emitted` pair.
    pub fn drain_stalled_slots(
        &mut self,
        now_ns: u64,
        threshold_ns: u64,
        mut cb: impl FnMut(u32, u64, u64, BeatOrigin),
    ) {
        for slot in &mut self.entries[..self.len] {
            if !slot.used || slot.stall_emitted {
                continue;
            }
            if now_ns.saturating_sub(slot.last_ns) >= threshold_ns {
                slot.stall_emitted = true;
                self.stall_emitted_count = self.stall_emitted_count.saturating_add(1);
                cb(slot.pid, slot.last_nonce, slot.last_ns, slot.origin);
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

    /// Recompute `stall_emitted_count` from scratch and assert it matches
    /// the maintained counter. Cheap (single linear pass over `len` slots),
    /// gated to debug builds to keep the release-mode hot path untouched.
    #[cfg(debug_assertions)]
    fn debug_assert_stall_count(&self) {
        let observed = self.entries[..self.len]
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
        let mut t = Tracker::new(cap, EvictionPolicy::Strict);
        let threshold_ns = 1_000;
        // Fill at t=0 so silence isn't a factor either.
        for pid in 1u32..=(cap as u32) {
            assert_eq!(
                t.record(&frame(pid, 1), 0, threshold_ns, ORIGIN),
                Update::Inserted
            );
        }
        assert_eq!(t.len(), cap);
        assert_eq!(t.stall_emitted_count, 0);

        // Even at very large "now_ns" (silence >> 10× threshold), Strict
        // policy must bail without scanning: no slot has stall_emitted=true.
        let now_ns = threshold_ns * 100;
        let result = t.record(&frame(99_999, 1), now_ns, threshold_ns, ORIGIN);
        assert_eq!(result, Update::CapacityExceeded);
        // Cursor must NOT have advanced through the table (fast-bail path).
        assert_eq!(t.eviction_scan_cursor, 0);
    }

    /// drain_stalled_slots marks slots; counter must reflect that, and the
    /// next find_evictable_slot must actually scan and (eventually) succeed.
    #[test]
    fn stall_counter_enables_eviction_after_drain() {
        let cap = 8;
        let mut t = Tracker::new(cap, EvictionPolicy::Strict);
        let threshold_ns = 100;

        for pid in 1u32..=(cap as u32) {
            assert_eq!(
                t.record(&frame(pid, 1), 0, threshold_ns, ORIGIN),
                Update::Inserted
            );
        }
        // Time advances past threshold — every slot stalls.
        let now_ns = threshold_ns * 20;
        let mut stalled = 0u32;
        t.drain_stalled_slots(now_ns, threshold_ns, |_, _, _, _| stalled += 1);
        assert_eq!(stalled, cap as u32);
        assert_eq!(t.stall_emitted_count, cap);

        // Silence now exceeds 10× threshold → eviction succeeds.
        let result = t.record(&frame(9_999, 1), now_ns, threshold_ns, ORIGIN);
        assert_eq!(result, Update::Inserted);
        // The replacing slot is fresh — stall counter decremented once.
        assert_eq!(t.stall_emitted_count, cap - 1);
    }

    /// A fresh beat on a previously-stalled slot must decrement the counter.
    #[test]
    fn stall_counter_decrements_on_refresh() {
        let mut t = Tracker::new(4, EvictionPolicy::Strict);
        let threshold_ns = 100;
        assert_eq!(
            t.record(&frame(1, 1), 0, threshold_ns, ORIGIN),
            Update::Inserted
        );
        t.drain_stalled_slots(threshold_ns * 2, threshold_ns, |_, _, _, _| {});
        assert_eq!(t.stall_emitted_count, 1);

        // New beat with strictly increasing nonce → refresh and clear flag.
        assert_eq!(
            t.record(&frame(1, 2), threshold_ns * 3, threshold_ns, ORIGIN),
            Update::Refreshed
        );
        assert_eq!(t.stall_emitted_count, 0);
    }

    /// The bounded scan window must cap per-call work. Fill 4096 slots
    /// at t=0, stall them all, then verify each find_evictable_slot call
    /// advances the cursor by at most WINDOW slots.
    #[test]
    fn find_evictable_slot_scan_is_bounded_to_window() {
        let cap = MAX_CAPACITY;
        let mut t = Tracker::new(cap, EvictionPolicy::Strict);
        let threshold_ns = 100;
        for pid in 1u32..=(cap as u32) {
            assert_eq!(
                t.record(&frame(pid, 1), 0, threshold_ns, ORIGIN),
                Update::Inserted
            );
        }
        // Stall everything.
        let now_ns = threshold_ns * 20;
        t.drain_stalled_slots(now_ns, threshold_ns, |_, _, _, _| {});
        assert_eq!(t.stall_emitted_count, cap);

        // Each new-pid insert evicts one slot. Cursor must advance by ≤
        // EVICTION_SCAN_WINDOW on every miss, ≤ 1 on every hit.
        let start_cursor = t.eviction_scan_cursor;
        let _ = t.record(&frame(50_001, 1), now_ns, threshold_ns, ORIGIN);
        let advanced = t.eviction_scan_cursor.wrapping_sub(start_cursor) % cap;
        assert!(
            advanced <= EVICTION_SCAN_WINDOW,
            "cursor advanced by {advanced}, expected ≤ {EVICTION_SCAN_WINDOW}"
        );
    }

    /// Cursor must wrap past `len` correctly so a long sequence of failed
    /// evictions doesn't go out of bounds.
    #[test]
    fn scan_window_cursor_wraps_correctly() {
        let cap = 4;
        let mut t = Tracker::new(cap, EvictionPolicy::Strict);
        let threshold_ns = 100;
        for pid in 1u32..=(cap as u32) {
            assert_eq!(
                t.record(&frame(pid, 1), 0, threshold_ns, ORIGIN),
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
        let mut t = Tracker::new(32, EvictionPolicy::Balanced);
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
                    let _ = t.record(&frame(pid, now_ns), now_ns, threshold_ns, ORIGIN);
                }
                1 => {
                    // Advance and drain (may flip flags to true).
                    now_ns = now_ns.saturating_add(threshold_ns * 2);
                    t.drain_stalled_slots(now_ns, threshold_ns, |_, _, _, _| {});
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
        let mut t = Tracker::new(32, EvictionPolicy::Strict);
        let threshold_ns = 100;
        for pid in 1u32..=32 {
            assert_eq!(
                t.record(&frame(pid, 1), 0, threshold_ns, ORIGIN),
                Update::Inserted
            );
        }
        // Table full, no stalls emitted → strict bails, balanced not used →
        // counter still increments since we returned None at capacity.
        let _ = t.record(&frame(99_999, 1), threshold_ns * 100, threshold_ns, ORIGIN);
        assert_eq!(t.take_eviction_scan_truncated(), 1);
        // Take resets.
        assert_eq!(t.take_eviction_scan_truncated(), 0);
    }

    /// First-origin-wins: once a slot is pinned to an origin, a beat with a
    /// different origin is dropped as `OriginConflict` without mutating the
    /// slot or incrementing the slot's `last_ns`.
    #[test]
    fn origin_conflict_first_origin_wins() {
        let mut t = Tracker::new(8, EvictionPolicy::Strict);
        let threshold_ns = 100;

        // Beat 1 arrives via UDS (kernel-attested) and pins the slot.
        assert_eq!(
            t.record(&frame(7, 1), 10, threshold_ns, BeatOrigin::KernelAttested),
            Update::Inserted
        );

        // Beat 2 arrives via UDP with the same pid — must be rejected.
        assert_eq!(
            t.record(
                &frame(7, 2),
                20,
                threshold_ns,
                BeatOrigin::NetworkUnverified
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
            t.record(&frame(7, 3), 30, threshold_ns, BeatOrigin::KernelAttested),
            Update::Refreshed
        );
    }

    /// drain_stalled_slots propagates each slot's pinned origin to the
    /// callback so downstream consumers (Recovery) can gate on transport
    /// trust.
    #[test]
    fn drain_stalled_slots_emits_pinned_origin() {
        let mut t = Tracker::new(4, EvictionPolicy::Strict);
        let threshold_ns = 100;

        assert_eq!(
            t.record(&frame(11, 1), 0, threshold_ns, BeatOrigin::KernelAttested),
            Update::Inserted
        );
        assert_eq!(
            t.record(
                &frame(22, 1),
                0,
                threshold_ns,
                BeatOrigin::NetworkUnverified
            ),
            Update::Inserted
        );

        let mut seen: Vec<(u32, BeatOrigin)> = Vec::new();
        t.drain_stalled_slots(threshold_ns * 2, threshold_ns, |pid, _, _, origin| {
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
}
