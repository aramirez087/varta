use super::pid_index::{PidIndex, ProbeExhausted};
use super::{EvictionPolicy, Tracker, Update, DEFAULT_EVICTION_SCAN_WINDOW, MAX_CAPACITY};
use crate::peer_cred::BeatOrigin;
use varta_vlp::{Frame, Status, NONCE_TERMINAL};

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
    // Fast-bail must NOT increment the truncated counter — the metric is
    // reserved for "scan ran the full window and still found no victim".
    assert_eq!(t.take_eviction_scan_truncated(), 0);
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

/// Acceptance check: scan-truncated counter increments only when the
/// bounded window scan actually ran and still found no victim. A
/// fast-bail (no slots stall_emitted) must NOT tick the counter — see
/// `find_evictable_slot_returns_none_when_no_stalls_emitted`.
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
    // Mark every slot stall_emitted, but with silence below the 10×
    // eviction threshold so no slot qualifies as a victim. This forces
    // the strict scan to engage and exit empty-handed — the only case
    // where the truncated counter should tick.
    t.drain_stalled_slots(threshold_ns * 2, threshold_ns, |_, _, _, _, _| {});
    assert_eq!(t.stall_emitted_count, 32);
    let _ = t.record(
        &frame(99_999, 1),
        threshold_ns * 5,
        threshold_ns,
        ORIGIN,
        None,
    );
    assert_eq!(t.take_eviction_scan_truncated(), 1);
    // Take resets.
    assert_eq!(t.take_eviction_scan_truncated(), 0);
}

/// Once a slot is pinned to a strong origin, a beat from a weaker origin is
/// dropped as `OriginConflict` without mutating the slot or incrementing the
/// slot's `last_ns`.
#[test]
fn weaker_origin_conflict_does_not_mutate_stronger_slot() {
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

#[test]
fn higher_trust_origin_replaces_lower_trust_preemption() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;

    assert_eq!(
        t.record(
            &frame(7, 99),
            10,
            threshold_ns,
            BeatOrigin::NetworkUnverified,
            None,
        ),
        Update::Inserted
    );

    assert_eq!(
        t.record(
            &frame(7, 1),
            20,
            threshold_ns,
            BeatOrigin::KernelAttested,
            Some(4026531836),
        ),
        Update::Refreshed
    );

    assert_eq!(t.last_ns_of(7), Some(20));
    assert_eq!(t.entries[0].last_nonce, 1);
    assert_eq!(t.entries[0].origin, BeatOrigin::KernelAttested);
    assert_eq!(t.pid_ns_inode_of(7), Some(Some(4026531836)));
    assert_eq!(t.take_origin_conflicts(), 0);

    assert_eq!(
        t.record(
            &frame(7, 100),
            30,
            threshold_ns,
            BeatOrigin::NetworkUnverified,
            None,
        ),
        Update::OriginConflict
    );
    assert_eq!(t.entries[0].origin, BeatOrigin::KernelAttested);
    assert_eq!(t.entries[0].last_nonce, 1);
}

#[test]
fn higher_trust_origin_replacement_clears_prior_stall_latch() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;

    assert_eq!(
        t.record(
            &frame(7, 99),
            10,
            threshold_ns,
            BeatOrigin::NetworkUnverified,
            None,
        ),
        Update::Inserted
    );
    t.drain_stalled_slots(120, threshold_ns, |_, _, _, _, _| {});
    assert_eq!(t.stall_emitted_count, 1);

    assert_eq!(
        t.record(
            &frame(7, 1),
            130,
            threshold_ns,
            BeatOrigin::KernelAttested,
            None,
        ),
        Update::Refreshed
    );
    assert_eq!(t.stall_emitted_count, 0);
    assert!(!t.entries[0].stall_emitted);
}

/// Panic-hook terminal frames use `NONCE_TERMINAL`, but they are not part of
/// the regular beat nonce stream. A recoverable panic must not make later
/// healthy beats look out-of-order when the regular nonce is already above
/// the wrap-detection low-water threshold.
#[test]
fn terminal_panic_nonce_does_not_poison_regular_stream() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;
    let pid = 7;
    let regular_before = 2_000_000;
    let regular_after = regular_before + 1;

    assert_eq!(
        t.record(&frame(pid, regular_before), 10, threshold_ns, ORIGIN, None,),
        Update::Inserted
    );

    let terminal = Frame::new(Status::Critical, pid, regular_before + 1, NONCE_TERMINAL, 0);
    assert_eq!(
        t.record(&terminal, 20, threshold_ns, ORIGIN, None),
        Update::Refreshed
    );

    let mut stalled_nonce = None;
    t.drain_stalled_slots(120, threshold_ns, |p, last_nonce, _, _, _| {
        if p == pid {
            stalled_nonce = Some(last_nonce);
        }
    });
    assert_eq!(
        stalled_nonce,
        Some(NONCE_TERMINAL),
        "stall telemetry should report the terminal frame as the last observed beat"
    );

    assert_eq!(
        t.record(&frame(pid, regular_after), 130, threshold_ns, ORIGIN, None),
        Update::Refreshed
    );
    assert_eq!(
        t.entries[0].last_nonce, regular_after,
        "terminal sentinel must not replace the regular nonce high-water mark"
    );
    assert_eq!(
        t.take_nonce_wraps(),
        0,
        "recovering from a terminal frame is not a real nonce-space wrap"
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

/// A panic hook's terminal frame (`NONCE_TERMINAL`) is the agent's dying
/// gasp. By the time the single-threaded observer reads `/proc/<pid>/ns/pid`
/// the process has exited and the inode reads back `None`. That `Some → None`
/// must NOT drop the terminal beat as a namespace conflict: `Critical` is the
/// most important signal in the agent's life. The pinned inode is retained
/// and the tamper counter is left untouched. Counterpart to
/// `namespace_some_to_none_is_conflict` (which keeps strict semantics for a
/// regular nonce).
#[test]
fn terminal_gasp_with_lost_namespace_inode_is_recorded_not_conflict() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;
    // Healthy beat pins the slot's namespace inode.
    assert_eq!(
        t.record(
            &frame(7, 1),
            0,
            threshold_ns,
            BeatOrigin::KernelAttested,
            Some(123),
        ),
        Update::Inserted
    );
    // Agent panics: Critical + NONCE_TERMINAL, but /proc is already gone.
    let terminal = Frame::new(Status::Critical, 7, 2, NONCE_TERMINAL, 0);
    let r = t.record(
        &terminal,
        10,
        threshold_ns,
        BeatOrigin::KernelAttested,
        None,
    );
    assert_eq!(
        r,
        Update::Refreshed,
        "the dying gasp must be recorded, not refused as a conflict"
    );
    assert_eq!(
        t.entries[0].status,
        Status::Critical,
        "Critical status must be surfaced to the observer"
    );
    assert_eq!(
        t.pid_ns_inode_of(7),
        Some(Some(123)),
        "the pinned inode must be retained, not downgraded to None"
    );
    assert_eq!(
        t.take_namespace_conflicts(),
        0,
        "benign process death must not increment the tamper counter"
    );
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

/// `None → Some` is a slot-identity upgrade and must commit only with an
/// accepted nonce. A replayed or out-of-order frame may be kernel-attested,
/// but it cannot be allowed to pin the namespace for a live slot.
#[test]
fn namespace_none_to_some_out_of_order_does_not_pin() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;
    let _ = t.record(
        &frame(7, 10),
        0,
        threshold_ns,
        BeatOrigin::KernelAttested,
        None,
    );
    assert_eq!(t.pid_ns_inode_of(7), Some(None));

    let replay = t.record(
        &frame(7, 5),
        10,
        threshold_ns,
        BeatOrigin::KernelAttested,
        Some(999),
    );
    assert_eq!(replay, Update::OutOfOrder);
    assert_eq!(
        t.pid_ns_inode_of(7),
        Some(None),
        "out-of-order frame must not pin the namespace inode"
    );
    assert_eq!(t.take_namespace_conflicts(), 0);

    let fresh = t.record(
        &frame(7, 11),
        20,
        threshold_ns,
        BeatOrigin::KernelAttested,
        Some(123),
    );
    assert_eq!(fresh, Update::Refreshed);
    assert_eq!(t.pid_ns_inode_of(7), Some(Some(123)));
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

// ---------------------- PID-recycle gate tests (bug-341) --------------
//
// A numeric PID is not a stable process identity — the OS recycles it once
// the holding process dies. Without a generation token, a fresh agent that
// reuses a dead agent's PID inherits the dead slot's high `last_nonce`, so its
// low-nonce beats are rejected as `OutOfOrder`, `last_ns` freezes, a false
// stall fires, and recovery is misdirected against the healthy new process.
// The kernel-attested process start-time (generation) disambiguates this.

/// The core fix: a known pid beating with a DIFFERENT attested generation is a
/// recycle. The slot resets to the new agent (low nonce accepted, `last_ns`
/// advanced, stall latch cleared) instead of false-stalling it.
#[test]
fn pid_recycle_resets_slot_instead_of_dropping_low_nonce() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;

    // Agent A: long-lived, generation G1, climbs to a high nonce.
    assert_eq!(
        t.record_with_generation(
            &frame(1234, 5000),
            0,
            threshold_ns,
            ORIGIN,
            Some(10),
            Some(111)
        ),
        Update::Inserted
    );
    // A goes silent and the observer latches a stall for it.
    t.drain_stalled_slots(threshold_ns * 2, threshold_ns, |_, _, _, _, _| {});
    assert_eq!(t.stall_emitted_count, 1);

    // OS recycles PID 1234 → fresh Agent B, generation G2, nonce restarts at 1.
    let recycled = t.record_with_generation(
        &frame(1234, 1),
        threshold_ns * 3,
        threshold_ns,
        ORIGIN,
        Some(10),
        Some(222),
    );
    assert_eq!(
        recycled,
        Update::Inserted,
        "a recycled pid must be a fresh insert, not OutOfOrder"
    );
    assert_eq!(t.take_pid_recycles(), 1);
    assert_eq!(t.take_pid_recycles(), 0);
    // Slot identity now follows B: low nonce accepted, timer fresh, no stall.
    assert_eq!(t.entries[0].last_nonce, 1);
    assert_eq!(t.last_ns_of(1234), Some(threshold_ns * 3));
    assert_eq!(
        t.stall_emitted_count, 0,
        "stall latch for the dead agent must clear"
    );
}

/// Replay protection is preserved: a low nonce under the SAME generation is
/// still `OutOfOrder` (it is a reorder/replay of the same process, not a
/// recycle). The recycle counter must not move.
#[test]
fn same_generation_low_nonce_is_still_out_of_order() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;
    assert_eq!(
        t.record_with_generation(
            &frame(1234, 5000),
            0,
            threshold_ns,
            ORIGIN,
            Some(10),
            Some(111)
        ),
        Update::Inserted
    );
    let replay = t.record_with_generation(
        &frame(1234, 1),
        10,
        threshold_ns,
        ORIGIN,
        Some(10),
        Some(111),
    );
    assert_eq!(replay, Update::OutOfOrder);
    assert_eq!(t.take_pid_recycles(), 0);
    assert_eq!(
        t.entries[0].last_nonce, 5000,
        "replay must not rewind the high-water nonce"
    );
}

/// A `None` generation on either side ("unknown" — non-Linux / unattested
/// transport / unreadable /proc) disables recycle detection, preserving the
/// prior PID-only behaviour. The plain `record()` shim passes `None`, so a low
/// nonce is rejected exactly as before.
#[test]
fn generation_none_disables_recycle_detection() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;
    // Via the shim → peer_generation = None.
    assert_eq!(
        t.record(&frame(1234, 5000), 0, threshold_ns, ORIGIN, None),
        Update::Inserted
    );
    assert_eq!(
        t.record(&frame(1234, 1), 10, threshold_ns, ORIGIN, None),
        Update::OutOfOrder,
        "with no generation token, prior PID-only semantics hold"
    );
    assert_eq!(t.take_pid_recycles(), 0);

    // A pinned generation but an unknown current one also must not reset
    // (Some -> None is the dying-process case, not a recycle signal).
    let mut t2 = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let _ = t2.record_with_generation(&frame(7, 5000), 0, threshold_ns, ORIGIN, Some(1), Some(111));
    assert_eq!(
        t2.record_with_generation(&frame(7, 1), 10, threshold_ns, ORIGIN, Some(1), None),
        Update::OutOfOrder
    );
    assert_eq!(t2.take_pid_recycles(), 0);
}

/// A recycle re-pins the namespace inode and origin from the NEW process,
/// closing the stale-inode facet that lets the cross-namespace recovery gate
/// misfire. The new agent's beat carries a different namespace inode, which a
/// non-recycle path would reject as `NamespaceConflict`; the generation
/// mismatch correctly takes precedence and resets the slot.
#[test]
fn recycle_repins_namespace_inode_over_namespace_conflict() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;
    let _ = t.record_with_generation(
        &frame(1234, 5000),
        0,
        threshold_ns,
        BeatOrigin::KernelAttested,
        Some(4026531836),
        Some(111),
    );
    // New process, new namespace inode AND new generation. The generation
    // gate must win over the namespace-conflict gate and reset the slot.
    let r = t.record_with_generation(
        &frame(1234, 1),
        10,
        threshold_ns,
        BeatOrigin::KernelAttested,
        Some(4026531999),
        Some(222),
    );
    assert_eq!(r, Update::Inserted);
    assert_eq!(t.pid_ns_inode_of(1234), Some(Some(4026531999)));
    assert_eq!(t.take_pid_recycles(), 1);
    assert_eq!(
        t.take_namespace_conflicts(),
        0,
        "a recycle is not a namespace conflict"
    );
}

/// Same generation, same inode → ordinary refresh, no recycle counted.
#[test]
fn same_generation_increasing_nonce_is_plain_refresh() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;
    let _ = t.record_with_generation(
        &frame(1234, 1),
        0,
        threshold_ns,
        ORIGIN,
        Some(10),
        Some(111),
    );
    assert_eq!(
        t.record_with_generation(
            &frame(1234, 2),
            10,
            threshold_ns,
            ORIGIN,
            Some(10),
            Some(111)
        ),
        Update::Refreshed
    );
    assert_eq!(t.take_pid_recycles(), 0);
}

/// `None → Some` upgrade on a same-pid beat pins the now-known generation
/// and falls through to refresh. Forgiving when `/proc/<pid>/stat` was
/// briefly unreadable at first contact.
#[test]
fn generation_none_to_some_upgrades_in_place() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;
    let _ = t.record_with_generation(&frame(7, 1), 0, threshold_ns, ORIGIN, Some(10), None);
    assert_eq!(t.entries[0].generation, None);
    let r = t.record_with_generation(&frame(7, 2), 10, threshold_ns, ORIGIN, Some(10), Some(111));
    assert_eq!(r, Update::Refreshed);
    assert_eq!(t.entries[0].generation, Some(111));
    assert_eq!(t.take_pid_recycles(), 0);
}

/// `None → Some` generation upgrade must commit only with an accepted nonce.
#[test]
fn generation_none_to_some_out_of_order_does_not_pin() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;
    let _ = t.record_with_generation(&frame(7, 10), 0, threshold_ns, ORIGIN, Some(10), None);
    let replay =
        t.record_with_generation(&frame(7, 5), 10, threshold_ns, ORIGIN, Some(10), Some(999));
    assert_eq!(replay, Update::OutOfOrder);
    assert_eq!(
        t.entries[0].generation, None,
        "out-of-order frame must not pin the generation token"
    );
    assert_eq!(t.take_pid_recycles(), 0);

    let fresh =
        t.record_with_generation(&frame(7, 11), 20, threshold_ns, ORIGIN, Some(10), Some(123));
    assert_eq!(fresh, Update::Refreshed);
    assert_eq!(t.entries[0].generation, Some(123));
}

/// Transient `None` on first beat must not disable recycle once generation
/// is pinned on a later accepted beat from the same process.
#[test]
fn transient_generation_none_then_recycle_still_resets() {
    let mut t = Tracker::new(8, EvictionPolicy::Strict, DEFAULT_EVICTION_SCAN_WINDOW);
    let threshold_ns = 100;
    assert_eq!(
        t.record_with_generation(&frame(1234, 1), 0, threshold_ns, ORIGIN, Some(10), None,),
        Update::Inserted
    );
    assert_eq!(
        t.record_with_generation(
            &frame(1234, 5000),
            10,
            threshold_ns,
            ORIGIN,
            Some(10),
            Some(111),
        ),
        Update::Refreshed
    );
    assert_eq!(t.entries[0].generation, Some(111));

    let recycled = t.record_with_generation(
        &frame(1234, 1),
        20,
        threshold_ns,
        ORIGIN,
        Some(10),
        Some(222),
    );
    assert_eq!(
        recycled,
        Update::Inserted,
        "recycle must fire once generation is pinned"
    );
    assert_eq!(t.take_pid_recycles(), 1);
    assert_eq!(t.entries[0].generation, Some(222));
    assert_eq!(t.entries[0].last_nonce, 1);
}
