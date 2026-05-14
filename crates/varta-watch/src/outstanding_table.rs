#![allow(missing_docs)]
//! Bounded slab + pid-indexed lookup for [`crate::recovery::Recovery`]'s
//! outstanding-child bookkeeping.
//!
//! Replaces `HashMap<u32, Outstanding>` in `recovery.rs`. The slab is
//! pre-allocated at `capacity` and never reallocates; the index is a
//! `BoundedIndex<u32>` so every operation has the same WCET bound as the
//! tracker hot path (see `probe_table.rs`).
//!
//! Capacity is set from the observer's `tracker_capacity` at construction
//! so the table can hold one outstanding child per tracked agent — the
//! same implicit bound the old `HashMap` already had, but now enforced
//! structurally with a fail-graceful `InsertError::Full` outcome.

use crate::probe_table::{BoundedIndex, ProbeExhausted};

/// Returned by [`OutstandingTable::try_insert`] when the table cannot
/// accept the new entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertError {
    /// `pid` already has an outstanding child. Recovery's call site is
    /// guarded by `contains` before insert, so this is unreachable in
    /// well-behaved code — paths that hit it fall through to a
    /// debug-assert.
    AlreadyPresent,
    /// Slab is full (one slot per tracked agent already in flight) or
    /// the index ran out of probe budget. The caller should treat this
    /// as a fail-closed refusal; in `Recovery` it surfaces as
    /// `RecoveryOutcome::RefusedOutstandingCapacity`.
    Full,
}

impl From<ProbeExhausted> for InsertError {
    fn from(_: ProbeExhausted) -> Self {
        InsertError::Full
    }
}

pub struct OutstandingTable<V> {
    /// One slot per pid. `Some(value)` for occupied; `None` for free.
    /// Length is fixed at construction and never reallocates.
    slab: Vec<Option<V>>,
    /// LIFO of available slab indices. Initialised to
    /// `(0..capacity).rev()` so the first insert lands at slot 0.
    free_list: Vec<u32>,
    /// `pid → slab index` mapping. Sized identically to the slab so the
    /// load factor invariant for `BoundedIndex` holds.
    pid_to_slot: BoundedIndex<u32>,
}

impl<V> OutstandingTable<V> {
    pub fn with_capacity(capacity: usize) -> Self {
        debug_assert!(capacity > 0, "OutstandingTable capacity must be > 0");
        let mut slab = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slab.push(None);
        }
        let mut free_list = Vec::with_capacity(capacity);
        for i in (0..capacity as u32).rev() {
            free_list.push(i);
        }
        Self {
            slab,
            free_list,
            pid_to_slot: BoundedIndex::new(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.pid_to_slot.len()
    }

    pub fn capacity(&self) -> usize {
        self.slab.len()
    }

    pub fn contains(&self, pid: u32) -> bool {
        self.pid_to_slot.get(pid).is_some()
    }

    #[allow(dead_code)]
    pub fn get(&self, pid: u32) -> Option<&V> {
        let idx = self.pid_to_slot.get(pid)?;
        self.slab.get(idx)?.as_ref()
    }

    pub fn get_mut(&mut self, pid: u32) -> Option<&mut V> {
        let idx = self.pid_to_slot.get(pid)?;
        self.slab.get_mut(idx)?.as_mut()
    }

    /// Insert `value` for `pid`. Returns
    /// [`InsertError::AlreadyPresent`] without touching the slab if `pid`
    /// is already mapped (caller is responsible for guarding against this
    /// with `contains` if it wants distinct semantics).
    pub fn try_insert(&mut self, pid: u32, value: V) -> Result<(), InsertError> {
        if self.pid_to_slot.get(pid).is_some() {
            return Err(InsertError::AlreadyPresent);
        }
        let Some(slot_idx) = self.free_list.pop() else {
            return Err(InsertError::Full);
        };
        // Reserve the index in the probe table first. If it fails we
        // must return the slot to the free list so we don't leak
        // capacity.
        if let Err(e) = self.pid_to_slot.insert(pid, slot_idx as usize) {
            self.free_list.push(slot_idx);
            return Err(e.into());
        }
        if let Some(slot) = self.slab.get_mut(slot_idx as usize) {
            *slot = Some(value);
            Ok(())
        } else {
            // Slab index from `free_list` should always be in range; if
            // not, surface as Full and roll back the probe-table insert.
            self.pid_to_slot.remove(pid);
            self.free_list.push(slot_idx);
            Err(InsertError::Full)
        }
    }

    pub fn remove(&mut self, pid: u32) -> Option<V> {
        let slot_idx = self.pid_to_slot.remove(pid)?;
        let taken = self.slab.get_mut(slot_idx)?.take();
        if taken.is_some() {
            // Return the index to the free list only when we actually
            // freed a slot. If `taken` is `None` the slab and index were
            // already out of sync; surface `None` and let the
            // probe-exhausted counter remain a diagnostic surface.
            self.free_list.push(slot_idx as u32);
        }
        taken
    }

    /// Iterate the pids of live entries. Order is the probe table's
    /// internal order — not insertion order — but is deterministic for a
    /// given sequence of inserts and removes.
    pub fn iter_pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.pid_to_slot.iter().map(|(pid, _)| pid)
    }

    /// Drain every live entry. Resets the slab to all-free, clears the
    /// pid index, and rebuilds the free list. Used by `Recovery::Drop` to
    /// kill all outstanding children at shutdown.
    pub fn drain(&mut self) -> impl Iterator<Item = V> + '_ {
        self.pid_to_slot.clear();
        self.free_list.clear();
        for i in (0..self.slab.len() as u32).rev() {
            self.free_list.push(i);
        }
        // `Vec::iter_mut().filter_map(Option::take)` yields owned values
        // and leaves each slot in `None` state.
        self.slab.iter_mut().filter_map(Option::take)
    }

    pub fn take_probe_exhausted(&mut self) -> u64 {
        self.pid_to_slot.take_probe_exhausted()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_remove_roundtrip() {
        let mut t: OutstandingTable<&'static str> = OutstandingTable::with_capacity(4);
        assert_eq!(t.len(), 0);
        t.try_insert(10, "a").unwrap();
        t.try_insert(20, "b").unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(t.get(10), Some(&"a"));
        assert_eq!(t.get(20), Some(&"b"));
        assert_eq!(t.get(30), None);

        assert_eq!(t.remove(10), Some("a"));
        assert_eq!(t.len(), 1);
        assert!(!t.contains(10));
        assert!(t.contains(20));
    }

    #[test]
    fn double_insert_returns_already_present() {
        let mut t: OutstandingTable<u32> = OutstandingTable::with_capacity(4);
        t.try_insert(7, 100).unwrap();
        assert_eq!(t.try_insert(7, 200), Err(InsertError::AlreadyPresent));
        // Original value untouched.
        assert_eq!(t.get(7), Some(&100));
    }

    #[test]
    fn insert_full_returns_full_and_no_capacity_leak() {
        let mut t: OutstandingTable<u32> = OutstandingTable::with_capacity(3);
        t.try_insert(1, 1).unwrap();
        t.try_insert(2, 2).unwrap();
        t.try_insert(3, 3).unwrap();
        assert_eq!(t.try_insert(4, 4), Err(InsertError::Full));
        // Remove one and confirm a new insert succeeds — i.e. Full
        // outcomes didn't leak capacity from the free list.
        assert_eq!(t.remove(2), Some(2));
        t.try_insert(4, 4).unwrap();
        assert_eq!(t.get(4), Some(&4));
    }

    #[test]
    fn iter_pids_mirrors_inserts() {
        let mut t: OutstandingTable<u32> = OutstandingTable::with_capacity(8);
        for k in [3u32, 7, 11, 13] {
            t.try_insert(k, k).unwrap();
        }
        let mut seen: Vec<u32> = t.iter_pids().collect();
        seen.sort_unstable();
        assert_eq!(seen, vec![3, 7, 11, 13]);
    }

    #[test]
    fn drain_yields_all_and_resets_table() {
        let mut t: OutstandingTable<u32> = OutstandingTable::with_capacity(4);
        for k in [1u32, 2, 3, 4] {
            t.try_insert(k, k * 10).unwrap();
        }
        let mut drained: Vec<u32> = t.drain().collect();
        drained.sort_unstable();
        assert_eq!(drained, vec![10, 20, 30, 40]);
        assert_eq!(t.len(), 0);
        assert!(!t.contains(1));
        // Table is reusable post-drain.
        t.try_insert(99, 999).unwrap();
        assert_eq!(t.get(99), Some(&999));
    }

    #[test]
    fn remove_of_absent_pid_is_none() {
        let mut t: OutstandingTable<u32> = OutstandingTable::with_capacity(4);
        assert_eq!(t.remove(123), None);
        t.try_insert(1, 1).unwrap();
        assert_eq!(t.remove(2), None);
        assert!(t.contains(1));
    }
}
