//! Open-addressed pid→slot-index lookup table.

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
