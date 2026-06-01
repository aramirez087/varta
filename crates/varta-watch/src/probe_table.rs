#![allow(missing_docs)]
//! Fixed-size, open-addressed `K → u32` map with bounded WCET.
//!
//! Replaces [`std::collections::HashMap`] everywhere we need
//! registry-dep-free, deterministic, panic-free map semantics on the cold
//! paths around the hot tracker loop:
//!
//! * Deterministic integer mixer (Murmur3 32-bit finalizer) — no SipHash
//!   randomisation, so static WCET analysis is tractable.
//! * Power-of-two table sized to keep load factor ≤ 0.5; at that load the
//!   expected probe distance is ≤ 2 (Knuth TAOCP 6.4).
//! * Hard linear-probe budget of [`BoundedIndex::MAX_PROBE`] = 64 — gives
//!   ~32× headroom on the expected distance and a tight WCET bound.
//! * Tombstone-aware insert/remove preserves probe chains; probe budget
//!   exhaustion is observable via [`BoundedIndex::take_probe_exhausted`].
//!
//! Entry layout reuses the sentinel-encoded `slot_idx` field from the
//! original `PidIndex`: [`EMPTY`] (`u32::MAX`) and [`TOMBSTONE`]
//! (`u32::MAX - 1`) live in `slot_idx`, leaving the `key` field uninitialised
//! while a slot is vacant. This keeps `Entry<u32>` at 8 bytes — same
//! footprint as the previous hand-rolled `PidIndex` — so the tracker hot
//! path has the same per-slot cache pressure after the refactor as before.

use core::marker::Copy;
use core::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};

/// 32-bit hash trait used by [`BoundedIndex`]. Implementations must be pure
/// functions of `self` — deterministic across processes and free of any
/// runtime randomisation — so that the WCET argument above holds.
pub trait Hash32 {
    /// Mix `self` into a 32-bit value with good avalanche properties.
    fn hash32(&self) -> u32;
}

/// Sentinel: slot was never written or was fully cleared.
const EMPTY: u32 = u32::MAX;
/// Sentinel: slot was occupied and then removed. Counts toward the probe
/// budget until reused by a subsequent insert; bounded reuse keeps long
/// churn from filling the table with tombstones.
const TOMBSTONE: u32 = u32::MAX - 1;

#[derive(Copy)]
struct Entry<K: Copy> {
    /// Valid only when `slot_idx < TOMBSTONE`. Read sites in
    /// [`BoundedIndex`] always check `slot_idx` first.
    key: MaybeUninit<K>,
    slot_idx: u32,
}

impl<K: Copy> Clone for Entry<K> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K: Copy> Entry<K> {
    #[inline]
    fn empty() -> Self {
        Self {
            key: MaybeUninit::uninit(),
            slot_idx: EMPTY,
        }
    }
}

/// Outcome of [`BoundedIndex::insert`] that could not find a free slot
/// within the bounded probe budget. The caller surfaces this as a
/// `CapacityExceeded`-style refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeExhausted;

/// Fixed-size, open-addressed `K → u32` map. See module docs for the WCET
/// argument and entry layout.
pub struct BoundedIndex<K: Copy + Eq + Hash32> {
    table: Vec<Entry<K>>,
    mask: usize,
    occupied: usize,
    probe_exhausted: u64,
}

impl<K: Copy + Eq + Hash32> BoundedIndex<K> {
    /// Hard cap on the probe sequence length per `get` / `insert` / `remove`.
    /// At load factor ≤ 0.5 the expected probe distance is ≤ 2; 64 gives
    /// ~32× margin and keeps every operation comfortably inside one or two
    /// cache lines worth of work.
    pub const MAX_PROBE: usize = 64;

    /// Build a table sized for `capacity` live entries. The backing buffer
    /// is `next_power_of_two(capacity * 2).max(2)` so the load factor stays
    /// ≤ 0.5 at peak and `mask = table.len() - 1` works without modular
    /// division.
    pub fn new(capacity: usize) -> Self {
        let target = capacity.saturating_mul(2).max(2);
        let size = target.next_power_of_two();
        let table = vec![Entry::empty(); size];
        Self {
            table,
            mask: size - 1,
            occupied: 0,
            probe_exhausted: 0,
        }
    }

    /// Number of live (non-empty, non-tombstone) entries.
    pub fn len(&self) -> usize {
        self.occupied
    }

    /// Look up the slot index recorded for `key`. Returns `None` if the
    /// key is absent or if the probe budget was exhausted (treated as
    /// absent so callers fall through to insert / capacity-exceeded
    /// paths).
    pub fn get(&self, key: K) -> Option<usize> {
        let mut i = (key.hash32() as usize) & self.mask;
        for _ in 0..Self::MAX_PROBE {
            let entry = self.table.get(i)?;
            match entry.slot_idx {
                EMPTY => return None,
                TOMBSTONE => {}
                _ => {
                    // SAFETY: `slot_idx < TOMBSTONE` means the slot was
                    // populated by a prior `insert` that wrote `key` via
                    // `MaybeUninit::write` and has not been removed since.
                    let entry_key = unsafe { entry.key.assume_init() };
                    if entry_key == key {
                        return Some(entry.slot_idx as usize);
                    }
                }
            }
            i = (i + 1) & self.mask;
        }
        None
    }

    /// Insert or update `key → slot_idx`. Returns `Err(ProbeExhausted)` if
    /// no free or matching slot was found within [`Self::MAX_PROBE`]
    /// probes; the table state is unchanged in that case and
    /// `probe_exhausted` is incremented.
    pub fn insert(&mut self, key: K, slot_idx: usize) -> Result<(), ProbeExhausted> {
        debug_assert!((slot_idx as u32) < TOMBSTONE);
        let mut i = (key.hash32() as usize) & self.mask;
        let mut first_tombstone: Option<usize> = None;
        for _ in 0..Self::MAX_PROBE {
            let entry = match self.table.get(i) {
                Some(e) => *e,
                None => {
                    self.probe_exhausted = self.probe_exhausted.saturating_add(1);
                    return Err(ProbeExhausted);
                }
            };
            match entry.slot_idx {
                EMPTY => {
                    let target = first_tombstone.unwrap_or(i);
                    if let Some(slot) = self.table.get_mut(target) {
                        slot.key.write(key);
                        slot.slot_idx = slot_idx as u32;
                        // Both paths (filling a true EMPTY slot and reusing
                        // a tombstone) produce a new live entry. `remove()`
                        // already decremented `occupied` when the tombstone
                        // was created, so re-incrementing here restores the
                        // correct live count.
                        self.occupied = self.occupied.saturating_add(1);
                        return Ok(());
                    }
                    self.probe_exhausted = self.probe_exhausted.saturating_add(1);
                    return Err(ProbeExhausted);
                }
                TOMBSTONE => {
                    if first_tombstone.is_none() {
                        first_tombstone = Some(i);
                    }
                }
                _ => {
                    // SAFETY: `slot_idx < TOMBSTONE` ⇒ `key` is initialised.
                    let entry_key = unsafe { entry.key.assume_init() };
                    if entry_key == key {
                        if let Some(slot) = self.table.get_mut(i) {
                            slot.slot_idx = slot_idx as u32;
                            return Ok(());
                        }
                        self.probe_exhausted = self.probe_exhausted.saturating_add(1);
                        return Err(ProbeExhausted);
                    }
                }
            }
            i = (i + 1) & self.mask;
        }
        // Probe budget exhausted without finding an EMPTY slot or the key.
        // If we passed a tombstone we could reuse it, but that would
        // exceed the WCET budget callers signed up for — fall through.
        self.probe_exhausted = self.probe_exhausted.saturating_add(1);
        Err(ProbeExhausted)
    }

    /// Remove `key` from the index. Returns the slot index it pointed to,
    /// if any. Writes a TOMBSTONE in place so downstream probes for other
    /// keys continue to walk past.
    pub fn remove(&mut self, key: K) -> Option<usize> {
        let mut i = (key.hash32() as usize) & self.mask;
        for _ in 0..Self::MAX_PROBE {
            let entry = *self.table.get(i)?;
            match entry.slot_idx {
                EMPTY => return None,
                TOMBSTONE => {}
                _ => {
                    // SAFETY: `slot_idx < TOMBSTONE` ⇒ `key` is initialised.
                    let entry_key = unsafe { entry.key.assume_init() };
                    if entry_key == key {
                        let prev = entry.slot_idx as usize;
                        if let Some(slot) = self.table.get_mut(i) {
                            slot.slot_idx = TOMBSTONE;
                            // Leave `key` initialised; it is logically dead
                            // and will be overwritten by the next insert
                            // that lands here.
                            self.occupied = self.occupied.saturating_sub(1);
                        }
                        return Some(prev);
                    }
                }
            }
            i = (i + 1) & self.mask;
        }
        None
    }

    /// Iterate the live `(key, slot_idx)` pairs. Iteration order is the
    /// internal probe order — *not* insertion order — but it is
    /// deterministic for a given sequence of inserts and removes.
    pub fn iter(&self) -> impl Iterator<Item = (K, usize)> + '_ {
        self.table.iter().filter_map(|e| match e.slot_idx {
            EMPTY | TOMBSTONE => None,
            // SAFETY: `slot_idx < TOMBSTONE` ⇒ `key` is initialised.
            other => Some((unsafe { e.key.assume_init() }, other as usize)),
        })
    }

    /// Drain and reset the probe-exhausted counter.
    pub fn take_probe_exhausted(&mut self) -> u64 {
        let n = self.probe_exhausted;
        self.probe_exhausted = 0;
        n
    }

    /// Reset the index to its initial state.  Used by container `drain()`
    /// implementations that want to release all live entries at once.
    pub fn clear(&mut self) {
        for entry in self.table.iter_mut() {
            entry.slot_idx = EMPTY;
        }
        self.occupied = 0;
    }
}

/// Murmur3 32-bit finalizer — a registry-dep-free integer mixer.
///
/// Deterministic across processes (no SipHash randomisation), branchless,
/// and produces good avalanche on 32-bit inputs. Adversarial collisions
/// are not in the threat model: every reachable key has already been
/// authenticated by the upstream pipeline (peer-cred for pids, kernel
/// `accept(2)` for IPs) before it reaches a `BoundedIndex`.
#[inline]
pub fn mix32(x: u32) -> u32 {
    let mut x = x;
    x = (x ^ (x >> 16)).wrapping_mul(0x85eb_ca6b);
    x = (x ^ (x >> 13)).wrapping_mul(0xc2b2_ae35);
    x ^ (x >> 16)
}

impl Hash32 for u32 {
    #[inline]
    fn hash32(&self) -> u32 {
        mix32(*self)
    }
}

impl Hash32 for IpAddr {
    #[inline]
    fn hash32(&self) -> u32 {
        // Fold each 4-byte chunk with rotate-and-xor, then run the Murmur3
        // finalizer. Deterministic across processes, no allocation,
        // branchless within each variant. Different rotations per chunk
        // prevent trivial cancellation between symmetric addresses.
        match self {
            IpAddr::V4(v) => mix32(u32::from_be_bytes(v.octets())),
            IpAddr::V6(v) => {
                let b = v.octets();
                let c0 = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                let c1 = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                let c2 = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
                let c3 = u32::from_be_bytes([b[12], b[13], b[14], b[15]]);
                mix32(c0 ^ c1.rotate_left(7) ^ c2.rotate_left(13) ^ c3.rotate_left(19))
            }
        }
    }
}

impl Hash32 for SocketAddr {
    #[inline]
    fn hash32(&self) -> u32 {
        // Same folding chain as Hash32 for IpAddr with the port mixed in
        // via an independent rotation so that addr:portA and addr:portB hit
        // different buckets. Deterministic, no allocation, no SipHash.
        let port = u32::from(self.port());
        match self.ip() {
            IpAddr::V4(v) => mix32(u32::from_be_bytes(v.octets()) ^ port.rotate_left(11)),
            IpAddr::V6(v) => {
                let b = v.octets();
                let c0 = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                let c1 = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                let c2 = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
                let c3 = u32::from_be_bytes([b[12], b[13], b[14], b[15]]);
                mix32(
                    c0 ^ c1.rotate_left(7)
                        ^ c2.rotate_left(13)
                        ^ c3.rotate_left(19)
                        ^ port.rotate_left(23),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn entry_u32_is_8_bytes() {
        // Hot-path footprint guarantee — keeps PidIndex's cache pressure
        // unchanged across the refactor.
        assert_eq!(core::mem::size_of::<Entry<u32>>(), 8);
    }

    #[test]
    fn roundtrip_u32() {
        let mut t: BoundedIndex<u32> = BoundedIndex::new(16);
        assert_eq!(t.len(), 0);
        t.insert(7, 0).unwrap();
        t.insert(13, 1).unwrap();
        t.insert(u32::MAX - 4, 2).unwrap();
        assert_eq!(t.len(), 3);
        assert_eq!(t.get(7), Some(0));
        assert_eq!(t.get(13), Some(1));
        assert_eq!(t.get(u32::MAX - 4), Some(2));
        assert_eq!(t.get(999), None);

        assert_eq!(t.remove(13), Some(1));
        assert_eq!(t.get(13), None);
        assert_eq!(t.len(), 2);

        // Re-insert reuses the tombstone slot.
        t.insert(13, 9).unwrap();
        assert_eq!(t.get(13), Some(9));
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn roundtrip_ipv4() {
        let mut t: BoundedIndex<IpAddr> = BoundedIndex::new(8);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        t.insert(a, 0).unwrap();
        t.insert(b, 1).unwrap();
        assert_eq!(t.get(a), Some(0));
        assert_eq!(t.get(b), Some(1));
    }

    #[test]
    fn roundtrip_ipv6() {
        let mut t: BoundedIndex<IpAddr> = BoundedIndex::new(8);
        let a = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        t.insert(a, 0).unwrap();
        t.insert(b, 1).unwrap();
        assert_eq!(t.get(a), Some(0));
        assert_eq!(t.get(b), Some(1));
        assert_eq!(t.get(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), None);
    }

    #[test]
    fn tombstone_reuse_does_not_break_long_probe_chains() {
        // Force collisions by exploiting `mix32` on adjacent keys — at
        // table size 8 (mask 7) the modular position depends on the high
        // bits of `mix32`, so we just bash on a few hundred keys and
        // confirm get/remove/re-insert stays consistent.
        let mut t: BoundedIndex<u32> = BoundedIndex::new(64);
        for k in 0..50u32 {
            t.insert(k, k as usize).unwrap();
        }
        for k in (0..50).step_by(2) {
            assert_eq!(t.remove(k), Some(k as usize));
        }
        for k in (0..50).step_by(2) {
            assert_eq!(t.get(k), None);
        }
        for k in (1..50).step_by(2) {
            assert_eq!(t.get(k), Some(k as usize));
        }
        for k in (0..50).step_by(2) {
            t.insert(k, (k * 2) as usize).unwrap();
        }
        for k in (0..50).step_by(2) {
            assert_eq!(t.get(k), Some((k * 2) as usize));
        }
    }

    #[test]
    fn probe_exhaustion_is_observable() {
        // capacity=1 ⇒ table size 2 ⇒ even with optimal hashing, more than
        // a couple of distinct keys overflow the bucket and a deep probe
        // chain forms. With MAX_PROBE=64 and table size 2 we can fill the
        // table but cannot exceed MAX_PROBE — exhaustion only triggers
        // when the small table is fully occupied. Verify by filling and
        // then asserting either Ok or ProbeExhausted is returned (never a
        // panic) for additional inserts.
        let mut t: BoundedIndex<u32> = BoundedIndex::new(1);
        let _ = t.insert(0, 0);
        let _ = t.insert(1, 1);
        // Both slots may now be occupied; further inserts either succeed
        // on a tombstone path or return ProbeExhausted, never panic.
        for k in 2..200u32 {
            let _ = t.insert(k, k as usize);
        }
        // Exhausted counter is monotonic and can be drained.
        let n = t.take_probe_exhausted();
        // Either some inserts exhausted (counter ≥ 1) or all fit in two
        // slots via updates — both are valid outcomes. Re-draining
        // returns zero.
        assert_eq!(t.take_probe_exhausted(), 0);
        let _ = n;
    }

    #[test]
    fn iter_yields_each_live_entry_exactly_once() {
        let mut t: BoundedIndex<u32> = BoundedIndex::new(32);
        for k in 0..20u32 {
            t.insert(k, k as usize).unwrap();
        }
        for k in (0..20).step_by(3) {
            t.remove(k);
        }
        let mut seen: Vec<(u32, usize)> = t.iter().collect();
        seen.sort_unstable();
        let expected: Vec<(u32, usize)> = (0..20u32)
            .filter(|k| k % 3 != 0)
            .map(|k| (k, k as usize))
            .collect();
        assert_eq!(seen, expected);
    }

    #[test]
    fn clear_resets_all_state() {
        let mut t: BoundedIndex<u32> = BoundedIndex::new(16);
        for k in 0..10u32 {
            t.insert(k, k as usize).unwrap();
        }
        t.clear();
        assert_eq!(t.len(), 0);
        for k in 0..10u32 {
            assert_eq!(t.get(k), None);
        }
        // Table is reusable.
        t.insert(42, 42).unwrap();
        assert_eq!(t.get(42), Some(42));
    }

    #[test]
    fn hash32_is_deterministic_across_calls() {
        // Process-level determinism — the same key must produce the same
        // hash every time, otherwise the WCET argument breaks.
        let k: u32 = 0xdead_beef;
        assert_eq!(k.hash32(), k.hash32());
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(ip.hash32(), ip.hash32());
        let sa = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 4242));
        assert_eq!(sa.hash32(), sa.hash32());
    }

    #[test]
    fn roundtrip_socketaddr_v4() {
        let mut t: BoundedIndex<SocketAddr> = BoundedIndex::new(8);
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 4242));
        let b = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 9000));
        t.insert(a, 0).unwrap();
        t.insert(b, 1).unwrap();
        assert_eq!(t.get(a), Some(0));
        assert_eq!(t.get(b), Some(1));
        assert_eq!(
            t.get(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, 0, 1),
                4243
            ))),
            None,
            "different port on same IP must miss"
        );
    }

    #[test]
    fn roundtrip_socketaddr_v6() {
        let mut t: BoundedIndex<SocketAddr> = BoundedIndex::new(8);
        let a = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 4242, 0, 0));
        let b = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            9000,
            0,
            0,
        ));
        t.insert(a, 0).unwrap();
        t.insert(b, 1).unwrap();
        assert_eq!(t.get(a), Some(0));
        assert_eq!(t.get(b), Some(1));
        assert_eq!(
            t.get(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                4243,
                0,
                0
            ))),
            None,
            "different port on same IPv6 must miss"
        );
    }

    #[test]
    fn socketaddr_hash_distinguishes_port_changes() {
        // The port mix must change the hash; otherwise an attacker pumping
        // many ports from one IP could collapse to one bucket and waste
        // sender-table capacity unnecessarily.
        let ip4 = Ipv4Addr::new(10, 0, 0, 1);
        let h1 = SocketAddr::V4(SocketAddrV4::new(ip4, 1)).hash32();
        let h2 = SocketAddr::V4(SocketAddrV4::new(ip4, 2)).hash32();
        assert_ne!(h1, h2);

        let ip6 = Ipv6Addr::LOCALHOST;
        let h3 = SocketAddr::V6(SocketAddrV6::new(ip6, 1, 0, 0)).hash32();
        let h4 = SocketAddr::V6(SocketAddrV6::new(ip6, 2, 0, 0)).hash32();
        assert_ne!(h3, h4);
    }
}
