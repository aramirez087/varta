#![allow(missing_docs)]
//! Bounded per-source-IP token-bucket table for the Prometheus exporter.
//!
//! Replaces `HashMap<IpAddr, PromIpState>` in `exporter.rs`.  Slab + index
//! pattern, same as [`crate::outstanding_table`], but keyed on `IpAddr`
//! and with TTL-aware eviction primitives suitable for the existing
//! `allow_ip` flow:
//!
//! * [`Self::evict_older_than`] replaces `HashMap::retain` for the
//!   periodic sweep.
//! * [`Self::oldest_ip`] returns the IP with the smallest `last_seen`
//!   value for the force-evict fallback when the slab is full.
//!
//! Capacity is fixed at construction (1024 in production) so the slab is
//! pre-allocated and never reallocates.

#![cfg(feature = "prometheus-exporter")]

use core::net::IpAddr;
use std::time::{Duration, Instant};

use crate::probe_table::{BoundedIndex, ProbeExhausted};

/// Slab full and probe-budget exhausted.  The caller already has an
/// existing fallback (force-evict the oldest entry); `insert` returning
/// `Err(Full)` is the signal that even that fallback couldn't make room.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Full;

impl From<ProbeExhausted> for Full {
    fn from(_: ProbeExhausted) -> Self {
        Full
    }
}

pub struct IpStateTable<V: Copy> {
    slab: Vec<Option<IpSlot<V>>>,
    free_list: Vec<u32>,
    ip_to_slot: BoundedIndex<IpAddr>,
}

#[derive(Clone, Copy)]
struct IpSlot<V: Copy> {
    ip: IpAddr,
    state: V,
}

impl<V: Copy> IpStateTable<V> {
    pub fn with_capacity(capacity: usize) -> Self {
        debug_assert!(capacity > 0, "IpStateTable capacity must be > 0");
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
            ip_to_slot: BoundedIndex::new(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.ip_to_slot.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ip_to_slot.len() == 0
    }

    pub fn get_mut(&mut self, ip: IpAddr) -> Option<&mut V> {
        let idx = self.ip_to_slot.get(ip)?;
        Some(&mut self.slab.get_mut(idx)?.as_mut()?.state)
    }

    /// Insert `state` for `ip`.  If `ip` is already in the table, the
    /// existing entry is replaced in place (preserving the slab slot).
    pub fn insert(&mut self, ip: IpAddr, state: V) -> Result<(), Full> {
        if let Some(idx) = self.ip_to_slot.get(ip) {
            if let Some(slot) = self.slab.get_mut(idx) {
                *slot = Some(IpSlot { ip, state });
                return Ok(());
            }
        }
        let Some(slot_idx) = self.free_list.pop() else {
            return Err(Full);
        };
        if let Err(e) = self.ip_to_slot.insert(ip, slot_idx as usize) {
            self.free_list.push(slot_idx);
            return Err(e.into());
        }
        if let Some(slot) = self.slab.get_mut(slot_idx as usize) {
            *slot = Some(IpSlot { ip, state });
            Ok(())
        } else {
            self.ip_to_slot.remove(ip);
            self.free_list.push(slot_idx);
            Err(Full)
        }
    }

    pub fn remove(&mut self, ip: IpAddr) -> Option<V> {
        let slot_idx = self.ip_to_slot.remove(ip)?;
        let taken = self.slab.get_mut(slot_idx)?.take();
        if let Some(s) = taken {
            self.free_list.push(slot_idx as u32);
            Some(s.state)
        } else {
            None
        }
    }

    pub fn take_probe_exhausted(&mut self) -> u64 {
        self.ip_to_slot.take_probe_exhausted()
    }
}

/// Operations that need to peek at the value type — kept as an extension
/// trait-style impl block so the generic `IpStateTable<V>` stays usable
/// with any `Copy` value type while the exporter-specific helpers (TTL
/// sweep, oldest-by-last-seen) only require the field accessors below.
impl<V: Copy + LastSeen> IpStateTable<V> {
    /// Drop entries whose `last_seen()` value is older than `ttl`
    /// relative to `now`.  Linear scan over the slab — O(capacity) — but
    /// capacity is fixed at construction so the work is bounded.
    pub fn evict_older_than(&mut self, now: Instant, ttl: Duration) {
        // Snapshot the IPs to evict before mutating, so we don't perturb
        // the slab while iterating it.  Bounded by `len()` which is in
        // turn bounded by capacity.
        let mut victims: Vec<IpAddr> = Vec::new();
        for slot in self.slab.iter() {
            if let Some(s) = slot {
                if now.saturating_duration_since(s.state.last_seen()) >= ttl {
                    victims.push(s.ip);
                }
            }
        }
        for ip in victims {
            self.remove(ip);
        }
    }

    /// Return the IP whose `last_seen()` is smallest, if any.  Used as
    /// the force-evict fallback when [`Self::evict_older_than`] cannot
    /// make room.  O(capacity).
    pub fn oldest_ip(&self) -> Option<IpAddr> {
        let mut best: Option<(IpAddr, Instant)> = None;
        for slot in self.slab.iter() {
            if let Some(s) = slot {
                let seen = s.state.last_seen();
                match best {
                    None => best = Some((s.ip, seen)),
                    Some((_, b)) if seen < b => best = Some((s.ip, seen)),
                    _ => {}
                }
            }
        }
        best.map(|(ip, _)| ip)
    }
}

/// Per-value accessor required by [`IpStateTable::evict_older_than`] and
/// [`IpStateTable::oldest_ip`].  Implemented in `exporter.rs` for
/// `PromIpState` so the table stays generic.
pub trait LastSeen {
    fn last_seen(&self) -> Instant;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    #[derive(Clone, Copy)]
    struct TestState {
        seen: Instant,
        payload: u32,
    }

    impl LastSeen for TestState {
        fn last_seen(&self) -> Instant {
            self.seen
        }
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn insert_get_remove_roundtrip() {
        let mut t: IpStateTable<TestState> = IpStateTable::with_capacity(4);
        let now = Instant::now();
        assert!(t
            .insert(
                ip(1),
                TestState {
                    seen: now,
                    payload: 11
                }
            )
            .is_ok());
        assert!(t
            .insert(
                ip(2),
                TestState {
                    seen: now,
                    payload: 22
                }
            )
            .is_ok());
        assert_eq!(t.len(), 2);
        assert_eq!(t.get_mut(ip(1)).map(|s| s.payload), Some(11));
        assert_eq!(t.get_mut(ip(2)).map(|s| s.payload), Some(22));
        assert_eq!(t.remove(ip(1)).map(|s| s.payload), Some(11));
        assert_eq!(t.len(), 1);
        assert!(t.get_mut(ip(1)).is_none());
    }

    #[test]
    fn insert_replaces_in_place_for_same_ip() {
        let mut t: IpStateTable<TestState> = IpStateTable::with_capacity(4);
        let now = Instant::now();
        t.insert(
            ip(1),
            TestState {
                seen: now,
                payload: 11,
            },
        )
        .unwrap();
        t.insert(
            ip(1),
            TestState {
                seen: now,
                payload: 99,
            },
        )
        .unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t.get_mut(ip(1)).map(|s| s.payload), Some(99));
    }

    #[test]
    fn full_returns_full_and_remove_reopens() {
        let mut t: IpStateTable<TestState> = IpStateTable::with_capacity(2);
        let now = Instant::now();
        t.insert(
            ip(1),
            TestState {
                seen: now,
                payload: 1,
            },
        )
        .unwrap();
        t.insert(
            ip(2),
            TestState {
                seen: now,
                payload: 2,
            },
        )
        .unwrap();
        assert_eq!(
            t.insert(
                ip(3),
                TestState {
                    seen: now,
                    payload: 3
                }
            ),
            Err(Full)
        );
        t.remove(ip(1));
        t.insert(
            ip(3),
            TestState {
                seen: now,
                payload: 3,
            },
        )
        .unwrap();
        assert_eq!(t.get_mut(ip(3)).map(|s| s.payload), Some(3));
    }

    #[test]
    fn evict_older_than_ttl_drops_stale() {
        let mut t: IpStateTable<TestState> = IpStateTable::with_capacity(4);
        let now = Instant::now();
        t.insert(
            ip(1),
            TestState {
                seen: now - Duration::from_secs(120),
                payload: 1,
            },
        )
        .unwrap();
        t.insert(
            ip(2),
            TestState {
                seen: now,
                payload: 2,
            },
        )
        .unwrap();
        t.evict_older_than(now, Duration::from_secs(60));
        assert_eq!(t.len(), 1);
        assert!(t.get_mut(ip(1)).is_none());
        assert!(t.get_mut(ip(2)).is_some());
    }

    #[test]
    fn oldest_ip_picks_min_last_seen() {
        let mut t: IpStateTable<TestState> = IpStateTable::with_capacity(4);
        let now = Instant::now();
        t.insert(
            ip(1),
            TestState {
                seen: now - Duration::from_secs(10),
                payload: 1,
            },
        )
        .unwrap();
        t.insert(
            ip(2),
            TestState {
                seen: now - Duration::from_secs(30), // oldest
                payload: 2,
            },
        )
        .unwrap();
        t.insert(
            ip(3),
            TestState {
                seen: now - Duration::from_secs(5),
                payload: 3,
            },
        )
        .unwrap();
        assert_eq!(t.oldest_ip(), Some(ip(2)));
        t.remove(ip(2));
        assert_eq!(t.oldest_ip(), Some(ip(1)));
    }

    #[test]
    fn oldest_ip_is_none_for_empty_table() {
        let t: IpStateTable<TestState> = IpStateTable::with_capacity(4);
        assert!(t.oldest_ip().is_none());
    }
}
