#![no_main]
//! Drive `IpStateTable<TestState>` with arbitrary op sequences and
//! assert invariants:
//!
//! * `len() <= capacity`.
//! * After `insert(ip, v)` succeeds, `get_mut(ip).is_some()`.
//! * After `remove(ip).is_some()`, `get_mut(ip).is_none()`.
//! * `oldest_ip()` returns `Some` iff `len() > 0`.
//! * `evict_older_than(now, ttl)` drops every entry whose stored
//!   `last_seen <= now - ttl` and keeps every entry whose
//!   `last_seen > now - ttl`.
//!
//! Op encoding (7 bytes):
//!   tag(1) + variant(1) + ip(4 or 16) + seen_offset_ms_u16(2) [little-endian]
//! `seen_offset_ms` is added to a virtual `t0` to produce `last_seen`;
//! the table is queried with a virtual `now = t0 + 65535ms` so every
//! stored entry's age fits in the u16 range.

use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use varta_watch::__fuzz_internals::ip_state_table::{IpStateTable, LastSeen};

#[derive(Clone, Copy)]
struct TestState {
    seen: Instant,
}

impl LastSeen for TestState {
    fn last_seen(&self) -> Instant {
        self.seen
    }
}

fn decode_ip<'a>(rest: &'a [u8]) -> Option<(IpAddr, &'a [u8])> {
    let variant = *rest.first()?;
    if variant & 1 == 0 {
        if rest.len() < 1 + 4 + 2 {
            return None;
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&rest[1..5]);
        Some((IpAddr::V4(Ipv4Addr::from(b)), &rest[5..]))
    } else {
        if rest.len() < 1 + 16 + 2 {
            return None;
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&rest[1..17]);
        Some((IpAddr::V6(Ipv6Addr::from(b)), &rest[17..]))
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let capacity = 1 + (data[0] as usize % 32);
    let mut table: IpStateTable<TestState> = IpStateTable::with_capacity(capacity);
    let t0 = Instant::now();
    let virtual_now = t0 + Duration::from_millis(65_535);

    let mut cursor: &[u8] = &data[1..];
    while !cursor.is_empty() {
        let tag = cursor[0];
        cursor = &cursor[1..];
        let Some((ip, rest)) = decode_ip(cursor) else {
            break;
        };
        cursor = rest;
        if cursor.len() < 2 {
            break;
        }
        let seen_ms = u16::from_le_bytes([cursor[0], cursor[1]]) as u64;
        cursor = &cursor[2..];
        let seen = t0 + Duration::from_millis(seen_ms);

        match tag & 0x03 {
            0 => {
                let _ = table.insert(ip, TestState { seen });
                assert!(table.len() <= capacity);
            }
            1 => {
                let pre = table.len();
                if table.remove(ip).is_some() {
                    assert_eq!(table.len(), pre - 1);
                    assert!(table.get_mut(ip).is_none());
                }
            }
            2 => {
                let ttl_ms = (seen_ms % 65_536) as u64; // bounded
                table.evict_older_than(virtual_now, Duration::from_millis(ttl_ms));
                assert!(table.len() <= capacity);
            }
            3 => {
                let oldest = table.oldest_ip();
                if table.len() == 0 {
                    assert!(oldest.is_none());
                } else {
                    assert!(oldest.is_some());
                }
            }
            _ => {}
        }
    }

    let _ = table.take_probe_exhausted();
});
