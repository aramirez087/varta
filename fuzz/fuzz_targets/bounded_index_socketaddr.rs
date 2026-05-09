#![no_main]
//! Fuzz `BoundedIndex<SocketAddr>` (Hash32 for SocketAddr) against a
//! `HashMap<SocketAddr, usize>` oracle. Op encoding mirrors
//! `bounded_index_ip`, but each op also carries a 2-byte port so v4/v6
//! addresses + port are exercised together.
//!
//! Encoding per op (variable length):
//!   tag(1) + variant(1) + ip(4 or 16) + port(2) + slot(1)
//!   tag 0 → get
//!   tag 1 → insert
//!   tag 2 → remove
//!   variant 0 → V4 (4 bytes follow + 2 port bytes)
//!   variant 1 → V6 (16 bytes follow + 2 port bytes)

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use varta_watch::__fuzz_internals::probe_table::BoundedIndex;

fn decode_addr<'a>(rest: &'a [u8]) -> Option<(SocketAddr, &'a [u8])> {
    let variant = *rest.first()?;
    if variant & 1 == 0 {
        if rest.len() < 1 + 4 + 2 {
            return None;
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&rest[1..5]);
        let port = u16::from_le_bytes([rest[5], rest[6]]);
        let sa = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(b), port));
        Some((sa, &rest[7..]))
    } else {
        if rest.len() < 1 + 16 + 2 {
            return None;
        }
        let mut b = [0u8; 16];
        b.copy_from_slice(&rest[1..17]);
        let port = u16::from_le_bytes([rest[17], rest[18]]);
        let sa = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(b), port, 0, 0));
        Some((sa, &rest[19..]))
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let capacity = 1 + (data[0] as usize % 64);
    let mut idx: BoundedIndex<SocketAddr> = BoundedIndex::new(capacity);
    let mut oracle: HashMap<SocketAddr, usize> = HashMap::new();

    let mut cursor: &[u8] = &data[1..];
    while !cursor.is_empty() {
        let tag = cursor[0];
        cursor = &cursor[1..];
        let Some((addr, rest)) = decode_addr(cursor) else {
            break;
        };
        cursor = rest;
        let Some(&slot_byte) = cursor.first() else {
            break;
        };
        cursor = &cursor[1..];
        let slot = (slot_byte as usize) & 0x3f;

        match tag & 0x03 {
            0 => {
                let got = idx.get(addr);
                if let Some(expected) = oracle.get(&addr).copied() {
                    if let Some(g) = got {
                        assert_eq!(g, expected);
                    }
                }
            }
            1 => {
                if idx.insert(addr, slot).is_ok() {
                    oracle.insert(addr, slot);
                }
            }
            2 => {
                let removed = idx.remove(addr);
                let expected = oracle.remove(&addr);
                if let (Some(r), Some(e)) = (removed, expected) {
                    assert_eq!(r, e);
                }
            }
            _ => {}
        }
    }

    let _ = idx.take_probe_exhausted();
});
