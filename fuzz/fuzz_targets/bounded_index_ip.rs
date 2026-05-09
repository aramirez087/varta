#![no_main]
//! Fuzz `BoundedIndex<IpAddr>` (Hash32 for IpAddr) against a
//! HashMap<IpAddr, usize> oracle. Op encoding mirrors `bounded_index_u32`,
//! but each op carries an IpAddr (V4 or V6 by tag bit).
//!
//! Encoding per op (variable length):
//!   tag(1) + variant(1) + ip(4 or 16) + slot(1)
//!   tag 0 → get
//!   tag 1 → insert
//!   tag 2 → remove
//!   variant 0 → V4 (4 bytes follow)
//!   variant 1 → V6 (16 bytes follow)

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use varta_watch::__fuzz_internals::probe_table::BoundedIndex;

fn decode_ip<'a>(rest: &'a [u8]) -> Option<(IpAddr, &'a [u8])> {
    let variant = *rest.first()?;
    if variant & 1 == 0 {
        if rest.len() < 1 + 4 {
            return None;
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&rest[1..5]);
        Some((IpAddr::V4(Ipv4Addr::from(b)), &rest[5..]))
    } else {
        if rest.len() < 1 + 16 {
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
    let capacity = 1 + (data[0] as usize % 64);
    let mut idx: BoundedIndex<IpAddr> = BoundedIndex::new(capacity);
    let mut oracle: HashMap<IpAddr, usize> = HashMap::new();

    let mut cursor: &[u8] = &data[1..];
    while !cursor.is_empty() {
        let tag = cursor[0];
        cursor = &cursor[1..];
        let Some((ip, rest)) = decode_ip(cursor) else {
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
                let got = idx.get(ip);
                if let Some(expected) = oracle.get(&ip).copied() {
                    if let Some(g) = got {
                        assert_eq!(g, expected);
                    }
                }
            }
            1 => {
                if idx.insert(ip, slot).is_ok() {
                    oracle.insert(ip, slot);
                }
            }
            2 => {
                let removed = idx.remove(ip);
                let expected = oracle.remove(&ip);
                if let (Some(r), Some(e)) = (removed, expected) {
                    assert_eq!(r, e);
                }
            }
            _ => {}
        }
    }

    let _ = idx.take_probe_exhausted();
});
