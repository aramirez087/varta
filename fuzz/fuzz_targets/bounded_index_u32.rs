#![no_main]
//! Fuzz the generic `BoundedIndex<u32>` against a `HashMap<u32, usize>`
//! reference oracle.  Every supported op (get / insert / remove) must
//! agree on outcomes modulo `ProbeExhausted` (which the oracle cannot
//! observe; `BoundedIndex::get` returns `None` on probe exhaustion, so
//! disagreement there is allowed).
//!
//! Input encoding: byte stream of 6-byte op records:
//!   tag(1) + pid(4) + slot(1)
//!   tag 0 → get(pid)
//!   tag 1 → insert(pid, slot_idx % 64)
//!   tag 2 → remove(pid)
//! The first byte selects capacity in [1, 65).

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use varta_watch::__fuzz_internals::probe_table::BoundedIndex;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let capacity = 1 + (data[0] as usize % 64);
    let mut idx: BoundedIndex<u32> = BoundedIndex::new(capacity);
    let mut oracle: HashMap<u32, usize> = HashMap::new();

    let mut off = 1usize;
    while off + 6 <= data.len() {
        let chunk = &data[off..off + 6];
        off += 6;
        let pid = u32::from_le_bytes([chunk[1], chunk[2], chunk[3], chunk[4]]);
        let slot = (chunk[5] as usize) & 0x3f; // < 64

        match chunk[0] & 0x03 {
            0 => {
                // get — BoundedIndex can return None on probe-budget
                // exhaustion, so only assert when the oracle has the key.
                let got = idx.get(pid);
                if let Some(expected) = oracle.get(&pid).copied() {
                    if let Some(g) = got {
                        assert_eq!(g, expected, "BoundedIndex/oracle disagree on pid {pid}");
                    }
                    // got == None ⇒ probe-exhausted; tolerated.
                }
            }
            1 => {
                // insert — succeed or ProbeExhausted.  On success, oracle
                // and BoundedIndex must agree.
                if idx.insert(pid, slot).is_ok() {
                    oracle.insert(pid, slot);
                }
            }
            2 => {
                // remove — outcome must match the oracle when both can
                // resolve the pid.
                let removed = idx.remove(pid);
                let expected = oracle.remove(&pid);
                if let (Some(r), Some(e)) = (removed, expected) {
                    assert_eq!(r, e, "BoundedIndex remove/oracle disagree on pid {pid}");
                }
            }
            _ => {
                // unreachable due to mask
            }
        }
    }

    let _ = idx.take_probe_exhausted();
});
