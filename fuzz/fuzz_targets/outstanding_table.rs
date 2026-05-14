#![no_main]
//! Drive `OutstandingTable<u32>` with arbitrary op sequences and assert
//! invariants that hold for any valid sequence:
//!
//! * `len()` stays in `[0, capacity()]`.
//! * `iter_pids().count() == len()`.
//! * For every pid yielded by `iter_pids`, `get()` returns `Some`.
//! * `try_insert` never panics; `Full` is the only acceptable error
//!   alongside `AlreadyPresent`.
//! * After `drain()`, `len() == 0` and the table is reusable.
//!
//! Op encoding (5 bytes each):
//!   tag(1) + pid(4)
//!   tag 0 → try_insert(pid, pid_as_value)
//!   tag 1 → remove(pid)
//!   tag 2 → contains(pid)
//!   tag 3 → drain (full)

use libfuzzer_sys::fuzz_target;
use varta_watch::__fuzz_internals::outstanding_table::{InsertError, OutstandingTable};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let capacity = 1 + (data[0] as usize % 64);
    let mut table: OutstandingTable<u32> = OutstandingTable::with_capacity(capacity);

    let mut off = 1usize;
    while off + 5 <= data.len() {
        let chunk = &data[off..off + 5];
        off += 5;
        let pid = u32::from_le_bytes([chunk[1], chunk[2], chunk[3], chunk[4]]);

        match chunk[0] & 0x03 {
            0 => {
                let pre_len = table.len();
                match table.try_insert(pid, pid) {
                    Ok(()) => assert!(table.len() <= table.capacity()),
                    Err(InsertError::AlreadyPresent) => {
                        assert_eq!(table.len(), pre_len);
                    }
                    Err(InsertError::Full) => {
                        assert_eq!(table.len(), pre_len);
                    }
                }
            }
            1 => {
                let pre_len = table.len();
                let removed = table.remove(pid);
                if removed.is_some() {
                    assert_eq!(table.len(), pre_len - 1);
                } else {
                    assert_eq!(table.len(), pre_len);
                }
            }
            2 => {
                let _ = table.contains(pid);
            }
            3 => {
                let drained: Vec<u32> = table.drain().collect();
                assert!(drained.len() <= capacity);
                assert_eq!(table.len(), 0);
            }
            _ => {}
        }

        // Universal invariants checked after every op.
        let live: Vec<u32> = table.iter_pids().collect();
        assert_eq!(live.len(), table.len());
        for p in &live {
            assert!(table.contains(*p));
        }
    }

    let _ = table.take_probe_exhausted();
});
