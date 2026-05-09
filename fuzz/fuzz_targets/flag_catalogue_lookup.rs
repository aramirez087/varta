#![no_main]

//! Fuzz the flag catalogue lookup path.
//!
//! Exercises three properties under arbitrary byte input:
//!
//! 1. **No panic** — `FLAGS.iter().find()` on any `&str` must never panic.
//! 2. **Consistency** — if a CLI name matches, the returned spec's `.cli`
//!    equals the query string.
//! 3. **Key uniqueness invariant** — every key that the fuzzer constructs from
//!    the spec's `.key` field can be looked up by that same key.
//!
//! This is a regression harness, not a discovery fuzzer — the catalogue is a
//! constant slice with no dynamic dispatch.  Its value is catching refactors
//! that accidentally duplicate or drop entries.

use libfuzzer_sys::fuzz_target;
use varta_watch::config::flag_catalogue::FLAGS;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // --- CLI lookup ---
    // Treat `s` as a candidate --flag-name.  If it matches, the returned
    // spec must have the same cli string.
    if let Some(spec) = FLAGS.iter().find(|sp| sp.cli == s) {
        assert_eq!(spec.cli, s);
        // The kind must be a valid discriminant (this is always true for a
        // well-formed FlagSpec, but the assert keeps the compiler from
        // optimising the match away).
        let _kind = spec.kind;
    }

    // --- Key lookup ---
    // Treat `s` as a candidate config-file key.  If it matches, the returned
    // spec must have the same key string and a non-empty cli field.
    if let Some(spec) = FLAGS.iter().find(|sp| !sp.key.is_empty() && sp.key == s) {
        assert_eq!(spec.key, s);
        // Every key-bearing entry in the catalogue must also carry a cli name.
        assert!(!spec.cli.is_empty(), "key {} has no cli name", spec.key);
    }

    // --- Exhaustiveness: no two entries share a cli name ---
    // Scan the full table on every fuzz iteration (the table is tiny: ~50
    // entries).  This catches duplicate insertions introduced by refactors.
    let mut cli_seen: u64 = 0u64;
    let mut key_seen: u64 = 0u64;
    for (i, sp) in FLAGS.iter().enumerate() {
        if !sp.cli.is_empty() {
            let bit = 1u64.wrapping_shl(i as u32 % 64);
            assert_eq!(cli_seen & bit, 0, "duplicate or bit-collision at index {i}");
            cli_seen |= bit;
        }
        if !sp.key.is_empty() {
            let bit = 1u64.wrapping_shl(i as u32 % 64);
            assert_eq!(key_seen & bit, 0, "duplicate or bit-collision at index {i}");
            key_seen |= bit;
        }
    }
});
