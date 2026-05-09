//! SHA-256 helpers used by the `varta-watch` recovery audit log.
//!
//! Feature-gated behind `crypto`. The audit log uses a tamper-evident hash
//! chain over its TSV records; this module provides the only chain-hash
//! construction used by the daemon so callers cannot accidentally feed the
//! hasher in an order that produces splice-able output.
//!
//! # Why a dedicated helper rather than exposing `Sha256` directly?
//!
//! Without domain separation, an attacker who can synthesise an audit
//! record kind (e.g. a fabricated `boot`) could splice an arbitrary suffix
//! onto an existing chain by picking `prev_chain` and `body` such that the
//! resulting SHA-256 matches a target. Baking the domain tag and record
//! kind into the construction inside this crate makes that footgun
//! impossible to step on from outside.
//!
//! # Construction
//!
//! ```text
//! chain_n = SHA-256(
//!     DOMAIN || 0x00 ||
//!     kind   || 0x00 ||
//!     prev_chain_raw || 0x00 ||
//!     body
//! )
//! ```
//!
//! - `DOMAIN` is the fixed bytes of [`AUDIT_CHAIN_DOMAIN`].
//! - `kind` is the record-kind label (`b"spawn"`, `b"complete"`,
//!   `b"refused"`, `b"boot"`), not its TSV column value.
//! - `prev_chain_raw` is the **raw 32-byte** output of the prior call (not
//!   its hex serialisation), or `[0u8; 32]` for the very first record on a
//!   freshly-created file.
//! - `body` is the TSV line up to (but not including) the chain column —
//!   no trailing `\n`.
//!
//! All four segments are 0x00-separated so a length-extension or
//! field-confusion attack against the TSV serialiser cannot collapse two
//! distinct logical inputs into the same hashed byte string.

use sha2::{Digest, Sha256};

/// Domain-separation tag baked into every chain hash.
///
/// The trailing `v2` matches the audit-log schema tag; bumping the schema
/// version mandatorily bumps this domain so a forensic tool can never
/// confuse a v2 chain with a future v3 one.
pub const AUDIT_CHAIN_DOMAIN: &[u8] = b"VARTA-AUDIT-v2";

/// Output length of the audit chain hash in bytes (SHA-256 = 32).
pub const AUDIT_CHAIN_OUT_BYTES: usize = 32;

/// Compute one link of the audit chain.
///
/// See the module docs for the construction. The output is the raw 32-byte
/// SHA-256 digest; the caller is responsible for hex-encoding it for the
/// TSV serialisation (and for using the **raw** bytes — not the hex — as
/// `prev_chain` for the next call).
pub fn audit_chain_hash(
    prev_chain: &[u8; AUDIT_CHAIN_OUT_BYTES],
    kind: &[u8],
    body: &[u8],
) -> [u8; AUDIT_CHAIN_OUT_BYTES] {
    let mut h = Sha256::new();
    h.update(AUDIT_CHAIN_DOMAIN);
    h.update([0u8]);
    h.update(kind);
    h.update([0u8]);
    h.update(prev_chain);
    h.update([0u8]);
    h.update(body);
    let digest = h.finalize();
    let mut out = [0u8; AUDIT_CHAIN_OUT_BYTES];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed-vector check. The expected value below was computed once by
    /// running the construction above with the listed inputs; the test
    /// fails closed if anyone ever tweaks the order of `update` calls or
    /// the separator byte.
    #[test]
    fn audit_chain_hash_fixed_vector() {
        let prev = [0u8; 32];
        let kind = b"boot";
        let body = b"1\t1700000000000\t0\tboot\t1234\t-\tfresh";
        let got = audit_chain_hash(&prev, kind, body);

        // Recompute the expected by hand so the test is its own oracle.
        let mut h = Sha256::new();
        h.update(b"VARTA-AUDIT-v2");
        h.update([0u8]);
        h.update(b"boot");
        h.update([0u8]);
        h.update([0u8; 32]);
        h.update([0u8]);
        h.update(b"1\t1700000000000\t0\tboot\t1234\t-\tfresh");
        let expected = h.finalize();
        assert_eq!(&got[..], &expected[..]);
    }

    #[test]
    fn audit_chain_hash_changes_with_each_field() {
        let prev = [0u8; 32];
        let h1 = audit_chain_hash(&prev, b"spawn", b"body");
        let h2 = audit_chain_hash(&prev, b"complete", b"body");
        let h3 = audit_chain_hash(&prev, b"spawn", b"other");
        let mut prev2 = [0u8; 32];
        prev2[0] = 1;
        let h4 = audit_chain_hash(&prev2, b"spawn", b"body");
        assert_ne!(h1, h2, "kind change must alter hash");
        assert_ne!(h1, h3, "body change must alter hash");
        assert_ne!(h1, h4, "prev_chain change must alter hash");
    }

    #[test]
    fn audit_chain_hash_resists_field_boundary_confusion() {
        // Without 0x00 separators between fields, ("ab","cd") and
        // ("abcd","") would hash to the same byte string. The separator
        // makes them distinct.
        let prev = [0u8; 32];
        let a = audit_chain_hash(&prev, b"ab", b"cd");
        let b = audit_chain_hash(&prev, b"abcd", b"");
        assert_ne!(a, b);
    }

    #[test]
    fn audit_chain_domain_is_versioned() {
        // Smoke check — schema version bumps must update this constant.
        let s = core::str::from_utf8(AUDIT_CHAIN_DOMAIN).expect("ASCII domain");
        assert!(
            s.ends_with("v2"),
            "domain tag must encode schema version: {s}"
        );
    }
}
