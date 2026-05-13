//! Property-based tests for the ChaCha20-Poly1305 AEAD construction.
//!
//! Exercises cryptographically hard invariants against billions of random
//! inputs, complementing the deterministic known-answer tests and
//! coverage-guided fuzz targets in `fuzz/fuzz_targets/aead_roundtrip.rs`.
//!
//! Each test here must hold for *every* input — if any single counterexample
//! exists, `proptest` shrinks it to a minimal failing case and reports it.
//!
//! # Invariants covered
//!
//! * **Roundtrip**: `open(seal(k, n, p)) == p`
//! * **Wrong-key rejection**: `open(seal(k1, n, p), k2)` always fails when `k1 != k2`
//! * **Tampered ciphertext rejection**: flipping any byte of the ciphertext
//!   after sealing causes `open` to fail
//! * **Tampered tag rejection**: same for the Poly1305 authentication tag
//! * **Determinism**: `seal(k, n, p)` is a pure function

use proptest::array::uniform;
use proptest::prelude::*;
use varta_vlp::crypto::kdf::derive_iv_prefix;
use varta_vlp::crypto::{open, seal};

// ---------------------------------------------------------------------------
// Helper: roundtrip a single (key, nonce, plaintext) tuple and assert success.
// ---------------------------------------------------------------------------
fn assert_roundtrip(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8; 32]) {
    let (ciphertext, tag) = seal(key, nonce, b"", plaintext);
    let decrypted = open(key, nonce, b"", &ciphertext, &tag)
        .unwrap_or_else(|_| panic!("roundtrip failed for a valid seal"));
    assert_eq!(
        &decrypted, plaintext,
        "roundtrip must recover original plaintext"
    );
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    /// For any valid key, nonce, and plaintext, sealing then opening with the
    /// same parameters must recover the original plaintext.
    #[test]
    fn roundtrip_for_arbitrary_inputs(
        key in uniform::<_, 32>(any::<u8>()),
        nonce in uniform::<_, 12>(any::<u8>()),
        plaintext in uniform::<_, 32>(any::<u8>()),
    ) {
        assert_roundtrip(&key, &nonce, &plaintext);
    }

    /// Opening with the wrong key must always fail, even when nonce and
    /// ciphertext+tag come from a valid seal operation with a different key.
    #[test]
    fn wrong_key_detected(
        k1 in uniform::<_, 32>(any::<u8>()),
        k2 in uniform::<_, 32>(any::<u8>()),
        nonce in uniform::<_, 12>(any::<u8>()),
        plaintext in uniform::<_, 32>(any::<u8>()),
    ) {
        if k1 == k2 {
            return Ok(());
        }
        let (ciphertext, tag) = seal(&k1, &nonce, b"", &plaintext);
        let result = open(&k2, &nonce, b"", &ciphertext, &tag);
        prop_assert!(result.is_err(), "wrong key must be detected");
    }

    /// Flipping any single bit in the ciphertext must cause AEAD authentication
    /// to fail, even though the ChaCha20 decryption would produce *some* output.
    #[test]
    fn tampered_ciphertext_detected(
        key in uniform::<_, 32>(any::<u8>()),
        nonce in uniform::<_, 12>(any::<u8>()),
        plaintext in uniform::<_, 32>(any::<u8>()),
        flip_byte in 0usize..32,
        flip_bit in 0u8..8,
    ) {
        let (mut ciphertext, tag) = seal(&key, &nonce, b"", &plaintext);
        ciphertext[flip_byte] ^= 1u8 << flip_bit;
        let result = open(&key, &nonce, b"", &ciphertext, &tag);
        prop_assert!(result.is_err(), "tampered ciphertext must be detected");
    }

    /// Flipping any single bit in the authentication tag must cause AEAD
    /// authentication to fail. This tests that the Poly1305 MAC is actually
    /// validated, not just the ciphertext integrity.
    #[test]
    fn tampered_tag_detected(
        key in uniform::<_, 32>(any::<u8>()),
        nonce in uniform::<_, 12>(any::<u8>()),
        plaintext in uniform::<_, 32>(any::<u8>()),
        flip_byte in 0usize..16,
        flip_bit in 0u8..8,
    ) {
        let (ciphertext, mut tag) = seal(&key, &nonce, b"", &plaintext);
        tag[flip_byte] ^= 1u8 << flip_bit;
        let result = open(&key, &nonce, b"", &ciphertext, &tag);
        prop_assert!(result.is_err(), "tampered tag must be detected");
    }

    /// Sealing is deterministic: identical inputs always produce identical
    /// (ciphertext, tag) pairs. This is critical for nonce-reuse safety —
    /// if seal were non-deterministic, two calls with the same nonce might
    /// produce different keystreams, leaking relationships between plaintexts.
    #[test]
    fn deterministic_encryption(
        key in uniform::<_, 32>(any::<u8>()),
        nonce in uniform::<_, 12>(any::<u8>()),
        plaintext in uniform::<_, 32>(any::<u8>()),
    ) {
        let (ct1, tag1) = seal(&key, &nonce, b"", &plaintext);
        let (ct2, tag2) = seal(&key, &nonce, b"", &plaintext);
        prop_assert_eq!(ct1, ct2, "encryption must be deterministic");
        prop_assert_eq!(tag1, tag2, "tag must be deterministic");
    }

    /// Opening with the wrong nonce must always fail.
    #[test]
    fn wrong_nonce_detected(
        key in uniform::<_, 32>(any::<u8>()),
        n1 in uniform::<_, 12>(any::<u8>()),
        n2 in uniform::<_, 12>(any::<u8>()),
        plaintext in uniform::<_, 32>(any::<u8>()),
    ) {
        if n1 == n2 {
            return Ok(());
        }
        let (ciphertext, tag) = seal(&key, &n1, b"", &plaintext);
        let result = open(&key, &n2, b"", &ciphertext, &tag);
        prop_assert!(result.is_err(), "wrong nonce must be detected");
    }

    /// H6 — IV prefixes derived from a session salt + arbitrary prefix
    /// index must produce nonces that AEAD seal/open correctly. Models the
    /// `SecureUdpTransport` counter-wrap rotation path: a fresh prefix is
    /// derived from `(salt, prefix_index)` and combined with a fresh
    /// `iv_counter`. Every round-trip must succeed.
    #[test]
    fn seal_open_roundtrip_after_prefix_rotation(
        key in uniform::<_, 32>(any::<u8>()),
        session_salt in uniform::<_, 16>(any::<u8>()),
        prefix_index in any::<u32>(),
        iv_counter in any::<u32>(),
        plaintext in uniform::<_, 32>(any::<u8>()),
    ) {
        let prefix = derive_iv_prefix(&session_salt, prefix_index);
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&prefix);
        nonce[8..].copy_from_slice(&iv_counter.to_le_bytes());

        let (ciphertext, tag) = seal(&key, &nonce, b"", &plaintext);
        let decrypted = open(&key, &nonce, b"", &ciphertext, &tag)
            .expect("rotated-prefix round-trip must decrypt");
        prop_assert_eq!(&decrypted, &plaintext);
    }

    /// H6 — distinct prefix indices under the same session salt must
    /// produce distinct nonces (and therefore distinct ciphertexts for
    /// the same plaintext + key). Guards against any future regression
    /// that collapses the index dimension.
    #[test]
    fn distinct_prefix_indices_yield_distinct_nonces(
        session_salt in uniform::<_, 16>(any::<u8>()),
        idx_a in any::<u32>(),
        idx_b in any::<u32>(),
    ) {
        if idx_a == idx_b {
            return Ok(());
        }
        let p_a = derive_iv_prefix(&session_salt, idx_a);
        let p_b = derive_iv_prefix(&session_salt, idx_b);
        // Cryptographically extreme to collide on 64 bits.
        prop_assert_ne!(p_a, p_b);
    }
}
