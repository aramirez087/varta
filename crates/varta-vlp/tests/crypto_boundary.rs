//! Boundary-input regression tests for `varta-vlp::crypto`.
//!
//! The production code uses `match … unreachable!()` blocks on three call
//! sites (`aead::seal`, `kdf::derive_agent_key`, `kdf::derive_epoch_key`) that
//! delegate to RustCrypto APIs returning `Result`. Each `unreachable!()` is
//! sound because the input shape is statically fixed: 32-byte plaintext into
//! ChaCha20-Poly1305 and 32-byte OKM out of HKDF-SHA256, both well below the
//! upstream error thresholds.
//!
//! These tests pin that contract: every boundary value of the variable
//! inputs (key, nonce, agent_id, epoch) must complete without panicking. If
//! a future refactor accidentally lifts one of those call sites to a
//! non-fixed-size buffer, the panic surfaces here long before it ships.

#![cfg(feature = "crypto")]

use varta_vlp::crypto::{
    aead::{open, seal, AuthError},
    kdf::{derive_agent_key, derive_epoch_key},
    Key,
};

#[test]
fn seal_does_not_panic_on_boundary_keys_and_nonces() {
    let plaintexts: [[u8; 32]; 3] = [[0u8; 32], [0xFFu8; 32], [0xA5u8; 32]];
    let keys: [[u8; 32]; 3] = [[0u8; 32], [0xFFu8; 32], [0x5Au8; 32]];
    let nonces: [[u8; 12]; 3] = [[0u8; 12], [0xFFu8; 12], [0x42u8; 12]];

    for k in &keys {
        for n in &nonces {
            for p in &plaintexts {
                let (_ct, _tag) = seal(k, n, b"", p);
            }
        }
    }
}

#[test]
fn seal_open_round_trip_at_boundaries() {
    let cases: &[([u8; 32], [u8; 12], [u8; 32])] = &[
        ([0u8; 32], [0u8; 12], [0u8; 32]),
        ([0xFFu8; 32], [0xFFu8; 12], [0xFFu8; 32]),
        ([0x5Au8; 32], [0xA5u8; 12], [0x42u8; 32]),
    ];
    for (k, n, p) in cases {
        let (ct, tag) = seal(k, n, b"", p);
        let pt = open(k, n, b"", &ct, &tag).expect("authentic ciphertext should decrypt");
        assert_eq!(&pt, p);
    }
}

#[test]
fn open_rejects_tampered_tag_without_panic() {
    let k = [0x42u8; 32];
    let n = [0x11u8; 12];
    let p = [0x77u8; 32];
    let (ct, mut tag) = seal(&k, &n, b"", &p);
    tag[0] ^= 0x01;
    let err = open(&k, &n, b"", &ct, &tag).expect_err("tampered tag must fail to verify");
    assert_eq!(err, AuthError);
}

#[test]
fn aad_binding_rejects_wrong_aad_at_open() {
    let k = [0xABu8; 32];
    let n = [0xCDu8; 12];
    let p = [0xEFu8; 32];
    let aad: &[u8] = &[0x01, 0x00, 0x00, 0x00]; // agent_pid = 1 LE

    let (ct, tag) = seal(&k, &n, aad, &p);

    // Correct AAD must decrypt.
    open(&k, &n, aad, &ct, &tag).expect("correct AAD must verify");

    // Any mutation of the on-wire AAD must fail.
    for i in 0..aad.len() {
        let mut bad = aad.to_vec();
        bad[i] ^= 0xFF;
        assert!(open(&k, &n, &bad, &ct, &tag).is_err(), "mutated AAD byte {i} must fail");
    }

    // Missing AAD must fail.
    assert!(open(&k, &n, b"", &ct, &tag).is_err(), "empty AAD must fail for non-empty sealed");
}

#[test]
fn derive_agent_key_does_not_panic_at_pid_boundaries() {
    let master = Key::from_bytes([0xC3u8; 32]);
    for pid in [0u32, 1u32, u32::MAX, u32::MAX - 1, 0x8000_0000u32] {
        // Should never panic — `okm` is fixed [u8; 32], far below HKDF's
        // 255 × 32 = 8160-byte limit.
        let _k = derive_agent_key(&master, pid);
    }
}

#[test]
fn derive_epoch_key_does_not_panic_at_epoch_boundaries() {
    let agent = Key::from_bytes([0xC3u8; 32]);
    for epoch in [0u64, 1u64, u64::MAX, u64::MAX - 1, 0x8000_0000_0000_0000u64] {
        let _k = derive_epoch_key(&agent, epoch);
    }
}

#[test]
fn full_key_hierarchy_chain_does_not_panic() {
    // Walk the full key tree (master → agent → epoch) at boundary inputs.
    let masters: [[u8; 32]; 2] = [[0u8; 32], [0xFFu8; 32]];
    let pids: [u32; 2] = [0, u32::MAX];
    let epochs: [u64; 2] = [0, u64::MAX];

    for m in &masters {
        let master = Key::from_bytes(*m);
        for pid in &pids {
            let agent = derive_agent_key(&master, *pid);
            for ep in &epochs {
                let _epoch_key = derive_epoch_key(&agent, *ep);
            }
        }
    }
}
