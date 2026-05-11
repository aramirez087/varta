//! ChaCha20-Poly1305 AEAD construction — RFC 8439 §2.8.
//!
//! Implements `seal` (encrypt + authenticate) and `open` (verify + decrypt)
//! for 32-byte fixed-size plaintexts. This is the cipher used by
//! `SecureUdpTransport` and `SecureUdpListener`.
//!
//! # Construction
//!
//! 1. Generate one-time Poly1305 key from ChaCha20 block with counter=0.
//! 2. Encrypt plaintext with ChaCha20 keystream starting at counter=1.
//! 3. Authenticate the ciphertext (plus encoded lengths) with Poly1305.
//!
//! No additional authenticated data (AAD) is used — the nonce itself binds
//! the encrypted frame to the specific message context.
//!
//! # Wire format
//!
//! The [`seal`] function returns `(ciphertext, tag)`. The transport layer
//! places these on the wire alongside the 12-byte nonce split into its
//! two components — 4-byte `iv_random` and 8-byte `iv_counter`:
//!
//! ```text
//! [iv_random: 4] [iv_counter: 8] [ciphertext: 32] [tag: 16]
//! ```
//!
//! See [`varta_vlp::crypto`] for the wire format constant.

use super::chacha20::{chacha20_block, chacha20_xor};
use super::poly1305::poly1305_mac;

/// AEAD authentication failure — the tag did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthError;

/// Encrypt a 32-byte plaintext and produce a 16-byte authentication tag.
///
/// # Parameters
///
/// * `key` — 256-bit (32-byte) pre-shared symmetric key.
/// * `nonce` — 96-bit (12-byte) message nonce. **Must never be reused**
///   with the same key. The caller is responsible for nonce uniqueness.
/// * `plaintext` — 32-byte VLP frame to encrypt.
///
/// # Returns
///
/// `(ciphertext, tag)` where `ciphertext` is 32 bytes and `tag` is 16 bytes.
/// The transport layer joins these with the caller-provided nonce prefix
/// for a total of 60 bytes.
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8; 32]) -> ([u8; 32], [u8; 16]) {
    // Step 1: Generate one-time Poly1305 key (first 32 bytes of keystream
    // block at counter 0).
    let block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    // Step 2: Encrypt plaintext (block counter starts at 1).
    let mut ciphertext = *plaintext;
    chacha20_xor(key, 1, nonce, &mut ciphertext);

    // Step 3: Construct Poly1305 message:
    //   mac_data = pad(ciphertext) || le64(0) || le64(32)
    // Since ciphertext is exactly 32 bytes (a multiple of 16), no padding
    // is needed. AAD length is 0.
    let mut mac_data = [0u8; 48];
    mac_data[..32].copy_from_slice(&ciphertext);
    // le64(0) = already zeros at [32..40]
    mac_data[40..48].copy_from_slice(&32u64.to_le_bytes());

    let tag = poly1305_mac(&otk, &mac_data);

    (ciphertext, tag)
}

/// Verify and decrypt a ChaCha20-Poly1305 AEAD ciphertext.
///
/// # Parameters
///
/// * `key` — 256-bit (32-byte) pre-shared symmetric key.
/// * `nonce` — 96-bit (12-byte) message nonce (must match the nonce used
///   during encryption).
/// * `ciphertext` — 32-byte encrypted payload.
/// * `tag` — 16-byte Poly1305 authentication tag.
///
/// # Returns
///
/// `Ok(plaintext)` on successful authentication and decryption, or
/// `Err(AuthError)` if the tag does not verify (indicating tampering,
/// wrong key, or corrupted data).
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8; 32],
    tag: &[u8; 16],
) -> Result<[u8; 32], AuthError> {
    // Step 1: Regenerate one-time Poly1305 key.
    let block0 = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&block0[..32]);

    // Step 2: Verify the authentication tag.
    let mut mac_data = [0u8; 48];
    mac_data[..32].copy_from_slice(ciphertext);
    mac_data[40..48].copy_from_slice(&32u64.to_le_bytes());

    let computed_tag = poly1305_mac(&otk, &mac_data);

    // Constant-time comparison (timing-safe)
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ computed_tag[i];
    }
    if diff != 0 {
        return Err(AuthError);
    }

    // Step 3: Decrypt ciphertext.
    let mut plaintext = *ciphertext;
    chacha20_xor(key, 1, nonce, &mut plaintext);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::chacha20::{chacha20_block, chacha20_xor};
    use crate::crypto::poly1305::poly1305_mac;

    // Known-answer test: validate that seal() matches manually-composed
    // primitive output.  The chacha20 and poly1305 primitives are each
    // independently RFC-verified; this test ensures the AEAD glue layers
    // compose them correctly (counter start, mac_data layout, padding).
    #[test]
    fn aead_known_answer_against_primitives() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let plaintext = [0xdeu8; 32];

        // Compute expected via primitives (RFC-verified independently)
        let block0 = chacha20_block(&key, 0, &nonce);
        let mut otk = [0u8; 32];
        otk.copy_from_slice(&block0[..32]);

        let mut expected_ct = plaintext;
        chacha20_xor(&key, 1, &nonce, &mut expected_ct);

        let mut mac_data = [0u8; 48];
        mac_data[..32].copy_from_slice(&expected_ct);
        mac_data[40..48].copy_from_slice(&32u64.to_le_bytes());
        let expected_tag = poly1305_mac(&otk, &mac_data);

        let (ct, tag) = seal(&key, &nonce, &plaintext);
        assert_eq!(
            ct, expected_ct,
            "ciphertext must match primitive composition"
        );
        assert_eq!(tag, expected_tag, "tag must match primitive composition");
    }

    #[test]
    fn aead_roundtrip_rfc8439_params() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];

        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];

        // Roundtrip with 32-byte plaintext using the known test vector parameters
        let plaintext = [
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73,
        ];

        let (ciphertext, tag) = seal(&key, &nonce, &plaintext);
        let decrypted = open(&key, &nonce, &ciphertext, &tag)
            .expect("roundtrip with RFC params should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aead_roundtrip() {
        let key = [0xabu8; 32];
        let nonce = [0x42u8; 12];
        let plaintext = [0xdeu8; 32];

        let (ciphertext, tag) = seal(&key, &nonce, &plaintext);
        assert_ne!(ciphertext, plaintext, "encryption should change data");

        let decrypted = open(&key, &nonce, &ciphertext, &tag)
            .expect("decryption should succeed with correct key and nonce");
        assert_eq!(
            decrypted, plaintext,
            "roundtrip should recover original plaintext"
        );
    }

    #[test]
    fn aead_wrong_key_fails() {
        let key_a = [0xabu8; 32];
        let key_b = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = [0xdeu8; 32];

        let (ciphertext, tag) = seal(&key_a, &nonce, &plaintext);

        let result = open(&key_b, &nonce, &ciphertext, &tag);
        assert!(result.is_err(), "decryption with wrong key must fail");
    }

    #[test]
    fn aead_wrong_nonce_fails() {
        let key = [0xabu8; 32];
        let nonce_a = [0x01u8; 12];
        let nonce_b = [0x02u8; 12];
        let plaintext = [0xdeu8; 32];

        let (ciphertext, tag) = seal(&key, &nonce_a, &plaintext);

        let result = open(&key, &nonce_b, &ciphertext, &tag);
        assert!(result.is_err(), "decryption with wrong nonce must fail");
    }

    #[test]
    fn aead_tampered_ciphertext_fails() {
        let key = [0xabu8; 32];
        let nonce = [0x42u8; 12];
        let plaintext = [0xdeu8; 32];

        let (mut ciphertext, tag) = seal(&key, &nonce, &plaintext);
        ciphertext[15] ^= 0x01;

        let result = open(&key, &nonce, &ciphertext, &tag);
        assert!(
            result.is_err(),
            "decryption with tampered ciphertext must fail"
        );
    }

    #[test]
    fn aead_tampered_tag_fails() {
        let key = [0xabu8; 32];
        let nonce = [0x42u8; 12];
        let plaintext = [0xdeu8; 32];

        let (ciphertext, mut tag) = seal(&key, &nonce, &plaintext);
        tag[0] ^= 0x01;

        let result = open(&key, &nonce, &ciphertext, &tag);
        assert!(result.is_err(), "decryption with tampered tag must fail");
    }

    #[test]
    fn aead_same_input_same_output() {
        let key = [0xabu8; 32];
        let nonce = [0x42u8; 12];
        let plaintext = [0xdeu8; 32];

        let (ct1, tag1) = seal(&key, &nonce, &plaintext);
        let (ct2, tag2) = seal(&key, &nonce, &plaintext);

        assert_eq!(ct1, ct2, "same input must produce same ciphertext");
        assert_eq!(tag1, tag2, "same input must produce same tag");
    }
}
