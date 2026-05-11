//! ChaCha20 stream cipher — RFC 8439 §2.4.
//!
//! Implements the ChaCha20 quarter-round, block function (20 rounds), and
//! keystream generation used as the encryption primitive in the
//! ChaCha20-Poly1305 AEAD construction.
//!
//! All operations are pure arithmetic — naturally constant-time on any CPU
//! that executes adds/xors/rotates at fixed latency.

/// A single ChaCha20 quarter round on four 32-bit words.
///
/// Applied to state indices `(a, b, c, d)` in-place. This is the core
/// diffusion primitive — each column and diagonal of the 4×4 state matrix
/// goes through one quarter round per half-round.
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// Generate one 64-byte ChaCha20 keystream block.
///
/// `counter` is the 32-bit block counter (starting at 0 or 1 depending on
/// the AEAD construction). `nonce` is the 96-bit (12-byte) message nonce.
///
/// Returns 64 bytes of keystream. The caller XORs this with the plaintext
/// to encrypt (or with ciphertext to decrypt).
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    // State initialisation per RFC 8439 §2.3:
    //   [0..3]   = constant "expand 32-byte k"
    //   [4..11]  = 256-bit key
    //   [12]     = 32-bit block counter
    //   [13..15] = 96-bit nonce

    let mut state: [u32; 16] = [
        0x6170_7865, // "expa"
        0x3320_646e, // "nd 3"
        0x7962_2d32, // "2-by"
        0x6b20_6574, // "te k"
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0, // key (filled below)
        0, // counter
        0,
        0,
        0, // nonce
    ];

    for i in 0..8 {
        let base = 4 * i;
        state[4 + i] = u32::from_le_bytes([key[base], key[base + 1], key[base + 2], key[base + 3]]);
    }

    state[12] = counter;

    for i in 0..3 {
        let base = 4 * i;
        state[13 + i] = u32::from_le_bytes([
            nonce[base],
            nonce[base + 1],
            nonce[base + 2],
            nonce[base + 3],
        ]);
    }

    let mut working = state;

    // 20 rounds = 10 double rounds
    for _ in 0..10 {
        // Column round
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal round
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    // Add original state
    for i in 0..16 {
        working[i] = working[i].wrapping_add(state[i]);
    }

    // Serialise as 64 bytes little-endian
    let mut out = [0u8; 64];
    for i in 0..16 {
        let bytes = working[i].to_le_bytes();
        out[4 * i..4 * i + 4].copy_from_slice(&bytes);
    }
    out
}

/// XOR `data` in-place with the ChaCha20 keystream starting at `counter`.
///
/// Processes `data` in 64-byte blocks (each block consumes one counter value).
/// The last partial block uses only as many keystream bytes as needed.
pub fn chacha20_xor(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    for chunk in data.chunks_mut(64) {
        let keystream = chacha20_block(key, counter, nonce);
        for (d, k) in chunk.iter_mut().zip(keystream.iter()) {
            *d ^= k;
        }
        counter = counter.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8439 §2.4.2 — Test Vector for the ChaCha20 Block Function
    // https://datatracker.ietf.org/doc/html/rfc8439#section-2.4.2
    #[test]
    fn rfc8439_block_test_vector() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter: u32 = 1;

        let block = chacha20_block(&key, counter, &nonce);

        let expected: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];

        assert_eq!(block, expected, "RFC 8439 block test vector mismatch");
    }

    #[test]
    fn chacha20_block_different_nonce_different_output() {
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce_a: [u8; 12] = [0; 12];
        let nonce_b: [u8; 12] = [1; 12];

        let block_a = chacha20_block(&key, 0, &nonce_a);
        let block_b = chacha20_block(&key, 0, &nonce_b);
        assert_ne!(
            block_a, block_b,
            "different nonces must produce different output"
        );
    }

    #[test]
    fn chacha20_xor_roundtrip() {
        let key = [0xabu8; 32];
        let nonce = [0x42u8; 12];
        let mut data = [0xdeu8; 65]; // odd size to test partial block

        let original = data;
        chacha20_xor(&key, 0, &nonce, &mut data);
        assert_ne!(data, original, "encryption should change data");
        chacha20_xor(&key, 0, &nonce, &mut data);
        assert_eq!(data, original, "decryption should recover original");
    }

    #[test]
    fn chacha20_xor_empty() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut data: [u8; 0] = [];
        chacha20_xor(&key, 0, &nonce, &mut data);
    }
}
