//! Poly1305 one-time authenticator — RFC 8439 §2.5.
//!
//! Produces a 128-bit (16-byte) authentication tag given a 256-bit (32-byte)
//! one-time key and an arbitrary-length message. Used as the MAC primitive in
//! the ChaCha20-Poly1305 AEAD construction.
//!
//! Internal representation uses 5 limbs of 26 bits for the 130-bit
//! accumulator, with u128 for intermediate products to avoid overflow.

/// Decompose 16 bytes into five 26-bit limbs.
///
/// `has_padding` controls whether the 0x01 byte (at position `16`) is
/// appended. Set `true` for message blocks and `s` (the s component of the
/// one-time key), `false` for the clamped `r` component.
fn bytes_to_limbs_26(bytes: &[u8; 16], has_padding: bool) -> [u64; 5] {
    let val = u128::from_le_bytes(*bytes);
    let extra = if has_padding { 1u64 << 24 } else { 0u64 };
    // extra contributes 2^128 at bit position 104+24=128 in the 5th limb

    [
        (val as u64) & 0x03ff_ffff,
        ((val >> 26) as u64) & 0x03ff_ffff,
        ((val >> 52) as u64) & 0x03ff_ffff,
        ((val >> 78) as u64) & 0x03ff_ffff,
        ((val >> 104) as u64 & 0x03ff_ffff) | extra,
    ]
}

/// Decompose a partial block (len < 16 bytes) into five 26-bit limbs.
///
/// The 0x01 byte is placed at the end of the input per RFC 8439 §2.5.1.
fn partial_block_to_limbs(bytes: &[u8]) -> [u64; 5] {
    debug_assert!(bytes.len() < 16, "partial block must be < 16 bytes");
    let len = bytes.len().min(15);
    let mut buf = [0u8; 16];
    buf[..len].copy_from_slice(&bytes[..len]);
    buf[len] = 0x01;

    let val = u128::from_le_bytes(buf);
    // No extra bit needed — the 0x01 is inside the 128-bit val
    [
        (val as u64) & 0x03ff_ffff,
        ((val >> 26) as u64) & 0x03ff_ffff,
        ((val >> 52) as u64) & 0x03ff_ffff,
        ((val >> 78) as u64) & 0x03ff_ffff,
        ((val >> 104) as u64) & 0x03ff_ffff,
    ]
}

/// Multiply `h` (5×26-bit limbs) by `r` (5×26-bit limbs) modulo 2¹³⁰ − 5.
fn mul_mod(h: [u64; 5], r: [u64; 5]) -> [u64; 5] {
    // Schoolbook multiplication: d[k] = Σ h[i] * r[j]  for i + j = k.
    // Each product fits in u128; each sum fits in u64.
    let mut d: [u64; 9] = [0; 9];
    for i in 0..5 {
        let hi = h[i] as u128;
        for j in 0..5 {
            d[i + j] = d[i + j].wrapping_add((hi * r[j] as u128) as u64);
        }
    }

    // ── first carry propagation ──────────────────────────────────────────
    let mut carry: u64;
    macro_rules! carry_26 {
        ($idx:expr, $next:expr) => {
            carry = d[$idx] >> 26;
            d[$next] = d[$next].wrapping_add(carry);
            d[$idx] &= 0x03ff_ffff;
        };
    }
    carry_26!(0, 1);
    carry_26!(1, 2);
    carry_26!(2, 3);
    carry_26!(3, 4);
    carry_26!(4, 5);
    carry_26!(5, 6);
    carry_26!(6, 7);
    carry_26!(7, 8);

    // ── modular reduction: wrap d[5..8] via 2¹³⁰ ≡ 5 ────────────────────
    d[0] = d[0].wrapping_add(d[5].wrapping_mul(5));
    d[1] = d[1].wrapping_add(d[6].wrapping_mul(5));
    d[2] = d[2].wrapping_add(d[7].wrapping_mul(5));
    d[3] = d[3].wrapping_add(d[8].wrapping_mul(5));

    // ── second carry propagation ─────────────────────────────────────────
    carry_26!(0, 1);
    carry_26!(1, 2);
    carry_26!(2, 3);
    carry_26!(3, 4);

    // d[4] may still be >= 2²⁶ after the wrap adds. One more wrap handles it.
    carry = d[4] >> 26;
    d[0] = d[0].wrapping_add(carry.wrapping_mul(5));
    d[4] &= 0x03ff_ffff;

    // Final ripple from d[0]:
    carry = d[0] >> 26;
    d[1] = d[1].wrapping_add(carry);
    d[0] &= 0x03ff_ffff;

    [d[0], d[1], d[2], d[3], d[4]]
}

/// Convert five 26-bit limbs to a 16-byte little-endian tag (lower 128 bits).
fn limbs_to_bytes(h: [u64; 5]) -> [u8; 16] {
    // Only the lower 24 bits of h[4] contribute to the 128-bit output.
    let total = (h[0] as u128)
        | ((h[1] as u128) << 26)
        | ((h[2] as u128) << 52)
        | ((h[3] as u128) << 78)
        | (((h[4] as u128) & 0x00ff_ffff) << 104);
    total.to_le_bytes()
}

/// Process one 16-byte message block through the Poly1305 accumulator.
fn process_block(h: [u64; 5], r: [u64; 5], block: &[u8; 16]) -> [u64; 5] {
    let c = bytes_to_limbs_26(block, true);
    let mut h = h;
    for i in 0..5 {
        h[i] = h[i].wrapping_add(c[i]);
    }
    mul_mod(h, r)
}

/// Compute the Poly1305 one-time authenticator tag.
///
/// `otk` is the 32-byte one-time key (first 32 keystream bytes from ChaCha20
/// with counter=0). `msg` is the message to authenticate.
pub fn poly1305_mac(otk: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // Clamp r
    let mut r_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&otk[..16]);
    r_bytes[3] &= 15;
    r_bytes[7] &= 15;
    r_bytes[11] &= 15;
    r_bytes[15] &= 15;
    r_bytes[4] &= 252;
    r_bytes[8] &= 252;
    r_bytes[12] &= 252;

    let r = bytes_to_limbs_26(&r_bytes, false);

    let s_bytes: [u8; 16] = otk[16..32].try_into().unwrap();
    let s = bytes_to_limbs_26(&s_bytes, false);

    let mut h = [0u64; 5];

    // Process full 16-byte blocks
    let full_blocks = msg.len() / 16;
    let mut offset = 0;
    for _ in 0..full_blocks {
        let block: [u8; 16] = msg[offset..offset + 16].try_into().unwrap();
        h = process_block(h, r, &block);
        offset += 16;
    }

    // Process partial final block (if any)
    let remainder = &msg[offset..];
    if !remainder.is_empty() {
        let c = partial_block_to_limbs(remainder);
        for i in 0..5 {
            h[i] = h[i].wrapping_add(c[i]);
        }
        h = mul_mod(h, r);
    }

    // h = h + s
    for i in 0..5 {
        h[i] = h[i].wrapping_add(s[i]);
    }

    // Final carry propagation after s addition
    let mut carry: u64;
    carry = h[0] >> 26;
    h[1] = h[1].wrapping_add(carry);
    h[0] &= 0x03ff_ffff;

    carry = h[1] >> 26;
    h[2] = h[2].wrapping_add(carry);
    h[1] &= 0x03ff_ffff;

    carry = h[2] >> 26;
    h[3] = h[3].wrapping_add(carry);
    h[2] &= 0x03ff_ffff;

    carry = h[3] >> 26;
    h[4] = h[4].wrapping_add(carry);
    h[3] &= 0x03ff_ffff;

    carry = h[4] >> 26;
    h[0] = h[0].wrapping_add(carry.wrapping_mul(5));
    h[4] &= 0x03ff_ffff;

    carry = h[0] >> 26;
    h[1] = h[1].wrapping_add(carry);
    h[0] &= 0x03ff_ffff;

    limbs_to_bytes(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8439 §2.5.2 — Poly1305 Test Vector
    #[test]
    fn rfc8439_poly1305_test_vector() {
        let otk: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];

        let msg: [u8; 34] = [
            0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72, 0x61, 0x70, 0x68, 0x69, 0x63, 0x20,
            0x46, 0x6f, 0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
            0x20, 0x47, 0x72, 0x6f, 0x75, 0x70,
        ];

        let tag = poly1305_mac(&otk, &msg);

        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];

        assert_eq!(tag, expected, "RFC 8439 Poly1305 test vector mismatch");
    }

    #[test]
    fn poly1305_empty_message() {
        let otk = [0u8; 32];
        let tag = poly1305_mac(&otk, &[]);
        assert_eq!(tag.len(), 16);
    }

    #[test]
    fn poly1305_deterministic() {
        let otk = [0x42u8; 32];
        let msg = b"hello world";
        let tag1 = poly1305_mac(&otk, msg);
        let tag2 = poly1305_mac(&otk, msg);
        assert_eq!(tag1, tag2, "same input must produce same tag");
    }

    #[test]
    fn poly1305_different_key_different_tag() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let msg = b"test message";
        let tag1 = poly1305_mac(&key1, msg);
        let tag2 = poly1305_mac(&key2, msg);
        assert_ne!(tag1, tag2, "different keys must produce different tags");
    }
}
