//! Allocation-free utilities shared across protocol layers.
//!
//! This module is always compiled (unlike [`crate::crypto`], which is
//! feature-gated). The helpers here are needed both on the cryptographic
//! hot path (AEAD tag verification, key parsing) and on the
//! Prometheus `/metrics` bearer-token path inside `varta-watch`, which
//! does not require the `crypto` feature.

/// Error returned by [`decode_hex_32`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexDecodeError {
    /// Input was not exactly 64 ASCII characters.
    InvalidLength(usize),
    /// Input contained a non-hex byte at the given position.
    InvalidCharacter(usize, char),
}

impl core::fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HexDecodeError::InvalidLength(n) => {
                write!(f, "expected 64 hex characters, got {n}")
            }
            HexDecodeError::InvalidCharacter(pos, ch) => {
                write!(f, "invalid hex character {ch:?} at position {pos}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HexDecodeError {}

/// Decode 64 ASCII hex characters into a 32-byte array.
///
/// Used by [`crate::crypto::Key::from_hex`] and by the `varta-watch`
/// Prometheus bearer-token parser, both of which need allocation-free,
/// fixed-size hex decoding on a request hot path.
pub fn decode_hex_32(hex: &[u8]) -> Result<[u8; 32], HexDecodeError> {
    if hex.len() != 64 {
        return Err(HexDecodeError::InvalidLength(hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.chunks_exact(2).enumerate() {
        let hi =
            hex_val(pair[0]).ok_or(HexDecodeError::InvalidCharacter(i * 2, pair[0] as char))?;
        let lo =
            hex_val(pair[1]).ok_or(HexDecodeError::InvalidCharacter(i * 2 + 1, pair[1] as char))?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Constant-time byte slice equality.
///
/// Returns `false` immediately if the lengths differ (length is treated as
/// a public contract, not a secret). For equal-length inputs the loop ORs
/// all XOR differences before comparing, so wall-clock time is independent
/// of where the first mismatch lies. Used for AEAD tag verification and
/// for Prometheus bearer-token comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Encode a 32-byte array as 64 lowercase ASCII hex characters.
///
/// The inverse of [`decode_hex_32`]. Used by the `varta-watch` recovery
/// audit log to serialise the SHA-256 chain hash into a TSV column without
/// pulling a heap-allocating `hex` crate into the workspace.
pub fn encode_hex_32(bytes: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_hex_32_round_trips() {
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let bytes = decode_hex_32(hex.as_bytes()).expect("valid hex");
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[15], 0x0f);
        assert_eq!(bytes[31], 0x1f);
    }

    #[test]
    fn decode_hex_32_rejects_wrong_length() {
        assert!(matches!(
            decode_hex_32(b"00"),
            Err(HexDecodeError::InvalidLength(2))
        ));
        assert!(matches!(
            decode_hex_32(&[b'0'; 63]),
            Err(HexDecodeError::InvalidLength(63))
        ));
    }

    #[test]
    fn decode_hex_32_rejects_non_hex() {
        let mut bad = [b'0'; 64];
        bad[3] = b'z';
        assert!(matches!(
            decode_hex_32(&bad),
            Err(HexDecodeError::InvalidCharacter(3, 'z'))
        ));
    }

    #[test]
    fn encode_hex_32_round_trips_with_decode() {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let bytes = decode_hex_32(hex.as_bytes()).expect("valid hex");
        let round = encode_hex_32(&bytes);
        assert_eq!(core::str::from_utf8(&round).unwrap(), hex);
    }

    #[test]
    fn encode_hex_32_emits_lowercase() {
        let bytes = [0xab; 32];
        let hex = encode_hex_32(&bytes);
        assert!(hex.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn ct_eq_matches_equal_slices() {
        assert!(ct_eq(b"abcd", b"abcd"));
        assert!(ct_eq(&[0u8; 32], &[0u8; 32]));
    }

    #[test]
    fn ct_eq_rejects_mismatch_and_length_skew() {
        assert!(!ct_eq(b"abcd", b"abce"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(!ct_eq(b"", b"a"));
    }
}
