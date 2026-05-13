//! ChaCha20-Poly1305 AEAD for VLP secure transports — RFC 8439.
//!
//! Feature-gated behind `crypto`. Provides symmetric authenticated encryption
//! for 32-byte VLP frames. All operations are stack-allocated and allocation-free
//! on the steady-state path. Primitives are provided by the externally-audited
//! `chacha20poly1305` crate (RustCrypto, NCC Group audit 2020); no hand-rolled
//! crypto exists in this module.
//!
//! # Wire format
//!
//! Each secure frame is 60 bytes:
//!
//! ```text
//! [iv_random: 8] [iv_counter: 4] [ciphertext: 32] [tag: 16]
//! ```
//!
//! The 12-byte nonce for the AEAD construction is `iv_random || iv_counter`.

pub mod aead;
pub mod kdf;

pub use aead::{open, seal, AuthError};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of the pre-shared symmetric key (256 bits).
pub const KEY_BYTES: usize = 32;

/// Length of the AEAD nonce (96 bits).
pub const NONCE_BYTES: usize = 12;

/// Length of the Poly1305 authentication tag (128 bits).
pub const TAG_BYTES: usize = 16;

/// Total length of a secure frame on the wire.
///
/// 8 (iv_random) + 4 (iv_counter) + 32 (ciphertext) + 16 (tag) = 60.
pub const SECURE_FRAME_BYTES: usize = 60;

/// Error returned when a hex-encoded key fails to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The hex string has the wrong length (must be 64 hex chars = 32 bytes).
    InvalidLength(usize),
    /// The hex string contains a non-hex character.
    InvalidCharacter(usize, char),
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeyError::InvalidLength(len) => {
                write!(f, "key hex must be 64 characters, got {len}")
            }
            KeyError::InvalidCharacter(pos, ch) => {
                write!(f, "invalid hex character '{ch}' at position {pos}")
            }
        }
    }
}

/// A 256-bit pre-shared symmetric key for ChaCha20-Poly1305.
///
/// Created from a hex string (64 characters) or raw bytes. Both the agent
/// and observer must share the same key.
///
/// `Key` is intentionally **not** `Copy`. The `ZeroizeOnDrop` impl zeroes
/// the secret bytes on drop; an implicit copy would defeat that wipe by
/// leaving a silent duplicate behind in some other stack frame.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key {
    pub(crate) bytes: [u8; KEY_BYTES],
}

impl Key {
    /// Create a key from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Key { bytes }
    }

    /// Parse a key from a 64-character hex string.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::InvalidLength`] if the string is not exactly 64
    /// characters, or [`KeyError::InvalidCharacter`] if a non-hex digit is
    /// found.
    pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
        let bytes = crate::util::decode_hex_32(hex.as_bytes()).map_err(|e| match e {
            crate::util::HexDecodeError::InvalidLength(n) => KeyError::InvalidLength(n),
            crate::util::HexDecodeError::InvalidCharacter(pos, ch) => {
                KeyError::InvalidCharacter(pos, ch)
            }
        })?;
        Ok(Key { bytes })
    }

    /// Load a key from a file containing a 64-character hex string.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file cannot be read or the contents
    /// cannot be parsed as a hex key.
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let hex = std::fs::read_to_string(path)?;
        let hex = hex.trim();
        Key::from_hex(hex).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse key file {}: {e}", path.display()),
            )
        })
    }

    /// Expose the raw key bytes. For use by transport implementations that
    /// call `seal` / `open` directly.
    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.bytes
    }
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Key").finish_non_exhaustive()
    }
}

pub use crate::util::{ct_eq, decode_hex_32, HexDecodeError};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_from_hex_valid() {
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let key = Key::from_hex(hex).expect("valid hex key should parse");
        assert_eq!(key.bytes[0], 0x00);
        assert_eq!(key.bytes[1], 0x01);
        assert_eq!(key.bytes[31], 0x1f);
    }

    #[test]
    fn key_from_hex_invalid_length() {
        let hex = "00";
        let err = Key::from_hex(hex).unwrap_err();
        assert!(matches!(err, KeyError::InvalidLength(2)));
    }

    #[test]
    fn key_from_hex_invalid_char() {
        let hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let err = Key::from_hex(hex).unwrap_err();
        assert!(matches!(err, KeyError::InvalidCharacter(..)));
    }

    #[test]
    fn key_debug_format_hides_secret() {
        let key = Key::from_bytes([0x42; 32]);
        let debug_str = format!("{:?}", key);
        assert!(!debug_str.contains("42"))
    }
}
