//! ChaCha20-Poly1305 AEAD for VLP secure transports — RFC 8439.
//!
//! Feature-gated behind `crypto`. Provides symmetric authenticated encryption
//! for 32-byte VLP frames. All operations are stack-allocated and allocation-free
//! on the steady-state path.
//!
//! # Wire format
//!
//! Each secure frame is 60 bytes:
//!
//! ```text
//! [iv_random: 4] [iv_counter: 8] [ciphertext: 32] [tag: 16]
//! ```
//!
//! The 12-byte nonce for the AEAD construction is `iv_random || iv_counter`.

pub mod aead;
pub mod chacha20;
pub mod poly1305;

pub use aead::{open, seal, AuthError};

/// Length of the pre-shared symmetric key (256 bits).
pub const KEY_BYTES: usize = 32;

/// Length of the AEAD nonce (96 bits).
pub const NONCE_BYTES: usize = 12;

/// Length of the Poly1305 authentication tag (128 bits).
pub const TAG_BYTES: usize = 16;

/// Total length of a secure frame on the wire.
///
/// 4 (iv_random) + 8 (iv_counter) + 32 (ciphertext) + 16 (tag) = 60.
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
#[derive(Clone, PartialEq, Eq)]
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
        if hex.len() != 64 {
            return Err(KeyError::InvalidLength(hex.len()));
        }

        let mut bytes = [0u8; KEY_BYTES];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hi =
                hex_val(chunk[0]).ok_or(KeyError::InvalidCharacter(i * 2, chunk[0] as char))?;
            let lo =
                hex_val(chunk[1]).ok_or(KeyError::InvalidCharacter(i * 2 + 1, chunk[1] as char))?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Key { bytes })
    }

    /// Load a key from an environment variable.
    ///
    /// Reads the variable `name` and parses it as a hex-encoded 64-character
    /// string.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` with kind `NotFound` if the variable is not set,
    /// or kind `InvalidData` if the value cannot be parsed as a hex key.
    pub fn from_env(name: &str) -> std::io::Result<Self> {
        let val = std::env::var(name).map_err(|e| match e {
            std::env::VarError::NotPresent => std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("environment variable {name} is not set"),
            ),
            std::env::VarError::NotUnicode(_) => std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("environment variable {name} is not valid Unicode"),
            ),
        })?;
        Key::from_hex(&val).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse {name}: {e}"),
            )
        })
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
