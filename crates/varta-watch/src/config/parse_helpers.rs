#[cfg(not(feature = "compile-time-config"))]
use super::types::ConfigError;

#[cfg(not(feature = "compile-time-config"))]
pub(super) fn parse_u64(flag: &'static str, raw: &str) -> Result<u64, ConfigError> {
    raw.parse::<u64>().map_err(|_| ConfigError::BadInteger {
        flag,
        raw: raw.to_string(),
    })
}

#[cfg(not(feature = "compile-time-config"))]
pub(super) fn parse_u16(flag: &'static str, raw: &str) -> Result<u16, ConfigError> {
    raw.parse::<u16>().map_err(|_| ConfigError::BadInteger {
        flag,
        raw: raw.to_string(),
    })
}

#[cfg(not(feature = "compile-time-config"))]
pub(super) fn parse_octal(raw: &str) -> Result<u32, ConfigError> {
    // Accept the three forms a user might naturally type: bare octal (`600`),
    // leading-zero octal (`0600`), or Rust-literal octal (`0o600` / `0O600`).
    // `from_str_radix` only handles the first two; the prefix is stripped here.
    let digits = raw
        .strip_prefix("0o")
        .or_else(|| raw.strip_prefix("0O"))
        .unwrap_or(raw);
    if digits.is_empty() {
        return Err(ConfigError::BadSocketMode(raw.to_string()));
    }
    u32::from_str_radix(digits, 8).map_err(|_| ConfigError::BadSocketMode(raw.to_string()))
}
