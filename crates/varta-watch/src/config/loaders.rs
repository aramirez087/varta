use super::types::Config;
#[cfg(feature = "secure-udp")]
use super::validate::read_secret_file;
use super::validate::validate_recovery_file;
#[cfg(feature = "prometheus-exporter")]
use super::validate::validate_secret_file;

#[cfg(feature = "secure-udp")]
fn load_key_file(path: &std::path::Path) -> std::io::Result<Vec<varta_vlp::crypto::Key>> {
    use std::io;
    use varta_vlp::crypto::Key;

    let content = read_secret_file(path)?;
    let mut keys = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = Key::from_hex(line).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })?;
        keys.push(key);
    }
    Ok(keys)
}

impl Config {
    /// Resolve recovery mode from CLI flags, enforcing mutual exclusion
    /// and loading/validating any file-based command sources.
    ///
    /// Returns `Ok(None)` when no recovery is configured. Returns
    /// `Ok(Some(RecoveryMode::Exec{..}))` when `--recovery-exec` or
    /// `--recovery-exec-file` is set.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if a file cannot be read, its permissions are
    /// too open, or mutually exclusive flags are specified.
    pub fn resolve_recovery_mode(&self) -> std::io::Result<Option<crate::recovery::RecoveryMode>> {
        use crate::recovery::RecoveryMode;

        // Collect which sources are configured
        let has_exec = self.recovery_exec_cmd.is_some();
        let has_exec_file = self.recovery_exec_file.is_some();

        if has_exec && has_exec_file {
            #[cfg(not(feature = "compile-time-config"))]
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--recovery-exec and --recovery-exec-file are mutually exclusive",
            ));
            #[cfg(feature = "compile-time-config")]
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "inline exec-recovery command and exec-recovery file are mutually exclusive",
            ));
        }

        // Exec mode
        if let Some(ref cmd) = self.recovery_exec_cmd {
            let mut parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.is_empty() {
                #[cfg(not(feature = "compile-time-config"))]
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "--recovery-exec: command must not be empty",
                ));
                #[cfg(feature = "compile-time-config")]
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "exec-recovery command must not be empty",
                ));
            }
            let program = parts.remove(0).to_string();
            let args: Vec<String> = parts.into_iter().map(|s| s.to_string()).collect();
            return Ok(Some(RecoveryMode::Exec { program, args }));
        }
        if let Some(ref path) = self.recovery_exec_file {
            let cmd = validate_recovery_file(path)?;
            let mut parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{}: file is empty", path.display()),
                ));
            }
            let program = parts.remove(0).to_string();
            let args: Vec<String> = parts.into_iter().map(|s| s.to_string()).collect();
            return Ok(Some(RecoveryMode::Exec { program, args }));
        }

        Ok(None)
    }

    /// Load shared secure-UDP keys for AEAD transport.
    ///
    /// Both `--key-file` and `--accepted-key-file` flow through
    /// [`validate_secret_file`], guaranteeing mode 0600 ownership and an
    /// `O_NOFOLLOW` open. Environment-variable keys were removed (see
    /// `ConfigError::RemovedFlag`) because they leak through
    /// `/proc/<pid>/environ` and `docker inspect`.
    ///
    /// Returns `Ok(None)` when neither shared-key file is set. `--key-file`
    /// must contain exactly one key. `--accepted-key-file` may contain one or
    /// more additional keys and is loaded even when a master key, rather than
    /// a primary shared key, is configured.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file cannot be read, the key(s) cannot
    /// be parsed as 64-character hex strings, the primary key file contains
    /// more than one key, or a configured accepted-key file contains no usable
    /// key.
    #[cfg(feature = "secure-udp")]
    pub fn load_secure_keys(&self) -> std::io::Result<Option<Vec<varta_vlp::crypto::Key>>> {
        use std::io;

        let mut keys = Vec::new();

        if let Some(ref path) = self.secure_key_file {
            let mut primary_keys = load_key_file(path)?;
            if primary_keys.len() > 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: multiple primary keys found (expected exactly one)",
                        path.display()
                    ),
                ));
            }
            let Some(primary) = primary_keys.pop() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: no key found in file", path.display()),
                ));
            };
            keys.push(primary);
        }

        if let Some(ref path) = self.accepted_key_file {
            let accepted = load_key_file(path)?;
            if accepted.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: no key found in file", path.display()),
                ));
            }
            keys.extend(accepted);
        }

        if keys.is_empty() {
            return Ok(None);
        }

        Ok(Some(keys))
    }

    /// Load the master key for per-agent key derivation.
    ///
    /// Returns `Ok(None)` when `--master-key-file` is not set.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file cannot be read, the file does not
    /// meet [`validate_secret_file`]'s hardened requirements, or the key
    /// cannot be parsed as a 64-character hex string.
    #[cfg(feature = "secure-udp")]
    pub fn load_master_key(&self) -> std::io::Result<Option<varta_vlp::crypto::Key>> {
        use varta_vlp::crypto::Key;

        let Some(ref path) = self.master_key_file else {
            return Ok(None);
        };
        let hex = read_secret_file(path)?;
        Key::from_hex(hex.trim()).map(Some).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })
    }

    #[cfg(feature = "prometheus-exporter")]
    /// Load the Prometheus `/metrics` bearer token from
    /// [`Self::prom_token_file`].
    ///
    /// Returns `Ok(None)` when `--prom-token-file` is not set.  The file is
    /// validated through [`validate_secret_file`] (regular file, owned by
    /// the observer UID, mode `0o600` or stricter, `O_NOFOLLOW` open) and
    /// the contents must be exactly 64 hex characters (the same encoding
    /// used by [`varta_vlp::crypto::Key`], so operators can reuse
    /// `openssl rand -hex 32`).
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file fails validation or the contents
    /// cannot be decoded as 64 hex characters.
    pub fn load_prom_token(&self) -> std::io::Result<Option<varta_vlp::crypto::BearerToken>> {
        use std::io;
        let Some(ref path) = self.prom_token_file else {
            return Ok(None);
        };
        let raw = validate_secret_file(path)?;
        let trimmed = raw.trim();
        let bytes = varta_vlp::decode_hex_32(trimmed.as_bytes()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })?;
        Ok(Some(varta_vlp::crypto::BearerToken::from_bytes(bytes)))
    }
}
