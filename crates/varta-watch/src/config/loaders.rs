use super::types::Config;
use super::validate::validate_recovery_file;
#[cfg(any(feature = "secure-udp", feature = "prometheus-exporter"))]
use super::validate::validate_secret_file;
#[cfg(feature = "secure-udp")]
use super::validate::read_secret_file;

impl Config {
    /// Resolve recovery mode from CLI flags, enforcing mutual exclusion
    /// and loading/validating any file-based templates.
    ///
    /// Returns `Ok(None)` when no recovery is configured. Returns
    /// `Ok(Some(RecoveryMode::Shell(_)))` when `--recovery-cmd` or
    /// `--recovery-cmd-file` is set. Returns `Ok(Some(RecoveryMode::Exec{..}))`
    /// when `--recovery-exec` or `--recovery-exec-file` is set.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if a file cannot be read, its permissions are
    /// too open, or mutually exclusive flags are specified.
    pub fn resolve_recovery_mode(&self) -> std::io::Result<Option<crate::recovery::RecoveryMode>> {
        use crate::recovery::RecoveryMode;

        // Collect which sources are configured
        let has_cmd = self.recovery_cmd.is_some();
        let has_exec = self.recovery_exec_cmd.is_some();
        let has_cmd_file = self.recovery_cmd_file.is_some();
        let has_exec_file = self.recovery_exec_file.is_some();

        let shell_any = has_cmd || has_cmd_file;
        let exec_any = has_exec || has_exec_file;

        // Shell mode — inline OR file-based — spawns the system shell with
        // root-equivalent process authority.  A template-injection vector
        // can terminate any process the observer can reach.  Refuse to
        // proceed unless the operator has explicitly acknowledged the
        // risk; recommend the safer --recovery-exec path.  The check sits
        // before mutual-exclusion enforcement so the more actionable
        // diagnostic wins when both forms of misconfiguration are present.
        // Only compiled in when the feature is present; without it the
        // cfg(not) branch below fires first.
        #[cfg(feature = "unsafe-shell-recovery")]
        if shell_any && !self.i_accept_shell_risk {
            #[cfg(not(feature = "compile-time-config"))]
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "shell-mode recovery (--recovery-cmd / --recovery-cmd-file) runs \
                 the system shell with root-equivalent process authority. For production, \
                 use --recovery-exec (no shell, no injection surface). To proceed \
                 with shell mode anyway, pass --i-accept-shell-risk.",
            ));
            #[cfg(feature = "compile-time-config")]
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "shell-mode recovery requires the shell-risk acknowledgement to \
                 be set in the compile-time configuration",
            ));
        }

        // Shell and exec are mutually exclusive.  Class-A builds receive a
        // neutral message that does not embed argv flag names — those would
        // be linked into the binary's `strings` output even when this code
        // path is dead (`pub const &str` is always linked; the same rule
        // applies to format-string literals).  SRE builds keep the verbose
        // remediation that points at the specific flag pair the operator
        // wrote.
        if shell_any && exec_any {
            #[cfg(not(feature = "compile-time-config"))]
            {
                let shell_flag = if has_cmd {
                    "--recovery-cmd"
                } else {
                    "--recovery-cmd-file"
                };
                let exec_flag = if has_exec {
                    "--recovery-exec"
                } else {
                    "--recovery-exec-file"
                };
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{shell_flag} and {exec_flag} are mutually exclusive"),
                ));
            }
            #[cfg(feature = "compile-time-config")]
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "shell-mode and exec-mode recovery are mutually exclusive",
            ));
        }

        if has_cmd && has_cmd_file {
            #[cfg(not(feature = "compile-time-config"))]
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--recovery-cmd and --recovery-cmd-file are mutually exclusive",
            ));
            #[cfg(feature = "compile-time-config")]
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "inline shell-recovery template and shell-recovery file are mutually exclusive",
            ));
        }

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

        // Shell mode — only reachable when the feature is compiled in.
        // Without the feature, the variant doesn't exist; error here so
        // the operator gets a clear message pointing to --recovery-exec.
        #[cfg(feature = "unsafe-shell-recovery")]
        {
            if let Some(ref tpl) = self.recovery_cmd {
                return Ok(Some(RecoveryMode::Shell(tpl.clone())));
            }
            if let Some(ref path) = self.recovery_cmd_file {
                let template = validate_recovery_file(path)?;
                return Ok(Some(RecoveryMode::Shell(template)));
            }
        }
        #[cfg(not(feature = "unsafe-shell-recovery"))]
        if shell_any {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                super::types::ConfigError::ShellRecoveryNotCompiledIn,
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

    /// Load the primary and accepted secure keys for AEAD transport.
    ///
    /// `--key-file` is the sole source for secure-UDP keys: it is the only
    /// path that goes through [`validate_secret_file`], guaranteeing mode
    /// 0600 ownership and an `O_NOFOLLOW` open. Environment-variable keys
    /// were removed (see `ConfigError::RemovedFlag`) because they leak
    /// through `/proc/<pid>/environ` and `docker inspect`.
    ///
    /// Returns `Ok(None)` when `--key-file` is not set (UDP without AEAD).
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file cannot be read, the key(s) cannot
    /// be parsed as 64-character hex strings, or the primary key file contains
    /// more than one key.
    #[cfg(feature = "secure-udp")]
    pub fn load_secure_keys(
        &self,
    ) -> std::io::Result<Option<(varta_vlp::crypto::Key, Vec<varta_vlp::crypto::Key>)>> {
        use std::io;
        use varta_vlp::crypto::Key;

        let Some(ref path) = self.secure_key_file else {
            return Ok(None);
        };

        let content = read_secret_file(path)?;
        let mut primary: Option<Key> = None;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if primary.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: multiple primary keys found (expected exactly one)",
                        path.display()
                    ),
                ));
            }
            primary = Some(Key::from_hex(line).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })?);
        }

        let primary = match primary {
            Some(k) => k,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: no key found in file", path.display()),
                ))
            }
        };

        // Load accepted (rotation) keys
        let mut accepted = Vec::new();
        if let Some(ref path) = self.accepted_key_file {
            let content = read_secret_file(path)?;
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
                accepted.push(key);
            }
        }

        Ok(Some((primary, accepted)))
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
