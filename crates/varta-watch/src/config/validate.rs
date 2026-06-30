use std::path::Path;

use super::types::ConfigError;

/// Validate that a secret file (recovery command, key, or token) meets the
/// hardened requirements: regular file, owned by the observer's UID, mode
/// `0o600` or stricter, no symlinks (`O_NOFOLLOW` open).
///
/// The open-and-validate flow is collapsed into a single file descriptor to
/// eliminate the TOCTOU window between metadata check and file read. The
/// sequence is:
///
/// 1. `open(path, O_RDONLY | O_NOFOLLOW)` — atomically rejects a symlink at
///    the leaf component. The kernel returns `ELOOP` if the path resolves
///    to a symlink, so no separate `symlink_metadata` probe is needed.
/// 2. `fstat(fd)` (via `File::metadata`) — operates on the open inode, not
///    the path. An attacker who renames or replaces the file in the parent
///    directory after the open has no effect: the fd still refers to the
///    inode we just authenticated.
/// 3. Mode / UID / file-type checks on the fstat result.
/// 4. `read_to_string` from the same fd.
///
/// Returns the raw file contents on success.
pub(crate) fn validate_secret_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    let mut file = crate::file_security::open_nofollow(path, &mut options)?;

    // fstat(fd) - operates on the open inode, immune to path-level races.
    crate::file_security::validate_private_regular_file(&file, path)?;

    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

/// Recovery-command-file wrapper around [`validate_secret_file`] that also
/// trims surrounding whitespace from the contents (recovery templates do not
/// want a trailing newline appended to the command line).
pub(super) fn validate_recovery_file(path: &Path) -> std::io::Result<String> {
    let content = validate_secret_file(path)?;
    Ok(content.trim().to_string())
}

/// Validate and read a secret file (key, accepted-key, master-key, or
/// Prometheus token). Returns the raw bytes; callers are responsible for
/// trimming or splitting line-by-line.
#[cfg(feature = "secure-udp")]
pub(super) fn read_secret_file(path: &Path) -> std::io::Result<String> {
    validate_secret_file(path)
}

/// Parse a recovery command line into (program, args).
///
/// Splits on whitespace. Returns an error if the command line is empty.
pub fn parse_exec_cmd(cmd: &str) -> std::io::Result<(String, Vec<String>)> {
    let mut parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "recovery command must not be empty",
        ));
    }
    let program = parts.remove(0).to_string();
    let args: Vec<String> = parts.into_iter().map(|s| s.to_string()).collect();
    Ok((program, args))
}

/// Validate a recovery child environment override.
///
/// `std::process::Command::env` rejects names with `=` or NUL and values with
/// NUL at spawn time. The parser rejects those shapes up front so recovery
/// does not fail only after an agent has already stalled.
pub(super) fn validate_recovery_env_entry(raw: &str) -> Result<(), ConfigError> {
    if !crate::recovery::is_valid_recovery_env_entry(raw) {
        return Err(ConfigError::BadRecoveryEnv(raw.to_string()));
    }
    Ok(())
}
