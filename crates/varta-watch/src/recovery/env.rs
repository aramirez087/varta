//! Environment isolation for recovery child processes.

use std::process::Command;

fn split_env_entry(raw: &str) -> Option<(&str, &str)> {
    let (key, value) = raw.split_once('=')?;
    if key.is_empty() || key.contains('\0') || value.contains('\0') {
        return None;
    }
    Some((key, value))
}

/// Return whether a recovery child environment override is well formed.
pub(crate) fn is_valid_entry(raw: &str) -> bool {
    split_env_entry(raw).is_some()
}

fn invalid_entry_error(raw: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "recovery env entry must be KEY=VALUE with a non-empty key and no NUL bytes: {raw:?}"
        ),
    )
}

/// Apply environment isolation to a recovery child [`Command`].
///
/// Default (secure): clears the child env, sets `PATH=/usr/bin:/bin`, then applies
/// `env_vars` entries as an explicit allowlist. When `inherit` is `true`, the
/// observer's full environment is inherited and `env_vars` layer on top.
pub(super) fn apply_env(
    cmd: &mut Command,
    inherit: bool,
    env_vars: &[String],
) -> std::io::Result<()> {
    if !inherit {
        cmd.env_clear();
        cmd.env("PATH", "/usr/bin:/bin");
    }
    for entry in env_vars {
        let (key, value) = split_env_entry(entry).ok_or_else(|| invalid_entry_error(entry))?;
        cmd.env(key, value);
    }
    Ok(())
}
