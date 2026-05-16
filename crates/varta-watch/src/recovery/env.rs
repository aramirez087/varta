//! Environment isolation for recovery child processes.

use std::process::Command;

/// Apply environment isolation to a recovery child [`Command`].
///
/// Default (secure): clears the child env, sets `PATH=/usr/bin:/bin`, then applies
/// `env_vars` entries as an explicit allowlist. When `inherit` is `true`, the
/// observer's full environment is inherited and `env_vars` layer on top.
pub(super) fn apply_env(cmd: &mut Command, inherit: bool, env_vars: &[String]) {
    if !inherit {
        cmd.env_clear();
        cmd.env("PATH", "/usr/bin:/bin");
    }
    for entry in env_vars {
        if let Some((key, value)) = entry.split_once('=') {
            cmd.env(key, value);
        }
    }
}
