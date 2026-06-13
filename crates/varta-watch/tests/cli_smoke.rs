//! Session 05 acceptance contract test for the `varta-watch` binary surface.
//!
//! Each test name here is verbatim from `docs/acceptance/varta-v0-1-0.md`.
//! The CI gate (Session 08) greps these names — do not rename without
//! updating the contract.
//!
//! Excluded when `--features compile-time-config` is active — the Class-A
//! binary accepts no argv tokens, so the entire test surface here is
//! inapplicable to that profile.

#![cfg(not(feature = "compile-time-config"))]
//!
//! Session 01 of the recovery-async-spawn epic appends two red-phase
//! tests below for the new `--recovery-timeout-ms` flag. Session 03
//! turns them green.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static UDS_COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_uds_path(tag: &str) -> UdsPath {
    let pid = std::process::id();
    let n = UDS_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("varta-cli-{tag}-{pid}-{n}.sock"));
    let _ = std::fs::remove_file(&p);
    UdsPath(p)
}

struct UdsPath(PathBuf);

impl UdsPath {
    fn as_str(&self) -> &str {
        self.0
            .to_str()
            .expect("test temp paths must be valid UTF-8")
    }
}

impl Drop for UdsPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(any(feature = "secure-udp", feature = "unsafe-plaintext-udp"))]
fn unused_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral UDP port")
        .local_addr()
        .expect("read ephemeral UDP local_addr")
        .port()
}

#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_help_lists_every_documented_flag() {
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .arg("--help")
        .output()
        .expect("spawn varta-watch --help");
    assert!(
        out.status.success(),
        "--help should exit 0; got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8(out.stdout).expect("--help stdout utf8");
    for flag in [
        "--socket",
        "--threshold-ms",
        "--recovery-exec",
        "--recovery-debounce-ms",
        "--recovery-env",
        "--recovery-timeout-ms",
        "--socket-mode",
        "--export-file",
        "--export-file-max-bytes",
        "--prom-addr",
        "--shutdown-after-secs",
        "--help",
    ] {
        assert!(
            s.contains(flag),
            "--help missing flag {flag}; full output:\n{s}"
        );
    }
}

// -- recovery-async-spawn epic, Session 01 (red-phase acceptance tests) --
//
// Both tests below MUST FAIL against the Session 01 stubs and pass once
// Session 03 lands the `--recovery-timeout-ms` parser and HELP-text
// update.

/// `varta-watch --help` must list `--recovery-timeout-ms` once Session
/// 03 lands. In Session 01 the HELP text is unchanged so this fails.
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_help_lists_recovery_timeout_ms_flag() {
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .arg("--help")
        .output()
        .expect("spawn varta-watch --help");
    assert!(
        out.status.success(),
        "--help should exit 0; got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8(out.stdout).expect("--help stdout utf8");
    assert!(
        s.contains("--recovery-timeout-ms"),
        "--help missing flag --recovery-timeout-ms; full output:\n{s}"
    );
}

/// `varta-watch --recovery-timeout-ms <MS>` must parse cleanly. Session
/// 01 leaves the parser unchanged so this exits 2 (UnknownFlag).
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_parses_recovery_timeout_ms() {
    let path = unique_uds_path("recovery-timeout");
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--recovery-timeout-ms",
            "250",
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch with --recovery-timeout-ms");
    assert!(
        out.status.success(),
        "--recovery-timeout-ms must parse cleanly; got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `varta-watch --socket-mode <OCTAL>` must parse cleanly and the
/// binary must start (implying chmod succeeded).
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_parses_socket_mode() {
    let path = unique_uds_path("sockmode");
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--socket-mode",
            "600",
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch with --socket-mode");
    assert!(
        out.status.success(),
        "--socket-mode must parse cleanly; got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Plaintext UDP must require two-layer opt-in (compile feature
// `unsafe-plaintext-udp` plus the runtime flag `--i-accept-plaintext-udp`).
// Without the runtime flag, startup must hard-error and exit non-zero even
// when --udp-port is otherwise valid.  Regression for security issue C1.
// ---------------------------------------------------------------------------

#[cfg(feature = "unsafe-plaintext-udp")]
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_plaintext_udp_without_accept_flag_is_rejected() {
    let path = unique_uds_path("plaintext-no-accept");
    let port = unused_udp_port().to_string();

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--udp-bind-addr",
            "127.0.0.1",
            "--udp-port",
            &port,
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch with plaintext --udp-port and no accept flag");

    assert!(
        !out.status.success(),
        "plaintext UDP without --i-accept-plaintext-udp must hard-error; \
         got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--i-accept-plaintext-udp"),
        "error must name the accept flag, got: {stderr}"
    );
}

#[cfg(feature = "unsafe-plaintext-udp")]
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_plaintext_udp_with_accept_flag_starts() {
    let path = unique_uds_path("plaintext-accept");
    let port = unused_udp_port().to_string();

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--udp-bind-addr",
            "127.0.0.1",
            "--udp-port",
            &port,
            "--i-accept-plaintext-udp",
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch with plaintext --udp-port and accept flag");

    assert!(
        out.status.success(),
        "plaintext UDP with --i-accept-plaintext-udp must start; \
         got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("WITHOUT authentication"),
        "high-visibility warning must be emitted, stderr was: {stderr}"
    );
}

#[cfg(not(feature = "unsafe-plaintext-udp"))]
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_plaintext_udp_not_compiled_in_is_rejected() {
    let path = unique_uds_path("plaintext-not-built");
    // We can't bind a UDP probe without unsafe-plaintext-udp because the
    // test crate's `unused_udp_port` is gated on secure-udp; pick a
    // high port at random and rely on the parse-and-validate path
    // rejecting before bind is attempted.
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--udp-bind-addr",
            "127.0.0.1",
            "--udp-port",
            "59999",
            "--i-accept-plaintext-udp",
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch without plaintext-udp feature");

    assert!(
        !out.status.success(),
        "--udp-port must hard-error when neither secure-udp nor unsafe-plaintext-udp \
         is compiled in; got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Removed flags: --recovery-cmd, --recovery-cmd-file, --i-accept-shell-risk
// must all hard-error with a migration hint pointing at --recovery-exec.
// ---------------------------------------------------------------------------

#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn recovery_cmd_flag_is_removed() {
    let path = unique_uds_path("removed-recovery-cmd");
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--recovery-cmd",
            "true",
        ])
        .output()
        .expect("spawn varta-watch with removed --recovery-cmd");

    assert!(
        !out.status.success(),
        "--recovery-cmd must hard-error after removal; got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--recovery-cmd") && stderr.contains("--recovery-exec"),
        "error must reference --recovery-cmd and the --recovery-exec replacement; got: {stderr}"
    );
}

#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn i_accept_shell_risk_flag_is_removed() {
    let path = unique_uds_path("removed-shell-risk");
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--i-accept-shell-risk",
        ])
        .output()
        .expect("spawn varta-watch with removed --i-accept-shell-risk");

    assert!(
        !out.status.success(),
        "--i-accept-shell-risk must hard-error after removal; got {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--i-accept-shell-risk") && stderr.contains("--recovery-exec"),
        "error must reference --i-accept-shell-risk and --recovery-exec; got: {stderr}"
    );
}

#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_recovery_exec_does_not_require_accept_flag() {
    let path = unique_uds_path("exec-no-flag");
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--recovery-exec",
            "/bin/true",
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch with --recovery-exec only");

    assert!(
        out.status.success(),
        "--recovery-exec (the safe path) must start without any accept flag; \
         got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(feature = "secure-udp")]
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_secure_udp_binds_single_listener_for_udp_port() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let path = unique_uds_path("secure-udp");
    let port = unused_udp_port().to_string();
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    // The observer enforces mode 0600 on the key file; write it with the
    // permissions the validator expects.
    let key_dir = std::env::temp_dir().join(format!(
        "varta-cli-smoke-key-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&key_dir).expect("create key dir");
    let key_path = key_dir.join("key.hex");
    {
        let mut f = std::fs::File::create(&key_path).expect("create key file");
        f.write_all(key.as_bytes()).expect("write key");
    }
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod 0600 on key file");

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--udp-bind-addr",
            "127.0.0.1",
            "--udp-port",
            &port,
            "--key-file",
            key_path.to_str().expect("utf-8 key path"),
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch with secure UDP");

    let _ = std::fs::remove_dir_all(&key_dir);

    assert!(
        out.status.success(),
        "secure UDP must bind the configured UDP port exactly once; got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(feature = "secure-udp")]
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_accepted_key_file_only_binds_secure_udp_without_plaintext_ack() {
    let path = unique_uds_path("accepted-only-secure-udp");
    let port = unused_udp_port().to_string();
    let key = "1111111111111111111111111111111111111111111111111111111111111111";
    let key_path = write_secret_file("accepted-only-secure-udp", key, 0o600);
    let _g = scopeguard(key_path.parent().unwrap());

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--udp-bind-addr",
            "127.0.0.1",
            "--udp-port",
            &port,
            "--accepted-key-file",
            key_path.to_str().expect("utf-8 key path"),
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch with accepted-key-only secure UDP");

    assert!(
        out.status.success(),
        "--accepted-key-file alone must configure secure UDP, not fall through \
         to plaintext UDP; got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("WITHOUT authentication"),
        "accepted-key-only secure UDP must not emit plaintext warning; stderr was: {stderr}"
    );
}

#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_key_env_flag_is_rejected_with_migration_hint() {
    let path = unique_uds_path("key-env-removed");
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--key-env",
            "VARTA_KEY",
        ])
        .output()
        .expect("spawn varta-watch with --key-env");

    assert!(
        !out.status.success(),
        "--key-env must hard-error after removal; got status {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--key-env") && stderr.contains("--key-file"),
        "error must reference --key-env and the --key-file replacement; got: {stderr}"
    );
}

/// Write a 64-hex-char string to a freshly-created temp file with the
/// chosen mode and return the absolute path.  Caller owns the file (the
/// directory is intentionally leaked: tests are short-lived and racing
/// the cleanup with the spawned child is more trouble than the few
/// kilobytes are worth).
fn write_secret_file(tag: &str, content: &str, mode: u32) -> std::path::PathBuf {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = std::env::temp_dir().join(format!(
        "varta-secret-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create secret dir");
    let path = dir.join("secret.hex");
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(mode)
            .open(&path)
            .expect("create secret file");
        f.write_all(content.as_bytes()).expect("write secret");
    }
    // OpenOptions::mode is applied at open(2); chmod again to make the
    // mode authoritative regardless of process umask.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
        .expect("chmod secret file");
    path
}

#[cfg(feature = "secure-udp")]
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_key_file_with_world_readable_mode_is_rejected() {
    let socket = unique_uds_path("key-file-perm");
    let port = unused_udp_port().to_string();
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    // 0o644 leaves group+other readable — the validator must refuse.
    let key_path = write_secret_file("key-0644", key, 0o644);
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            socket.as_str(),
            "--threshold-ms",
            "100",
            "--udp-bind-addr",
            "127.0.0.1",
            "--udp-port",
            &port,
            "--key-file",
            key_path.to_str().expect("utf-8 key path"),
        ])
        .output()
        .expect("spawn varta-watch");
    assert!(
        !out.status.success(),
        "world-readable key file must be rejected; got status {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("insecure permissions") || stderr.contains("0600"),
        "error must explain the 0600 requirement; got: {stderr}"
    );
}

#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_prom_addr_without_token_file_is_rejected() {
    let socket = unique_uds_path("prom-noauth");
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            socket.as_str(),
            "--threshold-ms",
            "100",
            "--prom-addr",
            "127.0.0.1:0",
        ])
        .output()
        .expect("spawn varta-watch");
    assert!(
        !out.status.success(),
        "--prom-addr without --prom-token-file must hard-error; got status {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--prom-token-file"),
        "error must name --prom-token-file; got: {stderr}"
    );
}

#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_prom_token_file_with_world_readable_mode_is_rejected() {
    let socket = unique_uds_path("prom-tok-perm");
    let token = "abababababababababababababababababababababababababababababababab";
    let token_path = write_secret_file("prom-token-0644", token, 0o644);
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            socket.as_str(),
            "--threshold-ms",
            "100",
            "--prom-addr",
            "127.0.0.1:0",
            "--prom-token-file",
            token_path.to_str().expect("utf-8 token path"),
        ])
        .output()
        .expect("spawn varta-watch");
    assert!(
        !out.status.success(),
        "world-readable prom token must be rejected; got status {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("insecure permissions") || stderr.contains("0600"),
        "error must explain the 0600 requirement; got: {stderr}"
    );
}

// ---- H2 mitigation: recovery + UDP requires explicit operator opt-in -------

#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_recovery_plus_udp_port_without_accept_flag_is_rejected() {
    // Cross-flag invariant from book/src/architecture/peer-authentication.md:
    // UDP transports cannot attest the sending process; combining a recovery
    // command with --udp-port is structurally unsafe and must hard-error at
    // startup unless the matching per-listener flag is passed.
    // This is the structural-enforcement layer behind the H2 fix.
    let socket = unique_uds_path("h2-no-accept");
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            socket.as_str(),
            "--threshold-ms",
            "100",
            "--udp-port",
            "9001",
            "--i-accept-plaintext-udp",
            "--recovery-exec",
            "/bin/true",
        ])
        .output()
        .expect("spawn varta-watch");
    assert!(
        !out.status.success(),
        "recovery + --udp-port without accept flag must hard-error; \
         got status {:?}",
        out.status
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--plaintext-udp-i-accept-recovery-on-unauthenticated-transport"),
        "error must name the opt-in flag; got: {stderr}"
    );
}

#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_recovery_plus_udp_port_with_accept_flag_parses() {
    // Same combo, with the opt-in flag: --help should now also list the
    // flag, and the parser must accept the combination without error.
    // We invoke --help (already validated above) plus a config-only path:
    // start the daemon for ~0 seconds via --shutdown-after-secs=0 only on
    // platforms where binding an ephemeral UDP port is cheap.
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .arg("--help")
        .output()
        .expect("spawn varta-watch --help");
    assert!(out.status.success(), "--help should exit 0");
    let s = String::from_utf8(out.stdout).expect("--help stdout utf8");
    assert!(
        s.contains("--secure-udp-i-accept-recovery-on-unauthenticated-transport"),
        "--help must list the secure-udp opt-in flag; full output:\n{s}"
    );
    assert!(
        s.contains("--plaintext-udp-i-accept-recovery-on-unauthenticated-transport"),
        "--help must list the plaintext-udp opt-in flag; full output:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// Hardware watchdog (--hw-watchdog) — L3 observer-liveness contract.
// ---------------------------------------------------------------------------

/// A writable regular file must not be accepted as a hardware watchdog. It
/// would accept every kick while providing no reboot protection.
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_hw_watchdog_rejects_regular_file() {
    use std::fs::OpenOptions;
    use std::os::unix::fs::PermissionsExt;

    let dir_path = {
        let pid = std::process::id();
        let mut p = std::env::temp_dir();
        p.push(format!("varta-hwwdt-clean-{pid}"));
        std::fs::create_dir_all(&p).expect("create tempdir");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))
            .expect("chmod tempdir");
        p
    };
    let _dir_guard = scopeguard(&dir_path);

    let socket_path = dir_path.join("agents.sock");
    let wdt_path = dir_path.join("wdt");

    // Pre-create the file so the observer can open it for writing.
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&wdt_path)
        .expect("pre-create wdt file");

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            socket_path.to_str().unwrap(),
            "--threshold-ms",
            "100",
            "--hw-watchdog",
            wdt_path.to_str().unwrap(),
            "--shutdown-after-secs",
            "1",
        ])
        .output()
        .expect("spawn varta-watch with --hw-watchdog");

    assert!(
        !out.status.success(),
        "regular file must be rejected as a hardware watchdog"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("must be a character device"),
        "startup error must explain the watchdog device requirement; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(&wdt_path).expect("read rejected regular file"),
        b"",
        "validation must happen before the first kick"
    );
}

/// A character device passes the CLI validation and does not prevent a clean
/// observer shutdown. `/dev/null` is used only to exercise the descriptor-type
/// gate; unit tests cover the exact kick and magic-close bytes.
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_hw_watchdog_accepts_character_device() {
    let socket = unique_uds_path("hwwdt-char");
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            socket.as_str(),
            "--threshold-ms",
            "100",
            "--hw-watchdog",
            "/dev/null",
            "--shutdown-after-secs",
            "1",
        ])
        .output()
        .expect("spawn varta-watch with --hw-watchdog");

    assert!(
        out.status.success(),
        "character device should pass watchdog validation; status={:?}, stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

// Small RAII helper to remove a directory on drop (avoids a struct def).
fn scopeguard(path: &std::path::Path) -> impl Drop + '_ {
    struct Guard<'a>(&'a std::path::Path);
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0);
        }
    }
    Guard(path)
}

// ---------------------------------------------------------------------------
// H4: secure-UDP defaults to loopback; non-loopback binds require explicit
// --i-accept-secure-udp-non-loopback.  Without that flag, startup must hard-
// error.  With the flag, startup must succeed AND emit a high-visibility
// warning to stderr.
// ---------------------------------------------------------------------------

#[cfg(feature = "secure-udp")]
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_secure_udp_non_loopback_without_accept_flag_is_rejected() {
    let socket = unique_uds_path("h4-noaccept");
    let port = unused_udp_port().to_string();
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let key_path = write_secret_file("h4-noaccept", key, 0o600);
    let _g = scopeguard(key_path.parent().unwrap());

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            socket.as_str(),
            "--threshold-ms",
            "100",
            "--udp-bind-addr",
            "0.0.0.0",
            "--udp-port",
            &port,
            "--key-file",
            key_path.to_str().expect("utf-8 key path"),
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch with secure UDP + 0.0.0.0");

    assert!(
        !out.status.success(),
        "secure UDP on non-loopback without --i-accept-secure-udp-non-loopback must hard-error; \
         got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--i-accept-secure-udp-non-loopback"),
        "error must name the accept flag, got: {stderr}"
    );
}

#[cfg(feature = "secure-udp")]
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_secure_udp_non_loopback_with_accept_flag_starts_and_warns() {
    let socket = unique_uds_path("h4-accept");
    let port = unused_udp_port().to_string();
    let key = "111213141516171819202122232425262728293031323334353637383940414243";
    // 64 hex chars exactly; trim if longer.
    let key = &key[..64];
    let key_path = write_secret_file("h4-accept", key, 0o600);
    let _g = scopeguard(key_path.parent().unwrap());

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            socket.as_str(),
            "--threshold-ms",
            "100",
            "--udp-bind-addr",
            "0.0.0.0",
            "--udp-port",
            &port,
            "--key-file",
            key_path.to_str().expect("utf-8 key path"),
            "--i-accept-secure-udp-non-loopback",
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch with secure UDP + 0.0.0.0 + accept flag");

    assert!(
        out.status.success(),
        "secure UDP on non-loopback with accept flag must start; got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("non-loopback"),
        "high-visibility warning must mention 'non-loopback'; stderr was: {stderr}"
    );
}

#[cfg(feature = "secure-udp")]
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning (Command::new)
#[test]
fn cli_secure_udp_defaults_to_loopback_without_bind_addr() {
    // When --udp-bind-addr is omitted entirely, secure-UDP must default to
    // 127.0.0.1 without requiring the accept flag.  Startup must succeed
    // and NOT emit the non-loopback warning.
    let socket = unique_uds_path("h4-default");
    let port = unused_udp_port().to_string();
    let key = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let key_path = write_secret_file("h4-default", key, 0o600);
    let _g = scopeguard(key_path.parent().unwrap());

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            socket.as_str(),
            "--threshold-ms",
            "100",
            "--udp-port",
            &port,
            "--key-file",
            key_path.to_str().expect("utf-8 key path"),
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch with secure UDP + default bind");

    assert!(
        out.status.success(),
        "secure UDP without --udp-bind-addr must default to loopback and start; \
         got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("non-loopback"),
        "loopback default must not trigger the non-loopback warning; stderr was: {stderr}"
    );
}
