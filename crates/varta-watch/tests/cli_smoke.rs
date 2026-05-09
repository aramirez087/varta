//! Session 05 acceptance contract test for the `varta-watch` binary surface.
//!
//! Each test name here is verbatim from `docs/acceptance/varta-v0-1-0.md`.
//! The CI gate (Session 08) greps these names — do not rename without
//! updating the contract.
//!
//! Session 01 of the recovery-async-spawn epic appends two red-phase
//! tests below for the new `--recovery-timeout-ms` flag. Session 03
//! turns them green.

use std::process::Command;

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
        "--recovery-cmd",
        "--recovery-debounce-ms",
        "--export-file",
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
#[test]
fn cli_parses_recovery_timeout_ms() {
    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            "/tmp/varta-watch-cli-recovery-timeout.sock",
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
