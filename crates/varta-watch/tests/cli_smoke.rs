//! Session 05 acceptance contract test for the `varta-watch` binary surface.
//!
//! Each test name here is verbatim from `docs/acceptance/varta-v0-1-0.md`.
//! The CI gate (Session 08) greps these names — do not rename without
//! updating the contract.

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
