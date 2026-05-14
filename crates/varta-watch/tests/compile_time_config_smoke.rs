//! Class-A safety-critical smoke test.
//!
//! Exercises the `compile-time-config` profile end-to-end:
//!
//!   * `Config::compile_time()` returns a populated `Config` built from
//!     the build-time blob.
//!   * The binary refuses any argv tokens with
//!     `ConfigError::CompileTimeArgvForbidden`.
//!   * `Config::HELP` is the neutral one-liner and carries no `--` flag
//!     literals.
//!
//! The CI safety-profiles job builds the binary under this fixture (see
//! `crates/varta-watch/tests/fixtures/safety_critical.varta.conf`) and
//! runs this file as a release test.

#![cfg(feature = "compile-time-config")]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use varta_watch::signal_install::SignalHandlerMode;
use varta_watch::Config;

/// `Config::compile_time()` produces a value that matches the fixture
/// the build script consumed.  This is the contract that lets a Class-A
/// build use the runtime `Config` without going through `from_args`.
#[test]
fn compile_time_config_matches_fixture() {
    let cfg = Config::compile_time().expect("compile-time config must validate");
    assert_eq!(cfg.socket, PathBuf::from("/tmp/varta-classA-ci.sock"));
    assert_eq!(cfg.threshold, Duration::from_millis(5000));
    assert_eq!(cfg.socket_mode, 0o600);
    assert_eq!(cfg.tracker_capacity, 256);
    assert_eq!(cfg.iteration_budget, Duration::from_millis(250));
    assert_eq!(cfg.scrape_budget, Duration::from_millis(250));
    assert!(!cfg.i_accept_plaintext_udp);
    assert!(!cfg.i_accept_shell_risk);
    assert!(cfg.strict_namespace_check);
    assert!(cfg.recovery_cmd.is_none());
    assert!(cfg.recovery_exec_cmd.is_none());
    assert!(cfg.prom_addr.is_none());
    assert_eq!(
        cfg.signal_handler_mode,
        SignalHandlerMode::Direct,
        "fixture sets signal_handler_mode=direct; Class-A binary must default to Direct"
    );
}

/// `Config::HELP` under `compile-time-config` is the neutral one-liner —
/// it must not contain any `--`-prefixed flag literals.  This is the
/// programmatic counterpart to the CI `strings` audit and catches a
/// regression that re-introduced flag names into the help body.
#[test]
fn help_is_neutral_one_liner() {
    let help = Config::HELP;
    assert!(
        !help.contains("--"),
        "Class-A HELP must not contain `--` flag literals, got: {help:?}"
    );
    assert!(
        help.len() < 200,
        "Class-A HELP must be short (got {} bytes)",
        help.len()
    );
    assert!(
        help.contains("compile-time"),
        "Class-A HELP should point at the compile-time-config posture, got: {help:?}"
    );
}

/// The binary refuses `--signal-handler-mode=libc` — that flag does not exist
/// in the Class-A argv surface. The binary must exit non-zero and must not
/// echo the flag name (strings audit requirement).
#[test]
fn binary_rejects_signal_handler_mode_flag() {
    let bin = env!("CARGO_BIN_EXE_varta-watch");
    let out = Command::new(bin)
        .args(["--signal-handler-mode", "libc"])
        .output()
        .expect("spawn varta-watch --signal-handler-mode libc");
    assert!(
        !out.status.success(),
        "Class-A binary must reject --signal-handler-mode; status: {:?}",
        out.status,
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stderr.contains("--signal-handler-mode") && !stdout.contains("--signal-handler-mode"),
        "Class-A binary echoed the rejected flag name; stderr={stderr:?} stdout={stdout:?}"
    );
}

/// The binary refuses any argv tokens.  We invoke the test-spawned
/// release binary with a token that *would* be valid in an SRE build,
/// and assert that the binary exits non-zero without binding any
/// listener.
#[test]
fn binary_rejects_argv() {
    let bin = env!("CARGO_BIN_EXE_varta-watch");
    let out = Command::new(bin)
        .arg("--socket")
        .arg("/tmp/should-not-bind.sock")
        .output()
        .expect("spawn varta-watch");
    assert!(
        !out.status.success(),
        "Class-A binary must exit non-zero on argv input; status: {:?}, \
         stdout: {:?}, stderr: {:?}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    // The Class-A error path writes the (neutral) HELP to stderr.  We do
    // not assert on the wording — only that the stderr / stdout output
    // never echoes the rejected argv flag name.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stderr.contains("--socket") && !stdout.contains("--socket"),
        "Class-A binary echoed an argv flag name; stderr={stderr:?} \
         stdout={stdout:?}"
    );
}
