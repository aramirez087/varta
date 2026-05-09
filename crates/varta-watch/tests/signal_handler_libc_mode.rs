//! Integration test: `--signal-handler-mode=libc` installs handlers and exits
//! cleanly on SIGTERM.
//!
//! Spawns the real `varta-watch` binary with `--signal-handler-mode=libc` and
//! `--shutdown-after-secs=0` (immediate self-SIGTERM), then asserts the
//! process exits with status 0.  Mirrors the pattern used in
//! `cli_smoke.rs::cli_plaintext_udp_with_accept_flag_starts`.
//!
//! Excluded when `compile-time-config` is active (the Class-A binary accepts
//! no argv tokens) and on non-Linux platforms (libc mode is only meaningful
//! where the direct-syscall path exists as the alternative).
#![cfg(all(not(feature = "compile-time-config"), target_os = "linux",))]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static UDS_COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_uds_path(tag: &str) -> UdsPath {
    let pid = std::process::id();
    let n = UDS_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("varta-libc-{tag}-{pid}-{n}.sock"));
    let _ = std::fs::remove_file(&p);
    UdsPath(p)
}

struct UdsPath(PathBuf);

impl UdsPath {
    fn as_str(&self) -> &str {
        self.0.to_str().expect("temp path must be valid UTF-8")
    }
}

impl Drop for UdsPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `--signal-handler-mode=libc` must start and exit cleanly on Linux when
/// the daemon's self-SIGTERM fires via `--shutdown-after-secs=0`.
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning
#[test]
fn libc_mode_exits_cleanly_on_sigterm() {
    let path = unique_uds_path("libc");

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--signal-handler-mode",
            "libc",
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch --signal-handler-mode=libc");

    assert!(
        out.status.success(),
        "--signal-handler-mode=libc must start and exit 0; \
         got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
}

/// `--signal-handler-mode=direct` (default) must also start and exit cleanly,
/// as a regression guard alongside the libc path.
#[cfg(not(feature = "libc-signal-mode"))]
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning
#[test]
fn direct_mode_exits_cleanly_on_sigterm() {
    let path = unique_uds_path("direct");

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--signal-handler-mode",
            "direct",
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch --signal-handler-mode=direct");

    assert!(
        out.status.success(),
        "--signal-handler-mode=direct must start and exit 0; \
         got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Unknown mode value must be rejected with a non-zero exit status.
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning
#[test]
fn unknown_mode_is_rejected() {
    let path = unique_uds_path("unknown");

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--signal-handler-mode",
            "bogus",
        ])
        .output()
        .expect("spawn varta-watch --signal-handler-mode=bogus");

    assert!(
        !out.status.success(),
        "unknown mode must be rejected; got status {:?}",
        out.status,
    );
}
