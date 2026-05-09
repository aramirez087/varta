//! Integration tests for builds compiled with `--features libc-signal-mode`.
//!
//! Verifies two invariants of the libc-only build:
//!
//! 1. The daemon starts and exits cleanly on SIGTERM — the libc `sigaction(3)`
//!    wrapper path installs real handlers.
//! 2. `--signal-handler-mode=direct` is rejected at argv — the direct-syscall
//!    path (and its inline-asm trampoline) is not available in this build.
//!
//! Excluded on non-Linux platforms (the `libc-signal-mode` feature is only
//! meaningful where the direct-syscall path would otherwise exist) and when
//! `compile-time-config` is active (mutually exclusive with `libc-signal-mode`
//! at compile time; a build with both features fails with `compile_error!`).
#![cfg(all(
    feature = "libc-signal-mode",
    target_os = "linux",
    not(feature = "compile-time-config"),
))]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static UDS_COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_uds_path(tag: &str) -> UdsPath {
    let pid = std::process::id();
    let n = UDS_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("varta-libc-only-{tag}-{pid}-{n}.sock"));
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

/// A `libc-signal-mode` build must start and exit cleanly on SIGTERM.
///
/// Exercises the libc `sigaction(3)` wrapper path end-to-end: the daemon
/// installs SIGTERM → flips the shutdown latch → exits 0.
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning
#[test]
fn libc_only_build_exits_cleanly_on_sigterm() {
    let path = unique_uds_path("exit");

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--shutdown-after-secs",
            "0",
        ])
        .output()
        .expect("spawn varta-watch (libc-signal-mode build)");

    assert!(
        out.status.success(),
        "libc-signal-mode build must start and exit 0 on SIGTERM; \
         got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
}

/// `--signal-handler-mode=direct` must be rejected by a `libc-signal-mode` build.
///
/// The `Direct` variant does not exist in this build; passing its string
/// representation must produce a non-zero exit status with a `BadValue` error
/// on stderr mentioning `--signal-handler-mode`.
#[cfg_attr(miri, ignore)] // JUSTIFY: miri cannot model process spawning
#[test]
fn direct_mode_rejected_in_libc_only_build() {
    let path = unique_uds_path("direct-reject");

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            path.as_str(),
            "--threshold-ms",
            "100",
            "--signal-handler-mode",
            "direct",
        ])
        .output()
        .expect("spawn varta-watch --signal-handler-mode=direct (libc-signal-mode build)");

    assert!(
        !out.status.success(),
        "`--signal-handler-mode=direct` must be rejected (exit non-zero) \
         in a libc-signal-mode build; got {:?}",
        out.status,
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--signal-handler-mode"),
        "`--signal-handler-mode=direct` rejection must mention the flag name; \
         stderr: {stderr}",
    );
}
