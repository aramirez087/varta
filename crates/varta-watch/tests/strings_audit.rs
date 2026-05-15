//! Compile-time-feature-aware strings audit on the built `varta-watch`
//! binary.  Mirrors the CI `safety-profiles` step but runs under
//! `cargo test` so developers catch regressions locally.
//!
//! - Default-feature build: only the `/bin/sh` literal is rejected.
//! - `--features prometheus-exporter`: HTTP literals are expected; the
//!   audit still rejects `/bin/sh`.
//! - `--features compile-time-config`: HTTP literals **and** argv flag
//!   literals **and** `/bin/sh` are all rejected.  Mutually exclusive
//!   with `prometheus-exporter` by `compile_error!` in lib.rs, so this
//!   arm sees the strictest contract.
//!
//! The implementation shells out to `strings` (BSD or GNU).  Skips
//! gracefully when `strings` is not on `$PATH` — CI installs it as part
//! of binutils, but a developer environment may lack it.

use std::process::Command;

fn binary_strings() -> Option<String> {
    let bin = env!("CARGO_BIN_EXE_varta-watch");
    let out = Command::new("strings").arg(bin).output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

fn assert_absent(haystack: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            !haystack.contains(needle),
            "binary contains forbidden literal {needle:?}"
        );
    }
}

const SHELL_LITERAL: &[&str] = &["/bin/sh"];

#[cfg(feature = "compile-time-config")]
const HTTP_LITERALS: &[&str] = &[
    "GET /metrics",
    "HTTP/1.0",
    "HTTP/1.1",
    "WWW-Authenticate",
    "Bearer realm",
];

#[cfg(feature = "compile-time-config")]
const ARGV_FLAG_LITERALS: &[&str] = &[
    "--socket",
    "--threshold-ms",
    "--prom-addr",
    "--prom-token-file",
    "--recovery-cmd",
    "--recovery-exec",
    "--help",
    "--secure-key-file",
    "--clock-source",
    "--i-accept",
    "--allow-cross-namespace",
    "--key-file",
    "--master-key-file",
    "--udp-port",
    "--features audit-chain",
    "--features secure-udp",
    "--features unsafe-plaintext-udp",
];

#[test]
fn binary_contains_no_shell_literal_in_production_safe_builds() {
    let Some(blob) = binary_strings() else {
        eprintln!("strings(1) not available; skipping audit");
        return;
    };
    // Shell-mode recovery was permanently removed; `/bin/sh` must never
    // appear in any build profile.
    assert_absent(&blob, SHELL_LITERAL);
}

#[cfg(feature = "compile-time-config")]
#[test]
fn class_a_binary_contains_no_http_literals() {
    let Some(blob) = binary_strings() else {
        eprintln!("strings(1) not available; skipping audit");
        return;
    };
    assert_absent(&blob, HTTP_LITERALS);
}

#[cfg(feature = "compile-time-config")]
#[test]
fn class_a_binary_contains_no_argv_flag_literals() {
    let Some(blob) = binary_strings() else {
        eprintln!("strings(1) not available; skipping audit");
        return;
    };
    assert_absent(&blob, ARGV_FLAG_LITERALS);
}
