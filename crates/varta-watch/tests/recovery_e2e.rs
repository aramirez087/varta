//! Session 05 acceptance contract tests for `varta-watch::Recovery`.
//!
//! Each test name here is verbatim from `docs/acceptance/varta-v0-1-0.md`.
//! The CI gate (Session 08) greps these names — do not rename without
//! updating the contract.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use varta_watch::{Recovery, RecoveryOutcome};

static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Mint a unique per-test tempfile path. The file is removed on drop so
/// failed runs do not leave orphans behind.
fn unique_tmp(tag: &str) -> TempPath {
    let pid = std::process::id();
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("varta-watch-s05-{tag}-{pid}-{n}"));
    let _ = std::fs::remove_file(&p);
    TempPath(p)
}

struct TempPath(PathBuf);

impl TempPath {
    fn as_path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn recovery_cmd_fires_once_per_stall_within_debounce() {
    let marker = unique_tmp("marker");
    assert!(
        !marker.as_path().exists(),
        "marker must not exist before test"
    );
    let template = format!("touch {}", marker.as_path().display());
    let mut rec = Recovery::new(template, Duration::from_secs(1));

    let first = rec.on_stall(42);
    let second = rec.on_stall(42);

    match first {
        RecoveryOutcome::Spawned(status) => assert!(status.success(), "touch failed: {status:?}"),
        other => panic!("first stall should have spawned, got {other:?}"),
    }
    assert!(
        matches!(second, RecoveryOutcome::Debounced),
        "second stall within debounce window should be debounced, got {second:?}"
    );
    assert!(
        marker.as_path().exists(),
        "marker file should have been created exactly once"
    );
}

#[test]
fn recovery_cmd_template_substitutes_pid() {
    let log = unique_tmp("log");
    let template = format!("echo $$:{{pid}} >> {}", log.as_path().display());
    let mut rec = Recovery::new(template, Duration::from_secs(0));

    let outcome = rec.on_stall(12345);
    match outcome {
        RecoveryOutcome::Spawned(status) => assert!(status.success(), "echo failed: {status:?}"),
        other => panic!("expected Spawned, got {other:?}"),
    }

    let body = std::fs::read_to_string(log.as_path()).expect("read log");
    let trimmed = body.trim_end_matches('\n');
    assert!(
        trimmed.ends_with(":12345"),
        "log line did not end with substituted pid: {body:?}"
    );
}
