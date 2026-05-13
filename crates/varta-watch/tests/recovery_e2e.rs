//! Session 05 acceptance contract tests for `varta-watch::Recovery`.
//!
//! Each test name here is verbatim from `docs/acceptance/varta-v0-1-0.md`.
//! The CI gate (Session 08) greps these names — do not rename without
//! updating the contract.
//!
//! Session 01 of the recovery-async-spawn epic appends four red-phase
//! acceptance tests below the original two. Sessions 02 and 03 turn them
//! green.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

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

#[cfg(feature = "unsafe-shell-recovery")]
#[test]
fn recovery_cmd_fires_once_per_stall_within_debounce() {
    let marker = unique_tmp("marker");
    assert!(
        !marker.as_path().exists(),
        "marker must not exist before test"
    );
    let template = format!("touch {}", marker.as_path().display());
    let mut rec = Recovery::new(template, Duration::from_secs(1));

    let first = rec.on_stall(42, varta_watch::BeatOrigin::KernelAttested);
    let second = rec.on_stall(42, varta_watch::BeatOrigin::KernelAttested);

    match first {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("first stall should have spawned, got {other:?}"),
    }

    // Reap the child to confirm it succeeded.
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if Instant::now() >= deadline {
            panic!("timed out waiting for recovery child to be reaped");
        }
        let outcomes = rec.try_reap();
        if let Some(o) = outcomes.into_iter().find_map(|o| match o {
            RecoveryOutcome::Reaped { status, .. } => Some(status),
            _ => None,
        }) {
            assert!(o.success(), "touch failed: {o:?}");
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
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

#[cfg(feature = "unsafe-shell-recovery")]
#[test]
fn recovery_cmd_template_receives_pid_as_dollar_one() {
    let log = unique_tmp("log");
    let template = format!("echo $$:$1 >> {}", log.as_path().display());
    let mut rec = Recovery::new(template, Duration::from_secs(0));

    let outcome = rec.on_stall(12345, varta_watch::BeatOrigin::KernelAttested);
    match outcome {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned, got {other:?}"),
    }

    // Reap the child to confirm it succeeded.
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if Instant::now() >= deadline {
            panic!("timed out waiting for recovery child to be reaped");
        }
        let outcomes = rec.try_reap();
        if let Some(o) = outcomes.into_iter().find_map(|o| match o {
            RecoveryOutcome::Reaped { status, .. } => Some(status),
            _ => None,
        }) {
            assert!(o.success(), "echo failed: {o:?}");
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let body = std::fs::read_to_string(log.as_path()).expect("read log");
    let trimmed = body.trim_end_matches('\n');
    assert!(
        trimmed.ends_with(":12345"),
        "log line did not end with pid: {body:?}"
    );
}

// -- recovery-async-spawn epic, Session 01 (red-phase acceptance tests) ---
//
// The four tests below MUST FAIL against the Session 01 stubs and pass
// once Session 02 lands the non-blocking spawn / async-reap impl.

/// `on_stall` must return without waiting on the child. A template that
/// would block for ≥ 1 s must still hand control back to the observer
/// within 50 ms.
#[cfg(feature = "unsafe-shell-recovery")]
#[test]
fn recovery_spawn_returns_within_50ms_for_slow_template() {
    let mut rec = Recovery::new("sleep 1".to_string(), Duration::ZERO);
    let start = Instant::now();
    let outcome = rec.on_stall(13, varta_watch::BeatOrigin::KernelAttested);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(50),
        "on_stall blocked for {elapsed:?}; expected non-blocking spawn (< 50 ms). \
         Outcome was {outcome:?}"
    );
}

/// After a fast child exits, `try_reap` must surface a `Reaped` outcome
/// whose `status` reflects success. The observer never blocks waiting
/// for this transition.
#[cfg(feature = "unsafe-shell-recovery")]
#[test]
fn recovery_try_reap_yields_reaped_for_completed_child() {
    let mut rec = Recovery::with_template_and_timeout("true".to_string(), Duration::ZERO, None);
    let _ = rec.on_stall(99, varta_watch::BeatOrigin::KernelAttested);

    // Allow up to 500 ms for the child to exit and a subsequent
    // `try_reap` call to surface the transition. In green phase this
    // typically resolves in well under 100 ms.
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut saw_reaped = false;
    let mut last_observed: Vec<RecoveryOutcome> = Vec::new();
    while Instant::now() < deadline {
        let outcomes = rec.try_reap();
        if outcomes
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Reaped { status, .. } if status.success()))
        {
            saw_reaped = true;
            break;
        }
        last_observed = outcomes;
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        saw_reaped,
        "expected at least one RecoveryOutcome::Reaped(success) within 500 ms; \
         last observed batch was {last_observed:?}"
    );
}

/// A child that outlives the configured `recovery_timeout` must be
/// killed by `try_reap` and surface a `Killed` outcome carrying the
/// child's pid.
#[cfg(feature = "unsafe-shell-recovery")]
#[test]
fn recovery_try_reap_kills_after_timeout() {
    let mut rec = Recovery::with_template_and_timeout(
        "sleep 1".to_string(),
        Duration::ZERO,
        Some(Duration::from_millis(50)),
    );
    let _ = rec.on_stall(7, varta_watch::BeatOrigin::KernelAttested);

    let deadline = Instant::now() + Duration::from_millis(750);
    let mut saw_killed = false;
    let mut last_observed: Vec<RecoveryOutcome> = Vec::new();
    while Instant::now() < deadline {
        let outcomes = rec.try_reap();
        if outcomes
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Killed { .. }))
        {
            saw_killed = true;
            break;
        }
        last_observed = outcomes;
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        saw_killed,
        "expected at least one RecoveryOutcome::Killed within 750 ms; \
         last observed batch was {last_observed:?}"
    );
}

/// Two distinct stalled pids spawned back-to-back must run in parallel:
/// the wall-clock for the pair should be bounded by the slowest single
/// child, not by the sum of their durations.
#[cfg(feature = "unsafe-shell-recovery")]
#[test]
fn recovery_concurrent_pids_run_in_parallel() {
    let mut rec = Recovery::new("sleep 0.5".to_string(), Duration::ZERO);
    let start = Instant::now();
    let a = rec.on_stall(1, varta_watch::BeatOrigin::KernelAttested);
    let b = rec.on_stall(2, varta_watch::BeatOrigin::KernelAttested);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(750),
        "two on_stall calls took {elapsed:?}; expected concurrent spawn < 750 ms. \
         Outcomes were a={a:?} b={b:?}"
    );
}
