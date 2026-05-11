//! Integration tests for Observer socket lifecycle — M5 (bind races) and M7
//! (Drop unlinks socket file).
//!
//! Each test uses a unique socket path derived from the process id and an
//! atomic counter so parallel `cargo test` runs cannot collide.

use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use varta_watch::Observer;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_path(label: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "varta-obs-{}-{}-{}.sock",
        std::process::id(),
        label,
        n
    ))
}

const THRESHOLD: Duration = Duration::from_secs(1);

/// M5 baseline — Observer::bind creates the socket file with correct permissions.
#[test]
fn bind_succeeds_on_clean_path() {
    let path = unique_path("clean");
    assert!(!path.exists(), "path must not pre-exist");

    let _obs = Observer::bind(&path, THRESHOLD, 0o600, Duration::from_millis(100))
        .expect("bind on clean path should succeed");

    assert!(path.exists(), "socket file must exist after bind");
    let meta = std::fs::metadata(&path).expect("metadata");
    assert!(meta.file_type().is_socket(), "must be a socket");
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o600,
        "permissions must be 0o600"
    );

    // Belt-and-braces cleanup: Drop unlinks once M7 lands; until then, remove explicitly.
    let _ = std::fs::remove_file(&path);
}

/// M5 contract — a second bind to a path with a live listener returns AddrInUse
/// with the exact error-message prefix.
#[test]
fn bind_fails_when_live_observer_present() {
    let path = unique_path("live");

    let _first = Observer::bind(&path, THRESHOLD, 0o600, Duration::from_millis(100))
        .expect("first bind must succeed");

    let err = Observer::bind(&path, THRESHOLD, 0o600, Duration::from_millis(100))
        .err()
        .expect("second bind on live socket must fail");

    assert_eq!(err.kind(), ErrorKind::AddrInUse);
    assert!(
        err.to_string()
            .contains("another varta-watch is already running at "),
        "error message mismatch: {err}"
    );

    // Cleanup: drop _first, then unconditionally remove so the test is hermetic
    // regardless of whether M7 Drop impl is present.
    drop(_first);
    let _ = std::fs::remove_file(&path);
}

/// M5 contract — a regular file (stale artifact) at the path is removed and
/// replaced by the observer's socket.
#[test]
fn bind_cleans_up_stale_socket_file() {
    let path = unique_path("stale");

    // Plant a regular file to simulate a stale artifact.
    std::fs::write(&path, b"").expect("create stale file");
    assert!(path.exists());

    let _obs = Observer::bind(&path, THRESHOLD, 0o600, Duration::from_millis(100))
        .expect("bind over stale file must succeed");

    let meta = std::fs::metadata(&path).expect("metadata");
    assert!(
        meta.file_type().is_socket(),
        "stale file must be replaced by socket"
    );

    // Belt-and-braces cleanup.
    drop(_obs);
    let _ = std::fs::remove_file(&path);
}

/// M7 contract — dropping an Observer removes the socket file from disk.
///
/// **Depends on M7 Drop impl from session 02.**
/// Before M7 merges: the assertion `!path.exists()` fails because Drop does
/// not yet unlink the socket.
#[test]
fn drop_unlinks_bound_socket() {
    let path = unique_path("drop-unlink");

    let obs = Observer::bind(&path, THRESHOLD, 0o600, Duration::from_millis(100))
        .expect("bind must succeed");

    assert!(path.exists(), "socket must exist after bind");

    drop(obs);

    assert!(!path.exists(), "socket must be removed after drop");
}

/// M7 contract — if the socket file is manually removed before the Observer is
/// dropped, the drop completes silently without panicking.
///
/// **Depends on M7 Drop impl from session 02** for the ENOENT-swallow guarantee.
/// Before M7 merges: passes trivially because no Drop impl means no panic risk.
/// After M7 merges: continues to pass because Drop swallows missing-file errors.
#[test]
fn drop_swallows_missing_file() {
    let path = unique_path("drop-missing");

    let obs = Observer::bind(&path, THRESHOLD, 0o600, Duration::from_millis(100))
        .expect("bind must succeed");

    // Manually remove the file before drop.
    std::fs::remove_file(&path).expect("manual remove");
    assert!(!path.exists());

    // Must not panic. The Drop impl must swallow ENOENT.
    drop(obs);
    // Reaching here means no panic occurred.
}

/// M7 constraint #6 — if another Observer has won the path (different inode),
/// the original observer's Drop must NOT remove the foreign file.
///
/// **Depends on M7 Drop impl from session 02** (inode-compare in finish_bind + Drop).
/// Before M7 merges: the final `assert!(!path.exists())` fails because obs_b's
/// drop does not unlink the socket.
#[test]
fn drop_preserves_foreign_inode() {
    let path = unique_path("drop-inode");

    // First observer binds — owns inode A.
    let obs_a = Observer::bind(&path, THRESHOLD, 0o600, Duration::from_millis(100))
        .expect("first bind must succeed");

    // Simulate stale-cleanup scenario: manually remove the socket so a second
    // observer can win the path with a new inode.
    std::fs::remove_file(&path).expect("manual remove for inode swap");

    // Second observer binds — owns inode B at the same path.
    let obs_b = Observer::bind(&path, THRESHOLD, 0o600, Duration::from_millis(100))
        .expect("second bind must succeed");

    // Drop obs_a — its bound_dev/bound_ino no longer match the on-disk inode
    // (which belongs to obs_b). Drop must NOT remove the file.
    drop(obs_a);
    assert!(
        path.exists(),
        "drop of stale observer must not remove the current (foreign) socket"
    );

    // Drop obs_b — it owns the current inode, so it SHOULD remove the file.
    drop(obs_b);
    assert!(
        !path.exists(),
        "drop of current observer must remove the socket"
    );
}
