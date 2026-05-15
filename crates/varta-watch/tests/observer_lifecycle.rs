//! Integration tests for Observer socket lifecycle — M5 (bind races) and M7
//! (Drop unlinks socket file).
//!
//! Each test uses a unique socket path derived from the process id and an
//! atomic counter so parallel `cargo test` runs cannot collide.

use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use varta_watch::listener::{drain_bind_dir_fsync_failures, PreThreadAttestation};
use varta_watch::tracker::DEFAULT_EVICTION_SCAN_WINDOW;
use varta_watch::{ClockSource, EvictionPolicy, Observer};

/// Return a token that skips the single-thread probe.
///
/// Tests run inside a multi-threaded test runner; the umask window is benign
/// because each test uses a unique socket path and no concurrent thread in
/// the test process creates files at those paths.
///
/// # Safety
/// Callers must ensure no concurrent thread creates filesystem objects at the
/// socket path during the `Observer::bind` window, which is true by
/// construction in this isolated test module.
#[allow(unsafe_code)]
fn pre_thread() -> PreThreadAttestation {
    // SAFETY: documented above.
    unsafe { PreThreadAttestation::new_unchecked() }
}

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

    let _obs = Observer::bind(
        &path,
        THRESHOLD,
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre_thread(),
    )
    .expect("bind on clean path should succeed");

    assert!(path.exists(), "socket file must exist after bind");
    let meta = std::fs::metadata(&path).expect("metadata");
    assert!(meta.file_type().is_socket(), "must be a socket");
    assert_eq!(
        meta.permissions().mode() & 0o777,
        0o600,
        "permissions must be 0o600"
    );

    drop(_obs);
    assert!(
        !path.exists(),
        "socket file must be removed on observer drop"
    );
}

/// M5 contract — a second bind to a path with a live listener returns AddrInUse
/// with the exact error-message prefix.
#[test]
fn bind_fails_when_live_observer_present() {
    let path = unique_path("live");

    let _first = Observer::bind(
        &path,
        THRESHOLD,
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre_thread(),
    )
    .expect("first bind must succeed");

    let err = Observer::bind(
        &path,
        THRESHOLD,
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre_thread(),
    )
    .err()
    .expect("second bind on live socket must fail");

    assert_eq!(err.kind(), ErrorKind::AddrInUse);
    assert!(
        err.to_string()
            .contains("another varta-watch is already running at "),
        "error message mismatch: {err}"
    );

    drop(_first);
    let _ = std::fs::remove_file(&path);
}

/// M5 contract — a stale socket inode at the path is removed and replaced by
/// the observer's socket.
#[test]
fn bind_cleans_up_stale_socket_file() {
    let path = unique_path("stale");

    let stale = UnixDatagram::bind(&path).expect("create stale socket");
    drop(stale);
    assert!(
        std::fs::metadata(&path)
            .expect("stale socket metadata")
            .file_type()
            .is_socket(),
        "test setup must leave a stale socket inode"
    );

    let _obs = Observer::bind(
        &path,
        THRESHOLD,
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre_thread(),
    )
    .expect("bind over stale socket must succeed");

    let meta = std::fs::metadata(&path).expect("metadata");
    assert!(
        meta.file_type().is_socket(),
        "stale file must be replaced by socket"
    );

    drop(_obs);
    let _ = std::fs::remove_file(&path);
}

/// M5 safety constraint — a non-socket occupant is not a stale observer
/// socket and must never be unlinked by bind recovery.
#[test]
fn bind_preserves_non_socket_file_at_path() {
    let path = unique_path("regular-file");

    std::fs::write(&path, b"do not delete").expect("create regular file");

    let err = Observer::bind(
        &path,
        THRESHOLD,
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre_thread(),
    )
    .err()
    .expect("bind over regular file must fail");

    assert_eq!(err.kind(), ErrorKind::AddrInUse);
    assert!(
        err.to_string().contains("path exists and is not a socket"),
        "error message mismatch: {err}"
    );
    assert_eq!(
        std::fs::read(&path).expect("regular file must be preserved"),
        b"do not delete"
    );

    let _ = std::fs::remove_file(&path);
}

/// M7 contract — dropping an Observer removes its bound socket file from disk.
/// Cleanup is owned by the UdsListener inside the Observer.
#[test]
fn drop_unlinks_bound_socket() {
    let path = unique_path("drop-unlink");

    let obs = Observer::bind(
        &path,
        THRESHOLD,
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre_thread(),
    )
    .expect("bind must succeed");

    assert!(path.exists(), "socket must exist after bind");

    drop(obs);
    assert!(!path.exists(), "socket must be removed after observer drop");
}

/// M7 contract — if the socket file is manually removed before the
/// Observer is dropped, the drop completes silently without panicking.
#[test]
fn drop_swallows_missing_file() {
    let path = unique_path("drop-missing");

    let obs = Observer::bind(
        &path,
        THRESHOLD,
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre_thread(),
    )
    .expect("bind must succeed");

    std::fs::remove_file(&path).expect("manual remove");
    assert!(!path.exists());

    drop(obs);
}

/// Bind on a tempdir path must not increment the dir-fsync failure counter.
/// Asserts that fsync_parent_dir runs and succeeds on a normal filesystem.
#[test]
fn bind_fsyncs_parent_directory_without_error() {
    let path = unique_path("dirfsync");
    let pre = drain_bind_dir_fsync_failures();

    let _obs = Observer::bind(
        &path,
        THRESHOLD,
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre_thread(),
    )
    .expect("bind must succeed and dir-fsync must not error");

    let post = drain_bind_dir_fsync_failures();
    assert_eq!(
        post, pre,
        "dir-fsync must not have failed on a normal tempdir"
    );
    drop(_obs);
}

/// Stale-recovery bind path must also fsync the parent directory without error.
#[test]
fn bind_fsyncs_parent_directory_after_stale_recovery() {
    let path = unique_path("dirfsync-stale");

    let stale = UnixDatagram::bind(&path).expect("create stale socket");
    drop(stale);

    let pre = drain_bind_dir_fsync_failures();

    let _obs = Observer::bind(
        &path,
        THRESHOLD,
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre_thread(),
    )
    .expect("stale-recovery bind must succeed and dir-fsync must not error");

    let post = drain_bind_dir_fsync_failures();
    assert_eq!(
        post, pre,
        "dir-fsync must not have failed on a normal tempdir (stale-recovery path)"
    );
    drop(_obs);
    let _ = std::fs::remove_file(&path);
}

/// PreThreadAttestation — the happy path (single-threaded process) is validated
/// by the production binary itself: `main.rs` calls `PreThreadAttestation::new()?`
/// as its very first statement. If that call returned an error, the binary would
/// refuse to start.  No integration-test can replicate a truly single-threaded
/// process because the test harness spawns infrastructure threads before the
/// first test function runs; any probe here would falsely detect multi-threadedness.
#[test]
#[ignore = "probe always fails in the multi-threaded test harness; \
            the success case is validated by the production binary startup"]
fn pre_thread_attestation_succeeds_when_single_threaded() {
    let _tok = PreThreadAttestation::new()
        .expect("single-threaded probe must succeed");
}

/// PreThreadAttestation — the probe must reject a multi-threaded process.
#[test]
fn pre_thread_attestation_rejects_multi_threaded_process() {
    // Park a background thread so the process has ≥ 2 threads.
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let b2 = std::sync::Arc::clone(&barrier);
    let handle = std::thread::spawn(move || {
        b2.wait(); // signal that we are running
        std::thread::park();
    });
    barrier.wait(); // wait until the spawned thread is alive

    let result = PreThreadAttestation::new();

    handle.thread().unpark();
    let _ = handle.join();

    // On Linux and macOS the probe must hard-error.
    // On other platforms it is best-effort (no probe), so we skip the assertion.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let err = result.expect_err("multi-threaded process must be rejected");
        assert!(
            err.to_string().contains("multi-threaded"),
            "error message must mention multi-threaded, got: {err}"
        );
    }
    // On platforms without a probe, result is Ok — no assertion needed.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = result;
}

/// M7 constraint #6 — if another Observer has won the path (different inode),
/// the original Observer's Drop must NOT remove the foreign file.
#[test]
fn drop_preserves_foreign_inode() {
    let path = unique_path("drop-inode");

    let obs_a = Observer::bind(
        &path,
        THRESHOLD,
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre_thread(),
    )
    .expect("first bind must succeed");

    std::fs::remove_file(&path).expect("manual remove for inode swap");

    let obs_b = Observer::bind(
        &path,
        THRESHOLD,
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre_thread(),
    )
    .expect("second bind must succeed");

    drop(obs_a);
    assert!(
        path.exists(),
        "drop of stale observer must not remove the current (foreign) socket"
    );

    drop(obs_b);
    assert!(
        !path.exists(),
        "drop of current observer must remove the socket"
    );
}
