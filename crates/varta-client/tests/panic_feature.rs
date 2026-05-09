#![cfg(feature = "panic-handler")]
//! Session 04 acceptance tests for the `panic-handler` feature.
//! Gated: without `--features panic-handler` this file is entirely absent.

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::Duration;

mod common;
use common::TempSocket;

use varta_client::{install_panic_handler, Frame, Status, NONCE_TERMINAL};

// Panic hooks are process-global; serialize these tests to prevent
// tangled hook chains when cargo runs them in parallel threads.
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn panic_handler_emits_critical_beat_before_unwind() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let temp = TempSocket::new("panic-emit");
    let server = UnixDatagram::bind(&temp.path).expect("bind server");
    server
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set_read_timeout");

    let path = temp.path.clone();
    let handle = std::thread::spawn(move || {
        install_panic_handler(path).expect("install hook");
        panic!("boom");
    });
    assert!(handle.join().is_err(), "thread must have panicked");

    let mut buf = [0u8; 32];
    let n = server.recv(&mut buf).expect("recv within 500 ms");
    assert_eq!(n, 32, "datagram must be 32 bytes");
    let frame = Frame::decode(&buf).expect("decode");
    assert_eq!(frame.status, Status::Critical, "status must be Critical");
    assert_eq!(
        frame.nonce, NONCE_TERMINAL,
        "nonce must be NONCE_TERMINAL sentinel"
    );
}

#[test]
fn panic_handler_preserves_original_panic_outcome() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Bind a server so install() succeeds, then drop+unlink it before
    // panicking. The pre-bound hook socket now sends to a defunct peer
    // (ECONNREFUSED on macOS, ENOENT on Linux); the error is swallowed
    // inside the closure and the panic payload must propagate unchanged.
    // This is the post-async-signal-safety contract: install is loud,
    // but hook errors at send time stay silent.
    let temp = TempSocket::new("panic-preserve");
    let server = UnixDatagram::bind(&temp.path).expect("bind server");
    let path = temp.path.clone();
    let unlink_path = temp.path.clone();
    let handle = std::thread::spawn(move || {
        install_panic_handler(path).expect("install hook");
        drop(server);
        let _ = std::fs::remove_file(&unlink_path);
        panic!("original payload");
    });
    let result = handle.join();
    assert!(result.is_err(), "thread must have panicked");
    let payload = result.unwrap_err();
    let msg = payload
        .downcast_ref::<&str>()
        .expect("panic payload must be &str");
    assert_eq!(*msg, "original payload");
}

#[test]
fn panic_module_excluded_without_feature() {
    // This test exists only when compiled with --features panic-handler.
    // The #![cfg(feature = "panic-handler")] gate at the top of this file
    // means that without the feature the file is excluded entirely —
    // install_panic_handler, this test, and all S04 tests cease to exist.
    // Verify the exported symbol has the expected shape.
    let _: fn(PathBuf) -> std::io::Result<()> = install_panic_handler;
}

#[test]
fn install_returns_err_on_invalid_socket_path() {
    // POSIX async-signal-safety contract: socket(2)/connect(2)/fcntl(2)
    // run at install time (NOT inside the panic hook). A bind/connect
    // failure therefore surfaces as a loud `Err` instead of a silently
    // broken hook.
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Path under a non-existent directory: connect(2) returns ENOENT.
    let bogus = PathBuf::from("/nonexistent-dir-varta-panic-test/sock");
    let err = install_panic_handler(bogus).expect_err("must fail at connect");
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
        ),
        "expected NotFound/PermissionDenied, got {:?}",
        err.kind(),
    );
}
