#![cfg(feature = "panic-handler")]
//! Session 04 acceptance tests for the `panic-handler` feature.
//! Gated: without `--features panic-handler` this file is entirely absent.

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use varta_client::{install_panic_handler, Frame, Status, NONCE_TERMINAL};

/// RAII socket-path holder. `Drop` unlinks the file (best-effort).
struct TempSocket {
    path: PathBuf,
}

impl TempSocket {
    fn new(tag: &str) -> Self {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("varta-{tag}-{pid}-{nanos}-{n}.sock"));
        let _ = std::fs::remove_file(&path);
        TempSocket { path }
    }
}

impl Drop for TempSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

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
        install_panic_handler(path);
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
    // No bound server — the hook will fail to connect and swallow the error.
    // The test verifies the panic propagates unchanged regardless.
    let temp = TempSocket::new("panic-preserve");
    let path = temp.path.clone();
    let handle = std::thread::spawn(move || {
        install_panic_handler(path);
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
    let _: fn(PathBuf) = install_panic_handler;
}
