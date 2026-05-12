//! Runtime verification that signal handlers can be installed and deliver
//! correctly to a lock-free atomic flag. Uses `SIGURG` (a benign signal
//! unlikely to be in use by the test runner) to avoid interfering with
//! `SIGINT`/`SIGTERM` that the real daemon relies on.
//!
//! Platform-gated to Linux, macOS, and FreeBSD — the three platforms whose
//! `SigAction` layouts are asserted at compile time in `main.rs`.

#![cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]

use std::sync::atomic::{AtomicBool, Ordering};

static GOT_SIGNAL: AtomicBool = AtomicBool::new(false);

extern "C" fn handle(_sig: i32) {
    GOT_SIGNAL.store(true, Ordering::Release);
}

/// SigAction layout for the current platform. Mirrors the definitions in
/// `main.rs` and guarded by compile-time size assertions there.
#[cfg(target_os = "linux")]
#[repr(C)]
struct SigAction {
    sa_handler: *const (),
    sa_mask: [u8; 128],
    sa_flags: i32,
    _pad: i32,
    sa_restorer: *const (),
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct SigAction {
    sa_handler: *const (),
    sa_mask: u32,
    sa_flags: i32,
}

#[cfg(target_os = "freebsd")]
#[repr(C)]
struct SigAction {
    sa_handler: *const (),
    sa_flags: i32,
    sa_mask: [u8; 16],
}

extern "C" {
    fn sigaction(signum: i32, act: *const SigAction, oldact: *mut SigAction) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn getpid() -> i32;
}

const SIGURG: i32 = 16;

/// Install a handler for `SIGURG`, deliver the signal via `kill`, and assert
/// the handler's atomic flag is set. Then restore the default disposition
/// so the test process is not left with a dangling handler.
#[test]
fn sigurg_handler_sets_atomic_flag() {
    // SAFETY: MaybeUninit::zeroed() allocates zeroed stack memory without
    // constructing a SigAction value. We write sa_handler through the raw
    // pointer before passing the struct to sigaction(2). The handler is
    // async-signal-safe: it writes to a lock-free AtomicBool only.
    let mut act = std::mem::MaybeUninit::<SigAction>::zeroed();
    let mut old = std::mem::MaybeUninit::<SigAction>::zeroed();
    unsafe {
        (*act.as_mut_ptr()).sa_handler = handle as *const ();
    }
    let act = unsafe { act.assume_init() };

    unsafe {
        let ret = sigaction(SIGURG, &act, old.as_mut_ptr());
        assert_eq!(ret, 0, "sigaction(SIGURG) failed");
    }

    // Deliver the signal to our own process.
    unsafe {
        let pid = getpid();
        let ret = kill(pid, SIGURG);
        assert_eq!(ret, 0, "kill(SIGURG) failed");
    }

    // The signal may not be delivered immediately; sleep briefly.
    std::thread::sleep(std::time::Duration::from_millis(50));

    assert!(
        GOT_SIGNAL.load(Ordering::Acquire),
        "SIGURG handler did not set the atomic flag"
    );

    // Restore the original handler (prevents interference with process exit).
    let old = unsafe { old.assume_init() };
    unsafe {
        sigaction(SIGURG, &old, std::ptr::null_mut());
    }
}
