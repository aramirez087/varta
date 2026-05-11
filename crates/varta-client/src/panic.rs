//! Opt-in panic hook that emits a [`varta_vlp::Status::Critical`] VLP frame to
//! the observer before normal panic unwinding resumes.
//!
//! Call [`install`] once at process start. Each call chains the previously
//! installed hook via [`std::panic::take_hook`], so multiple installations are
//! safe — the most-recently registered socket path wins.

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::Instant;

use varta_vlp::{Frame, Status, NONCE_TERMINAL};

/// Register a panic hook that emits a [`Status::Critical`] VLP frame on the
/// Unix Domain Socket at `socket_path` before resuming normal unwinding.
///
/// The hook creates a fresh [`UnixDatagram`], connects to `socket_path`,
/// encodes a 32-byte frame into a stack buffer, and calls `send`. All I/O
/// errors are silently swallowed — panicking inside a panic hook triggers an
/// immediate process abort, which is far worse than losing one datagram.
///
/// # Nonce sentinel
///
/// The frame carries `nonce = NONCE_TERMINAL`, distinct from the monotonically
/// incrementing nonces produced by [`crate::Varta::beat`], so observers can
/// identify it as a terminal signal.
///
/// # Allocation
///
/// The sole heap allocation is the `Box` created by [`std::panic::set_hook`]
/// at install time. The hook closure itself operates entirely on the stack.
///
/// # Chaining
///
/// This function captures the previously registered hook via
/// [`std::panic::take_hook`] and invokes it after firing the VLP frame,
/// preserving the default panic message and any user-installed hooks.
pub fn install(socket_path: impl Into<PathBuf>) {
    let path: PathBuf = socket_path.into();
    let start = Instant::now();
    let prev = std::panic::take_hook();
    // The Box allocation happens here, at install time — not in the hot path.
    std::panic::set_hook(Box::new(move |info| {
        // All errors are swallowed. Panicking inside a panic hook triggers an
        // immediate process abort, bypassing unwinding entirely.
        let _ = (|| {
            let sock = UnixDatagram::unbound().ok()?;
            sock.connect(&path).ok()?;
            let timestamp = start.elapsed().as_nanos() as u64;
            let frame = Frame::new(
                Status::Critical,
                std::process::id(),
                timestamp,
                NONCE_TERMINAL,
                0,
            );
            let mut buf = [0u8; 32];
            frame.encode(&mut buf);
            sock.send(&buf).ok()
        })();
        prev(info);
    }));
}
