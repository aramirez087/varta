//! Opt-in panic hook that emits a [`varta_vlp::Status::Critical`] VLP frame to
//! the observer before normal panic unwinding resumes.
//!
//! Call [`install`] once at process start. Each call chains the previously
//! installed hook via [`std::panic::take_hook`], so multiple installations are
//! safe — the most-recently registered socket path wins.

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::Instant;

#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
use varta_vlp::crypto::Key;
use varta_vlp::{Frame, Status, NONCE_TERMINAL};

#[cfg(feature = "udp")]
fn bind_udp_any_for(addr: std::net::SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    match addr {
        std::net::SocketAddr::V4(_) => std::net::UdpSocket::bind("0.0.0.0:0"),
        std::net::SocketAddr::V6(_) => std::net::UdpSocket::bind("[::]:0"),
    }
}

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
/// at install time. The hook closure body performs no heap allocations;
/// kernel-side allocation inside connect(2) and send(2) is out of our
/// control but does not affect the Rust allocator.
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

/// Register a panic hook that emits a [`Status::Critical`] VLP frame over UDP
/// to `addr` before resuming normal unwinding.
///
/// The hook creates a fresh [`UdpSocket`] on an ephemeral source port, connects
/// to `addr`, encodes a 32-byte frame into a stack buffer, and calls `send`.
/// All I/O errors are silently swallowed — panicking inside a panic hook
/// triggers an immediate process abort.
///
/// # Nonce sentinel
///
/// The frame carries `nonce = NONCE_TERMINAL`, distinct from the monotonically
/// incrementing nonces produced by [`crate::Varta::beat`].
///
/// # Allocation
///
/// The sole heap allocation is the `Box` created by [`std::panic::set_hook`]
/// at install time. The hook closure body performs no heap allocations.
///
/// # Chaining
///
/// This function captures the previously registered hook via
/// [`std::panic::take_hook`] and invokes it after firing the VLP frame.
#[cfg(feature = "udp")]
pub fn install_panic_handler_udp(addr: std::net::SocketAddr) {
    let start = Instant::now();
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = (|| {
            let sock = bind_udp_any_for(addr).ok()?;
            sock.connect(addr).ok()?;
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

/// Install a UDP panic handler with ChaCha20-Poly1305 encryption.
///
/// On panic, creates a one-shot secure UDP socket, encrypts a `Critical`
/// frame with `NONCE_TERMINAL` using the provided key, and sends it to
/// `addr`.
///
/// All I/O and crypto errors are silently ignored.
///
/// # Chaining
///
/// This function captures the previously registered hook via
/// [`std::panic::take_hook`] and invokes it after firing the secure VLP frame.
#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
pub fn install_panic_handler_secure_udp(addr: std::net::SocketAddr, key: Key) {
    use crate::secure_transport::{lcg_iv_random, read_iv_random};
    use varta_vlp::crypto::{self, NONCE_BYTES};

    let start = Instant::now();
    // Pre-compute the IV random prefix at install time — /dev/urandom
    // reads are not async-signal-safe and must not happen inside the
    // panic hook.  Fall back to the LCG if /dev/urandom is unavailable.
    let iv_random: [u8; 8] = read_iv_random().unwrap_or_else(|_| lcg_iv_random());
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = (|| {
            let sock = bind_udp_any_for(addr).ok()?;
            sock.connect(addr).ok()?;
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

            // Use the pre-computed IV from install time (read_iv_random() or
            // LCG fallback).  File I/O inside a panic hook is not signal-safe.
            let iv_counter = 1u32;

            let mut nonce = [0u8; NONCE_BYTES];
            nonce[..8].copy_from_slice(&iv_random);
            nonce[8..12].copy_from_slice(&iv_counter.to_le_bytes());

            let (ciphertext, tag) = crypto::seal(key.as_bytes(), &nonce, &buf);

            let mut secure_frame = [0u8; crypto::SECURE_FRAME_BYTES];
            secure_frame[..8].copy_from_slice(&iv_random);
            secure_frame[8..12].copy_from_slice(&iv_counter.to_le_bytes());
            secure_frame[12..44].copy_from_slice(&ciphertext);
            secure_frame[44..60].copy_from_slice(&tag);

            sock.send(&secure_frame).ok()
        })();
        prev(info);
    }));
}
