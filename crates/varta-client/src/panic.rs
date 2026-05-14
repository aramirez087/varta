//! Opt-in panic hook that emits a [`varta_vlp::Status::Critical`] VLP frame to
//! the observer before normal panic unwinding resumes.
//!
//! Call [`install`] once at process start. Each call chains the previously
//! installed hook via [`std::panic::take_hook`], so multiple installations are
//! safe — the most-recently registered socket path wins.

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::Instant;

#[cfg(any(feature = "udp", feature = "secure-udp"))]
use crate::transport::bind_ephemeral;
#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
use varta_vlp::crypto::Key;
use varta_vlp::{Frame, Status, NONCE_TERMINAL};

/// Error returned by [`install_panic_handler_secure_udp`] when entropy is
/// unavailable at install time.
///
/// This type is not `#[non_exhaustive]`; adding a variant is a deliberate
/// breaking change (consistent with the project's exhaustiveness policy for
/// `Status` and `DecodeError`).
#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
#[derive(Debug)]
pub enum PanicInstallError {
    /// Both `getrandom`/`getentropy` and `/dev/urandom` failed. Proceeding
    /// would require the non-cryptographic `fallback_iv_random()`, which risks
    /// nonce reuse under the same AEAD key if the process panics more than
    /// once. Use [`install_panic_handler_secure_udp_accept_degraded_entropy`]
    /// to opt in explicitly.
    EntropyUnavailable(std::io::Error),
}

#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
impl core::fmt::Display for PanicInstallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PanicInstallError::EntropyUnavailable(e) => {
                write!(
                    f,
                    "varta: panic-hook install failed — entropy unavailable: {e}"
                )
            }
        }
    }
}

#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
impl std::error::Error for PanicInstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PanicInstallError::EntropyUnavailable(e) => Some(e),
        }
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
            sock.set_nonblocking(true).ok()?;
            let timestamp = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
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
            let sock = bind_ephemeral(&addr).ok()?;
            sock.connect(addr).ok()?;
            sock.set_nonblocking(true).ok()?;
            let timestamp = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
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

/// Inner implementation used by both public secure-UDP panic-hook installers.
///
/// `provider` is called once at install time to obtain the 8-byte IV random
/// prefix. If it returns `Err`, installation is aborted and the error is
/// returned to the caller; the panic hook is NOT registered.
#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
pub(crate) fn install_with_entropy_provider<F>(
    addr: std::net::SocketAddr,
    key: Key,
    provider: F,
) -> Result<(), PanicInstallError>
where
    F: FnOnce() -> std::io::Result<[u8; 8]>,
{
    use varta_vlp::crypto::{self, NONCE_BYTES};

    let start = Instant::now();
    // Pre-compute the IV random prefix at install time — /dev/urandom
    // reads are not async-signal-safe and must not happen inside the
    // panic hook.
    let iv_random: [u8; 8] = provider().map_err(PanicInstallError::EntropyUnavailable)?;
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = (|| {
            let sock = bind_ephemeral(&addr).ok()?;
            sock.connect(addr).ok()?;
            sock.set_nonblocking(true).ok()?;
            let timestamp = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let frame = Frame::new(
                Status::Critical,
                std::process::id(),
                timestamp,
                NONCE_TERMINAL,
                0,
            );
            let mut buf = [0u8; 32];
            frame.encode(&mut buf);

            // Use the pre-computed IV from install time.
            // File I/O inside a panic hook is not async-signal-safe.
            let iv_counter = 1u32;

            let mut nonce = [0u8; NONCE_BYTES];
            nonce[..8].copy_from_slice(&iv_random);
            nonce[8..12].copy_from_slice(&iv_counter.to_le_bytes());

            // Shared-key panic frame: AAD is empty (matches the
            // SecureUdpListener shared-key parse at recv time).
            let (ciphertext, tag) = crypto::seal(key.as_bytes(), &nonce, b"", &buf);

            let mut secure_frame = [0u8; crypto::SECURE_FRAME_BYTES];
            secure_frame[..8].copy_from_slice(&iv_random);
            secure_frame[8..12].copy_from_slice(&iv_counter.to_le_bytes());
            secure_frame[12..44].copy_from_slice(&ciphertext);
            secure_frame[44..60].copy_from_slice(&tag);

            sock.send(&secure_frame).ok()
        })();
        prev(info);
    }));
    Ok(())
}

/// Install a UDP panic handler with ChaCha20-Poly1305 encryption.
///
/// On panic, creates a one-shot secure UDP socket, encrypts a `Critical`
/// frame with `NONCE_TERMINAL` using the provided key, and sends it to
/// `addr`.
///
/// All I/O and crypto errors are silently ignored.
///
/// # Entropy requirement
///
/// This function reads 8 bytes of cryptographic entropy at install time
/// (`getrandom`/`getentropy`, falling back to `/dev/urandom`). If all
/// sources fail — common in chrooted or stripped-container environments
/// without a mounted `/dev` — installation is **aborted** and
/// `Err(PanicInstallError::EntropyUnavailable)` is returned. The hook is
/// NOT registered in that case.
///
/// To opt into a non-cryptographic IV fallback (with nonce-reuse risk),
/// use [`install_panic_handler_secure_udp_accept_degraded_entropy`] instead.
///
/// # Chaining
///
/// This function captures the previously registered hook via
/// [`std::panic::take_hook`] and invokes it after firing the secure VLP frame.
#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
pub fn install_panic_handler_secure_udp(
    addr: std::net::SocketAddr,
    key: Key,
) -> Result<(), PanicInstallError> {
    use crate::secure_transport::read_iv_random;
    install_with_entropy_provider(addr, key, read_iv_random)
}

/// Install a UDP panic handler with ChaCha20-Poly1305 encryption, accepting
/// degraded entropy as a fallback.
///
/// Identical to [`install_panic_handler_secure_udp`] except that when
/// `getrandom`/`getentropy` and `/dev/urandom` all fail, the IV is derived
/// from a non-cryptographic mix of PID, TID, monotonic time, and a counter
/// (SipHash-2-4 keyed by `RandomState`). This always succeeds.
///
/// # Safety / Correctness
///
/// If the non-cryptographic fallback is used, multiple panic frames from the
/// same process under the same AEAD key **may collide on IV**, causing nonce
/// reuse — a catastrophic confidentiality and integrity failure. Use this
/// function only in environments where panic frequency is controlled or where
/// frame confidentiality is not load-bearing. The verbose name is intentional:
/// the operator must type the risk out explicitly (matching the project's
/// `--i-accept-<risk>` convention for safety-critical configuration).
///
/// # Chaining
///
/// This function captures the previously registered hook via
/// [`std::panic::take_hook`] and invokes it after firing the secure VLP frame.
#[cfg(feature = "accept-degraded-entropy")]
pub fn install_panic_handler_secure_udp_accept_degraded_entropy(
    addr: std::net::SocketAddr,
    key: Key,
) {
    use crate::secure_transport::{fallback_iv_random, read_iv_random};
    let _ = install_with_entropy_provider(addr, key, || {
        Ok(read_iv_random().unwrap_or_else(|_| fallback_iv_random()))
    });
}

#[cfg(all(test, feature = "panic-handler", feature = "secure-udp"))]
mod tests {
    use super::*;
    use std::io;
    use std::net::SocketAddr;

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn dummy_key() -> Key {
        Key::from_bytes([0u8; 32])
    }

    #[test]
    fn install_with_entropy_provider_happy_path_returns_ok() {
        let result = install_with_entropy_provider(dummy_addr(), dummy_key(), || Ok([1u8; 8]));
        assert!(result.is_ok());
        // Restore default hook so other tests are not affected.
        let _ = std::panic::take_hook();
    }

    #[test]
    fn install_with_entropy_provider_failure_returns_err_and_does_not_install() {
        let err = io::Error::new(io::ErrorKind::NotFound, "no /dev in chroot");
        let result = install_with_entropy_provider(dummy_addr(), dummy_key(), || Err(err));
        match result {
            Err(PanicInstallError::EntropyUnavailable(inner)) => {
                assert_eq!(inner.kind(), io::ErrorKind::NotFound);
            }
            Ok(()) => panic!("expected Err but got Ok"),
        }
    }

    #[cfg(feature = "accept-degraded-entropy")]
    #[test]
    fn accept_degraded_entropy_always_succeeds() {
        // The degraded-entropy variant must never panic or return an error.
        install_panic_handler_secure_udp_accept_degraded_entropy(dummy_addr(), dummy_key());
        let _ = std::panic::take_hook();
    }
}
