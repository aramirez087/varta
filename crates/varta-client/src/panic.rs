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

/// Error returned by [`install_panic_handler_secure_udp`] when installation
/// fails — either entropy is unavailable at install time, or the underlying
/// UDP socket cannot be bound/connected.
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
    /// `bind(2)`, `connect(2)`, or `fcntl(2)` failed at install time. The
    /// socket is pre-bound at install time so the panic-hook closure body
    /// performs only async-signal-safe operations (`send(2)`); a failure
    /// here means the hook cannot be registered at all.
    SocketBind(std::io::Error),
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
            PanicInstallError::SocketBind(e) => {
                write!(
                    f,
                    "varta: panic-hook install failed — socket bind/connect: {e}"
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
            PanicInstallError::SocketBind(e) => Some(e),
        }
    }
}

/// Register a panic hook that emits a [`Status::Critical`] VLP frame on the
/// Unix Domain Socket at `socket_path` before resuming normal unwinding.
///
/// The [`UnixDatagram`] is created, connected, and switched to non-blocking
/// mode **at install time**. The hook closure body then performs only
/// `send(2)` on the pre-bound socket. All I/O errors inside the closure are
/// silently swallowed — panicking inside a panic hook triggers an immediate
/// process abort, which is far worse than losing one datagram.
///
/// # Async-signal safety
///
/// The hook closure invokes only `send(2)`, which is on POSIX.1-2017's
/// async-signal-safe syscall list (§2.4.3). The socket FD and `Instant`
/// baseline are captured at install time. The closure performs no
/// `socket(2)`, `connect(2)`, `fcntl(2)`, or `malloc(3)`, so it is safe to
/// fire from a signal-driven panic (e.g., a user `SIGSEGV` handler that
/// calls `panic!()`).
///
/// # Errors
///
/// Returns `Err` if [`UnixDatagram::unbound`], `connect`, or
/// `set_nonblocking` fails at install time. In that case the hook is **not**
/// registered and the previously installed hook remains in place —
/// installation is loud rather than silently broken.
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
/// at install time. The hook closure body performs no heap allocations.
///
/// # Chaining
///
/// This function captures the previously registered hook via
/// [`std::panic::take_hook`] and invokes it after firing the VLP frame,
/// preserving the default panic message and any user-installed hooks.
pub fn install(socket_path: impl Into<PathBuf>) -> std::io::Result<()> {
    let path: PathBuf = socket_path.into();
    let start = Instant::now();
    // Pre-bind the socket at install time: socket(2)/connect(2)/fcntl(2)
    // are NOT async-signal-safe per POSIX.1-2017 §2.4.3. Doing them here
    // (normal code path) means the hook closure body only needs send(2),
    // which IS async-signal-safe.
    let sock = UnixDatagram::unbound()?;
    sock.connect(&path)?;
    sock.set_nonblocking(true)?;
    let prev = std::panic::take_hook();
    // The Box allocation happens here, at install time — not in the hook body.
    std::panic::set_hook(Box::new(move |info| {
        // All errors are swallowed. Panicking inside a panic hook triggers an
        // immediate process abort, bypassing unwinding entirely.
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
        let _ = sock.send(&buf);
        prev(info);
    }));
    Ok(())
}

/// Register a panic hook that emits a [`Status::Critical`] VLP frame over UDP
/// to `addr` before resuming normal unwinding.
///
/// A fresh [`std::net::UdpSocket`] on an ephemeral source port is bound,
/// connected to `addr`, and switched to non-blocking mode **at install
/// time**. The hook closure body then performs only `send(2)` on the
/// pre-bound socket. All I/O errors inside the closure are silently
/// swallowed — panicking inside a panic hook triggers an immediate process
/// abort.
///
/// # Async-signal safety
///
/// The hook closure invokes only `send(2)`, which is on POSIX.1-2017's
/// async-signal-safe syscall list (§2.4.3). The socket FD and `Instant`
/// baseline are captured at install time; the closure performs no
/// `socket(2)`, `bind(2)`, `connect(2)`, `fcntl(2)`, or `malloc(3)`.
///
/// # Errors
///
/// Returns `Err` if [`bind_ephemeral`], `connect`, or `set_nonblocking`
/// fails. In that case the hook is **not** registered.
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
pub fn install_panic_handler_udp(addr: std::net::SocketAddr) -> std::io::Result<()> {
    let start = Instant::now();
    // Pre-bind at install time — see async-signal-safety rationale on
    // [`install`]. bind(2)/connect(2)/fcntl(2) are NOT in the POSIX
    // async-signal-safe list.
    let sock = bind_ephemeral(&addr)?;
    sock.connect(addr)?;
    sock.set_nonblocking(true)?;
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
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
        let _ = sock.send(&buf);
        prev(info);
    }));
    Ok(())
}

/// Inner implementation used by both public secure-UDP panic-hook installers.
///
/// `provider` is called once at install time to obtain the 8-byte IV random
/// prefix. If it returns `Err`, installation is aborted and the error is
/// returned to the caller; the panic hook is NOT registered.
///
/// `refresh` is called inside the panic hook when [`std::process::id`] differs
/// from the PID at install time — i.e. the process has `fork(2)`-ed since.
/// Without this refresh, the child's panic frame would use the same cached
/// `iv_random` + `iv_counter = 1` pair as the parent under the same AEAD key,
/// which is **catastrophic nonce reuse**. A `None` return from `refresh`
/// signals that no usable IV is available; the secure frame is then skipped
/// entirely and the previous panic hook still fires.
#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
pub(crate) fn install_with_entropy_provider<F, G>(
    addr: std::net::SocketAddr,
    key: Key,
    provider: F,
    refresh: G,
) -> Result<(), PanicInstallError>
where
    F: FnOnce() -> std::io::Result<[u8; 8]>,
    G: Fn() -> Option<[u8; 8]> + Send + Sync + 'static,
{
    use varta_vlp::crypto::{self, NONCE_BYTES};

    let start = Instant::now();
    // Pre-compute the IV random prefix at install time — /dev/urandom
    // reads are not async-signal-safe and must not happen inside the
    // panic hook on the steady-state (non-forked) path.
    let iv_random: [u8; 8] = provider().map_err(PanicInstallError::EntropyUnavailable)?;
    // Snapshot the PID at install time. If a forked child later panics,
    // it would otherwise re-use the parent's cached `iv_random` under the
    // same key — a catastrophic AEAD nonce collision. We detect the fork
    // by PID mismatch and re-run the entropy chain via `refresh`.
    let install_pid = std::process::id();
    // Pre-bind the UDP socket at install time. bind(2)/connect(2)/fcntl(2)
    // are NOT async-signal-safe per POSIX.1-2017 §2.4.3, so the hook
    // closure must never call them. Socket FD is inherited across fork(2);
    // send(2) on the inherited FD routes to the connected peer in both
    // parent and child. Cross-fork nonce reuse is prevented by the
    // PID-mismatch entropy refresh above.
    let sock = bind_ephemeral(&addr).map_err(PanicInstallError::SocketBind)?;
    sock.connect(addr).map_err(PanicInstallError::SocketBind)?;
    sock.set_nonblocking(true)
        .map_err(PanicInstallError::SocketBind)?;
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = (|| {
            let panic_pid = std::process::id();
            let nonce_prefix: [u8; 8] = if panic_pid != install_pid {
                // Forked since install. Refresh entropy at panic time.
                // `refresh()` returning `None` means no usable source is
                // reachable; bail out of the inner closure so we do NOT
                // emit a nonce-reusing frame.
                refresh()?
            } else {
                iv_random
            };

            let timestamp = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let frame = Frame::new(Status::Critical, panic_pid, timestamp, NONCE_TERMINAL, 0);
            let mut buf = [0u8; 32];
            frame.encode(&mut buf);

            let iv_counter = 1u32;

            let mut nonce = [0u8; NONCE_BYTES];
            nonce[..8].copy_from_slice(&nonce_prefix);
            nonce[8..12].copy_from_slice(&iv_counter.to_le_bytes());

            // Shared-key panic frame: AAD is empty (matches the
            // SecureUdpListener shared-key parse at recv time).
            let (ciphertext, tag) = crypto::seal(key.as_bytes(), &nonce, b"", &buf);

            let mut secure_frame = [0u8; crypto::SECURE_FRAME_BYTES];
            secure_frame[..8].copy_from_slice(&nonce_prefix);
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
/// The UDP socket is bound, connected, and switched to non-blocking mode
/// **at install time**. On panic, the hook encrypts a `Critical` frame
/// with `NONCE_TERMINAL` using the provided key and sends it via the
/// pre-bound socket. All I/O and crypto errors inside the hook are
/// silently ignored.
///
/// # Async-signal safety
///
/// The hook closure invokes only `send(2)`, AEAD encryption on stack
/// buffers, and `getpid(2)`/`clock_gettime(2)` — all on POSIX.1-2017's
/// async-signal-safe syscall list (§2.4.3). The socket FD, AEAD key, and
/// IV material are captured at install time; the closure performs no
/// `socket(2)`, `bind(2)`, `connect(2)`, `fcntl(2)`, or `malloc(3)`.
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
/// # Errors
///
/// - [`PanicInstallError::EntropyUnavailable`] — entropy chain failed.
/// - [`PanicInstallError::SocketBind`] — UDP socket bind, connect, or
///   non-blocking flag failed at install time.
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
    // Fork-time refresh uses the same entropy chain as the install-time
    // read. On failure (e.g. no `/dev` in a stripped container) we return
    // `None` to fail closed — the child's panic frame is skipped rather
    // than emitted with the parent's cached IV.
    install_with_entropy_provider(addr, key, read_iv_random, || read_iv_random().ok())
}

/// Install a UDP panic handler with ChaCha20-Poly1305 encryption, accepting
/// degraded entropy as a fallback.
///
/// Identical to [`install_panic_handler_secure_udp`] except that when
/// `getrandom`/`getentropy` and `/dev/urandom` all fail, the IV is derived
/// from a non-cryptographic mix of PID, TID, monotonic time, and a counter
/// (SipHash-2-4 keyed by `RandomState`). The entropy step always succeeds;
/// only socket bind/connect can fail.
///
/// # Async-signal safety
///
/// Inherits the async-signal-safety contract of
/// [`install_panic_handler_secure_udp`]: the hook closure invokes only
/// `send(2)`, AEAD encryption on stack buffers, and async-signal-safe
/// clock/PID syscalls.
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
/// # Errors
///
/// Returns `Err` if UDP socket bind, connect, or non-blocking flag fails
/// at install time. The entropy step never fails (the degraded fallback
/// always returns a value).
///
/// # Chaining
///
/// This function captures the previously registered hook via
/// [`std::panic::take_hook`] and invokes it after firing the secure VLP frame.
#[cfg(feature = "accept-degraded-entropy")]
pub fn install_panic_handler_secure_udp_accept_degraded_entropy(
    addr: std::net::SocketAddr,
    key: Key,
) -> std::io::Result<()> {
    use crate::secure_transport::{fallback_iv_random, read_iv_random};
    // Both install-time and fork-time refresh fall through to the
    // non-cryptographic `fallback_iv_random` when OS entropy is
    // unreachable. This always returns `Some`, so the panic frame
    // is always emitted — at the documented degraded-entropy risk.
    match install_with_entropy_provider(
        addr,
        key,
        || Ok(read_iv_random().unwrap_or_else(|_| fallback_iv_random())),
        || Some(read_iv_random().unwrap_or_else(|_| fallback_iv_random())),
    ) {
        Ok(()) => Ok(()),
        Err(PanicInstallError::SocketBind(e)) => Err(e),
        // The degraded-entropy provider above always returns `Ok`, so the
        // entropy arm is structurally unreachable.
        Err(PanicInstallError::EntropyUnavailable(_)) => {
            unreachable!("degraded-entropy provider is infallible by construction")
        }
    }
}

#[cfg(all(test, feature = "panic-handler", feature = "secure-udp"))]
mod tests {
    use super::*;
    use std::io;
    use std::net::SocketAddr;

    fn dummy_addr() -> SocketAddr {
        // Use a non-zero destination port: UDP `connect(2)` rejects port 0
        // with `EADDRNOTAVAIL` on macOS (and the POSIX spec is silent on
        // it). The target need not be listening — UDP `connect` only
        // records the peer address. Picking a high arbitrary port avoids
        // any possible privileged-port issues.
        "127.0.0.1:65535".parse().unwrap()
    }

    fn dummy_key() -> Key {
        Key::from_bytes([0u8; 32])
    }

    #[test]
    fn install_with_entropy_provider_happy_path_returns_ok() {
        let result = install_with_entropy_provider(
            dummy_addr(),
            dummy_key(),
            || Ok([1u8; 8]),
            || Some([2u8; 8]),
        );
        assert!(result.is_ok());
        // Restore default hook so other tests are not affected.
        let _ = std::panic::take_hook();
    }

    #[test]
    fn install_with_entropy_provider_failure_returns_err_and_does_not_install() {
        let err = io::Error::new(io::ErrorKind::NotFound, "no /dev in chroot");
        let result = install_with_entropy_provider(
            dummy_addr(),
            dummy_key(),
            || Err(err),
            || Some([2u8; 8]),
        );
        match result {
            Err(PanicInstallError::EntropyUnavailable(inner)) => {
                assert_eq!(inner.kind(), io::ErrorKind::NotFound);
            }
            Err(PanicInstallError::SocketBind(e)) => {
                panic!("expected EntropyUnavailable, got SocketBind({e})")
            }
            Ok(()) => panic!("expected Err but got Ok"),
        }
    }

    #[test]
    fn socket_bind_error_display_and_source() {
        // Validate the new variant's Display/source impls. Construction is
        // direct (no syscall) so this test is deterministic across
        // platforms.
        let inner = io::Error::from(io::ErrorKind::PermissionDenied);
        let err = PanicInstallError::SocketBind(inner);
        let msg = format!("{err}");
        assert!(
            msg.contains("socket bind/connect"),
            "Display must mention socket bind/connect; got: {msg}"
        );
        assert!(
            std::error::Error::source(&err).is_some(),
            "source() must return the inner io::Error"
        );
    }

    #[cfg(feature = "accept-degraded-entropy")]
    #[test]
    fn accept_degraded_entropy_always_succeeds() {
        // The degraded-entropy variant must never fail at the entropy step.
        // (Socket bind/connect to 127.0.0.1:0 also succeeds on every
        // platform Varta supports.)
        install_panic_handler_secure_udp_accept_degraded_entropy(dummy_addr(), dummy_key())
            .expect("degraded-entropy install must succeed for loopback addr");
        let _ = std::panic::take_hook();
    }
}
