//! Opt-in panic hook that emits a [`varta_vlp::Status::Critical`] VLP frame to
//! the observer before normal panic unwinding resumes.
//!
//! Call [`install`] once at process start. Each call chains the previously
//! installed hook via [`std::panic::take_hook`], so multiple installations are
//! safe — the most-recently registered socket path wins.

#![forbid(unsafe_code)]

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
    /// would require non-cryptographic fallback IV material, which risks nonce
    /// reuse under the same AEAD key if the fallback inputs collide. Use
    /// [`install_panic_handler_secure_udp_accept_degraded_entropy`] to opt in
    /// explicitly.
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

/// Build the 60-byte shared-key secure panic frame for one `(nonce_prefix,
/// iv_counter)` pair. Returns `None` only if AEAD seal fails — structurally
/// unreachable for fixed 32-byte inputs against the pinned RustCrypto
/// `chacha20poly1305 = "=0.10.1"` crate, but a clean `Option` short-circuit
/// keeps the panic-hook closure free of any `unwrap`/`expect` that could
/// abort the process during unwinding.
#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
fn build_secure_panic_frame(
    key: &Key,
    nonce_prefix: [u8; 8],
    iv_counter: u32,
    panic_pid: u32,
    timestamp: u64,
) -> Option<[u8; varta_vlp::crypto::SECURE_FRAME_BYTES]> {
    use varta_vlp::crypto::{self, NONCE_BYTES};

    let frame = Frame::new(Status::Critical, panic_pid, timestamp, NONCE_TERMINAL, 0);
    let mut buf = [0u8; 32];
    frame.encode(&mut buf);

    let mut nonce = [0u8; NONCE_BYTES];
    nonce[..8].copy_from_slice(&nonce_prefix);
    nonce[8..12].copy_from_slice(&iv_counter.to_le_bytes());

    // Shared-key panic frame: AAD is empty (matches the
    // SecureUdpListener shared-key parse at recv time).
    let (ciphertext, tag) = crypto::seal(key.as_bytes(), &nonce, b"", &buf).ok()?;

    let mut secure_frame = [0u8; crypto::SECURE_FRAME_BYTES];
    secure_frame[..8].copy_from_slice(&nonce_prefix);
    secure_frame[8..12].copy_from_slice(&iv_counter.to_le_bytes());
    secure_frame[12..44].copy_from_slice(&ciphertext);
    secure_frame[44..60].copy_from_slice(&tag);

    Some(secure_frame)
}

#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
#[inline]
fn claim_secure_panic_counter(counter: &std::sync::atomic::AtomicU64) -> Option<u32> {
    let claimed = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    u32::try_from(claimed).ok()
}

/// Entropy material read before installing the secure panic hook.
#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
#[derive(Clone, Copy)]
pub(crate) struct SecurePanicEntropy {
    /// Salt used to derive *every* panic-frame IV prefix — installer, forked
    /// child, and PID-recycled descendant alike — via HKDF-SHA256 with no OS
    /// call in the hook body.
    fork_salt: [u8; 16],
}

/// Inner implementation used by both public secure-UDP panic-hook installers.
///
/// `provider` is called once at install time to obtain all IV material. If it
/// returns `Err`, installation is aborted and the error is returned to the
/// caller; the panic hook is NOT registered.
///
/// Forked children cannot reuse the install-time `iv_random`, but they also
/// cannot safely call the OS entropy chain from inside the hook. Instead, the
/// hook derives a child-specific prefix from the pre-read `fork_salt` via
/// HKDF-SHA256 using only stack computation.
#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
pub(crate) fn install_with_entropy_provider<F>(
    addr: std::net::SocketAddr,
    key: Key,
    provider: F,
) -> Result<(), PanicInstallError>
where
    F: FnOnce() -> std::io::Result<SecurePanicEntropy>,
{
    use std::sync::atomic::AtomicU64;

    let start = Instant::now();
    // Pre-compute all IV material at install time — /dev/urandom reads are
    // not async-signal-safe and must never happen inside the panic hook.
    let entropy = provider().map_err(PanicInstallError::EntropyUnavailable)?;
    let fork_salt = entropy.fork_salt;
    // Per-fire AEAD counter. The hook closure may be invoked more than
    // once per process: `std::panic::set_hook`'s closure is called for
    // every panic, and Rust serialises but does not deduplicate multiple
    // concurrent thread panics. Hardcoding `iv_counter = 1` would reuse
    // the same `(iv_random, 1)` 12-byte ChaCha20-Poly1305 nonce under
    // the same key on every fire — catastrophic AEAD nonce reuse
    // (recovers plaintext, lets attackers forge messages). Atomic
    // fetch-add guarantees each fire claims a distinct counter value. The
    // first value is 0, matching the secure transport spec's "new sessions
    // start at iv_counter = 0" rule. The claim state is wider than the
    // 32-bit wire counter so exhaustion drops the frame instead of wrapping
    // into nonce reuse.
    let iv_counter_atom = AtomicU64::new(0);
    // Pre-bind the UDP socket at install time. bind(2)/connect(2)/fcntl(2)
    // are NOT async-signal-safe per POSIX.1-2017 §2.4.3, so the hook
    // closure must never call them. Socket FD is inherited across fork(2);
    // send(2) on the inherited FD routes to the connected peer in both
    // parent and child. Cross-fork *and* PID-recycle nonce reuse is
    // prevented by deriving every prefix from `fork_salt` via HKDF over
    // (panic_pid, timestamp, iv_counter) in the hook below — there is no
    // raw-prefix fast path that an inherited, recyclable PID could alias.
    let sock = bind_ephemeral(&addr).map_err(PanicInstallError::SocketBind)?;
    sock.connect(addr).map_err(PanicInstallError::SocketBind)?;
    sock.set_nonblocking(true)
        .map_err(PanicInstallError::SocketBind)?;
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = (|| {
            let panic_pid = std::process::id();
            let timestamp = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            // Claim a unique counter for this fire. The first panic frame uses
            // iv_counter = 0, then 1, 2, ... matching vlp-secure.md §5.
            let iv_counter = claim_secure_panic_counter(&iv_counter_atom)?;
            // Derive the 8-byte prefix for EVERY fire — installer, forked
            // child, and PID-recycled descendant alike — from `fork_salt` via
            // HKDF over (panic_pid, timestamp, iv_counter). Pure stack work:
            // no getrandom(2) / `/dev/urandom` read, which are not
            // async-signal-safe. There is deliberately no `panic_pid ==
            // install_pid` fast path returning a raw inherited prefix: PID
            // equality is unsound under PID recycling (a descendant reassigned
            // the installer's PID would reuse the inherited prefix at
            // iv_counter=0). The monotonic `timestamp` (elapsed since the
            // shared install instant) differs between the installer and any
            // later descendant, so the derived (prefix, iv_counter) can never
            // collide under the same key.
            let nonce_prefix: [u8; 8] = varta_vlp::crypto::kdf::derive_panic_iv_prefix(
                &fork_salt, panic_pid, timestamp, iv_counter,
            )
            .ok()?;

            let secure_frame =
                build_secure_panic_frame(&key, nonce_prefix, iv_counter, panic_pid, timestamp)?;
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
/// The hook closure invokes only `send(2)`, AEAD encryption, HKDF-SHA256
/// IV-prefix derivation, and `getpid(2)` /
/// `clock_gettime(2)`. The socket FD, AEAD key, and IV seed material are
/// captured at install time; the closure performs no `socket(2)`,
/// `bind(2)`, `connect(2)`, `fcntl(2)`, OS entropy read, or `malloc(3)`.
///
/// # Entropy requirement
///
/// This function reads cryptographic entropy at install time
/// (`getrandom`/`getentropy`, falling back to `/dev/urandom`): a 16-byte
/// salt from which every panic-frame IV prefix is derived via HKDF-SHA256.
/// If the entropy chain fails — common in chrooted or
/// stripped-container environments without a mounted `/dev` — installation
/// is **aborted** and `Err(PanicInstallError::EntropyUnavailable)` is
/// returned. The hook is NOT registered in that case.
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
    use crate::secure_transport::read_iv_session_salt;
    install_with_entropy_provider(addr, key, || {
        Ok(SecurePanicEntropy {
            fork_salt: read_iv_session_salt()?,
        })
    })
}

/// Install a UDP panic handler with ChaCha20-Poly1305 encryption, accepting
/// degraded entropy as a fallback.
///
/// Identical to [`install_panic_handler_secure_udp`] except that when
/// `getrandom`/`getentropy` and `/dev/urandom` all fail, the IV prefix and
/// fork salt are derived from a non-cryptographic mix of PID, TID, monotonic
/// time, and counters (SipHash-2-4 keyed by `RandomState`). The entropy step
/// always succeeds; only socket bind/connect can fail.
///
/// # Async-signal safety
///
/// Inherits the async-signal-safety contract of
/// [`install_panic_handler_secure_udp`]: the hook closure invokes only
/// `send(2)`, AEAD encryption on stack buffers, optional HKDF-SHA256
/// derivation for forked children, and async-signal-safe clock/PID syscalls.
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
    use crate::secure_transport::{fallback_iv_session_salt, read_iv_session_salt};
    // All entropy material is prepared at install time. The degraded
    // fallback remains explicit, but the hook body still performs no OS
    // entropy calls if a forked child panics.
    match install_with_entropy_provider(addr, key, || {
        Ok(SecurePanicEntropy {
            fork_salt: read_iv_session_salt().unwrap_or_else(|_| fallback_iv_session_salt()),
        })
    }) {
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
        let result = install_with_entropy_provider(dummy_addr(), dummy_key(), || {
            Ok(SecurePanicEntropy {
                fork_salt: [2u8; 16],
            })
        });
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

    /// Regression: the secure panic-hook closure can fire more than once per
    /// process (multi-thread panic, signal-driven panic). Each fire must
    /// claim a distinct `iv_counter` so successive frames carry distinct
    /// 12-byte ChaCha20-Poly1305 nonces under the same key. Asserting via
    /// the testable `build_secure_panic_frame` helper rather than driving
    /// `set_hook` keeps the test out of the process-global panic-hook
    /// pathway (interferes with concurrent tests in the same binary).
    #[test]
    fn secure_panic_frame_counter_advances_per_fire() {
        let key = dummy_key();
        let nonce_prefix = [0xAAu8; 8];
        let panic_pid = 1234;
        let timestamp = 1_000_000u64;

        let f1 = build_secure_panic_frame(&key, nonce_prefix, 0, panic_pid, timestamp)
            .expect("seal must succeed for the pinned 32-byte panic frame");
        let f2 = build_secure_panic_frame(&key, nonce_prefix, 1, panic_pid, timestamp)
            .expect("seal must succeed for the pinned 32-byte panic frame");

        assert_eq!(
            &f1[8..12],
            &[0, 0, 0, 0],
            "secure panic-hook sessions must start at iv_counter=0"
        );

        // On-wire counter bytes (offset 8..12) must differ.
        assert_ne!(
            &f1[8..12],
            &f2[8..12],
            "iv_counter must change between fires (regression: was hardcoded to 1)"
        );

        // And the ciphertext+tag region (offset 12..60) must differ —
        // proof that the AEAD nonce changed for real, not just the
        // plaintext counter prefix.
        assert_ne!(
            &f1[12..60],
            &f2[12..60],
            "AEAD output must reflect the rotated nonce — nonce reuse is catastrophic"
        );
    }

    /// The atomic counter must be claimed in a single fetch-add so concurrent
    /// panics from multiple threads cannot observe the same `iv_counter`
    /// value. This is a structural guard on the primitive itself; the
    /// closure body relies on this invariant for AEAD nonce uniqueness.
    #[test]
    fn atomic_fetch_add_claims_distinct_counters_under_contention() {
        use std::sync::atomic::AtomicU64;
        use std::sync::Arc;
        use std::thread;

        const THREADS: u32 = 8;
        const PER_THREAD: u32 = 1_000;

        let atom = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::with_capacity(THREADS as usize);
        for _ in 0..THREADS {
            let a = Arc::clone(&atom);
            handles.push(thread::spawn(move || {
                let mut seen = Vec::with_capacity(PER_THREAD as usize);
                for _ in 0..PER_THREAD {
                    seen.push(claim_secure_panic_counter(&a).expect("counter space available"));
                }
                seen
            }));
        }
        let mut all: Vec<u32> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("thread"))
            .collect();
        let total = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(
            all.len(),
            total,
            "fetch_add must give every concurrent caller a distinct counter"
        );
    }

    #[test]
    fn secure_panic_counter_exhaustion_drops_before_reuse() {
        use std::sync::atomic::AtomicU64;

        let atom = AtomicU64::new(u32::MAX as u64);

        assert_eq!(
            claim_secure_panic_counter(&atom),
            Some(u32::MAX),
            "last in-range wire counter remains valid"
        );
        assert_eq!(
            claim_secure_panic_counter(&atom),
            None,
            "counter exhaustion must not wrap to iv_counter=0 under the same prefix"
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
