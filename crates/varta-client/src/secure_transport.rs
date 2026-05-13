//! Secure UDP transport backed by ChaCha20-Poly1305 AEAD.
//!
//! [`SecureUdpTransport`] wraps a UDP socket with authenticated encryption
//! using `varta_vlp::crypto`. Every 32-byte VLP frame is encrypted and
//! authenticated before transmission; the 60-byte wire format includes a
//! per-session IV prefix, a monotonic message counter, the encrypted frame,
//! and a Poly1305 tag.
//!
//! # IV scheme (H6 — counter-mode KDF)
//!
//! A 16-byte **session salt** is read from OS entropy exactly once at
//! `connect()` time. All subsequent 8-byte IV prefixes are derived from
//! the salt via [`varta_vlp::crypto::kdf::derive_iv_prefix`] — a
//! deterministic HKDF-SHA256 expansion keyed by a `u32` prefix index. On
//! `u32` AEAD-counter wrap the prefix index advances by one and a new
//! prefix is derived; **no OS entropy syscall fires on the beat path**.
//!
//! * **Nonce uniqueness**: each `(prefix_index, iv_counter)` pair yields a
//!   unique 96-bit nonce. The product space is `u32 × u32 = 2^64` distinct
//!   nonces per session — ~584M years at 1 kHz beat rate.
//! * **Counter capacity**: the 32-bit counter allows ~4 billion beats per
//!   prefix (at 1 kHz this is ~50 days; at 1 Hz, ~136 years). On wrap the
//!   transport rotates the prefix in-process — the observer sees a new IV
//!   prefix (treated as a new session, same as today's behaviour).
//! * **Prefix-index exhaustion**: if the `u32` prefix index ever wraps
//!   (unreachable in any realistic deployment), `send()` calls
//!   [`SecureUdpTransport::reconnect`] — the documented manual escape
//!   hatch — to re-read OS entropy and start a fresh session.
//!
//! # Why no entropy on the beat path
//!
//! `getrandom(2)` on Linux with `flags=0` blocks until the kernel entropy
//! pool is initialised. At boot or under fork-bomb conditions this can
//! stall for seconds. Heartbeat liveness MUST NOT depend on a syscall that
//! can block; the counter-mode KDF gives us cryptographically independent
//! prefixes with zero syscalls.
//!
//! # Fork-safety
//!
//! After `fork(2)` the child inherits the parent's `iv_session_salt` and
//! `iv_prefix_index` — both would derive identical prefixes and conflict
//! on counter values, causing catastrophic nonce reuse under the same
//! AEAD key. **The application MUST call [`crate::Varta::reconnect`] in
//! the child** (or construct a fresh `Varta` instance there) before the
//! first beat. The library does not auto-detect fork (cerebrum
//! 2026-05-13: `last_pid` was deliberately removed).
//!
//! **This transport is designed for trusted local networks.**

use std::io;
use std::net::{SocketAddr, UdpSocket};

use varta_vlp::crypto::{self, Key, NONCE_BYTES, SECURE_FRAME_MASTER_BYTES};

use crate::transport::{bind_ephemeral, BeatTransport};

/// Wire length for a shared-key frame.
const SECURE_FRAME_LEN: usize = crypto::SECURE_FRAME_BYTES;

/// Wire length for a master-key frame.
const SECURE_FRAME_MASTER_LEN: usize = SECURE_FRAME_MASTER_BYTES;

/// UDP transport with ChaCha20-Poly1305 AEAD encryption and authentication.
///
/// Created via [`SecureUdpTransport::connect`] and used as the backend for
/// [`Varta::connect_secure_udp`].
///
/// On each `send`, the 32-byte VLP frame is encrypted with a unique 96-bit
/// nonce (8-byte random prefix + 4-byte monotonic counter). The resulting
/// 60-byte AEAD frame is sent over UDP.
///
/// # Security properties
///
/// * **Confidentiality**: Frame contents are encrypted (ChaCha20 stream cipher).
/// * **Integrity**: Tampering is detected (Poly1305 authentication tag).
/// * **Replay resistance**: Monotonic counter per connection; observer verifies
///   that counter values strictly increase for a given IV prefix.
/// * **Nonce uniqueness**: The 8-byte random prefix (from `/dev/urandom` at
///   connect time) plus the 4-byte counter ensures no nonce reuse within a
///   connection lifetime.
///
/// # Security
///
/// See the [module-level security documentation](self) for important
/// caveats about the 32-bit counter space.
///
/// [`Varta::connect_secure_udp`]: crate::Varta::connect_secure_udp
/// [module-level security documentation]: self#security
pub struct SecureUdpTransport {
    sock: UdpSocket,
    addr: SocketAddr,
    key: Key,
    iv_counter: u32,
    /// Read once from OS entropy at `connect()`; never re-read on the beat
    /// path. Used as HKDF input to derive `iv_prefix` per-session.
    iv_session_salt: [u8; 16],
    /// Increments on AEAD-counter wrap; mixed into the HKDF info string.
    iv_prefix_index: u32,
    /// Cache of `derive_iv_prefix(session_salt, prefix_index)`. Recomputed
    /// only on `connect`, `reconnect`, or counter wrap — not per beat.
    iv_prefix: [u8; 8],
    is_master_mode: bool,
}

impl SecureUdpTransport {
    /// Create a non-blocking secure UDP socket connected to `addr`.
    ///
    /// The socket is bound to an ephemeral source port. A 16-byte session
    /// salt is read from OS entropy at connect time (no syscall on the
    /// beat path — see module-level docs).
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the socket cannot be created, connected,
    /// switched to non-blocking mode, or if OS entropy is unavailable.
    pub fn connect(addr: SocketAddr, key: Key) -> io::Result<Self> {
        use varta_vlp::crypto::kdf;

        let sock = bind_ephemeral(&addr)?;
        sock.connect(addr)?;
        sock.set_nonblocking(true)?;

        let iv_session_salt = read_iv_session_salt()?;
        let iv_prefix = kdf::derive_iv_prefix(&iv_session_salt, 0);

        Ok(SecureUdpTransport {
            sock,
            addr,
            key,
            iv_counter: 0,
            iv_session_salt,
            iv_prefix_index: 0,
            iv_prefix,
            is_master_mode: false,
        })
    }

    /// Create a secure UDP socket using a master key with per-agent key
    /// derivation.
    ///
    /// The agent key is derived from the master key and the calling
    /// process's PID using [`varta_vlp::crypto::kdf::derive_agent_key`].
    /// On each beat the PID is sent as a 4-byte plaintext prefix (AAD)
    /// so the observer can derive the same agent key before decrypting.
    ///
    /// The 8-byte `iv_random` is filled entirely from OS entropy — the PID
    /// is no longer embedded in it. This gives a 64-bit random birthday
    /// bound (~2^32 reconnects before collision probability reaches 50%),
    /// versus the old 32-bit bound of ~2^16 reconnects.
    ///
    /// # Wire format (master-key mode, 64 bytes)
    ///
    /// ```text
    /// [agent_pid: 4] [iv_random: 8] [iv_counter: 4] [ciphertext: 32] [tag: 16]
    /// ```
    ///
    /// `agent_pid` is bound as Additional Authenticated Data (AAD) into the
    /// Poly1305 tag; tampering the on-wire PID causes authentication failure.
    ///
    /// # Security
    ///
    /// Per-agent key derivation means compromising one agent's derived key
    /// does not reveal other agents' keys or the master key.
    pub fn connect_with_master(addr: SocketAddr, master_key: Key) -> io::Result<Self> {
        use varta_vlp::crypto::kdf;

        let peer_pid = std::process::id();
        let agent_key = kdf::derive_agent_key(&master_key, peer_pid);

        let sock = bind_ephemeral(&addr)?;
        sock.connect(addr)?;
        sock.set_nonblocking(true)?;

        // 16-byte session salt — HKDF-expanded into the 8-byte on-wire
        // `iv_random` field. The PID is sent as a plaintext AAD field in
        // the 64-byte wire frame.
        let iv_session_salt = read_iv_session_salt()?;
        let iv_prefix = kdf::derive_iv_prefix(&iv_session_salt, 0);

        Ok(SecureUdpTransport {
            sock,
            addr,
            key: agent_key,
            iv_counter: 0,
            iv_session_salt,
            iv_prefix_index: 0,
            iv_prefix,
            is_master_mode: true,
        })
    }

    /// Test-only setter to fast-forward the AEAD counter, exercising the
    /// counter-wrap rotation path without sending billions of beats.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_iv_counter_for_test(&mut self, value: u32) {
        self.iv_counter = value;
    }

    /// Test-only accessor for the current derived prefix.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn iv_prefix_for_test(&self) -> [u8; 8] {
        self.iv_prefix
    }

    /// Test-only accessor for the prefix index.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn iv_prefix_index_for_test(&self) -> u32 {
        self.iv_prefix_index
    }
}

impl BeatTransport for SecureUdpTransport {
    fn send(&mut self, buf: &[u8; 32]) -> io::Result<usize> {
        self.iv_counter = match self.iv_counter.checked_add(1) {
            Some(n) => n,
            None => {
                // AEAD counter exhausted — rotate the per-session IV prefix
                // via HKDF derivation.  No OS entropy syscall: the session
                // salt was sampled once at connect() and the KDF gives us
                // cryptographically independent prefixes.
                match self.iv_prefix_index.checked_add(1) {
                    Some(next_index) => {
                        self.iv_prefix_index = next_index;
                        self.iv_prefix = varta_vlp::crypto::kdf::derive_iv_prefix(
                            &self.iv_session_salt,
                            self.iv_prefix_index,
                        );
                        // First beat in the rotated prefix's counter space.
                        1
                    }
                    None => {
                        // Prefix index also exhausted (2^64 nonces — ~584M
                        // years at 1 kHz). Fall back to the documented
                        // manual escape hatch: refresh the salt via the
                        // entropy chain. Retry the beat against the fresh
                        // session.
                        self.reconnect()?;
                        return self.send(buf);
                    }
                }
            }
        };

        // Build 12-byte nonce: iv_prefix (8) || iv_counter (4) LE
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[..8].copy_from_slice(&self.iv_prefix);
        nonce[8..12].copy_from_slice(&self.iv_counter.to_le_bytes());

        if self.is_master_mode {
            // Master-key wire format (64 bytes):
            // [agent_pid: 4] [iv_random: 8] [iv_counter: 4] [ciphertext: 32] [tag: 16]
            //
            // The on-wire `iv_random` field is now sourced from the
            // KDF-derived `iv_prefix` cache — byte budget preserved.
            //
            // agent_pid is read fresh each beat (never cached — see cerebrum
            // 2026-05-11) and bound as AAD so tampering the PID prefix fails
            // authentication.
            let agent_pid = std::process::id();
            let agent_pid_bytes = agent_pid.to_le_bytes();
            let (ciphertext, tag) =
                crypto::seal(self.key.as_bytes(), &nonce, &agent_pid_bytes, buf);

            let mut frame = [0u8; SECURE_FRAME_MASTER_LEN];
            frame[0..4].copy_from_slice(&agent_pid_bytes);
            frame[4..12].copy_from_slice(&self.iv_prefix);
            frame[12..16].copy_from_slice(&self.iv_counter.to_le_bytes());
            frame[16..48].copy_from_slice(&ciphertext);
            frame[48..64].copy_from_slice(&tag);

            self.sock.send(&frame)
        } else {
            // Shared-key wire format (60 bytes):
            // [iv_random: 8] [iv_counter: 4] [ciphertext: 32] [tag: 16]
            let (ciphertext, tag) = crypto::seal(self.key.as_bytes(), &nonce, b"", buf);

            let mut frame = [0u8; SECURE_FRAME_LEN];
            frame[..8].copy_from_slice(&self.iv_prefix);
            frame[8..12].copy_from_slice(&self.iv_counter.to_le_bytes());
            frame[12..44].copy_from_slice(&ciphertext);
            frame[44..60].copy_from_slice(&tag);

            self.sock.send(&frame)
        }
    }

    /// Manual session refresh — re-binds the ephemeral socket, re-reads OS
    /// entropy for a fresh 16-byte session salt, and resets prefix/counter
    /// state. This is the **only** path after `connect()` that touches OS
    /// entropy.
    ///
    /// Call after `fork(2)` in the child (the inherited `iv_session_salt`
    /// would otherwise cause catastrophic nonce reuse), or when an
    /// operator wants a fresh AEAD session for forward-secrecy hygiene.
    fn reconnect(&mut self) -> io::Result<()> {
        use varta_vlp::crypto::kdf;

        let sock = bind_ephemeral(&self.addr)?;
        sock.connect(self.addr)?;
        sock.set_nonblocking(true)?;
        self.sock = sock;

        // Refresh the session salt and re-derive prefix-0.  The observer
        // tracks per-sender state by (SocketAddr, iv_prefix); a new salt
        // produces a fresh prefix series that the observer treats as a new
        // session.
        self.iv_session_salt = read_iv_session_salt()?;
        self.iv_prefix_index = 0;
        self.iv_prefix = kdf::derive_iv_prefix(&self.iv_session_salt, 0);
        self.iv_counter = 0;

        Ok(())
    }
}

// --- OS-level random bytes via kernel syscall ---------------------------
//
// `os_random` tries the most direct kernel interface first (`getrandom(2)`
// on Linux, `getentropy(3)` on macOS/BSD).  These do not require a mounted
// `/dev`, so they work inside chroots and stripped containers where
// `/dev/urandom` may be absent.  `read_iv_random` falls through to
// `/dev/urandom` only when `os_random` fails.

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn os_random(buf: &mut [u8]) -> io::Result<()> {
    extern "C" {
        // glibc 2.25+ / musl 1.1.20+ wraps the getrandom(2) syscall.
        fn getrandom(buf: *mut u8, buflen: usize, flags: u32) -> isize;
    }
    // flags = 0: block until the entropy pool is initialised (correct for
    // connect-time calls that are never on the beat path). EINTR is retried;
    // ENOSYS (kernel < 3.17) propagates and the caller falls through to
    // /dev/urandom.
    //
    // SAFETY: `buf` is a valid slice of `buf.len()` bytes; getrandom writes
    // at most `buflen` bytes and returns the number written on success.
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = unsafe { getrandom(buf.as_mut_ptr().add(filled), buf.len() - filled, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        filled += n as usize;
    }
    Ok(())
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
#[allow(unsafe_code)]
fn os_random(buf: &mut [u8]) -> io::Result<()> {
    extern "C" {
        // Available since macOS 10.12, FreeBSD 12, NetBSD 10, OpenBSD 5.6.
        fn getentropy(buf: *mut u8, buflen: usize) -> i32;
    }
    // getentropy(3) requires buflen <= 256.  Both call sites request 4 or 8
    // bytes, so this assertion is always satisfied.
    assert!(buf.len() <= 256, "getentropy: buflen must be <= 256");
    // SAFETY: `buf` is a valid slice; getentropy writes exactly `buflen`
    // bytes on success.
    let rc = unsafe { getentropy(buf.as_mut_ptr(), buf.len()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
)))]
fn os_random(_buf: &mut [u8]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no OS random source on this platform",
    ))
}

// -----------------------------------------------------------------------

/// Read a cryptographically-random 8-byte IV prefix.
///
/// Called once at `connect()` / `reconnect()` time — never on the beat path.
/// Tries `getrandom(2)` / `getentropy(3)` first (no `/dev` mount required),
/// then falls back to `/dev/urandom`.
///
/// **Note:** `SecureUdpTransport` no longer calls this — it uses
/// [`read_iv_session_salt`] for the 16-byte session salt. Retained here for
/// the panic-hook installer which emits a one-shot frame with a fresh
/// 8-byte IV.
#[cfg_attr(
    not(any(test, all(feature = "panic-handler", feature = "secure-udp"))),
    allow(dead_code)
)]
pub(crate) fn read_iv_random() -> io::Result<[u8; 8]> {
    let mut buf = [0u8; 8];
    if os_random(&mut buf).is_ok() {
        return Ok(buf);
    }
    std::fs::File::open("/dev/urandom").and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut buf)
    })?;
    Ok(buf)
}

/// Read a cryptographically-random 16-byte session salt.
///
/// Called once at `connect()` / `reconnect()` time — never on the beat path
/// (H6 contract). The salt seeds the per-session HKDF that produces 8-byte
/// IV prefixes on counter wrap, so subsequent prefix rotations require no
/// OS entropy.
///
/// Tries `getrandom(2)` / `getentropy(3)` first, then falls back to
/// `/dev/urandom`. 16 bytes is well below `getentropy(3)`'s 256-byte limit.
pub(crate) fn read_iv_session_salt() -> io::Result<[u8; 16]> {
    let mut buf = [0u8; 16];
    if os_random(&mut buf).is_ok() {
        return Ok(buf);
    }
    std::fs::File::open("/dev/urandom").and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut buf)
    })?;
    Ok(buf)
}

/// Hashed 8-byte IV prefix — last-resort fallback for the panic hook.
///
/// Reached only when both `getrandom(2)`/`getentropy(3)` and `/dev/urandom`
/// fail (typically: extremely constrained embedded environments).  Mixes
/// multiple entropy sources through a `RandomState`-keyed SipHash-2-4
/// hasher:
///
/// * `RandomState::new()` uses OS entropy for its key on most platforms; even
///   where it falls back to a deterministic startup seed, the time deltas and
///   counter below keep successive calls distinct.
/// * Monotonic elapsed time since the first call (high-resolution).
/// * Wall-clock nanos (independent entropy axis).
/// * PID + TID + monotonic call counter.
///
/// **Stack-address entropy deliberately omitted**: it contributes zero bits on
/// no-ASLR platforms (QNX, VxWorks, some RTOS), which are exactly the
/// deployments that reach this fallback.
///
/// **Not cryptographically secure.**  Use only when the above sources are
/// unavailable.
#[cfg_attr(
    not(any(test, all(feature = "panic-handler", feature = "secure-udp"))),
    allow(dead_code)
)]
pub(crate) fn fallback_iv_random() -> [u8; 8] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hash, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    static SEQ: AtomicU64 = AtomicU64::new(0);
    static START: OnceLock<Instant> = OnceLock::new();

    let mut hasher = RandomState::new().build_hasher();
    std::process::id().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    SEQ.fetch_add(1, Ordering::Relaxed).hash(&mut hasher);
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_nanos()
        .hash(&mut hasher);
    if let Ok(d) = SystemTime::now().duration_since(UNIX_EPOCH) {
        d.as_nanos().hash(&mut hasher);
    }

    hasher.finish().to_le_bytes()
}

/// 16-byte session-salt analogue of [`fallback_iv_random`] — last-resort
/// fallback when both `getrandom(2)`/`getentropy(3)` and `/dev/urandom` are
/// unavailable. Two independent SipHash passes (distinct `SEQ` ticks per
/// pass) are concatenated to produce 128 bits.
///
/// **Entropy density is degraded** vs. an OS read: the underlying
/// `RandomState` key is the dominant entropy source, plus the time / PID /
/// TID mixers. Use only when no OS entropy source is reachable.
///
/// Currently consumed only by the in-module collision test; retained as a
/// parity API for a future panic-hook `accept_degraded_entropy` variant
/// that needs a 16-byte salt (mirroring the existing 8-byte
/// `install_panic_handler_secure_udp_accept_degraded_entropy`).
#[allow(dead_code)]
pub(crate) fn fallback_iv_session_salt() -> [u8; 16] {
    let lo = fallback_iv_random();
    let hi = fallback_iv_random();
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&lo);
    out[8..].copy_from_slice(&hi);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    #[test]
    fn ipv6_connect_does_not_fail_with_einval() {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9876, 0, 0));
        let key = Key::from_bytes([0x42; 32]);
        let result = SecureUdpTransport::connect(addr, key);
        assert!(result.is_ok(), "IPv6 connect failed: {:?}", result.err());
    }

    #[test]
    fn fallback_iv_random_unique_across_calls() {
        use std::collections::HashSet;
        let outputs: HashSet<[u8; 8]> = (0..1000).map(|_| fallback_iv_random()).collect();
        assert_eq!(
            outputs.len(),
            1000,
            "collisions detected in fallback_iv_random"
        );
    }

    #[test]
    fn os_random_yields_distinct_outputs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        match (os_random(&mut a), os_random(&mut b)) {
            (Ok(()), Ok(())) => assert_ne!(a, b, "os_random returned identical outputs"),
            (Err(e), _) | (_, Err(e)) if e.kind() == io::ErrorKind::Unsupported => {}
            (Err(e), _) | (_, Err(e)) => panic!("os_random failed: {e}"),
        }
    }

    #[test]
    fn read_iv_random_succeeds() {
        assert!(
            read_iv_random().is_ok(),
            "read_iv_random failed on this platform"
        );
    }

    #[test]
    fn fallback_iv_session_salt_unique_across_calls() {
        use std::collections::HashSet;
        let outputs: HashSet<[u8; 16]> = (0..1000).map(|_| fallback_iv_session_salt()).collect();
        assert_eq!(
            outputs.len(),
            1000,
            "collisions detected in fallback_iv_session_salt"
        );
    }

    #[test]
    fn read_iv_session_salt_succeeds() {
        assert!(
            read_iv_session_salt().is_ok(),
            "read_iv_session_salt failed on this platform"
        );
    }

    /// Once `connect()` has returned, any further call to the entropy
    /// chain on the steady-state beat path is a regression. This test
    /// guards by setting a poison flag that an entropy-mock in
    /// `BeatTransport::send` would trip; since the new scheme does NOT
    /// call any entropy helper on `send`, we simply verify that
    /// `send_local_loopback_after_wrap` does not panic and rotates state
    /// without calling `read_iv_session_salt`.  The latter is observable
    /// indirectly: the prefix changes, prefix_index increments, and
    /// `iv_counter` resets to 1.
    #[test]
    fn counter_wrap_rotates_prefix_without_entropy_read() {
        // Use a loopback UDP socket as a black-hole receiver. We don't
        // actually need anyone to receive; we just need send() to succeed.
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9876, 0, 0));
        let key = Key::from_bytes([0u8; 32]);
        let mut tx = SecureUdpTransport::connect(addr, key).expect("connect");

        let prefix_before = tx.iv_prefix_for_test();
        let salt_before = tx.iv_session_salt;
        tx.set_iv_counter_for_test(u32::MAX);

        // Send a stub buffer — the destination is a closed ephemeral
        // address so the send may fail at the network layer, but the
        // wrap-rotation logic runs before the syscall.
        let buf = [0u8; 32];
        let _ = <SecureUdpTransport as BeatTransport>::send(&mut tx, &buf);

        // Salt must NOT have changed — no entropy refresh.
        assert_eq!(
            tx.iv_session_salt, salt_before,
            "salt rotated unexpectedly on wrap"
        );
        // Prefix index advanced; prefix differs from the prior session-0.
        assert_eq!(
            tx.iv_prefix_index_for_test(),
            1,
            "prefix_index should advance to 1 on wrap"
        );
        assert_ne!(
            tx.iv_prefix_for_test(),
            prefix_before,
            "rotated prefix should differ from prior prefix"
        );
        assert_eq!(tx.iv_counter, 1, "counter should reset to 1 on wrap");
    }

    /// The wrap path must NOT call the OS entropy chain.  We assert this
    /// structurally: after `connect()`, freezing the salt and forcing a
    /// wrap must leave the salt unchanged.  Any future regression that
    /// re-introduces an entropy call on `send()` will flip the salt and
    /// fail this assertion.
    #[test]
    fn wrap_path_does_not_call_read_iv_session_salt() {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9876, 0, 0));
        let key = Key::from_bytes([0u8; 32]);
        let mut tx = SecureUdpTransport::connect(addr, key).expect("connect");

        let salt_snapshot = tx.iv_session_salt;
        // Run several wrap rotations back-to-back.
        for expected_index in 1..=4 {
            tx.set_iv_counter_for_test(u32::MAX);
            let buf = [0u8; 32];
            let _ = <SecureUdpTransport as BeatTransport>::send(&mut tx, &buf);
            assert_eq!(
                tx.iv_session_salt, salt_snapshot,
                "salt mutated during wrap rotation (regression)"
            );
            assert_eq!(tx.iv_prefix_index_for_test(), expected_index);
        }
    }

    /// `reconnect()` IS allowed to re-read entropy — it's the documented
    /// manual escape hatch for fork-safety and salt refresh.
    #[test]
    fn manual_reconnect_does_re_read_entropy() {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9876, 0, 0));
        let key = Key::from_bytes([0u8; 32]);
        let mut tx = SecureUdpTransport::connect(addr, key).expect("connect");

        let salt_before = tx.iv_session_salt;
        let prefix_before = tx.iv_prefix_for_test();
        tx.iv_prefix_index = 42;
        tx.iv_counter = 12345;

        <SecureUdpTransport as BeatTransport>::reconnect(&mut tx).expect("reconnect");

        // Counter / index reset.
        assert_eq!(tx.iv_prefix_index_for_test(), 0);
        assert_eq!(tx.iv_counter, 0);
        // Salt should be fresh (cryptographically near-impossible to collide
        // with the previous read at 16 bytes).
        assert_ne!(
            tx.iv_session_salt, salt_before,
            "reconnect should refresh the session salt"
        );
        // Prefix-0 of the new salt is overwhelmingly likely to differ from
        // prefix-0 of the old salt.
        assert_ne!(tx.iv_prefix_for_test(), prefix_before);
    }
}
