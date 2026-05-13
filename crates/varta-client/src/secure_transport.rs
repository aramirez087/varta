//! Secure UDP transport backed by ChaCha20-Poly1305 AEAD.
//!
//! [`SecureUdpTransport`] wraps a UDP socket with authenticated encryption
//! using `varta_vlp::crypto`. Every 32-byte VLP frame is encrypted and
//! authenticated before transmission; the 60-byte wire format includes a
//! per-connection random IV prefix, a monotonic message counter, the
//! encrypted frame, and a Poly1305 tag.
//!
//! # Security
//!
//! The IV random prefix is read from `/dev/urandom` at `connect()` time
//! (once, not on the beat path).  This gives a cryptographically random
//! 8-byte (64-bit) IV prefix with a birthday bound of ~2^32 agents
//! sharing the same key — effectively unbounded for practical deployments.
//!
//! * **Nonce uniqueness guarantee**: Within a single connection the
//!   monotonic 4-byte counter ensures unique nonces. Across connections the
//!   8-byte `iv_random` prefix (fresh `/dev/urandom` read each `connect`
//!   or `reconnect`) provides uniqueness.
//! * **Counter capacity**: The 32-bit counter allows ~4 billion beats per
//!   connection before wraparound (at 1000 Hz this is ~50 days; at 1 Hz
//!   this is ~136 years). On wraparound `send()` automatically reconnects,
//!   deriving a fresh IV prefix and resetting the counter — observer-side
//!   replay rejection is avoided because the new IV prefix creates a
//!   distinct session.
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
    iv_random: [u8; 8],
    is_master_mode: bool,
}

impl SecureUdpTransport {
    /// Create a non-blocking secure UDP socket connected to `addr`.
    ///
    /// The socket is bound to an ephemeral source port. The IV random prefix
    /// is read from `/dev/urandom` at connect time (no syscall on the beat path).
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the socket cannot be created, connected,
    /// or switched to non-blocking mode.
    pub fn connect(addr: SocketAddr, key: Key) -> io::Result<Self> {
        let sock = bind_ephemeral(&addr)?;
        sock.connect(addr)?;
        sock.set_nonblocking(true)?;

        let iv_random = read_iv_random()?;

        Ok(SecureUdpTransport {
            sock,
            addr,
            key,
            iv_counter: 0,
            iv_random,
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

        // Full 8 bytes of OS entropy — no PID embedded in iv_random.
        // The PID is sent as a plaintext AAD field in the 64-byte wire frame.
        let iv_random = read_iv_random()?;

        Ok(SecureUdpTransport {
            sock,
            addr,
            key: agent_key,
            iv_counter: 0,
            iv_random,
            is_master_mode: true,
        })
    }
}

impl BeatTransport for SecureUdpTransport {
    fn send(&mut self, buf: &[u8; 32]) -> io::Result<usize> {
        self.iv_counter = match self.iv_counter.checked_add(1) {
            Some(n) => n,
            None => {
                // Counter exhausted — derive a fresh session.
                // reconnect() opens a new ephemeral socket, reads a fresh
                // iv_random from /dev/urandom, and resets iv_counter to 0.
                // We then set iv_counter to 1, giving this beat a unique
                // nonce in a brand-new session from the observer's
                // perspective.
                self.reconnect()?;
                1
            }
        };

        // Build 12-byte nonce: iv_random (8) || iv_counter (4) LE
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[..8].copy_from_slice(&self.iv_random);
        nonce[8..12].copy_from_slice(&self.iv_counter.to_le_bytes());

        if self.is_master_mode {
            // Master-key wire format (64 bytes):
            // [agent_pid: 4] [iv_random: 8] [iv_counter: 4] [ciphertext: 32] [tag: 16]
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
            frame[4..12].copy_from_slice(&self.iv_random);
            frame[12..16].copy_from_slice(&self.iv_counter.to_le_bytes());
            frame[16..48].copy_from_slice(&ciphertext);
            frame[48..64].copy_from_slice(&tag);

            self.sock.send(&frame)
        } else {
            // Shared-key wire format (60 bytes):
            // [iv_random: 8] [iv_counter: 4] [ciphertext: 32] [tag: 16]
            let (ciphertext, tag) = crypto::seal(self.key.as_bytes(), &nonce, b"", buf);

            let mut frame = [0u8; SECURE_FRAME_LEN];
            frame[..8].copy_from_slice(&self.iv_random);
            frame[8..12].copy_from_slice(&self.iv_counter.to_le_bytes());
            frame[12..44].copy_from_slice(&ciphertext);
            frame[44..60].copy_from_slice(&tag);

            self.sock.send(&frame)
        }
    }

    fn reconnect(&mut self) -> io::Result<()> {
        let sock = bind_ephemeral(&self.addr)?;
        sock.connect(self.addr)?;
        sock.set_nonblocking(true)?;
        self.sock = sock;

        // Derive a fresh iv_random from /dev/urandom.  The observer tracks
        // per-sender state by (SocketAddr, iv_random), so a changed prefix
        // makes this a new session from the observer's perspective.  Resetting
        // iv_counter to 0 is safe — the next send() increments it to 1, and
        // no prior session with this iv_random prefix exists in the observer's
        // state (different iv_random = different session).
        self.iv_random = read_iv_random()?;
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
}
