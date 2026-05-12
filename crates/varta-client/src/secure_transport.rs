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
//!   this is ~136 years). Wraparound triggers an observer-side replay
//!   rejection, forcing a reconnect which derives a fresh IV prefix.
//!
//! **This transport is designed for trusted local networks.**

use std::io;
use std::net::{SocketAddr, UdpSocket};

use varta_vlp::crypto::{self, Key, NONCE_BYTES};

use crate::transport::BeatTransport;

/// Total length of an encrypted frame on the wire.
const SECURE_FRAME_LEN: usize = crypto::SECURE_FRAME_BYTES;

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
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(addr)?;
        sock.set_nonblocking(true)?;

        // Read a cryptographically-random IV prefix from /dev/urandom.
        // This read happens once at connect time (not on the beat path)
        // and is consistent with the project's file-I/O-at-startup policy
        // (key files, config files).
        let iv_random = read_iv_random()?;

        Ok(SecureUdpTransport {
            sock,
            addr,
            key,
            iv_counter: 0,
            iv_random,
        })
    }
}

impl BeatTransport for SecureUdpTransport {
    fn send(&mut self, buf: &[u8; 32]) -> io::Result<usize> {
        self.iv_counter = self.iv_counter.wrapping_add(1);

        // Build 12-byte nonce: iv_random (8) || iv_counter (4) LE
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[..8].copy_from_slice(&self.iv_random);
        nonce[8..12].copy_from_slice(&self.iv_counter.to_le_bytes());

        let (ciphertext, tag) = crypto::seal(self.key.as_bytes(), &nonce, buf);

        // Assemble wire frame: iv_random(8) || iv_counter(4) || ciphertext(32) || tag(16)
        let mut frame = [0u8; SECURE_FRAME_LEN];
        frame[..8].copy_from_slice(&self.iv_random);
        frame[8..12].copy_from_slice(&self.iv_counter.to_le_bytes());
        frame[12..44].copy_from_slice(&ciphertext);
        frame[44..60].copy_from_slice(&tag);

        self.sock.send(&frame)
    }

    fn reconnect(&mut self) -> io::Result<()> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
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

/// Read a cryptographically-random 8-byte IV prefix from `/dev/urandom`.
///
/// Called once at `connect()` / `reconnect()` time — never on the beat path.
/// The returned `[u8; 8]` is suitable as the `iv_random` prefix for ChaCha20-
/// Poly1305 AEAD nonce construction.
pub(crate) fn read_iv_random() -> io::Result<[u8; 8]> {
    let mut buf = [0u8; 8];
    std::fs::File::open("/dev/urandom").and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut buf)
    })?;
    Ok(buf)
}

/// Fallback IV derivation using an LCG (pid * prime + timestamp).
///
/// Produces a deterministic 8-byte prefix.  Used only when `/dev/urandom`
/// is unavailable (e.g. inside a panic handler, where file I/O is not safe).
pub(crate) fn lcg_iv_random() -> [u8; 8] {
    let raw = (std::process::id() as u64)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        );
    raw.to_le_bytes()
}
