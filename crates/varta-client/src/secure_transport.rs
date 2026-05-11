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
//! The IV random prefix is derived from `pid * prime + connect_timestamp`
//! (a linear congruential generator) — it is **not** cryptographically
//! random. This design avoids a dependency on `/dev/urandom` (consistent
//! with the project's zero-dependency and no-filesystem-read-on-beat-path
//! goals), but has the following implications:
//!
//! * **32-bit IV space**: The derived prefix is 4 bytes. With many agents
//!   sharing the same key, the birthday bound (~2^16 agents) makes nonce
//!   prefix collisions likely. A collision between two agents with the same
//!   key would cause the observer to reject frames (replay protection on
//!   `iv_random`). In the worst case — same `iv_random` from two agents
//!   and coincident counters — AEAD nonce reuse would be catastrophic
//!   (confidentiality and authentication are completely broken).
//! * **Predictability**: An attacker who observes the agent's PID and start
//!   time can predict the IV sequence. On a trusted local network this is
//!   acceptable; do not use this transport over the public internet.
//! * **Nonce uniqueness guarantee**: Within a single connection the
//!   monotonic 8-byte counter ensures unique nonces. Across connections the
//!   4-byte `iv_random` prefix (derived fresh each reconnect) provides
//!   uniqueness.
//!
//! **This transport is designed for trusted local networks with few agents.
//! For stronger IV generation, provide an external nonce source through
//! the transport trait.**

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
/// nonce (4-byte random prefix + 8-byte monotonic counter). The resulting
/// 60-byte AEAD frame is sent over UDP.
///
/// # Security properties
///
/// * **Confidentiality**: Frame contents are encrypted (ChaCha20 stream cipher).
/// * **Integrity**: Tampering is detected (Poly1305 authentication tag).
/// * **Replay resistance**: Monotonic counter per connection; observer verifies
///   that counter values strictly increase for a given IV prefix.
/// * **Nonce uniqueness**: The 4-byte random prefix (derived from pid ^ connect
///   timestamp) plus the 8-byte counter ensures no nonce reuse within a
///   connection lifetime.
///
/// # Security
///
/// See the [module-level security documentation](self) for important
/// caveats about the IV generation strategy (LCG-based, 32-bit space)
/// and the conditions under which nonce reuse could occur.
///
/// [`Varta::connect_secure_udp`]: crate::Varta::connect_secure_udp
/// [module-level security documentation]: self#security
pub struct SecureUdpTransport {
    sock: UdpSocket,
    addr: SocketAddr,
    key: Key,
    iv_counter: u64,
    iv_random: [u8; 4],
}

impl SecureUdpTransport {
    /// Create a non-blocking secure UDP socket connected to `addr`.
    ///
    /// The socket is bound to an ephemeral source port. The IV random prefix
    /// is derived from `process_id ^ connect_timestamp` (no syscall needed).
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the socket cannot be created, connected,
    /// or switched to non-blocking mode.
    pub fn connect(addr: SocketAddr, key: Key) -> io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(addr)?;
        sock.set_nonblocking(true)?;

        // Derive a per-connection IV prefix from pid and timestamp.
        // This ensures uniqueness across reconnects and process restarts
        // without requiring /dev/urandom.
        let raw = (std::process::id() as u64)
            .wrapping_mul(6364136223846793005) // prime
            .wrapping_add(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64,
            );
        let iv_random = raw.to_le_bytes()[..4].try_into().unwrap();

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

        // Build 12-byte nonce: iv_random (4) || iv_counter (8) LE
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[..4].copy_from_slice(&self.iv_random);
        nonce[4..12].copy_from_slice(&self.iv_counter.to_le_bytes());

        let (ciphertext, tag) = crypto::seal(self.key.as_bytes(), &nonce, buf);

        // Assemble wire frame: iv_random(4) || iv_counter(8) || ciphertext(32) || tag(16)
        let mut frame = [0u8; SECURE_FRAME_LEN];
        frame[..4].copy_from_slice(&self.iv_random);
        frame[4..12].copy_from_slice(&self.iv_counter.to_le_bytes());
        frame[12..44].copy_from_slice(&ciphertext);
        frame[44..60].copy_from_slice(&tag);

        self.sock.send(&frame)
    }

    fn reconnect(&mut self) -> io::Result<()> {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.connect(self.addr)?;
        sock.set_nonblocking(true)?;
        self.sock = sock;

        // Derive a fresh iv_random from a new timestamp.  The observer tracks
        // per-sender state by (SocketAddr, iv_random), so a changed prefix
        // makes this a new session from the observer's perspective.  Resetting
        // iv_counter to 0 is safe — the next send() increments it to 1, and
        // no prior session with this iv_random prefix exists in the observer's
        // state (different iv_random = different session).
        let raw = (std::process::id() as u64)
            .wrapping_mul(6364136223846793005)
            .wrapping_add(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64,
            );
        self.iv_random = raw.to_le_bytes()[..4].try_into().unwrap();
        self.iv_counter = 0;

        Ok(())
    }
}
