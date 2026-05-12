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

use crate::transport::{bind_ephemeral, BeatTransport};

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
        })
    }

    /// Create a secure UDP socket using a master key with per-agent key
    /// derivation.
    ///
    /// The agent key is derived from the master key and the calling
    /// process's PID using [`varta_vlp::crypto::kdf::derive_agent_key`].
    /// The PID is also embedded in `iv_random[0..4]` so the observer can
    /// derive the same agent key before decrypting the frame.
    ///
    /// `iv_random[4..8]` is filled with 4 random bytes from `/dev/urandom`
    /// to ensure nonce uniqueness across connections.
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

        // Encode PID in iv_random[0..4] so the observer can derive the
        // agent key before decryption. Fill iv_random[4..8] with random
        // bytes for nonce uniqueness across reconnects.
        let mut iv_random = [0u8; 8];
        iv_random[..4].copy_from_slice(&(peer_pid as u32).to_le_bytes());
        iv_random[4..].copy_from_slice(&read_iv_random_prefix_4()?);

        Ok(SecureUdpTransport {
            sock,
            addr,
            key: agent_key,
            iv_counter: 0,
            iv_random,
        })
    }
}

impl BeatTransport for SecureUdpTransport {
    fn send(&mut self, buf: &[u8; 32]) -> io::Result<usize> {
        self.iv_counter = match self.iv_counter.checked_add(1) {
            Some(n) => n,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "iv_counter exhausted; reconnect required to derive fresh iv_random",
                ));
            }
        };

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

/// Read 4 cryptographically-random bytes from `/dev/urandom`.
///
/// Used for the random component of the IV prefix in master-key mode,
/// alongside the 4-byte PID prefix.
fn read_iv_random_prefix_4() -> io::Result<[u8; 4]> {
    let mut buf = [0u8; 4];
    std::fs::File::open("/dev/urandom").and_then(|mut f| {
        use std::io::Read;
        f.read_exact(&mut buf)
    })?;
    Ok(buf)
}
///
/// Produces a deterministic 8-byte prefix.  Used only when `/dev/urandom`
/// is unavailable (e.g. inside a panic handler, where file I/O is not safe).
#[allow(dead_code)]
pub(crate) fn lcg_iv_random() -> [u8; 8] {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let raw = (std::process::id() as u64)
        .wrapping_mul(6364136223846793005)
        .wrapping_add(SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    raw.to_le_bytes()
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
}
