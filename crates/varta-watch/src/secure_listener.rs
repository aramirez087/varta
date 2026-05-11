//! Secure UDP listener backed by ChaCha20-Poly1305 AEAD.
//!
//! [`SecureUdpListener`] receives 60-byte encrypted frames from remote agents,
//! decrypts and verifies them using the pre-shared key(s), and returns the
//! decrypted 32-byte VLP frame via the standard [`BeatListener`] trait.
//!
//! Replay protection is enforced at two layers:
//! 1. The listener rejects frames where the IV counter does not strictly
//!    increase for a given (sender, iv_random) pair.
//! 2. The observer's [`Tracker`] enforces per-pid nonce monotonicity on
//!    the decrypted frame.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use varta_vlp::crypto::{self, Key, NONCE_BYTES, TAG_BYTES};

use crate::listener::BeatListener;
use crate::peer_cred::RecvResult;

/// Total wire size of a secure VLP frame.
const SECURE_FRAME_LEN: usize = crypto::SECURE_FRAME_BYTES;

/// Maximum number of unique senders tracked simultaneously. Prevents
/// unbounded memory growth from short-lived agents (cron jobs, CI runners).
const MAX_SENDER_STATES: usize = 1024;

/// How long a sender's replay state is retained after its last seen frame.
const EVICTION_TTL: Duration = Duration::from_secs(600); // 10 minutes

/// How often the stale-sender sweep runs.
const EVICTION_INTERVAL: Duration = Duration::from_secs(60);

/// Per-sender replay guard state.
#[derive(Clone, Debug)]
struct SenderState {
    iv_random: [u8; 4],
    last_counter: u64,
    last_seen: Instant,
}

/// UDP listener with AEAD decryption and replay protection.
///
/// Created via [`SecureUdpListener::bind`] and used with
/// [`Observer::from_listener`] or [`Observer::add_listener`].
///
/// Supports key rotation: `keys[0]` is the primary key, and `keys[1..]` are
/// accepted keys for incoming frames during rotation windows. Decryption is
/// attempted with each key in order until one succeeds.
pub struct SecureUdpListener {
    sock: UdpSocket,
    keys: Vec<Key>,
    sender_state: HashMap<SocketAddr, SenderState>,
    next_eviction_check: Instant,
    decrypt_failures: u64,
    truncated_count: u64,
}

impl SecureUdpListener {
    /// Bind a non-blocking UDP socket on `addr` and prepare AEAD decryption
    /// with the given key(s).
    ///
    /// `keys` must be non-empty. The first key is the primary; additional keys
    /// are accepted for incoming frames (zero-downtime rotation).
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the socket cannot be bound or switched to
    /// non-blocking mode.
    pub fn bind(addr: SocketAddr, keys: Vec<Key>) -> io::Result<Self> {
        if keys.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SecureUdpListener requires at least one key",
            ));
        }
        let sock = UdpSocket::bind(addr)?;
        sock.set_nonblocking(true)?;
        Ok(SecureUdpListener {
            sock,
            keys,
            sender_state: HashMap::with_capacity(64),
            next_eviction_check: Instant::now() + EVICTION_INTERVAL,
            decrypt_failures: 0,
            truncated_count: 0,
        })
    }

    /// Remove senders that haven't been seen in [`EVICTION_TTL`].
    /// Called periodically from [`recv`] to prevent unbounded growth from
    /// short-lived agents (cron jobs, CI runners).
    fn evict_stale_senders(&mut self) {
        let cutoff = Instant::now() - EVICTION_TTL;
        self.sender_state
            .retain(|_, state| state.last_seen > cutoff);
    }

    /// Check replay: returns `true` if the (sender, iv_random, counter)
    /// combination is valid (counter strictly increases, or new iv_random).
    ///
    /// Note: `counter > state.last_counter` would become false after u64
    /// wraparound, but at 1 beat/nanosecond this requires ~585 million
    /// years — not a practical concern.
    fn check_replay(&mut self, sender: SocketAddr, iv_random: [u8; 4], counter: u64) -> bool {
        match self.sender_state.get(&sender) {
            Some(state) => {
                if state.iv_random == iv_random {
                    // Same IV prefix: counter must strictly increase
                    counter > state.last_counter
                } else {
                    // Different IV prefix: new session, always accept
                    true
                }
            }
            None => true, // New sender, always accept
        }
    }
}

impl BeatListener for SecureUdpListener {
    fn recv(&mut self) -> RecvResult {
        let mut buf = [0u8; SECURE_FRAME_LEN];
        loop {
            // Periodic eviction sweep for stale senders
            let now = Instant::now();
            if now >= self.next_eviction_check {
                self.evict_stale_senders();
                self.next_eviction_check = now + EVICTION_INTERVAL;
            }

            let (nread, sender) = match self.sock.recv_from(&mut buf) {
                Ok((n, addr)) => (n, addr),
                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                        return RecvResult::WouldBlock;
                    }
                    io::ErrorKind::Interrupted => continue,
                    _ => return RecvResult::IoError(e),
                },
            };

            if nread != SECURE_FRAME_LEN {
                self.truncated_count = self.truncated_count.wrapping_add(1);
                continue;
            }

            // Parse wire format: iv_random(4) || iv_counter(8) || ciphertext(32) || tag(16)
            let iv_random: [u8; 4] = buf[..4].try_into().unwrap();
            let iv_counter = u64::from_le_bytes(buf[4..12].try_into().unwrap());

            // Replay check
            if !self.check_replay(sender, iv_random, iv_counter) {
                self.decrypt_failures = self.decrypt_failures.wrapping_add(1);
                continue;
            }

            // Build 12-byte nonce
            let mut nonce = [0u8; NONCE_BYTES];
            nonce[..4].copy_from_slice(&iv_random);
            nonce[4..12].copy_from_slice(&iv_counter.to_le_bytes());

            let ciphertext: [u8; 32] = buf[12..44].try_into().unwrap();
            let tag: [u8; TAG_BYTES] = buf[44..60].try_into().unwrap();

            // Try each key in order
            for key in &self.keys {
                match crypto::open(key.as_bytes(), &nonce, &ciphertext, &tag) {
                    Ok(plaintext) => {
                        // Update replay state (with capacity guard)
                        if self.sender_state.len() >= MAX_SENDER_STATES {
                            // Map is full — try one more sweep before dropping
                            self.evict_stale_senders();
                        }
                        if self.sender_state.len() < MAX_SENDER_STATES {
                            self.sender_state.insert(
                                sender,
                                SenderState {
                                    iv_random,
                                    last_counter: iv_counter,
                                    last_seen: Instant::now(),
                                },
                            );
                        }
                        // If still full, silently drop the beat (extreme edge
                        // case — 1024+ unique concurrently-beating agents).

                        return RecvResult::Authenticated {
                            peer_pid: 0,
                            data: plaintext,
                        };
                    }
                    Err(_) => continue, // try next key
                }
            }

            // No key matched — authentication failure
            self.decrypt_failures = self.decrypt_failures.wrapping_add(1);
        }
    }

    fn drain_decrypt_failures(&mut self) -> u64 {
        let n = self.decrypt_failures;
        self.decrypt_failures = 0;
        n
    }

    fn drain_truncated(&mut self) -> u64 {
        let n = self.truncated_count;
        self.truncated_count = 0;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Key {
        Key::from_bytes([0xabu8; 32])
    }

    #[test]
    fn bind_requires_at_least_one_key() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = SecureUdpListener::bind(addr, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn check_replay_new_sender_accepted() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let mut listener =
            SecureUdpListener::bind("127.0.0.1:0".parse().unwrap(), vec![test_key()])
                .expect("bind should succeed");

        assert!(listener.check_replay(addr, [0x01, 0x02, 0x03, 0x04], 1));
    }

    #[test]
    fn check_replay_increasing_counter_accepted() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let mut listener =
            SecureUdpListener::bind("127.0.0.1:0".parse().unwrap(), vec![test_key()])
                .expect("bind should succeed");

        let iv = [0x01, 0x02, 0x03, 0x04];
        assert!(listener.check_replay(addr, iv, 1));
        listener.sender_state.insert(
            addr,
            SenderState {
                iv_random: iv,
                last_counter: 1,
                last_seen: Instant::now(),
            },
        );
        assert!(listener.check_replay(addr, iv, 2));
    }

    #[test]
    fn check_replay_same_counter_rejected() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let mut listener =
            SecureUdpListener::bind("127.0.0.1:0".parse().unwrap(), vec![test_key()])
                .expect("bind should succeed");

        let iv = [0x01, 0x02, 0x03, 0x04];
        listener.sender_state.insert(
            addr,
            SenderState {
                iv_random: iv,
                last_counter: 5,
                last_seen: Instant::now(),
            },
        );
        assert!(!listener.check_replay(addr, iv, 5)); // same counter = replay
        assert!(!listener.check_replay(addr, iv, 3)); // lower counter = replay
    }

    #[test]
    fn check_replay_new_iv_random_accepted() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let mut listener =
            SecureUdpListener::bind("127.0.0.1:0".parse().unwrap(), vec![test_key()])
                .expect("bind should succeed");

        let iv1 = [0x01, 0x02, 0x03, 0x04];
        let iv2 = [0x05, 0x06, 0x07, 0x08];
        listener.sender_state.insert(
            addr,
            SenderState {
                iv_random: iv1,
                last_counter: 100,
                last_seen: Instant::now(),
            },
        );
        assert!(listener.check_replay(addr, iv2, 1));
    }
}
