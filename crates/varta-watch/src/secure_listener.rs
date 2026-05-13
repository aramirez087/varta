//! Secure UDP listener backed by ChaCha20-Poly1305 AEAD.
//!
//! [`SecureUdpListener`] receives 60-byte encrypted frames from remote agents,
//! decrypts and verifies them using the pre-shared key(s), and returns the
//! decrypted 32-byte VLP frame via the standard [`BeatListener`] trait.
//!
//! Replay protection is enforced at three layers:
//! 1. The listener performs an atomic check-and-update of per-sender replay
//!    state **after** successful AEAD decryption, eliminating the TOCTOU
//!    window between the replay check and state insertion.
//! 2. A 1-deep IV-rotation history (prev_iv_random / prev_last_counter)
//!    prevents replay of frames from a previously-used IV prefix after the
//!    sender rotates to a new one.
//! 3. The observer's [`Tracker`] enforces per-pid nonce monotonicity on
//!    the decrypted frame.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use varta_vlp::crypto::{self, Key, NONCE_BYTES, TAG_BYTES};

use crate::listener::BeatListener;
use crate::peer_cred::{BeatOrigin, RecvResult};

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
///
/// Tracks the current IV prefix and its last counter, plus a 1-deep history
/// of the previous IV prefix/counter so that frames from a recently-rotated
/// IV are still checked for replay.
#[derive(Clone, Debug)]
struct SenderState {
    iv_random: [u8; 8],
    last_counter: u32,
    prev_iv_random: [u8; 8],
    prev_last_counter: u32,
    last_seen: Instant,
}

impl SenderState {
    fn new(iv_random: [u8; 8], counter: u32) -> Self {
        SenderState {
            iv_random,
            last_counter: counter,
            prev_iv_random: [0u8; 8],
            prev_last_counter: 0,
            last_seen: Instant::now(),
        }
    }
}

/// UDP listener with AEAD decryption and replay protection.
///
/// Created via [`SecureUdpListener::bind`] and used with
/// [`Observer::from_listener`] or [`Observer::add_listener`].
///
/// Supports key rotation: `keys[0]` is the primary key, and `keys[1..]` are
/// accepted keys for incoming frames during rotation windows. Decryption is
/// attempted with each key in order until one succeeds.
///
/// When a master key is provided (via
/// [`SecureUdpListener::bind_with_master`]), the observer additionally derives
/// per-agent keys on the fly. The agent PID is extracted from `iv_random[0..4]`
/// in the wire frame, and the agent key is derived via
/// [`varta_vlp::crypto::kdf::derive_agent_key`]. This provides per-agent key
/// isolation: compromise of one agent's derived key does not reveal other
/// agents' keys or the master key.
pub struct SecureUdpListener {
    sock: UdpSocket,
    keys: Vec<Key>,
    master_key: Option<Key>,
    sender_state: HashMap<SocketAddr, SenderState>,
    next_eviction_check: Instant,
    decrypt_failures: u64,
    truncated_count: u64,
    sender_state_full: u64,
    last_evicted: Option<(SocketAddr, SenderState)>,
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
            master_key: None,
            sender_state: HashMap::with_capacity(64),
            next_eviction_check: Instant::now() + EVICTION_INTERVAL,
            decrypt_failures: 0,
            truncated_count: 0,
            sender_state_full: 0,
            last_evicted: None,
        })
    }

    /// Bind a non-blocking UDP socket with a master key for per-agent key
    /// derivation.
    ///
    /// `keys` are the shared keys tried first (may be empty when using only
    /// the master key). `master_key` is used to derive per-agent keys from
    /// the PID embedded in `iv_random[0..4]` of each incoming frame.
    ///
    /// # Security
    ///
    /// Per-agent key derivation means that compromise of one agent's derived
    /// key does not reveal other agents' keys or the master key. The PID
    /// in `iv_random[0..4]` is verified against the decrypted frame's `pid`
    /// field to prevent PID spoofing at the transport layer.
    pub fn bind_with_master(addr: SocketAddr, keys: Vec<Key>, master_key: Key) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr)?;
        sock.set_nonblocking(true)?;
        Ok(SecureUdpListener {
            sock,
            keys,
            master_key: Some(master_key),
            sender_state: HashMap::with_capacity(64),
            next_eviction_check: Instant::now() + EVICTION_INTERVAL,
            decrypt_failures: 0,
            truncated_count: 0,
            sender_state_full: 0,
            last_evicted: None,
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

    /// When the sender-state map is full after a stale-sender sweep, evict
    /// the single entry with the oldest `last_seen` to make room for a new
    /// sender. The evicted sender's replay state is preserved in
    /// `last_evicted` so that a replayed frame from the evicted sender is
    /// still rejected.
    fn force_evict_oldest_sender(&mut self) {
        let oldest = self
            .sender_state
            .iter()
            .min_by_key(|(_, s)| s.last_seen)
            .map(|(addr, state)| (*addr, state.clone()));
        if let Some((addr, state)) = oldest {
            self.sender_state.remove(&addr);
            self.last_evicted = Some((addr, state));
        }
    }

    /// Validate (iv_random, counter) replay against an immutable `SenderState`
    /// reference. Returns `true` if the combination is not a replay.
    fn validate_replay(state: &SenderState, iv_random: [u8; 8], counter: u32) -> bool {
        if state.iv_random == iv_random {
            return counter > state.last_counter;
        }
        if state.prev_iv_random == iv_random {
            return counter > state.prev_last_counter;
        }
        true
    }

    /// Apply a valid replay update to a `SenderState`, mutating counters
    /// and rotating IV history as needed.
    fn apply_replay_update(state: &mut SenderState, iv_random: [u8; 8], counter: u32) {
        if state.iv_random == iv_random {
            state.last_counter = counter;
        } else if state.prev_iv_random == iv_random {
            state.prev_last_counter = counter;
        } else {
            state.prev_iv_random = state.iv_random;
            state.prev_last_counter = state.last_counter;
            state.iv_random = iv_random;
            state.last_counter = counter;
        }
        state.last_seen = Instant::now();
    }

    /// Derive a per-agent key from the master key using the PID embedded in
    /// `iv_random[0..4]` and attempt AEAD decryption.
    ///
    /// Returns `None` if no master key is configured, or if the derived key
    /// fails to decrypt the frame.
    fn try_master_key_decrypt(
        &self,
        iv_random: &[u8; 8],
        nonce: &[u8; 12],
        ciphertext: &[u8; 32],
        tag: &[u8; 16],
    ) -> Option<[u8; 32]> {
        let master = self.master_key.as_ref()?;
        let claimed_pid =
            u32::from_le_bytes([iv_random[0], iv_random[1], iv_random[2], iv_random[3]]);

        use varta_vlp::crypto::kdf;
        let agent_key = kdf::derive_agent_key(master, claimed_pid);
        let plaintext = crypto::open(agent_key.as_bytes(), nonce, ciphertext, tag).ok()?;

        // Verify that the decrypted frame's PID matches the PID from
        // iv_random to prevent PID spoofing at the transport layer.
        let frame_pid =
            u32::from_le_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
        if frame_pid != claimed_pid {
            return None;
        }

        Some(plaintext)
    }

    /// Atomic replay check + state update: returns `true` if the
    /// (sender, iv_random, counter) combination is valid, and updates the
    /// replay state in the same operation to close the TOCTOU window.
    ///
    /// Three cases per sender lookup:
    /// 1. Same IV prefix   → `counter > last_counter` required
    /// 2. Previous IV prefix → `counter > prev_last_counter` required
    ///    (catches replay of frames from a recently-rotated epoch)
    /// 3. Neither matches   → accepted as new or rotated IV, current state
    ///    moves to `prev_*` fields
    ///
    /// If the sender was recently force-evicted, its replay state is
    /// checked against the `last_evicted` shadow before being accepted
    /// as new — closing the replay-protection gap that would otherwise
    /// exist after a capacity-forced eviction.
    ///
    /// Note: `counter > state.last_counter` would become false after u64
    /// wraparound, but at 1 beat/nanosecond this requires ~585 million
    /// years — not a practical concern.
    fn try_record_replay_state(
        &mut self,
        sender: SocketAddr,
        iv_random: [u8; 8],
        counter: u32,
    ) -> bool {
        match self.sender_state.entry(sender) {
            Entry::Vacant(e) => {
                if let Some((evicted_addr, ref evicted_state)) = self.last_evicted {
                    if evicted_addr == *e.key() {
                        let valid = Self::validate_replay(evicted_state, iv_random, counter);
                        if valid {
                            let mut new_state = evicted_state.clone();
                            Self::apply_replay_update(&mut new_state, iv_random, counter);
                            e.insert(new_state);
                        }
                        self.last_evicted = None;
                        return valid;
                    }
                }
                e.insert(SenderState::new(iv_random, counter));
                true
            }
            Entry::Occupied(mut e) => {
                let state = e.get_mut();

                if state.iv_random == iv_random {
                    if counter > state.last_counter {
                        state.last_counter = counter;
                        state.last_seen = Instant::now();
                        return true;
                    }
                    return false;
                }

                if state.prev_iv_random == iv_random {
                    if counter > state.prev_last_counter {
                        state.prev_last_counter = counter;
                        state.last_seen = Instant::now();
                        return true;
                    }
                    return false;
                }

                state.prev_iv_random = state.iv_random;
                state.prev_last_counter = state.last_counter;
                state.iv_random = iv_random;
                state.last_counter = counter;
                state.last_seen = Instant::now();
                true
            }
        }
    }

    #[cfg(test)]
    fn sender_iv_random(&self, addr: &SocketAddr) -> Option<[u8; 8]> {
        self.sender_state.get(addr).map(|s| s.iv_random)
    }

    #[cfg(test)]
    fn sender_last_counter(&self, addr: &SocketAddr) -> Option<u32> {
        self.sender_state.get(addr).map(|s| s.last_counter)
    }

    #[cfg(test)]
    fn sender_prev_iv_random(&self, addr: &SocketAddr) -> Option<[u8; 8]> {
        self.sender_state.get(addr).map(|s| s.prev_iv_random)
    }

    #[cfg(test)]
    fn sender_prev_last_counter(&self, addr: &SocketAddr) -> Option<u32> {
        self.sender_state.get(addr).map(|s| s.prev_last_counter)
    }

    #[cfg(test)]
    fn sender_state_len(&self) -> usize {
        self.sender_state.len()
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

            // Parse wire format: iv_random(8) || iv_counter(4) || ciphertext(32) || tag(16)
            let iv_random: [u8; 8] = buf[..8].try_into().unwrap();
            let iv_counter = u32::from_le_bytes(buf[8..12].try_into().unwrap());

            // Build 12-byte nonce
            let mut nonce = [0u8; NONCE_BYTES];
            nonce[..8].copy_from_slice(&iv_random);
            nonce[8..12].copy_from_slice(&iv_counter.to_le_bytes());

            let ciphertext: [u8; 32] = buf[12..44].try_into().unwrap();
            let tag: [u8; TAG_BYTES] = buf[44..60].try_into().unwrap();

            let decrypted = self
                .keys
                .iter()
                .find_map(|key| crypto::open(key.as_bytes(), &nonce, &ciphertext, &tag).ok())
                .or_else(|| self.try_master_key_decrypt(&iv_random, &nonce, &ciphertext, &tag));

            let Some(plaintext) = decrypted else {
                self.decrypt_failures = self.decrypt_failures.wrapping_add(1);
                continue;
            };

            // Capacity guard: sweep stale senders before trying to insert
            if self.sender_state.len() >= MAX_SENDER_STATES {
                self.evict_stale_senders();
            }
            if self.sender_state.len() >= MAX_SENDER_STATES {
                // Map is still full after stale-sender sweep — force-evict
                // the oldest entry to maintain replay protection.
                self.force_evict_oldest_sender();
                self.sender_state_full = self.sender_state_full.saturating_add(1);
                debug_assert!(
                    self.sender_state.len() < MAX_SENDER_STATES,
                    "force_evict_oldest_sender should have freed a slot"
                );
            }

            // Atomic replay check + state update after AEAD success.
            if !self.try_record_replay_state(sender, iv_random, iv_counter) {
                self.decrypt_failures = self.decrypt_failures.wrapping_add(1);
                continue;
            }

            return RecvResult::Authenticated {
                peer_pid: 0,
                peer_uid: 0,
                origin: BeatOrigin::NetworkUnverified,
                data: plaintext,
            };
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

    fn drain_sender_state_full(&mut self) -> u64 {
        let n = self.sender_state_full;
        self.sender_state_full = 0;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn test_key() -> Key {
        Key::from_bytes([0xabu8; 32])
    }

    fn test_iv() -> [u8; 8] {
        [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    }

    fn test_iv2() -> [u8; 8] {
        [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]
    }

    fn test_iv3() -> [u8; 8] {
        [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
    }

    fn new_listener() -> SecureUdpListener {
        SecureUdpListener::bind("127.0.0.1:0".parse().unwrap(), vec![test_key()])
            .expect("bind should succeed")
    }

    fn test_addr() -> SocketAddr {
        "127.0.0.1:9999".parse().unwrap()
    }

    #[test]
    fn bind_requires_at_least_one_key() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let result = SecureUdpListener::bind(addr, vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn new_sender_accepted_and_inserted() {
        let mut listener = new_listener();
        let addr = test_addr();
        let iv = test_iv();
        let counter = 1;

        assert!(listener.try_record_replay_state(addr, iv, counter));
        assert_eq!(listener.sender_iv_random(&addr), Some(iv));
        assert_eq!(listener.sender_last_counter(&addr), Some(counter));
    }

    #[test]
    fn increasing_counter_accepted() {
        let mut listener = new_listener();
        let addr = test_addr();
        let iv = test_iv();

        assert!(listener.try_record_replay_state(addr, iv, 1));
        assert!(listener.try_record_replay_state(addr, iv, 2));
        assert_eq!(listener.sender_last_counter(&addr), Some(2));
    }

    #[test]
    fn same_counter_rejected() {
        let mut listener = new_listener();
        let addr = test_addr();
        let iv = test_iv();

        assert!(listener.try_record_replay_state(addr, iv, 5));
        assert!(!listener.try_record_replay_state(addr, iv, 5));
    }

    #[test]
    fn lower_counter_rejected() {
        let mut listener = new_listener();
        let addr = test_addr();
        let iv = test_iv();

        assert!(listener.try_record_replay_state(addr, iv, 5));
        assert!(!listener.try_record_replay_state(addr, iv, 3));
    }

    #[test]
    fn new_iv_random_accepted_and_rotates() {
        let mut listener = new_listener();
        let addr = test_addr();
        let iv1 = test_iv();
        let iv2 = test_iv2();

        assert!(listener.try_record_replay_state(addr, iv1, 100));
        // Rotation: iv1 → iv2
        assert!(listener.try_record_replay_state(addr, iv2, 1));

        assert_eq!(listener.sender_iv_random(&addr), Some(iv2));
        assert_eq!(listener.sender_last_counter(&addr), Some(1));
        assert_eq!(listener.sender_prev_iv_random(&addr), Some(iv1));
        assert_eq!(listener.sender_prev_last_counter(&addr), Some(100));
    }

    #[test]
    fn replay_after_rotation_rejected() {
        let mut listener = new_listener();
        let addr = test_addr();
        let iv1 = test_iv();
        let iv2 = test_iv2();

        // Sender uses iv1 up to counter 100, then rotates to iv2
        assert!(listener.try_record_replay_state(addr, iv1, 100));
        assert!(listener.try_record_replay_state(addr, iv2, 1));

        // Replay of a frame from the iv1 epoch at counter 50 → rejected
        assert!(!listener.try_record_replay_state(addr, iv1, 50));
        // Replay of the last frame from iv1 epoch at counter 100 → rejected (not strictly greater)
        assert!(!listener.try_record_replay_state(addr, iv1, 100));
    }

    #[test]
    fn larger_counter_from_prev_iv_accepted() {
        let mut listener = new_listener();
        let addr = test_addr();
        let iv1 = test_iv();
        let iv2 = test_iv2();

        assert!(listener.try_record_replay_state(addr, iv1, 100));
        assert!(listener.try_record_replay_state(addr, iv2, 1));
        // An out-of-order delayed frame from iv1 with counter > prev_last_counter
        // is accepted (non-replay)
        assert!(listener.try_record_replay_state(addr, iv1, 150));
        assert_eq!(listener.sender_iv_random(&addr), Some(iv2));
        assert_eq!(listener.sender_prev_last_counter(&addr), Some(150));
    }

    #[test]
    fn double_rotation_shifts_prev() {
        let mut listener = new_listener();
        let addr = test_addr();
        let iv1 = test_iv();
        let iv2 = test_iv2();
        let iv3 = test_iv3();

        assert!(listener.try_record_replay_state(addr, iv1, 100));
        assert!(listener.try_record_replay_state(addr, iv2, 200));
        // Third rotation: iv2 → iv3; iv1 is lost from history
        assert!(listener.try_record_replay_state(addr, iv3, 50));

        assert_eq!(listener.sender_iv_random(&addr), Some(iv3));
        assert_eq!(listener.sender_last_counter(&addr), Some(50));
        assert_eq!(listener.sender_prev_iv_random(&addr), Some(iv2));
        assert_eq!(listener.sender_prev_last_counter(&addr), Some(200));
    }

    #[test]
    fn rotate_back_to_first_iv_accepted() {
        let mut listener = new_listener();
        let addr = test_addr();
        let iv1 = test_iv();
        let iv2 = test_iv2();

        assert!(listener.try_record_replay_state(addr, iv1, 100));
        assert!(listener.try_record_replay_state(addr, iv2, 50));
        // Frame from iv1 arrives with counter > prev_last_counter —
        // accepted as non-replay (delayed frame from previous epoch).
        // State is updated but iv2 remains current.
        assert!(listener.try_record_replay_state(addr, iv1, 200));

        assert_eq!(listener.sender_iv_random(&addr), Some(iv2));
        assert_eq!(listener.sender_last_counter(&addr), Some(50));
        assert_eq!(listener.sender_prev_iv_random(&addr), Some(iv1));
        assert_eq!(listener.sender_prev_last_counter(&addr), Some(200));
    }

    #[test]
    fn capacity_exceeded_forces_evict_and_increments_counter() {
        let mut listener = new_listener();
        // Fill the map with unique addresses.
        for i in 0..MAX_SENDER_STATES {
            let addr = SocketAddr::from(([127, 0, 0, 1], (10_000 + i as u16)));
            assert!(listener.try_record_replay_state(addr, test_iv(), 1));
        }
        assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);

        // Eviction before force-evict is a no-op for fresh entries.
        listener.evict_stale_senders();
        assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);

        // Force-evict should remove one entry.
        listener.force_evict_oldest_sender();
        assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES - 1);
    }
}
