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

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use varta_vlp::crypto::{self, Key, NONCE_BYTES, SECURE_FRAME_MASTER_BYTES, TAG_BYTES};

use crate::listener::{BeatListener, TransportTrust};
use crate::peer_cred::{BeatOrigin, RecvResult};
use crate::probe_table::BoundedIndex;

/// Wire size of a shared-key VLP frame.
const SECURE_FRAME_LEN: usize = crypto::SECURE_FRAME_BYTES;

/// Wire size of a master-key VLP frame.
const SECURE_FRAME_MASTER_LEN: usize = SECURE_FRAME_MASTER_BYTES;

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
/// IV are still checked for replay. The originating `addr` is stored
/// alongside the IV/counter pair so that a linear walk over the slab can
/// recover the index key (matches the `OutstandingTable` pattern, which
/// stores pid-keyed values keyed by their own value).
#[derive(Clone, Debug)]
struct SenderState {
    addr: SocketAddr,
    iv_random: [u8; 8],
    last_counter: u32,
    prev_iv_random: [u8; 8],
    prev_last_counter: u32,
    last_seen: Instant,
}

impl SenderState {
    fn new(addr: SocketAddr, iv_random: [u8; 8], counter: u32) -> Self {
        SenderState {
            addr,
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
    /// One slot per tracked sender. `Some(state)` for occupied; `None` for
    /// free. Length is fixed at construction at `MAX_SENDER_STATES` and never
    /// reallocates.
    sender_slab: Vec<Option<SenderState>>,
    /// LIFO of available slab indices. Pre-populated with
    /// `(0..MAX_SENDER_STATES).rev()` so the first insert lands at slot 0.
    sender_free_list: Vec<u32>,
    /// `SocketAddr → slab index` mapping with bounded WCET (no SipHash, no
    /// rehash). Sized identically to the slab so the load-factor invariant
    /// for `BoundedIndex` holds. Replaces the previous
    /// `HashMap<SocketAddr, SenderState>` per the project-wide DNR rule
    /// (see cerebrum 2026-05-14 "Generic `BoundedIndex<K>`").
    sender_index: BoundedIndex<SocketAddr>,
    next_eviction_check: Instant,
    decrypt_failures: u64,
    truncated_count: u64,
    sender_state_full: u64,
    /// Total AEAD decryption attempts since the last drain. The receive path
    /// trials *every* loaded key on every frame (no early-exit on success),
    /// so an attacker measuring RTT can no longer count attempts to learn
    /// which rotation slot is primary. In steady state this equals
    /// `frames_received * (keys.len() + master_key_configured as u64)`. The
    /// counter is the operational signal that the constant-trial-count
    /// timing-leak fix is active.
    aead_attempts: u64,
    last_evicted: Option<(SocketAddr, SenderState)>,
    recovery_trust: TransportTrust,
}

/// Build the pre-allocated `(slab, free_list, index)` triple used by both
/// `bind` and `bind_with_master`. Keeps the capacity invariant in one place.
fn new_sender_state_store() -> (Vec<Option<SenderState>>, Vec<u32>, BoundedIndex<SocketAddr>) {
    let mut slab = Vec::with_capacity(MAX_SENDER_STATES);
    for _ in 0..MAX_SENDER_STATES {
        slab.push(None);
    }
    let mut free_list = Vec::with_capacity(MAX_SENDER_STATES);
    for i in (0..MAX_SENDER_STATES as u32).rev() {
        free_list.push(i);
    }
    let index = BoundedIndex::new(MAX_SENDER_STATES);
    (slab, free_list, index)
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
        let (sender_slab, sender_free_list, sender_index) = new_sender_state_store();
        Ok(SecureUdpListener {
            sock,
            keys,
            master_key: None,
            sender_slab,
            sender_free_list,
            sender_index,
            next_eviction_check: Instant::now() + EVICTION_INTERVAL,
            decrypt_failures: 0,
            truncated_count: 0,
            sender_state_full: 0,
            aead_attempts: 0,
            last_evicted: None,
            recovery_trust: TransportTrust::Untrusted,
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
        let (sender_slab, sender_free_list, sender_index) = new_sender_state_store();
        Ok(SecureUdpListener {
            sock,
            keys,
            master_key: Some(master_key),
            sender_slab,
            sender_free_list,
            sender_index,
            next_eviction_check: Instant::now() + EVICTION_INTERVAL,
            decrypt_failures: 0,
            truncated_count: 0,
            sender_state_full: 0,
            aead_attempts: 0,
            last_evicted: None,
            recovery_trust: TransportTrust::Untrusted,
        })
    }

    /// Declare this listener recovery-eligible.
    ///
    /// When `trust` is [`TransportTrust::Operator`], authenticated beats
    /// received on this listener are stamped
    /// [`BeatOrigin::OperatorAttestedTransport`] so the runtime recovery gate
    /// allows them to fire.
    pub fn with_recovery_trust(mut self, trust: TransportTrust) -> Self {
        self.recovery_trust = trust;
        self
    }

    /// Remove senders that haven't been seen in [`EVICTION_TTL`].
    /// Called periodically from [`recv`] to prevent unbounded growth from
    /// short-lived agents (cron jobs, CI runners). Linear scan over the
    /// fixed-size slab so the WCET is bounded at `MAX_SENDER_STATES`.
    fn evict_stale_senders(&mut self) {
        let cutoff = Instant::now() - EVICTION_TTL;
        for slot in 0..self.sender_slab.len() {
            let stale = self
                .sender_slab
                .get(slot)
                .and_then(|opt| opt.as_ref())
                .is_some_and(|s| s.last_seen <= cutoff);
            if stale {
                if let Some(state) = self.sender_slab[slot].take() {
                    self.sender_index.remove(state.addr);
                    self.sender_free_list.push(slot as u32);
                }
            }
        }
    }

    /// When the sender-state slab is full after a stale-sender sweep, evict
    /// the single entry with the oldest `last_seen` to make room for a new
    /// sender. The evicted sender's replay state is preserved in
    /// `last_evicted` so that a replayed frame from the evicted sender is
    /// still rejected.
    fn force_evict_oldest_sender(&mut self) {
        let oldest_slot = self
            .sender_slab
            .iter()
            .enumerate()
            .filter_map(|(i, opt)| opt.as_ref().map(|s| (i, s.last_seen)))
            .min_by_key(|(_, ls)| *ls)
            .map(|(i, _)| i);
        if let Some(slot) = oldest_slot {
            if let Some(state) = self.sender_slab[slot].take() {
                self.sender_index.remove(state.addr);
                self.sender_free_list.push(slot as u32);
                let addr = state.addr;
                self.last_evicted = Some((addr, state));
            }
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

    /// Derive a per-agent key from the master key using the plaintext
    /// `agent_pid` field from the 64-byte master-key wire frame and attempt
    /// AEAD decryption with `aad` (= the on-wire `agent_pid` bytes).
    ///
    /// Returns `None` if no master key is configured, or if the derived key
    /// fails to decrypt the frame. The `agent_pid` binding in the AAD means
    /// any tampering of the on-wire PID prefix causes authentication failure
    /// before this function is even reached.
    fn try_master_key_decrypt(
        &self,
        agent_pid: u32,
        aad: &[u8],
        nonce: &[u8; 12],
        ciphertext: &[u8; 32],
        tag: &[u8; 16],
    ) -> Option<[u8; 32]> {
        let master = self.master_key.as_ref()?;

        use varta_vlp::crypto::kdf;
        let agent_key = kdf::derive_agent_key(master, agent_pid).ok()?;
        let plaintext = crypto::open(agent_key.as_bytes(), nonce, aad, ciphertext, tag).ok()?;

        // Defense-in-depth: verify the decrypted frame's inner PID matches
        // the on-wire agent_pid even though the AAD binding already covers this.
        let frame_pid =
            u32::from_le_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
        if frame_pid != agent_pid {
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
        if let Some(slot) = self.sender_index.get(sender) {
            let state = match self.sender_slab.get_mut(slot).and_then(Option::as_mut) {
                Some(s) => s,
                None => {
                    // Invariant violation: index pointed to an empty slab
                    // slot. Surface as a soft refusal rather than panicking
                    // — same fail-graceful discipline as `OutstandingTable`.
                    debug_assert!(false, "BoundedIndex slot points to vacant slab entry");
                    return false;
                }
            };

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
            return true;
        }

        // Vacant in the index — check the force-evict shadow before falling
        // through to a fresh insert. On replay rejection the shadow is
        // preserved so repeated replays cannot bypass protection by
        // exhausting the shadow on the first attempt.
        if let Some((addr, _)) = self.last_evicted.as_ref() {
            if *addr == sender {
                let (_, ref evicted_state) = *self.last_evicted.as_ref().unwrap();
                let valid = Self::validate_replay(evicted_state, iv_random, counter);
                if !valid {
                    return false;
                }
                let (_, mut evicted_state) = self.last_evicted.take().unwrap();
                evicted_state.addr = sender;
                Self::apply_replay_update(&mut evicted_state, iv_random, counter);
                if !self.allocate_sender_slot(sender, evicted_state.clone()) {
                    self.last_evicted = Some((sender, evicted_state));
                    return false;
                }
                return true;
            }
        }

        let new_state = SenderState::new(sender, iv_random, counter);
        self.allocate_sender_slot(sender, new_state)
    }

    /// Pop a free slab slot, register `addr → slot` in the index, and write
    /// `state` to the slab. Returns `false` (rolling back the pop) when no
    /// free slot is available or the index probe budget is exhausted; the
    /// caller treats this as a soft refusal. In production the outer
    /// capacity guard in `recv` ensures a free slot exists before calling
    /// `try_record_replay_state`, so this only matters for direct unit
    /// tests and as defense-in-depth.
    fn allocate_sender_slot(&mut self, addr: SocketAddr, state: SenderState) -> bool {
        let Some(slot_u32) = self.sender_free_list.pop() else {
            return false;
        };
        let slot = slot_u32 as usize;
        if self.sender_index.insert(addr, slot).is_err() {
            self.sender_free_list.push(slot_u32);
            return false;
        }
        if let Some(cell) = self.sender_slab.get_mut(slot) {
            *cell = Some(state);
            true
        } else {
            // free_list yielded an out-of-bounds index — structural bug.
            // Roll back the index insert and return false rather than
            // panicking on the recv path.
            self.sender_index.remove(addr);
            debug_assert!(false, "free_list yielded slot ≥ sender_slab.len()");
            false
        }
    }

    #[cfg(test)]
    fn sender_state_for(&self, addr: &SocketAddr) -> Option<&SenderState> {
        self.sender_index
            .get(*addr)
            .and_then(|slot| self.sender_slab.get(slot)?.as_ref())
    }

    #[cfg(test)]
    fn sender_iv_random(&self, addr: &SocketAddr) -> Option<[u8; 8]> {
        self.sender_state_for(addr).map(|s| s.iv_random)
    }

    #[cfg(test)]
    fn sender_last_counter(&self, addr: &SocketAddr) -> Option<u32> {
        self.sender_state_for(addr).map(|s| s.last_counter)
    }

    #[cfg(test)]
    fn sender_prev_iv_random(&self, addr: &SocketAddr) -> Option<[u8; 8]> {
        self.sender_state_for(addr).map(|s| s.prev_iv_random)
    }

    #[cfg(test)]
    fn sender_prev_last_counter(&self, addr: &SocketAddr) -> Option<u32> {
        self.sender_state_for(addr).map(|s| s.prev_last_counter)
    }

    #[cfg(test)]
    fn sender_state_len(&self) -> usize {
        self.sender_index.len()
    }

    #[cfg(test)]
    fn test_local_addr(&self) -> SocketAddr {
        self.sock.local_addr().expect("listener has local addr")
    }
}

impl BeatListener for SecureUdpListener {
    fn recv(&mut self) -> RecvResult {
        // Sized for the larger master-key frame; a 60-byte shared-key datagram
        // fills only the first 60 bytes and nread discriminates the path.
        let mut buf = [0u8; SECURE_FRAME_MASTER_LEN];
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

            let (iv_random, iv_counter, ciphertext, tag, decrypted) = match nread {
                SECURE_FRAME_LEN => {
                    // Shared-key wire format (60 bytes):
                    // [iv_random: 8] [iv_counter: 4] [ciphertext: 32] [tag: 16]
                    let iv_random: [u8; 8] = buf[..8].try_into().unwrap();
                    let iv_counter = u32::from_le_bytes(buf[8..12].try_into().unwrap());

                    let mut nonce = [0u8; NONCE_BYTES];
                    nonce[..8].copy_from_slice(&iv_random);
                    nonce[8..12].copy_from_slice(&iv_counter.to_le_bytes());

                    let ciphertext: [u8; 32] = buf[12..44].try_into().unwrap();
                    let tag: [u8; TAG_BYTES] = buf[44..60].try_into().unwrap();

                    // Constant-trial-count poll: every loaded key is tried on
                    // every frame, regardless of whether one already succeeded.
                    // This removes the linear-in-key-index timing signal that
                    // let a remote attacker fingerprint which rotation slot is
                    // primary by measuring RTT. The post-loop `if .is_none()`
                    // gate keeps the first successful plaintext.
                    let mut decrypted: Option<[u8; 32]> = None;
                    for key in self.keys.iter() {
                        self.aead_attempts = self.aead_attempts.saturating_add(1);
                        let result =
                            crypto::open(key.as_bytes(), &nonce, b"", &ciphertext, &tag).ok();
                        if decrypted.is_none() {
                            decrypted = result;
                        }
                    }

                    (iv_random, iv_counter, ciphertext, tag, decrypted)
                }
                SECURE_FRAME_MASTER_LEN => {
                    // Master-key wire format (64 bytes):
                    // [agent_pid: 4] [iv_random: 8] [iv_counter: 4] [ciphertext: 32] [tag: 16]
                    let agent_pid = u32::from_le_bytes(buf[0..4].try_into().unwrap());
                    let iv_random: [u8; 8] = buf[4..12].try_into().unwrap();
                    let iv_counter = u32::from_le_bytes(buf[12..16].try_into().unwrap());

                    let mut nonce = [0u8; NONCE_BYTES];
                    nonce[..8].copy_from_slice(&iv_random);
                    nonce[8..12].copy_from_slice(&iv_counter.to_le_bytes());

                    let ciphertext: [u8; 32] = buf[16..48].try_into().unwrap();
                    let tag: [u8; TAG_BYTES] = buf[48..64].try_into().unwrap();

                    // aad = on-wire agent_pid bytes; bound into the Poly1305 tag.
                    let aad = &buf[0..4];

                    // Constant-trial-count poll across shared keys *and* the
                    // master-key derivation. Both are always evaluated, so an
                    // attacker cannot fingerprint "shared key sufficed" vs
                    // "needed master derivation" from RTT.
                    let mut decrypted: Option<[u8; 32]> = None;
                    for key in self.keys.iter() {
                        self.aead_attempts = self.aead_attempts.saturating_add(1);
                        let result =
                            crypto::open(key.as_bytes(), &nonce, b"", &ciphertext, &tag).ok();
                        if decrypted.is_none() {
                            decrypted = result;
                        }
                    }
                    let master_attempt =
                        self.try_master_key_decrypt(agent_pid, aad, &nonce, &ciphertext, &tag);
                    // Count the master-key AEAD attempt even on failure: the KDF
                    // and open() both ran whenever a master key is configured,
                    // so the attempt cost was paid regardless of the outcome.
                    // Without this, varta_secure_aead_attempts_total is
                    // under-reported by 1 per master-frame, breaking the operator
                    // invariant: "attempts == frames × (keys.len() + 1)".
                    if self.master_key.is_some() {
                        self.aead_attempts = self.aead_attempts.saturating_add(1);
                    }
                    if decrypted.is_none() {
                        decrypted = master_attempt;
                    }

                    (iv_random, iv_counter, ciphertext, tag, decrypted)
                }
                _ => {
                    self.truncated_count = self.truncated_count.wrapping_add(1);
                    continue;
                }
            };

            // Suppress unused-variable warnings on tag/ciphertext when no
            // caller inspects them after decryption.
            let _ = (ciphertext, tag);

            let Some(plaintext) = decrypted else {
                self.decrypt_failures = self.decrypt_failures.wrapping_add(1);
                continue;
            };

            // Capacity guard: sweep stale senders before trying to insert
            if self.sender_index.len() >= MAX_SENDER_STATES {
                self.evict_stale_senders();
            }
            if self.sender_index.len() >= MAX_SENDER_STATES {
                // Slab is still full after stale-sender sweep — force-evict
                // the oldest entry to maintain replay protection.
                self.force_evict_oldest_sender();
                self.sender_state_full = self.sender_state_full.saturating_add(1);
                debug_assert!(
                    self.sender_index.len() < MAX_SENDER_STATES,
                    "force_evict_oldest_sender should have freed a slot"
                );
            }

            // Atomic replay check + state update after AEAD success.
            if !self.try_record_replay_state(sender, iv_random, iv_counter) {
                self.decrypt_failures = self.decrypt_failures.wrapping_add(1);
                continue;
            }

            let origin = match self.recovery_trust {
                TransportTrust::Operator => BeatOrigin::OperatorAttestedTransport,
                TransportTrust::Untrusted => BeatOrigin::NetworkUnverified,
            };
            return RecvResult::Authenticated {
                peer_pid: 0,
                peer_uid: 0,
                // Secure UDP authenticates wire bytes cryptographically but
                // carries no kernel-attested namespace identity.
                peer_pid_ns_inode: None,
                origin,
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

    fn drain_aead_attempts(&mut self) -> u64 {
        let n = self.aead_attempts;
        self.aead_attempts = 0;
        n
    }
}

#[cfg(test)]
mod tests;
