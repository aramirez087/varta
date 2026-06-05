//! Secure UDP listener backed by ChaCha20-Poly1305 AEAD.
//!
//! [`SecureUdpListener`] receives 60-byte encrypted frames from remote agents,
//! decrypts and verifies them using the pre-shared key(s), and returns the
//! decrypted 32-byte VLP frame via the standard [`BeatListener`] trait.
//!
//! Replay protection is enforced at several layers:
//! 1. The listener performs an atomic check-and-update of per-sender replay
//!    state **after** successful AEAD decryption, eliminating the TOCTOU
//!    window between the replay check and state insertion.
//! 2. A 1-deep IV-rotation history (prev_iv_random / prev_last_counter)
//!    bounds replay *within* the current and immediately-previous IV prefix
//!    via their per-prefix counters.
//! 3. A per-sender high-water mark of authenticated regular VLP nonces
//!    (`SenderState::max_regular_nonce`) bounds replay *across* prefix
//!    rotations: a non-terminal frame on a prefix that has aged out of the
//!    1-deep history is accepted only if its nonce strictly exceeds every
//!    regular nonce already seen for that sender. Terminal panic frames carry
//!    the reserved `NONCE_TERMINAL` sentinel, so they are tracked by their
//!    authenticated timestamp instead and cannot poison later normal liveness.
//! 4. The bounded sender table fails closed at capacity: known senders can
//!    advance their state, but unknown senders are refused after the stale
//!    sweep instead of evicting unrelated replay history.
//! 5. The observer's [`Tracker`] enforces per-pid nonce monotonicity on
//!    the decrypted frame (a backstop that is lost if the tracker slot is
//!    evicted under capacity pressure, which is why layer 3 enforces the same
//!    invariant at the dedicated replay layer).

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use varta_vlp::crypto::{self, Key, NONCE_BYTES, SECURE_FRAME_MASTER_BYTES, TAG_BYTES};
use varta_vlp::{Frame, NONCE_TERMINAL};

use crate::listener::{BeatListener, TransportTrust};
use crate::peer_cred::{BeatOrigin, RecvResult};
use crate::probe_table::{BoundedIndex, Hash32};

/// Wire size of a shared-key VLP frame.
const SECURE_FRAME_LEN: usize = crypto::SECURE_FRAME_BYTES;

/// Wire size of a master-key VLP frame.
const SECURE_FRAME_MASTER_LEN: usize = SECURE_FRAME_MASTER_BYTES;

/// Receive capacity with one byte of slack to detect overlong datagrams.
const SECURE_FRAME_RECV_CAP: usize = SECURE_FRAME_MASTER_LEN + 1;

/// Maximum number of unique senders tracked simultaneously. Prevents
/// unbounded memory growth from short-lived agents (cron jobs, CI runners).
const MAX_SENDER_STATES: usize = 1024;

/// How long a sender's replay state is retained after its last seen frame.
const EVICTION_TTL: Duration = Duration::from_secs(600); // 10 minutes

/// How often the stale-sender sweep runs.
const EVICTION_INTERVAL: Duration = Duration::from_secs(60);

/// Authenticated replay identity.
///
/// UDP source addresses are not stable enough, or authenticated enough, to
/// identify a secure sender: reconnects can legitimately change source ports,
/// while a replay attacker can transmit a captured ciphertext from a different
/// port. The decrypted VLP frame PID is AEAD-authenticated, and it matches the
/// observer's tracker identity, so replay state is keyed by that PID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReplayIdentity(u32);

impl ReplayIdentity {
    #[inline]
    fn from_frame(frame: &Frame) -> Self {
        Self(frame.pid)
    }

    #[cfg(test)]
    const fn from_pid(pid: u32) -> Self {
        Self(pid)
    }
}

impl Hash32 for ReplayIdentity {
    #[inline]
    fn hash32(&self) -> u32 {
        self.0.hash32()
    }
}

/// Per-sender replay guard state.
///
/// Tracks the current IV prefix and its last counter, plus a 1-deep history
/// of the previous IV prefix/counter so that frames from a recently-rotated
/// IV are still checked for replay. The authenticated `identity` is stored
/// alongside the IV/counter pair so that a linear walk over the slab can
/// recover the index key (matches the `OutstandingTable` pattern, which
/// stores pid-keyed values keyed by their own value).
///
/// `max_regular_nonce` is the high-water mark of authenticated non-terminal
/// VLP frame nonces seen for this sender across **all** IV prefixes. Terminal
/// panic frames use the reserved `NONCE_TERMINAL` sentinel (`u64::MAX`), which
/// would otherwise permanently poison the regular high-water mark; those
/// frames are instead replay-bounded by `max_terminal_timestamp`.
///
/// The IV-prefix pair only guards replay *within* the current/previous epoch;
/// the regular nonce / terminal timestamp high-water marks close replay of a
/// fully-aged-out prefix that the 1-deep IV history no longer remembers.
#[derive(Clone, Debug)]
struct SenderState {
    identity: ReplayIdentity,
    iv_random: [u8; 8],
    last_counter: u32,
    prev_iv_random: [u8; 8],
    prev_last_counter: u32,
    max_regular_nonce: u64,
    max_terminal_timestamp: Option<u64>,
    last_seen: Instant,
}

impl SenderState {
    fn new(
        identity: ReplayIdentity,
        iv_random: [u8; 8],
        counter: u32,
        frame_nonce: u64,
        frame_timestamp: u64,
    ) -> Self {
        let mut state = SenderState {
            identity,
            iv_random,
            last_counter: counter,
            prev_iv_random: [0u8; 8],
            prev_last_counter: 0,
            max_regular_nonce: 0,
            max_terminal_timestamp: None,
            last_seen: Instant::now(),
        };
        state.observe_frame_clock(frame_nonce, frame_timestamp);
        state
    }

    fn observe_frame_clock(&mut self, frame_nonce: u64, frame_timestamp: u64) {
        if frame_nonce == NONCE_TERMINAL {
            self.max_terminal_timestamp = Some(
                self.max_terminal_timestamp
                    .map_or(frame_timestamp, |max| max.max(frame_timestamp)),
            );
        } else {
            self.max_regular_nonce = self.max_regular_nonce.max(frame_nonce);
        }
    }

    fn accepts_aged_out_prefix(&self, frame_nonce: u64, frame_timestamp: u64) -> bool {
        if frame_nonce == NONCE_TERMINAL {
            return match self.max_terminal_timestamp {
                Some(max) => frame_timestamp > max,
                None => true,
            };
        }
        frame_nonce > self.max_regular_nonce
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
    /// `ReplayIdentity → slab index` mapping with bounded WCET (no SipHash, no
    /// rehash). Sized identically to the slab so the load-factor invariant
    /// for `BoundedIndex` holds. Replaces the previous
    /// `HashMap<ReplayIdentity, SenderState>` per the project-wide DNR rule
    /// (see cerebrum 2026-05-14 "Generic `BoundedIndex<K>`").
    sender_index: BoundedIndex<ReplayIdentity>,
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
    recovery_trust: TransportTrust,
}

/// Build the pre-allocated `(slab, free_list, index)` triple used by both
/// `bind` and `bind_with_master`. Keeps the capacity invariant in one place.
fn new_sender_state_store() -> (
    Vec<Option<SenderState>>,
    Vec<u32>,
    BoundedIndex<ReplayIdentity>,
) {
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
        self.evict_stale_senders_at(Instant::now());
    }

    fn evict_stale_senders_at(&mut self, now: Instant) {
        for slot in 0..self.sender_slab.len() {
            let stale = self
                .sender_slab
                .get(slot)
                .and_then(|opt| opt.as_ref())
                // Compare by age rather than computing `now - EVICTION_TTL`:
                // `Instant` subtraction can underflow on low-uptime systems.
                .is_some_and(|s| now.saturating_duration_since(s.last_seen) >= EVICTION_TTL);
            if stale {
                if let Some(state) = self.sender_slab[slot].take() {
                    self.sender_index.remove(state.identity);
                    self.sender_free_list.push(slot as u32);
                }
            }
        }
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
    /// (sender, iv_random, counter, frame_nonce, frame_timestamp) combination
    /// is valid, and updates the replay state in the same operation to close
    /// the TOCTOU window.
    ///
    /// Three cases per sender lookup:
    /// 1. Same IV prefix   → `counter > last_counter` required
    /// 2. Previous IV prefix → `counter > prev_last_counter` required
    ///    (catches replay of frames from a recently-rotated epoch)
    /// 3. Neither matches (a new or rotated IV prefix) → regular frames are
    ///    accepted only if `frame_nonce > max_regular_nonce`; terminal panic
    ///    frames are accepted only if their authenticated timestamp is newer
    ///    than the previous terminal frame. The IV-prefix history is 1-deep,
    ///    so a captured frame from a prefix that has aged out of `iv_random` /
    ///    `prev_iv_random` would otherwise land here and be re-accepted as a
    ///    "fresh rotation".
    ///
    /// The high-water state is advanced on every accept (all three arms).
    /// Within the current / previous prefix, replay is still bounded by the
    /// per-prefix counter alone (arms 1 & 2 do not gate on the high-water
    /// marks), preserving the existing tolerance for in-flight reordering
    /// inside the recent epochs.
    fn try_record_replay_state(
        &mut self,
        identity: ReplayIdentity,
        iv_random: [u8; 8],
        counter: u32,
        frame_nonce: u64,
        frame_timestamp: u64,
    ) -> bool {
        if let Some(slot) = self.sender_index.get(identity) {
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
                    state.observe_frame_clock(frame_nonce, frame_timestamp);
                    state.last_seen = Instant::now();
                    return true;
                }
                return false;
            }

            if state.prev_iv_random == iv_random {
                if counter > state.prev_last_counter {
                    state.prev_last_counter = counter;
                    state.observe_frame_clock(frame_nonce, frame_timestamp);
                    state.last_seen = Instant::now();
                    return true;
                }
                return false;
            }

            // New or rotated IV prefix. The 1-deep prefix history has no
            // record of it, so the cross-prefix replay bound is the
            // authenticated regular nonce, or the authenticated terminal
            // timestamp for panic-hook sentinel frames.
            if !state.accepts_aged_out_prefix(frame_nonce, frame_timestamp) {
                return false;
            }

            state.prev_iv_random = state.iv_random;
            state.prev_last_counter = state.last_counter;
            state.iv_random = iv_random;
            state.last_counter = counter;
            state.observe_frame_clock(frame_nonce, frame_timestamp);
            state.last_seen = Instant::now();
            return true;
        }

        let new_state =
            SenderState::new(identity, iv_random, counter, frame_nonce, frame_timestamp);
        self.allocate_sender_slot(identity, new_state)
    }

    /// Pop a free slab slot, register `identity → slot` in the index, and write
    /// `state` to the slab. Returns `false` (rolling back the pop) when no
    /// free slot is available or the index probe budget is exhausted; the
    /// caller treats this as a soft refusal. In production the outer
    /// capacity guard in `recv` ensures a free slot exists before calling
    /// `try_record_replay_state`, so this only matters for direct unit
    /// tests and as defense-in-depth.
    fn allocate_sender_slot(&mut self, identity: ReplayIdentity, state: SenderState) -> bool {
        let Some(slot_u32) = self.sender_free_list.pop() else {
            return false;
        };
        let slot = slot_u32 as usize;
        if self.sender_index.insert(identity, slot).is_err() {
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
            self.sender_index.remove(identity);
            debug_assert!(false, "free_list yielded slot ≥ sender_slab.len()");
            false
        }
    }

    #[cfg(test)]
    fn sender_state_for(&self, identity: ReplayIdentity) -> Option<&SenderState> {
        self.sender_index
            .get(identity)
            .and_then(|slot| self.sender_slab.get(slot)?.as_ref())
    }

    #[cfg(test)]
    fn sender_max_regular_nonce(&self, identity: ReplayIdentity) -> Option<u64> {
        self.sender_state_for(identity).map(|s| s.max_regular_nonce)
    }

    /// Test-only shim that supplies a globally-monotonic inner nonce.
    ///
    /// The legacy IV/counter replay tests predate the cross-prefix nonce
    /// high-water mark and only exercise the per-prefix counter logic. Feeding
    /// each successive call a strictly newer nonce keeps their exact semantics:
    /// a genuine rotation (the third arm) is never refused by the regular
    /// nonce high-water guard, so every prior accept/reject expectation is
    /// preserved. Tests that exercise the cross-prefix guard itself call
    /// [`try_record_replay_state`] directly with explicit nonces.
    #[cfg(test)]
    fn record_for_test(
        &mut self,
        identity: ReplayIdentity,
        iv_random: [u8; 8],
        counter: u32,
    ) -> bool {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TEST_NONCE: AtomicU64 = AtomicU64::new(1);
        let nonce = TEST_NONCE.fetch_add(1, Ordering::Relaxed);
        self.try_record_replay_state(identity, iv_random, counter, nonce, nonce)
    }

    #[cfg(test)]
    fn sender_iv_random(&self, identity: ReplayIdentity) -> Option<[u8; 8]> {
        self.sender_state_for(identity).map(|s| s.iv_random)
    }

    #[cfg(test)]
    fn sender_last_counter(&self, identity: ReplayIdentity) -> Option<u32> {
        self.sender_state_for(identity).map(|s| s.last_counter)
    }

    #[cfg(test)]
    fn sender_prev_iv_random(&self, identity: ReplayIdentity) -> Option<[u8; 8]> {
        self.sender_state_for(identity).map(|s| s.prev_iv_random)
    }

    #[cfg(test)]
    fn sender_prev_last_counter(&self, identity: ReplayIdentity) -> Option<u32> {
        self.sender_state_for(identity).map(|s| s.prev_last_counter)
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
        // fills only the first 60 bytes and nread discriminates the path. The
        // extra byte makes overlong datagrams observable before decryption.
        let mut buf = [0u8; SECURE_FRAME_RECV_CAP];
        loop {
            // Periodic eviction sweep for stale senders
            let now = Instant::now();
            if now >= self.next_eviction_check {
                self.evict_stale_senders();
                self.next_eviction_check = now + EVICTION_INTERVAL;
            }

            let (nread, _sender) = match self.sock.recv_from(&mut buf) {
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
                    return RecvResult::ShortRead;
                }
            };

            // Suppress unused-variable warnings on tag/ciphertext when no
            // caller inspects them after decryption.
            let _ = (ciphertext, tag);

            let Some(plaintext) = decrypted else {
                self.decrypt_failures = self.decrypt_failures.wrapping_add(1);
                // One bad datagram is one poll unit. Do not privately drain
                // the socket here: a sustained unauthenticated flood must not
                // pin the observer inside this listener and starve maintenance.
                return RecvResult::WouldBlock;
            };

            let origin = match self.recovery_trust {
                TransportTrust::Operator => BeatOrigin::OperatorAttestedTransport,
                TransportTrust::Untrusted => BeatOrigin::NetworkUnverified,
            };
            // Replay state is keyed by the authenticated VLP identity, but it
            // must not be allocated until the VLP frame itself validates. A
            // holder of the UDP key can otherwise send authenticated garbage
            // with many fake pid fields and pin MAX_SENDER_STATES replay
            // slots before the observer later rejects the payload as
            // DecodeError. Return the plaintext unchanged so the observer's
            // existing decode-error metrics and file-export semantics stay
            // identical to UDS/plain UDP.
            let decoded_frame = match Frame::decode(&plaintext) {
                Ok(frame) => frame,
                Err(_) => {
                    return RecvResult::Authenticated {
                        peer_pid: 0,
                        peer_uid: 0,
                        peer_pid_ns_inode: None,
                        peer_pidfd: None,
                        origin,
                        data: plaintext,
                    };
                }
            };

            // Replay identity is authenticated data from the decoded VLP
            // frame, not the unauthenticated UDP source address. This closes
            // the source-port replay bypass and matches the observer tracker's
            // pid-keyed liveness model.
            let replay_identity = ReplayIdentity::from_frame(&decoded_frame);
            // Authenticated inner VLP nonce. Monotonic per pid across
            // IV-prefix rotations, so it bounds replay of an aged-out prefix
            // that the 1-deep `iv_random`/`prev_iv_random` history no longer
            // remembers.
            let frame_nonce = decoded_frame.nonce;
            let frame_timestamp = decoded_frame.timestamp;
            let known_identity = self.sender_index.get(replay_identity).is_some();
            if !known_identity && self.sender_index.len() >= MAX_SENDER_STATES {
                self.evict_stale_senders();
            }
            if !known_identity && self.sender_index.len() >= MAX_SENDER_STATES {
                // Fail closed: admitting an unknown sender would require
                // evicting live replay state. Drop the authenticated frame
                // and surface capacity pressure instead.
                self.sender_state_full = self.sender_state_full.saturating_add(1);
                // Same one-datagram budget as AEAD failures above.
                return RecvResult::WouldBlock;
            }

            // Atomic replay check + state update after AEAD success.
            if !self.try_record_replay_state(
                replay_identity,
                iv_random,
                iv_counter,
                frame_nonce,
                frame_timestamp,
            ) {
                if known_identity {
                    self.decrypt_failures = self.decrypt_failures.wrapping_add(1);
                } else {
                    self.sender_state_full = self.sender_state_full.saturating_add(1);
                }
                // Same one-datagram budget as AEAD failures above.
                return RecvResult::WouldBlock;
            }

            return RecvResult::Authenticated {
                peer_pid: 0,
                peer_uid: 0,
                // Secure UDP authenticates wire bytes cryptographically but
                // carries no kernel-attested namespace identity.
                peer_pid_ns_inode: None,
                peer_pidfd: None,
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
