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
//! After `fork(2)` the child inherits the parent's `iv_session_salt`,
//! `iv_prefix_index`, and `iv_counter` — three nominally-independent
//! fields whose product defines the AEAD nonce. Without intervention,
//! the child's first beat would reuse a 12-byte ChaCha20-Poly1305 nonce
//! the parent has already emitted under the same key — a catastrophic
//! confidentiality and integrity failure.
//!
//! [`crate::Varta`] enforces fork-safety **structurally** by snapshotting
//! [`std::process::id`] at [`crate::Varta::connect`] time and comparing on
//! every [`crate::Varta::beat`]. On mismatch, the wrapper calls
//! [`BeatTransport::reconnect`] *before* the frame is built — re-reading
//! OS entropy into a fresh 16-byte session salt and resetting
//! `iv_prefix_index`/`iv_counter` to zero. The forked child therefore
//! emits frames keyed by an IV prefix derived from independent entropy,
//! making nonce collision across the fork boundary impossible. The
//! recovery is silent to the caller and observable via
//! [`crate::Varta::fork_recoveries`].
//!
//! **Advanced callers using `SecureUdpTransport` directly** (without the
//! `Varta` wrapper) do not get this auto-detection — they must call
//! [`SecureUdpTransport::reconnect`] in the child themselves. The
//! [`BeatTransport`] trait is intentionally low-level; the safety policy
//! lives one layer up.
//!
//! Historical note (cerebrum 2026-05-13): a prior `last_pid` field in
//! `Varta` was removed because it detected fork but only reset clock
//! state — the IV state was still inherited, so the "fix" was theatre.
//! The current design is structurally different in that the PID-mismatch
//! response is `transport.reconnect()`, which is precisely where the IV
//! salt rotates.
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
    /// Retained only in master-key mode so `reconnect()` can re-derive
    /// `self.key` from the forked child's PID.
    master_key: Option<Key>,
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
        let iv_prefix = kdf::derive_iv_prefix(&iv_session_salt, 0)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "key derivation failure"))?;

        Ok(SecureUdpTransport {
            sock,
            addr,
            key,
            iv_counter: 0,
            iv_session_salt,
            iv_prefix_index: 0,
            iv_prefix,
            is_master_mode: false,
            master_key: None,
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
        let agent_key = kdf::derive_agent_key(&master_key, peer_pid)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "key derivation failure"))?;

        let sock = bind_ephemeral(&addr)?;
        sock.connect(addr)?;
        sock.set_nonblocking(true)?;

        // 16-byte session salt — HKDF-expanded into the 8-byte on-wire
        // `iv_random` field. The PID is sent as a plaintext AAD field in
        // the 64-byte wire frame.
        let iv_session_salt = read_iv_session_salt()?;
        let iv_prefix = kdf::derive_iv_prefix(&iv_session_salt, 0)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "key derivation failure"))?;

        // Retain master key so reconnect() can re-derive the agent key
        // from the forked child's PID.
        let retained_master = Key::from_bytes(*master_key.as_bytes());

        Ok(SecureUdpTransport {
            sock,
            addr,
            key: agent_key,
            iv_counter: 0,
            iv_session_salt,
            iv_prefix_index: 0,
            iv_prefix,
            is_master_mode: true,
            master_key: Some(retained_master),
        })
    }

    /// Test-only setter to fast-forward the AEAD counter, exercising the
    /// counter-wrap rotation path without sending billions of beats.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_iv_counter_for_test(&mut self, value: u32) {
        self.iv_counter = value;
    }

    /// Test-only accessor for the current committed `iv_counter`. Used to
    /// assert commit-on-success behaviour — that a failed `send` (e.g.
    /// `WouldBlock`) does NOT advance the counter.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn iv_counter_for_test(&self) -> u32 {
        self.iv_counter
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

    /// Test-only setter to fast-forward the prefix index, exercising the
    /// doubly-exhausted (counter + prefix-index wrap → reconnect) path.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_iv_prefix_index_for_test(&mut self, value: u32) {
        self.iv_prefix_index = value;
    }

    /// Test-only accessor for the current agent key bytes.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn key_bytes_for_test(&self) -> [u8; 32] {
        *self.key.as_bytes()
    }
}

/// Speculative result of [`SecureUdpTransport::advance_nonce`]. Carries the
/// values the next frame should use **without** committing them to `self`.
/// The caller in [`BeatTransport::send`] commits to `self` only after the
/// kernel accepts the datagram, preserving the commit-on-success contract
/// across the wrap boundary.
///
/// The `Reconnected` arm is a deliberate exception: `reconnect()` performs
/// an irreversible socket re-bind and OS entropy read, so its side effects
/// cannot be deferred to send-success. That arm only fires after `2^64`
/// beats (~584M years at 1 kHz), so the impact is purely theoretical.
#[must_use = "NonceAdvance must be committed to self on send-success"]
enum NonceAdvance {
    /// Common case — `iv_counter` is below `u32::MAX`. The stored
    /// `counter` is the value to place on the wire; the commit step
    /// writes `counter + 1` back to `self.iv_counter`.
    Simple { counter: u32 },
    /// Counter wrap — `iv_counter` exhausted but `iv_prefix_index` can
    /// still advance. The HKDF expansion ran into the local `next_prefix`;
    /// none of `self.iv_prefix_index` / `self.iv_prefix` have been mutated.
    /// Committing requires writing all three fields. `counter` is 0
    /// (first frame under the new prefix).
    Wrap {
        counter: u32,
        next_prefix_index: u32,
        next_prefix: [u8; 8],
    },
    /// Doubly-exhausted — `reconnect()` already mutated `self.sock`,
    /// `self.iv_session_salt`, `self.iv_prefix`, and zeroed both counters.
    /// `counter` is 0 (first frame of the new session); the commit step
    /// writes `counter + 1` back to `self.iv_counter`.
    Reconnected { counter: u32 },
}

impl SecureUdpTransport {
    /// Speculatively compute the values the next frame should use, without
    /// committing them to `self`. The returned `counter` is the value to
    /// place on the wire; the commit step in `send()` writes
    /// `counter + 1` back to `self.iv_counter`. Three branches:
    ///
    /// 1. **Common case** — `iv_counter < u32::MAX`. Use it as-is.
    /// 2. **Counter wrap** — derive a fresh prefix via HKDF into a local;
    ///    `self.iv_prefix_index` / `self.iv_prefix` are **not** mutated.
    ///    The caller commits on send-success. Counter resets to 0.
    /// 3. **Doubly-exhausted** — both `u32`s exhausted (`2^64` nonces,
    ///    ~584M years at 1 kHz). Fall back to [`Self::reconnect`]; that
    ///    side effect *is* committed eagerly because socket re-bind and
    ///    OS entropy read are irreversible. Counter resets to 0.
    fn advance_nonce(&mut self) -> io::Result<NonceAdvance> {
        if self.iv_counter < u32::MAX {
            return Ok(NonceAdvance::Simple {
                counter: self.iv_counter,
            });
        }
        if let Some(next_index) = self.iv_prefix_index.checked_add(1) {
            let next_prefix =
                varta_vlp::crypto::kdf::derive_iv_prefix(&self.iv_session_salt, next_index)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "key derivation failure"))?;
            return Ok(NonceAdvance::Wrap {
                counter: 0,
                next_prefix_index: next_index,
                next_prefix,
            });
        }
        // Prefix index also exhausted. Fall back to the manual escape
        // hatch; reconnect's side effects are eagerly committed because a
        // socket re-bind and OS entropy read cannot be deferred.
        self.reconnect()?;
        debug_assert_eq!(
            self.iv_counter, 0,
            "reconnect() must zero iv_counter — see secure_transport module docs"
        );
        debug_assert_eq!(
            self.iv_prefix_index, 0,
            "reconnect() must zero iv_prefix_index — see secure_transport module docs"
        );
        Ok(NonceAdvance::Reconnected { counter: 0 })
    }
}

impl BeatTransport for SecureUdpTransport {
    fn send(&mut self, buf: &[u8; 32]) -> io::Result<usize> {
        // Speculatively compute what the next frame should use. For the
        // common path and the wrap path, no `self.*` IV state has been
        // mutated yet — those mutations are deferred to send-success
        // below. Only the doubly-exhausted (`Reconnected`) path eagerly
        // mutates, because socket re-bind and OS entropy reads cannot be
        // unwound.
        let advance = self.advance_nonce()?;
        let (pending_counter, pending_prefix) = match &advance {
            NonceAdvance::Simple { counter } => (*counter, self.iv_prefix),
            NonceAdvance::Wrap {
                counter,
                next_prefix,
                ..
            } => (*counter, *next_prefix),
            NonceAdvance::Reconnected { counter } => (*counter, self.iv_prefix),
        };

        // Build 12-byte nonce: pending_prefix (8) || pending_counter (4) LE
        let mut nonce = [0u8; NONCE_BYTES];
        nonce[..8].copy_from_slice(&pending_prefix);
        nonce[8..12].copy_from_slice(&pending_counter.to_le_bytes());

        let result = if self.is_master_mode {
            // Master-key wire format (64 bytes):
            // [agent_pid: 4] [iv_random: 8] [iv_counter: 4] [ciphertext: 32] [tag: 16]
            //
            // The on-wire `iv_random` field is now sourced from the
            // KDF-derived prefix — byte budget preserved.
            //
            // agent_pid is read fresh each beat (never cached — see cerebrum
            // 2026-05-11) and bound as AAD so tampering the PID prefix fails
            // authentication.
            let agent_pid = std::process::id();
            let agent_pid_bytes = agent_pid.to_le_bytes();
            let (ciphertext, tag) =
                crypto::seal(self.key.as_bytes(), &nonce, &agent_pid_bytes, buf)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "AEAD seal failure"))?;

            let mut frame = [0u8; SECURE_FRAME_MASTER_LEN];
            frame[0..4].copy_from_slice(&agent_pid_bytes);
            frame[4..12].copy_from_slice(&pending_prefix);
            frame[12..16].copy_from_slice(&pending_counter.to_le_bytes());
            frame[16..48].copy_from_slice(&ciphertext);
            frame[48..64].copy_from_slice(&tag);

            self.sock.send(&frame)
        } else {
            // Shared-key wire format (60 bytes):
            // [iv_random: 8] [iv_counter: 4] [ciphertext: 32] [tag: 16]
            let (ciphertext, tag) = crypto::seal(self.key.as_bytes(), &nonce, b"", buf)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "AEAD seal failure"))?;

            let mut frame = [0u8; SECURE_FRAME_LEN];
            frame[..8].copy_from_slice(&pending_prefix);
            frame[8..12].copy_from_slice(&pending_counter.to_le_bytes());
            frame[12..44].copy_from_slice(&ciphertext);
            frame[44..60].copy_from_slice(&tag);

            self.sock.send(&frame)
        };

        // Commit-on-success — for all three branches.
        //
        // `WouldBlock` / `ENOBUFS` means the ciphertext never escaped the
        // process. On the wrap path, the speculative `next_prefix_index` /
        // `next_prefix` are dropped on failure; the next call re-enters
        // `advance_nonce`, recomputes the same `next_index` from the
        // unchanged `iv_session_salt`, and tries again. UDP `send(2)` is
        // datagram-atomic, so there is no "half-sent under this nonce"
        // state to reason about.
        if result.is_ok() {
            match advance {
                NonceAdvance::Simple { counter } => {
                    // counter < u32::MAX (guarded by advance_nonce), so + 1
                    // cannot overflow.
                    self.iv_counter = counter + 1;
                }
                NonceAdvance::Wrap {
                    counter,
                    next_prefix_index,
                    next_prefix,
                } => {
                    self.iv_prefix_index = next_prefix_index;
                    self.iv_prefix = next_prefix;
                    self.iv_counter = counter + 1;
                }
                NonceAdvance::Reconnected { counter } => {
                    self.iv_counter = counter + 1;
                }
            }
        }
        result
    }

    /// Manual session refresh — re-binds the ephemeral socket, re-reads OS
    /// entropy for a fresh 16-byte session salt, and resets prefix/counter
    /// state. This is the **only** path after `connect()` that touches OS
    /// entropy.
    ///
    /// Called automatically by [`crate::Varta::beat`] when a `fork(2)`
    /// transition is detected (PID mismatch against the connect-time
    /// snapshot). Advanced callers using `SecureUdpTransport` directly
    /// must invoke this themselves in the forked child — the inherited
    /// `iv_session_salt` would otherwise cause catastrophic AEAD nonce
    /// reuse. Also called by operators wanting a fresh session for
    /// forward-secrecy hygiene.
    fn reconnect(&mut self) -> io::Result<()> {
        use varta_vlp::crypto::kdf;

        // --- Prepare phase: every fallible call writes to a local.  Any
        //     `?` below this comment block returns with `self` byte-identical
        //     to entry.  The observer tracks per-sender state by
        //     (SocketAddr, iv_prefix); a new salt produces a fresh prefix
        //     series that the observer treats as a new session.
        let sock = bind_ephemeral(&self.addr)?;
        sock.connect(self.addr)?;
        sock.set_nonblocking(true)?;
        let new_salt = read_iv_session_salt()?;
        let new_prefix = kdf::derive_iv_prefix(&new_salt, 0)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "key derivation failure"))?;

        // In master-key mode, re-derive the agent key from the current
        // PID. After fork(2) the child has a different PID; the observer
        // derives the decryption key from the on-wire PID, so the
        // encryption key must match.
        let new_key = if let Some(ref mk) = self.master_key {
            Some(
                kdf::derive_agent_key(mk, std::process::id())
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "key derivation failure"))?,
            )
        } else {
            None
        };

        // --- Commit phase: NO `?` operator below this line.  Any future
        //     change that introduces a fallible call here is a transactional
        //     regression — a partial commit could leave `self.sock` paired
        //     with a stale `iv_session_salt`/`iv_prefix`, an internally
        //     inconsistent state that subsequent `advance_nonce` calls would
        //     have to converge out of via retry.
        self.sock = sock;
        self.iv_session_salt = new_salt;
        self.iv_prefix = new_prefix;
        self.iv_prefix_index = 0;
        self.iv_counter = 0;
        if let Some(k) = new_key {
            self.key = k;
        }
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
/// the panic-hook installer, which captures an install-process IV prefix and
/// separately captures a fork salt for forked children.
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
#[cfg(any(feature = "accept-degraded-entropy", test))]
#[cfg_attr(not(any(test, feature = "accept-degraded-entropy")), allow(dead_code))]
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
/// Consumed by the secure panic-hook degraded-entropy installer, which needs
/// fork-child IV prefixes to be derivable without calling OS entropy from the
/// hook body.
#[cfg(any(feature = "accept-degraded-entropy", test))]
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
mod tests;
