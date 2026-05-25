//! Agent surface — `Varta` connects to the observer over a configured
//! transport and `beat()` emits one fire-and-forget 32-byte VLP frame per call.

use std::fmt;
use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use varta_vlp::{Frame, Status, NONCE_TERMINAL};

use crate::transport::{BeatTransport, UdsTransport};

#[cfg(feature = "udp")]
use crate::transport::UdpTransport;

#[cfg(feature = "secure-udp")]
use crate::secure_transport::SecureUdpTransport;

#[cfg(feature = "secure-udp")]
use varta_vlp::crypto::Key;

/// Linux value of `ENOBUFS` from `<asm-generic/errno-base.h>` (Linux 2.6+,
/// verified against 6.12). Hard-coded to preserve the zero-dependency
/// invariant; do not replace with `libc`.
#[cfg(target_os = "linux")]
const ENOBUFS: i32 = 105;

/// Darwin / BSD value of `ENOBUFS` from `<sys/errno.h>` (macOS 15 / XNU,
/// FreeBSD 14, NetBSD 10, OpenBSD 7, DragonFly 6). Hard-coded for the
/// same reason.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
const ENOBUFS: i32 = 55;

/// Solaris / illumos value of `ENOBUFS` from `<sys/errno.h>`. Hard-coded
/// for the same reason.
#[cfg(any(target_os = "solaris", target_os = "illumos"))]
const ENOBUFS: i32 = 111;

/// Catch-all for unlisted Unix targets.
/// Cross-compilation to an unsupported target silently uses the wrong
/// value; fail at compile time instead.
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos",
)))]
compile_error!("ENOBUFS value is unknown for this target — add it to the cfg gates above");

/// Classify a `send(2)` error into a [`BeatOutcome`].
///
/// Checks the raw OS error code before the `ErrorKind` match so that
/// `ENOBUFS` (kernel buffer pressure, transient) is caught even when the
/// toolchain maps it to `ErrorKind::Other`.
pub fn classify_send_error(e: &io::Error) -> BeatOutcome {
    // (a) Raw-OS path first — catches ENOBUFS even when libstd has not
    //     minted a dedicated ErrorKind for it on this toolchain.
    if let Some(code) = e.raw_os_error() {
        if code == ENOBUFS {
            return BeatOutcome::Dropped(DropReason::KernelQueueFull);
        }
    }

    match e.kind() {
        // (b) Transient kernel pressure.
        io::ErrorKind::WouldBlock => BeatOutcome::Dropped(DropReason::KernelQueueFull),
        // (c) Observer not bound yet or socket file missing.
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound => {
            BeatOutcome::Dropped(DropReason::NoObserver)
        }
        // (d) Peer socket torn down since the last beat.
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotConnected
        | io::ErrorKind::BrokenPipe => BeatOutcome::Dropped(DropReason::PeerGone),
        // (e) Host out of disk space.
        io::ErrorKind::StorageFull => BeatOutcome::Dropped(DropReason::StorageFull),
        // (f) Unexpected error: capture as a Copy POD that cannot allocate.
        _ => BeatOutcome::Failed(BeatError::from_io(e)),
    }
}

/// Payload of [`BeatOutcome::Failed`].
///
/// `Copy` by construction: allocating a `BeatError` is structurally
/// impossible, so the [`Varta::beat`] slow path is allocation-free
/// regardless of how the underlying `io::Error` was represented.
/// Callers wanting a full `io::Error` can call [`Self::to_io_error`].
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct BeatError {
    /// Raw OS errno when the failure came from a syscall;
    /// [`BeatError::UNKNOWN_ERRNO`] (0) when not OS-derived.
    /// POSIX guarantees errno is never 0 on a real syscall failure.
    pub errno: i32,
    /// The libstd [`io::ErrorKind`] classification. Always populated.
    pub kind: io::ErrorKind,
}

impl BeatError {
    /// Sentinel value used when no OS error number is available.
    pub const UNKNOWN_ERRNO: i32 = 0;

    /// Capture the failure shape from an `io::Error` without cloning or allocating.
    pub fn from_io(e: &io::Error) -> Self {
        Self {
            errno: e.raw_os_error().unwrap_or(Self::UNKNOWN_ERRNO),
            kind: e.kind(),
        }
    }

    /// Reconstruct an `io::Error`. Allocation-free when `errno != 0` (uses
    /// `Repr::Os`); falls back to `Repr::Simple(kind)` otherwise.
    pub fn to_io_error(self) -> io::Error {
        if self.errno != Self::UNKNOWN_ERRNO {
            io::Error::from_raw_os_error(self.errno)
        } else {
            io::Error::from(self.kind)
        }
    }
}

impl fmt::Debug for BeatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BeatError")
            .field("errno", &self.errno)
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for BeatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errno != Self::UNKNOWN_ERRNO {
            write!(f, "send failed: {:?} (errno={})", self.kind, self.errno)
        } else {
            write!(f, "send failed: {:?}", self.kind)
        }
    }
}

impl std::error::Error for BeatError {}

/// Reason why a [`BeatOutcome::Dropped`] was produced.
///
/// Four-way taxonomy covering every `io::Error` classified as `Dropped`
/// by [`classify_send_error`]. `Copy` by construction; fits in a single byte
/// (statically asserted below). Operators can match on this to distinguish
/// "observer not yet listening" from "socket torn down" from "host full".
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum DropReason {
    /// The kernel send buffer or socket queue was full (transient).
    ///
    /// Source: `WouldBlock` or `ENOBUFS`. The observer is likely alive;
    /// retry after a short back-off or rely on
    /// [`set_reconnect_after`](Varta::set_reconnect_after).
    KernelQueueFull,
    /// No observer is bound at the target path or address.
    ///
    /// Source: `NotFound` or `ConnectionRefused`. Expected during a
    /// rolling observer restart before the new process has bound the socket.
    NoObserver,
    /// The peer socket was torn down since the last successful beat.
    ///
    /// Source: `ConnectionReset`, `NotConnected`, or `BrokenPipe`. The
    /// channel was live and then disappeared — typically a crash or explicit
    /// observer shutdown. Call [`reconnect`](Varta::reconnect) to recover.
    PeerGone,
    /// The host filesystem is out of space (UDS socket path on a full volume).
    ///
    /// Source: `StorageFull`. Retrying without clearing disk space will not
    /// resolve this; operator intervention is required.
    StorageFull,
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KernelQueueFull => f.write_str("kernel queue full"),
            Self::NoObserver => f.write_str("no observer"),
            Self::PeerGone => f.write_str("peer gone"),
            Self::StorageFull => f.write_str("storage full"),
        }
    }
}

// Four variants fit in a single byte — no heap footprint on the beat path.
const _: () = {
    assert!(core::mem::size_of::<DropReason>() == 1);
};

/// Result of a single [`Varta::beat`] call.
///
/// `beat()` never blocks and never panics; the kernel's view of the send is
/// translated into one of three steady-state outcomes. `Failed` carries the
/// underlying error for higher layers that wish to log or escalate.
#[must_use]
pub enum BeatOutcome {
    /// The 32-byte datagram was accepted by the kernel.
    Sent,
    /// The kernel could not accept the datagram; the agent should treat
    /// this as a no-op. The [`DropReason`] payload identifies the underlying
    /// cause and lets operators distinguish "observer absent" from "peer gone"
    /// from "kernel pressure" from "disk full".
    Dropped(DropReason),
    /// An unexpected I/O error surfaced from the underlying `send(2)`.
    /// Callers wanting an `io::Error` can call [`BeatError::to_io_error`].
    Failed(BeatError),
}

impl fmt::Debug for BeatOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sent => write!(f, "Sent"),
            Self::Dropped(r) => write!(f, "Dropped({r:?})"),
            Self::Failed(e) => write!(f, "Failed({e:?})"),
        }
    }
}

impl fmt::Display for BeatOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sent => write!(f, "sent"),
            Self::Dropped(r) => write!(f, "dropped: {r}"),
            Self::Failed(e) => write!(f, "failed: {e}"),
        }
    }
}

/// Agent-side handle that owns a configured [`BeatTransport`] and a 32-byte
/// scratch buffer.
///
/// `Varta::connect` is the single allocation point: it creates the transport,
/// switches it to non-blocking mode (where applicable), and captures the epoch
/// used for monotonic timestamps. The process ID is fetched afresh via
/// [`std::process::id`] on every [`beat`](Self::beat) so forked children
/// report their own PID. Every subsequent `beat()` reuses the owned buffer
/// and emits a frame without touching the heap.
///
/// The default transport is [`UdsTransport`] (Unix Domain Socket). Use
/// `Varta::connect()` to create a UDS-backed agent. Other transports (e.g.
/// UDP) are available behind feature flags.
///
/// # Examples
///
/// ```no_run
/// use varta_client::{Status, Varta};
/// let mut agent = Varta::connect("/tmp/varta.sock")?;
/// agent.beat(Status::Ok, 0);
/// # Ok::<(), std::io::Error>(())
/// ```
/// # Thread safety
///
/// `Varta` is [`Send`]: the underlying transport is `Send`, and a beat
/// issues no shared state. `Varta` is **not** [`Sync`]: concurrent
/// `&Varta::beat` calls would race on the kernel-side socket send buffer
/// ordering. To share across threads, wrap in a [`std::sync::Mutex`] or move
/// the handle into a dedicated emitter thread or channel.
///
/// After `fork(2)` the child inherits this handle. Fork is **auto-detected**
/// on the next [`beat`](Self::beat): if `std::process::id()` differs from the
/// PID captured at [`connect`](Self::connect) time, the underlying transport's
/// [`reconnect`](crate::transport::BeatTransport::reconnect) is invoked
/// **before** the frame is built. On secure-UDP this re-reads OS entropy and
/// rotates the AEAD session salt, making catastrophic nonce reuse across the
/// fork boundary structurally impossible. The recovery is silent — the caller
/// sees [`BeatOutcome::Sent`] — and is observable via
/// [`fork_recoveries`](Self::fork_recoveries). Calling
/// [`reconnect`](Self::reconnect) explicitly in the child is still supported
/// and idempotent.
pub struct Varta<T: BeatTransport = UdsTransport> {
    transport: T,
    buf: [u8; 32],
    start: Instant,
    nonce: u64,
    consecutive_dropped: u32,
    reconnect_after: u32,
    last_timestamp: u64,
    clock_regressions: u64,
    /// PID captured at `connect` / `reconnect` time. Compared against
    /// `std::process::id()` on every [`beat`](Self::beat) to detect `fork(2)`
    /// and trigger transport refresh before any frame leaves the process.
    /// See the struct-level docstring for the safety contract.
    connect_pid: u32,
    /// Saturating count of fork-recovery events surfaced via
    /// [`fork_recoveries`](Self::fork_recoveries).
    fork_recoveries: u64,
}

// Static assertion: Varta<UdsTransport> is Send and must remain so.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<Varta<UdsTransport>>();
};

impl Varta<UdsTransport> {
    /// Connect to the observer listening on `path` via Unix Domain Socket and
    /// prepare the agent for non-blocking emission.
    ///
    /// Stores an `Instant` for per-frame elapsed-nanosecond timestamps. The
    /// process ID is read afresh on every [`Varta::beat`] via
    /// [`std::process::id`] so each frame carries the current PID. Subsequent
    /// calls to [`Varta::beat`] do not allocate.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the socket cannot be created, the peer
    /// path cannot be reached, or non-blocking mode cannot be enabled.
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let transport = UdsTransport::connect(path)?;
        Ok(Self {
            transport,
            buf: [0u8; 32],
            start: Instant::now(),
            nonce: 0,
            consecutive_dropped: 0,
            reconnect_after: 0,
            last_timestamp: 0,
            clock_regressions: 0,
            connect_pid: std::process::id(),
            fork_recoveries: 0,
        })
    }
}

#[cfg(feature = "udp")]
impl Varta<UdpTransport> {
    /// Connect to the observer listening on `addr` via UDP and prepare the
    /// agent for non-blocking emission.
    ///
    /// The socket is bound to an ephemeral source port and connected to the
    /// target address. On a connected UDP socket, `send` writes to the fixed
    /// peer and ICMP errors (e.g. port-unreachable) are surfaced as I/O
    /// errors handled by [`classify_send_error`].
    ///
    /// UDP semantics: there is no connection state — `beat()` returns
    /// [`BeatOutcome::Sent`] even if no observer is listening. The observer
    /// must be bound before the first beat is emitted. Reconnect creates a
    /// fresh ephemeral socket.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the socket cannot be created, connected,
    /// or switched to non-blocking mode.
    pub fn connect_udp(addr: std::net::SocketAddr) -> io::Result<Self> {
        let transport = UdpTransport::connect(addr)?;
        Ok(Self {
            transport,
            buf: [0u8; 32],
            start: Instant::now(),
            nonce: 0,
            consecutive_dropped: 0,
            reconnect_after: 0,
            last_timestamp: 0,
            clock_regressions: 0,
            connect_pid: std::process::id(),
            fork_recoveries: 0,
        })
    }
}

#[cfg(feature = "secure-udp")]
impl Varta<SecureUdpTransport> {
    /// Connect to the observer listening on `addr` via secure UDP
    /// (ChaCha20-Poly1305 AEAD) and prepare the agent for non-blocking
    /// emission.
    ///
    /// Every [`beat`](Self::beat) is encrypted and authenticated with the
    /// provided pre-shared `key`. The observer must be configured with the
    /// same key and the `secure-udp` feature enabled.
    ///
    /// The IV random prefix is read from `/dev/urandom` at connect time —
    /// no file I/O on the beat path.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the socket cannot be created, connected,
    /// or switched to non-blocking mode.
    pub fn connect_secure_udp(addr: std::net::SocketAddr, key: Key) -> io::Result<Self> {
        let transport = SecureUdpTransport::connect(addr, key)?;
        Ok(Self {
            transport,
            buf: [0u8; 32],
            start: Instant::now(),
            nonce: 0,
            consecutive_dropped: 0,
            reconnect_after: 0,
            last_timestamp: 0,
            clock_regressions: 0,
            connect_pid: std::process::id(),
            fork_recoveries: 0,
        })
    }

    /// Connect via ChaCha20-Poly1305 AEAD over UDP using a master key.
    ///
    /// The per-agent key is derived via
    /// [`varta_vlp::crypto::kdf::derive_agent_key`] from the master key
    /// and the calling process's PID. The PID is also embedded in the
    /// `iv_random` prefix so the observer can derive the same agent key
    /// before decrypting the frame.
    ///
    /// Per-agent keys mean that compromise of one agent's derived key
    /// does not reveal other agents' keys or the master key.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the socket cannot be created, connected,
    /// or switched to non-blocking mode.
    pub fn connect_secure_udp_with_master(
        addr: std::net::SocketAddr,
        master_key: Key,
    ) -> io::Result<Self> {
        let transport = SecureUdpTransport::connect_with_master(addr, master_key)?;
        Ok(Self {
            transport,
            buf: [0u8; 32],
            start: Instant::now(),
            nonce: 0,
            consecutive_dropped: 0,
            reconnect_after: 0,
            last_timestamp: 0,
            clock_regressions: 0,
            connect_pid: std::process::id(),
            fork_recoveries: 0,
        })
    }

    /// Test-only: fast-forward the AEAD counter on the underlying transport
    /// so the next beat exercises the counter-wrap rotation path without
    /// emitting 2^32 beats. H6 integration test surface.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_iv_counter_for_test(&mut self, value: u32) {
        self.transport.set_iv_counter_for_test(value);
    }

    /// Test-only: read the currently-derived 8-byte IV prefix.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn iv_prefix_for_test(&self) -> [u8; 8] {
        self.transport.iv_prefix_for_test()
    }

    /// Test-only: read the current prefix index.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn iv_prefix_index_for_test(&self) -> u32 {
        self.transport.iv_prefix_index_for_test()
    }

    /// Test-only: read the currently-committed AEAD counter. Pairs with
    /// `set_iv_counter_for_test` to assert commit-on-success semantics on
    /// `BeatTransport::send` — a `Dropped` beat must NOT advance this value.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn iv_counter_for_test(&self) -> u32 {
        self.transport.iv_counter_for_test()
    }
}

impl<T: BeatTransport> Varta<T> {
    /// Test-only: spoof the connect-time PID snapshot so the next
    /// [`beat`](Self::beat) trips the fork-detection branch without an
    /// actual `fork(2)` syscall. Pair with the transport-level
    /// `iv_prefix_for_test()` accessor to assert that the IV salt rotated.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn set_connect_pid_for_test(&mut self, pid: u32) {
        self.connect_pid = pid;
    }
}

/// Nonce-wraparound warning emitted once per connection lifetime.
///
/// Writes a static message to stderr without heap allocation — no
/// [`format!`] and no [`eprintln!`].  Practically unreachable under
/// any realistic beat rate (hundreds of millions of years), but kept
/// as a diagnostic signal for correctness audits.
#[cold]
fn warn_nonce_wrapping() {
    let _ = io::stderr().write_all(b"[varta-client] nonce exhausted; wrapping to 0\n");
}

impl<T: BeatTransport> Varta<T> {
    fn send_frame(&mut self) -> BeatOutcome {
        match self.transport.send(&self.buf) {
            Ok(_) => BeatOutcome::Sent,
            Err(e) => classify_send_error(&e),
        }
    }

    /// Emit a single VLP frame carrying `status` and an opaque 8-byte
    /// `payload`.
    ///
    /// The nonce increments first (starting from 1) and wraps to 0 on
    /// exhaustion; the very first beat after `connect` carries `nonce == 1`. The frame is
    /// constructed on the stack, encoded into the owned scratch buffer, and
    /// handed to `send(2)`. The steady-state path (`Sent` / `Dropped`) neither
    /// blocks nor allocates; the rare `Failed` path may allocate when cloning
    /// the underlying [`io::Error`].
    ///
    /// When [`set_reconnect_after`](Self::set_reconnect_after) is enabled and
    /// the consecutive-dropped threshold is crossed, `beat` will internally
    /// reconnect the socket and retry the send before returning. The retry
    /// path allocates a fresh socket; this is acceptable because observer
    /// restarts are rare and the steady-state path remains allocation-free.
    pub fn beat(&mut self, status: Status, payload: u32) -> BeatOutcome {
        let pid = std::process::id();
        if pid != self.connect_pid {
            // Fork detected. Refresh the underlying transport so any
            // session-keyed state (e.g. secure-UDP iv_session_salt /
            // iv_prefix_index / iv_counter) is re-seeded from OS entropy
            // before the next frame is built. This is the only correct
            // response to a fork on the secure path — without it, the
            // child would derive the same 12-byte AEAD nonce its parent
            // has already used under the same ChaCha20-Poly1305 key.
            //
            // Reset the local epoch and frame counters so the child's
            // wire stream looks like a fresh session to the observer
            // (per-pid tracker keying makes this safe).
            match self.transport.reconnect() {
                Ok(()) => {
                    self.connect_pid = pid;
                    self.fork_recoveries = self.fork_recoveries.saturating_add(1);
                    self.nonce = 0;
                    self.start = Instant::now();
                    self.last_timestamp = 0;
                    self.consecutive_dropped = 0;
                }
                Err(e) => return BeatOutcome::Failed(BeatError::from_io(&e)),
            }
        }
        if self.nonce < NONCE_TERMINAL - 1 {
            self.nonce += 1;
        } else {
            warn_nonce_wrapping();
            self.nonce = 0;
        }
        // Saturate the nanosecond timestamp at `u64::MAX as u128` so the cast
        // never wraps. `u64::MAX` itself is reserved as a wire-level sentinel
        // (`DecodeError::BadTimestamp`); reaching it would require ~584.5
        // years of continuous uptime on a single connect handle, which is
        // physically unreachable. Note the resulting decode/encode asymmetry:
        // a hypothetical saturated agent observes `BeatOutcome::Sent` from
        // `send(2)` while the observer drops the frame as `BadTimestamp`.
        // Documented for completeness; matches `Frame::decode` in
        // `varta-vlp/src/lib.rs`.
        let raw_elapsed = self.start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        if raw_elapsed < self.last_timestamp {
            // Underlying Instant::now() regressed — surface via the counter
            // while preserving wire-format monotonicity through the .max()
            // clamp below.
            self.clock_regressions = self.clock_regressions.saturating_add(1);
        }
        self.last_timestamp = self.last_timestamp.max(raw_elapsed);
        let timestamp = self.last_timestamp;
        debug_assert!(
            self.nonce != NONCE_TERMINAL,
            "regular beat nonce must not equal NONCE_TERMINAL sentinel"
        );
        let frame = Frame::new(status, pid, timestamp, self.nonce, payload);
        frame.encode(&mut self.buf);
        let outcome = self.send_frame();
        match &outcome {
            BeatOutcome::Dropped(_) => {
                self.consecutive_dropped = self.consecutive_dropped.saturating_add(1);
                if self.reconnect_after > 0
                    && self.consecutive_dropped >= self.reconnect_after
                    && self.transport.reconnect().is_ok()
                {
                    let retry = self.send_frame();
                    self.consecutive_dropped = 0;
                    return retry;
                }
                outcome
            }
            _ => {
                self.consecutive_dropped = 0;
                outcome
            }
        }
    }

    /// Re-establish the underlying transport connection.
    ///
    /// After an observer restart the old channel is stale — every `beat()`
    /// returns [`BeatOutcome::Dropped`] (with reason [`DropReason::PeerGone`]
    /// or [`DropReason::NoObserver`]) until reconnected. Call `reconnect` to establish
    /// a fresh connection to the target stored at [`connect`](Self::connect)
    /// time. Agent identity (`nonce`, `start` clock) is preserved.
    ///
    /// Also refreshes the internal fork-detection snapshot so an explicit
    /// reconnect issued from a forked child (the documented manual escape
    /// hatch) cannot leave a stale parent PID behind that would re-trigger
    /// auto-recovery on the next beat.
    ///
    /// This is the only post-[`connect`](Self::connect) allocation site and
    /// should only be called when recovery is needed, not on the steady-state
    /// beat path.
    pub fn reconnect(&mut self) -> io::Result<()> {
        self.transport.reconnect()?;
        self.connect_pid = std::process::id();
        Ok(())
    }

    /// Enable automatic reconnect after `n` consecutive
    /// [`BeatOutcome::Dropped`] outcomes. Set to `0` to disable (the
    /// default).
    ///
    /// When enabled, [`beat`](Self::beat) increments an internal counter on
    /// each `Dropped` outcome. After `n` consecutive drops — a strong signal
    /// that the observer channel is stale — `beat` calls [`reconnect`](Self::reconnect)
    /// internally and retries the send before returning. The counter resets
    /// to zero on any `Sent` or `Failed` outcome, and after a successful
    /// reconnect.
    ///
    /// Resets the internal consecutive-dropped counter to zero so that the
    /// new threshold gates future drops rather than immediately triggering
    /// on a past-saturated counter.
    pub fn set_reconnect_after(&mut self, n: u32) {
        self.reconnect_after = n;
        self.consecutive_dropped = 0;
    }

    /// Number of times [`beat`](Self::beat) has observed
    /// [`Instant::now`](std::time::Instant::now) regress since
    /// [`connect`](Self::connect). Saturating; never wraps.
    ///
    /// The wire-format timestamp remains monotonic because `beat()` clamps
    /// it through `.max()`, so a regression manifests on the wire as a
    /// duplicate timestamp rather than a backwards jump. A non-zero value
    /// here is the only in-process signal of the underlying platform-clock
    /// bug.
    ///
    /// Consumers wiring a Prometheus exporter SHOULD publish this as a
    /// counter named `varta_client_clock_regression_total`.
    pub fn clock_regressions(&self) -> u64 {
        self.clock_regressions
    }

    /// Number of times [`beat`](Self::beat) has observed a `fork(2)`
    /// transition (i.e. `std::process::id()` differing from the PID captured
    /// at [`connect`](Self::connect) time) and refreshed the underlying
    /// transport in response. Saturating; never wraps.
    ///
    /// A non-zero value is the operational signal that auto-recovery has
    /// fired. On the secure-UDP transport, each event corresponds to one
    /// AEAD session-salt rotation in the forked child — the structural
    /// guarantee against nonce reuse across the fork boundary.
    ///
    /// Consumers wiring a Prometheus exporter SHOULD publish this as a
    /// counter named `varta_client_fork_recoveries_total`.
    pub fn fork_recoveries(&self) -> u64 {
        self.fork_recoveries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixDatagram;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Bind a fresh UDS listener at a unique tempdir path and return both
    /// the listener (kept alive by the caller) and its path. The listener
    /// silently drops every datagram — enough to satisfy `Varta::connect`.
    ///
    /// The path embeds (pid, nanos, atomic counter). The counter guards
    /// against same-process collisions when two unit tests in the same
    /// `cargo test` run hit the same `SystemTime::now()` nanosecond value —
    /// observed on macOS CI runners where the clock granularity is coarser
    /// than on Apple Silicon. Without the counter, parallel test execution
    /// can produce `AlreadyExists` from `create_dir`.
    fn bind_listener() -> (UnixDatagram, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TEMPDIR_COUNTER: AtomicU64 = AtomicU64::new(0);

        let counter = TEMPDIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "varta-clock-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            counter
        ));
        std::fs::create_dir(&dir).expect("create tempdir");
        // Cerebrum 2026-05-13: process-wide umask from a concurrent
        // UnixDatagram::bind elsewhere can strip the executable bit; force
        // 0o755 before any further open() inside this dir.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod 0o755");
        let sock_path = dir.join("varta.sock");
        let listener = UnixDatagram::bind(&sock_path).expect("bind listener");
        (listener, sock_path)
    }

    #[test]
    fn clock_regression_counter_stays_zero_on_forward_clock() {
        let (_listener, path) = bind_listener();
        let mut agent = Varta::connect(&path).expect("connect");
        // Outcome is irrelevant; this test asserts on the regression counter
        // side effect, not the send result. The explicit `let _` discharges
        // the `#[must_use]` on `BeatOutcome`.
        let _ = agent.beat(Status::Ok, 0);
        let _ = agent.beat(Status::Ok, 0);
        assert_eq!(
            agent.clock_regressions(),
            0,
            "no regression should be observed on a forward clock"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }

    #[test]
    fn clock_regression_counter_increments_on_backwards_clock() {
        let (_listener, path) = bind_listener();
        let mut agent = Varta::connect(&path).expect("connect");

        // Jam the high-water mark past any plausible `start.elapsed()` so
        // every subsequent beat trips the regression branch.
        agent.last_timestamp = u64::MAX / 2;
        let baseline_ts = agent.last_timestamp;

        // Outcome is irrelevant; this test asserts on the regression counter
        // side effect. The explicit `let _` discharges `#[must_use]`.
        let _ = agent.beat(Status::Ok, 0);
        assert_eq!(agent.clock_regressions(), 1);
        // Wire timestamp must remain monotonic — `.max()` is unchanged.
        assert_eq!(agent.last_timestamp, baseline_ts);

        let _ = agent.beat(Status::Ok, 0);
        assert_eq!(
            agent.clock_regressions(),
            2,
            "counter must accumulate across consecutive regressions"
        );
        assert_eq!(agent.last_timestamp, baseline_ts);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }

    /// Steady-state (no fork): the recovery counter must stay at zero
    /// across many beats. This guards against accidental triggering of
    /// the fork-detection branch on a forward-only PID.
    #[test]
    fn same_pid_does_not_trigger_fork_recovery() {
        let (_listener, path) = bind_listener();
        let mut agent = Varta::connect(&path).expect("connect");
        for _ in 0..64 {
            let _ = agent.beat(Status::Ok, 0);
        }
        assert_eq!(
            agent.fork_recoveries(),
            0,
            "no fork-recovery should fire in a single-process beat loop"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }

    /// Spoof a PID change via the test hook. The next `beat()` must
    /// detect the mismatch, refresh the UDS transport, and increment
    /// the fork-recovery counter. The frame counter (`nonce`) resets so
    /// the post-recovery beat carries `nonce == 1`.
    #[test]
    fn spoofed_fork_triggers_uds_transport_reconnect() {
        let (_listener, path) = bind_listener();
        let mut agent = Varta::connect(&path).expect("connect");

        // Emit a few beats so the counters are non-trivial pre-fork.
        let _ = agent.beat(Status::Ok, 0);
        let _ = agent.beat(Status::Ok, 0);
        assert_eq!(agent.fork_recoveries(), 0);
        assert_eq!(agent.nonce, 2);

        // Spoof: pretend a fork happened. The actual pid is unchanged;
        // the snapshot we lie about is `connect_pid`.
        let real_pid = std::process::id();
        agent.set_connect_pid_for_test(real_pid.wrapping_add(1));

        // The next beat must observe the mismatch and recover.
        let _ = agent.beat(Status::Ok, 0);
        assert_eq!(
            agent.fork_recoveries(),
            1,
            "fork-recovery counter must increment exactly once"
        );
        assert_eq!(
            agent.connect_pid, real_pid,
            "connect_pid must be refreshed to the current pid"
        );
        assert_eq!(
            agent.nonce, 1,
            "nonce must reset to 0 on recovery, then increment to 1 for the beat"
        );

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }

    /// A `BeatTransport` whose `reconnect()` always fails. Used to assert
    /// that a fork-recovery whose transport refresh fails surfaces as
    /// `BeatOutcome::Failed` *and* does not increment the counter.
    struct AlwaysFailReconnect {
        sent: u32,
    }

    impl BeatTransport for AlwaysFailReconnect {
        fn send(&mut self, _buf: &[u8; 32]) -> io::Result<usize> {
            self.sent = self.sent.saturating_add(1);
            Ok(32)
        }

        fn reconnect(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }

    fn varta_with_transport<T: BeatTransport>(transport: T) -> Varta<T> {
        Varta {
            transport,
            buf: [0u8; 32],
            start: Instant::now(),
            nonce: 0,
            consecutive_dropped: 0,
            reconnect_after: 0,
            last_timestamp: 0,
            clock_regressions: 0,
            connect_pid: std::process::id(),
            fork_recoveries: 0,
        }
    }

    #[test]
    fn fork_recovery_with_failing_reconnect_returns_failed() {
        let mut agent = varta_with_transport(AlwaysFailReconnect { sent: 0 });

        // Spoof a fork.
        agent.set_connect_pid_for_test(std::process::id().wrapping_add(1));

        let outcome = agent.beat(Status::Ok, 0);
        match outcome {
            BeatOutcome::Failed(e) => {
                assert_eq!(e.kind, io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected Failed on reconnect failure, got {other:?}"),
        }
        assert_eq!(
            agent.fork_recoveries(),
            0,
            "counter must NOT increment when the recovery transport refresh fails"
        );
        assert_eq!(
            agent.transport.sent, 0,
            "no frame should be sent when fork-recovery fails"
        );
    }

    /// Secure-UDP path: spoofing a fork must rotate the AEAD session salt
    /// and IV prefix. This is the load-bearing test — without salt
    /// rotation, the child would derive the parent's nonce stream under
    /// the same key.
    #[cfg(feature = "secure-udp")]
    #[test]
    fn spoofed_fork_rotates_secure_udp_session_salt() {
        use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
        use varta_vlp::crypto::Key;

        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9876, 0, 0));
        let key = Key::from_bytes([0x42; 32]);
        let mut agent = Varta::connect_secure_udp(addr, key).expect("connect");

        // Snapshot pre-fork crypto state.
        let prefix_before = agent.iv_prefix_for_test();

        // Spoof: pretend a fork happened.
        agent.set_connect_pid_for_test(std::process::id().wrapping_add(1));

        // The destination is a closed ephemeral address so the send may
        // fail at the network layer, but the fork-recovery + reconnect
        // logic runs before the syscall. The recovery and the IV
        // rotation are what we are asserting on.
        let _ = agent.beat(Status::Ok, 0);

        assert_eq!(
            agent.fork_recoveries(),
            1,
            "secure-UDP fork-recovery counter must increment"
        );
        let prefix_after = agent.iv_prefix_for_test();
        assert_ne!(
            prefix_before, prefix_after,
            "IV prefix must rotate on fork-recovery (defeats nonce reuse)"
        );
        assert_eq!(
            agent.iv_prefix_index_for_test(),
            0,
            "prefix_index must reset to 0 on transport.reconnect()"
        );
    }
}
