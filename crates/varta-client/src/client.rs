//! Agent surface — `Varta` connects to the observer over a configured
//! transport and `beat()` emits one fire-and-forget 32-byte VLP frame per call.

use std::io;
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

/// Linux value of `ENOBUFS` from `<asm-generic/errno.h>`. Hard-coded to
/// preserve the zero-dependency invariant; do not replace with `libc`.
#[cfg(target_os = "linux")]
const ENOBUFS: i32 = 105;

/// Darwin / BSD value of `ENOBUFS` from `<sys/errno.h>`. Hard-coded for
/// the same reason.
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
/// toolchain maps it to `ErrorKind::Other`. The `Failed` branch constructs
/// the returned error without heap allocation.
pub fn classify_send_error(e: &io::Error) -> BeatOutcome {
    // (a) Raw-OS path first — catches ENOBUFS even when libstd has not
    //     minted a dedicated ErrorKind for it on this toolchain.
    if let Some(code) = e.raw_os_error() {
        if code == ENOBUFS {
            return BeatOutcome::Dropped;
        }
    }

    match e.kind() {
        // (b) Peer not present or channel transiently full.
        io::ErrorKind::WouldBlock
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotFound
        | io::ErrorKind::NotConnected
        | io::ErrorKind::BrokenPipe
        // (c) Belt-and-braces: covers toolchains that surface ENOBUFS as a
        //     kind rather than a raw_os_error.
        | io::ErrorKind::OutOfMemory
        | io::ErrorKind::StorageFull => BeatOutcome::Dropped,

        // (d) Unexpected error: clone and escalate.
        //     This is on the Failed path (not steady-state), so a possible
        //     allocation inside io::Error is acceptable.
        _ => {
            let cloned = match e.raw_os_error() {
                // Repr::Os(i32) — platform-alloc-free.
                Some(code) => io::Error::from_raw_os_error(code),
                // Repr::Simple(kind) or Repr::Custom — may allocate.
                None => io::Error::from(e.kind()),
            };
            BeatOutcome::Failed(cloned)
        }
    }
}

/// Result of a single [`Varta::beat`] call.
///
/// `beat()` never blocks and never panics; the kernel's view of the send is
/// translated into one of three steady-state outcomes. `Failed` carries the
/// underlying error untouched for higher layers that wish to log or escalate.
#[derive(Debug)]
#[must_use]
pub enum BeatOutcome {
    /// The 32-byte datagram was accepted by the kernel.
    Sent,
    /// The kernel could not accept the datagram and the agent should treat
    /// this as a no-op. Possible causes: the observer is not listening, the
    /// socket file vanished, or the per-socket queue is full
    /// (`WouldBlock` under non-blocking I/O).
    Dropped,
    /// An unexpected I/O error surfaced from the underlying `send(2)`. The
    /// inner [`io::Error`] is forwarded verbatim; constructing it does not
    /// allocate on the heap. Callers must inspect the error rather than
    /// silently discarding it with `Failed(_)`.
    Failed(io::Error),
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
/// The fork-safety contract (pid re-read per beat) is unaffected by the
/// thread-safety choice.
pub struct Varta<T: BeatTransport = UdsTransport> {
    transport: T,
    buf: [u8; 32],
    start: Instant,
    nonce: u64,
    consecutive_dropped: u32,
    reconnect_after: u32,
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
    /// process ID is intentionally not cached here — it is read afresh on
    /// every [`Varta::beat`] via [`std::process::id`] so a child that forks
    /// after `connect` reports its own PID, not the parent's. Subsequent
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
        })
    }
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
    /// The nonce increments first (capping at `NONCE_TERMINAL - 1`), so the
    /// very first beat after `connect` carries `nonce == 1`. The frame is
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
    pub fn beat(&mut self, status: Status, payload: u64) -> BeatOutcome {
        if self.nonce < NONCE_TERMINAL - 1 {
            self.nonce += 1;
        }
        let timestamp = self.start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        let frame = Frame::new(status, std::process::id(), timestamp, self.nonce, payload);
        frame.encode(&mut self.buf);
        let outcome = self.send_frame();
        match &outcome {
            BeatOutcome::Dropped => {
                self.consecutive_dropped = self.consecutive_dropped.saturating_add(1);
                if self.reconnect_after > 0
                    && self.consecutive_dropped >= self.reconnect_after
                    && self.transport.reconnect().is_ok()
                {
                    let retry = self.send_frame();
                    if matches!(&retry, BeatOutcome::Dropped) {
                        self.consecutive_dropped = self.reconnect_after;
                    } else {
                        self.consecutive_dropped = 0;
                    }
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
    /// returns [`BeatOutcome::Dropped`] forever. Call `reconnect` to establish
    /// a fresh connection to the target stored at [`connect`](Self::connect)
    /// time. Agent identity (`nonce`, `start` clock) is preserved.
    ///
    /// This is the only post-[`connect`](Self::connect) allocation site and
    /// should only be called when recovery is needed, not on the steady-state
    /// beat path.
    pub fn reconnect(&mut self) -> io::Result<()> {
        self.transport.reconnect()
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
    pub fn set_reconnect_after(&mut self, n: u32) {
        self.reconnect_after = n;
    }
}
