//! Agent surface — `Varta` connects to the observer's UDS and `beat()` emits
//! one fire-and-forget 32-byte VLP frame per call.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::time::Instant;

use varta_vlp::{Frame, Status, NONCE_TERMINAL};

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

        // (d) Unexpected error: clone heap-free and escalate.
        _ => {
            let cloned = match e.raw_os_error() {
                // Repr::Os(i32) — no heap allocation.
                Some(code) => io::Error::from_raw_os_error(code),
                // Repr::Simple(kind) — no heap allocation.
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
    /// allocate on the heap.
    Failed(io::Error),
}

/// Agent-side handle that owns a connected [`UnixDatagram`] and a 32-byte
/// scratch buffer.
///
/// `Varta::connect` is the single allocation point: it creates the socket,
/// switches it to non-blocking mode, and captures the epoch used for
/// monotonic timestamps. The process ID is fetched afresh via
/// [`std::process::id`] on every [`beat`](Self::beat) so forked children
/// report their own PID. Every subsequent `beat()` reuses the owned buffer
/// and emits a frame without touching the heap.
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
/// `Varta` is [`Send`]: the underlying [`UnixDatagram`] is `Send`, and a beat
/// issues no shared state. `Varta` is **not** [`Sync`]: concurrent
/// `&Varta::beat` calls would race on the kernel-side socket send buffer
/// ordering. To share across threads, wrap in a [`std::sync::Mutex`] or move
/// the handle into a dedicated emitter thread or channel.
///
/// The fork-safety contract (pid re-read per beat) is unaffected by the
/// thread-safety choice.
pub struct Varta {
    sock: UnixDatagram,
    buf: [u8; 32],
    start: Instant,
    nonce: u64,
    path: PathBuf,
    consecutive_dropped: u32,
    reconnect_after: u32,
}

// Static assertion: Varta is Send and must remain so.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<Varta>();
};

impl Varta {
    /// Connect to the observer listening on `path` and prepare the agent for
    /// non-blocking emission.
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
        let path = path.as_ref().to_path_buf();
        let sock = UnixDatagram::unbound()?;
        sock.connect(&path)?;
        sock.set_nonblocking(true)?;
        Ok(Self {
            sock,
            buf: [0u8; 32],
            start: Instant::now(),
            nonce: 0,
            path,
            consecutive_dropped: 0,
            reconnect_after: 0,
        })
    }

    fn send_frame(&mut self) -> BeatOutcome {
        match self.sock.send(&self.buf) {
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
    /// handed to `send(2)`. This call neither blocks nor allocates on the
    /// heap on the steady-state path.
    ///
    /// When [`set_reconnect_after`](Self::set_reconnect_after) is enabled and
    /// the consecutive-dropped threshold is crossed, `beat` will internally
    /// reconnect the socket and retry the send before returning. The retry
    /// path allocates a fresh socket; this is acceptable because observer
    /// restarts are rare and the steady-state path remains allocation-free.
    pub fn beat(&mut self, status: Status, payload: u64) -> BeatOutcome {
        self.nonce = self.nonce.saturating_add(1).min(NONCE_TERMINAL - 1);
        let timestamp = self.start.elapsed().as_nanos() as u64;
        let frame = Frame::new(status, std::process::id(), timestamp, self.nonce, payload);
        frame.encode(&mut self.buf);
        let outcome = self.send_frame();
        match &outcome {
            BeatOutcome::Dropped => {
                self.consecutive_dropped += 1;
                if self.reconnect_after > 0
                    && self.consecutive_dropped >= self.reconnect_after
                    && self.reconnect().is_ok()
                {
                    return self.send_frame();
                }
                outcome
            }
            _ => {
                self.consecutive_dropped = 0;
                outcome
            }
        }
    }

    /// Re-bind the Unix datagram socket to the original observer path.
    ///
    /// After an observer restart the old socket inode is stale — every
    /// `beat()` returns [`BeatOutcome::Dropped`] forever. Call `reconnect`
    /// to bind a fresh socket against the path stored at [`connect`](Self::connect)
    /// time. Agent identity (`nonce`, `start` clock) is preserved; the PID
    /// is re-read from the kernel on every beat so reconnect cannot strand
    /// a stale identity.
    ///
    /// This is the only post-[`connect`](Self::connect) allocation site and
    /// should only be called when recovery is needed, not on the steady-state
    /// beat path.
    pub fn reconnect(&mut self) -> io::Result<()> {
        let sock = UnixDatagram::unbound()?;
        sock.connect(&self.path)?;
        sock.set_nonblocking(true)?;
        self.sock = sock;
        self.consecutive_dropped = 0;
        Ok(())
    }

    /// Enable automatic reconnect after `n` consecutive
    /// [`BeatOutcome::Dropped`] outcomes. Set to `0` to disable (the
    /// default).
    ///
    /// When enabled, [`beat`](Self::beat) increments an internal counter on
    /// each `Dropped` outcome. After `n` consecutive drops — a strong signal
    /// that the observer socket is stale — `beat` calls [`reconnect`](Self::reconnect)
    /// internally and retries the send before returning. The counter resets
    /// to zero on any `Sent` or `Failed` outcome, and after a successful
    /// reconnect.
    pub fn set_reconnect_after(&mut self, n: u32) {
        self.reconnect_after = n;
    }
}
