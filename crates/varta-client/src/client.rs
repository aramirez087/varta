//! Agent surface — `Varta` connects to the observer's UDS and `beat()` emits
//! one fire-and-forget 32-byte VLP frame per call.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::Instant;

use varta_vlp::{Frame, Status, MAGIC, VERSION};

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
/// switches it to non-blocking mode, and captures process identity plus the
/// epoch used for monotonic timestamps. Every subsequent `beat()` reuses the
/// owned buffer and emits a frame without touching the heap.
///
/// # Examples
///
/// ```no_run
/// use varta_client::{Status, Varta};
/// let mut agent = Varta::connect("/tmp/varta.sock")?;
/// agent.beat(Status::Ok, 0);
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct Varta {
    sock: UnixDatagram,
    buf: [u8; 32],
    pid: u32,
    start: Instant,
    nonce: u64,
}

impl Varta {
    /// Connect to the observer listening on `path` and prepare the agent for
    /// non-blocking emission.
    ///
    /// Captures `std::process::id()` once and stores an `Instant` for
    /// per-frame elapsed-nanosecond timestamps. Subsequent calls to
    /// [`Varta::beat`] do not allocate.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the socket cannot be created, the peer
    /// path cannot be reached, or non-blocking mode cannot be enabled.
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let sock = UnixDatagram::unbound()?;
        sock.connect(path.as_ref())?;
        sock.set_nonblocking(true)?;
        Ok(Self {
            sock,
            buf: [0u8; 32],
            pid: std::process::id(),
            start: Instant::now(),
            nonce: 0,
        })
    }

    /// Emit a single VLP frame carrying `status` and an opaque 8-byte
    /// `payload`.
    ///
    /// The nonce increments first (saturating at `u64::MAX`), so the very
    /// first beat after `connect` carries `nonce == 1`. The frame is
    /// constructed on the stack, encoded into the owned scratch buffer, and
    /// handed to `send(2)`. This call neither blocks nor allocates on the
    /// heap.
    pub fn beat(&mut self, status: Status, payload: u64) -> BeatOutcome {
        self.nonce = self.nonce.saturating_add(1);
        let timestamp = self.start.elapsed().as_nanos() as u64;
        let frame = Frame {
            magic: MAGIC,
            version: VERSION,
            status: status as u8,
            pid: self.pid,
            timestamp,
            nonce: self.nonce,
            payload,
        };
        frame.encode(&mut self.buf);
        match self.sock.send(&self.buf) {
            Ok(_) => BeatOutcome::Sent,
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::NotFound
                | io::ErrorKind::NotConnected
                | io::ErrorKind::BrokenPipe => BeatOutcome::Dropped,
                _ => BeatOutcome::Failed(e),
            },
        }
    }
}
