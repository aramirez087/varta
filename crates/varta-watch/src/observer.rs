//! Single-threaded observer: bind a Unix datagram socket, decode incoming
//! VLP frames, surface beats / stalls / decode errors via [`Event`].
//!
//! The observer never spawns threads, never allocates after [`Observer::bind`],
//! and surfaces exactly one [`Event`] per call to [`Observer::poll`]. The
//! caller drives the loop — see Session 05 for the daemon entrypoint.

use std::io::{self, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::{Duration, Instant};

use varta_vlp::{DecodeError, Frame, Status};

use crate::peer_cred::{self, RecvResult};
use crate::tracker::{Tracker, Update, CAPACITY};

/// How long [`Observer::poll`] blocks in `recv_from` before returning to the
/// caller. Bounded so stall detection latency cannot exceed this value.
const READ_TIMEOUT: Duration = Duration::from_millis(100);

/// Event surfaced by [`Observer::poll`].
///
/// Each call to `poll` returns at most one event. Unknown-pid overflow and
/// out-of-order beats are silently dropped at this layer; the bench / metrics
/// sessions can layer counters on top without changing this enum.
#[derive(Debug)]
pub enum Event {
    /// A well-formed beat was accepted for a tracked pid.
    Beat {
        /// OS process id of the emitting agent.
        pid: u32,
        /// Decoded health status of the beat.
        status: Status,
        /// Application-defined payload carried by the beat.
        payload: u64,
        /// Monotonic nonce of the beat.
        nonce: u64,
    },
    /// A tracked pid has not beaten within the configured threshold and the
    /// observer has not yet surfaced a stall event for this silence run.
    Stall {
        /// OS process id of the silent agent.
        pid: u32,
        /// Last nonce observed for this pid.
        last_nonce: u64,
        /// Observer-local timestamp (ns since [`Observer`] start) of the
        /// last accepted beat for this pid.
        last_ns: u64,
    },
    /// A 32-byte payload arrived but failed VLP decoding.
    Decode(DecodeError),
    /// Frame decoded but the `frame.pid` does not match the kernel-verified
    /// peer PID of the sender. The claimed pid is preserved so exporters can
    /// record what the frame *claimed* to be.
    AuthFailure {
        /// The pid the frame on the wire claimed to be.
        claimed_pid: u32,
    },
    /// Receiving from the socket failed with an error other than
    /// `WouldBlock` / `TimedOut`.
    Io(io::Error),
}

/// Observer process bound to a Unix Domain Socket.
///
/// The observer owns the socket file for its lifetime; dropping it does not
/// remove the file from disk (Session 05 owns the daemon shutdown sequence).
pub struct Observer {
    sock: UnixDatagram,
    tracker: Tracker,
    threshold_ns: u64,
    start: Instant,
    stall_queue: Vec<Option<Event>>,
    stall_pending: Vec<(u32, u64, u64)>,
    stall_cursor: usize,
}

impl Observer {
    /// Bind a Unix datagram socket at `path` and return an [`Observer`]
    /// configured with the given stall `threshold`.
    ///
    /// The socket file permissions are set to `socket_mode` (octal, e.g.
    /// `0o600`) immediately after a successful bind. Credential passing is
    /// enabled on the socket so that [`Observer::poll`] can verify the PID
    /// of every sender against the kernel's `SO_PASSCRED` / `LOCAL_CREDS`
    /// attestation.
    ///
    /// If a genuine stale socket exists at `path` (no one listening),
    /// it is cleaned up and the bind succeeds. If another process is
    /// already listening at `path`, the call fails with `AddrInUse`.
    /// If the path exists but the probe fails with
    /// `PermissionDenied`, the call fails — we cannot determine
    /// whether the socket is live and will not delete it.
    ///
    /// The socket is given a fixed read timeout (100 ms) so
    /// [`Observer::poll`] cannot block indefinitely.
    pub fn bind(path: impl AsRef<Path>, threshold: Duration, socket_mode: u32) -> io::Result<Self> {
        let path = path.as_ref();

        match UnixDatagram::bind(path) {
            Ok(sock) => {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(socket_mode))?;
                Self::finish_bind(sock, threshold)
            }
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                match probe_live(path) {
                    Ok(true) => Err(io::Error::new(
                        ErrorKind::AddrInUse,
                        format!(
                            "another varta-watch is already running at {}",
                            path.display()
                        ),
                    )),
                    Ok(false) => {
                        // Genuine stale socket — clean up and retry bind.
                        std::fs::remove_file(path)?;
                        let sock = UnixDatagram::bind(path)?;
                        std::fs::set_permissions(
                            path,
                            std::fs::Permissions::from_mode(socket_mode),
                        )?;
                        Self::finish_bind(sock, threshold)
                    }
                    Err(e) => Err(io::Error::new(
                        e.kind(),
                        format!("cannot probe socket at {}: {e}", path.display()),
                    )),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Receive at most one frame and return the corresponding [`Event`].
    ///
    /// Returns:
    /// - `Some(Event::Beat)` for an accepted, ordered frame.
    /// - `Some(Event::Decode(_))` if the next 32 bytes fail VLP decoding.
    /// - `Some(Event::Stall)` if the read timed out and a tracked pid has
    ///   crossed the configured threshold without yet being reported.
    /// - `Some(Event::Io(_))` for non-`WouldBlock` socket errors.
    /// - `None` if nothing actionable happened (timeout with no new stalls,
    ///   short reads, out-of-order beats, or capacity-exceeded inserts).
    pub fn poll(&mut self) -> Option<Event> {
        if self.stall_cursor < self.stall_queue.len() {
            let stall = self.stall_queue[self.stall_cursor].take();
            self.stall_cursor += 1;
            return stall;
        }

        match peer_cred::recv_authenticated(self.sock.as_raw_fd()) {
            RecvResult::Authenticated { peer_pid, data } => {
                let now_ns = self.now_ns();
                match Frame::decode(&data) {
                    Ok(frame) => {
                        // PID verification: on Linux the kernel provides
                        // SO_PASSCRED → SCM_CREDENTIALS with the true
                        // sender PID.  On macOS this mechanism is not
                        // available for unconnected SOCK_DGRAM, so we
                        // rely on --socket-mode 0600 to restrict access.
                        #[cfg(target_os = "linux")]
                        if frame.pid != peer_pid {
                            return Some(Event::AuthFailure {
                                claimed_pid: frame.pid,
                            });
                        }
                        let _ = peer_pid; // silence unused on macOS
                        match self.tracker.record(&frame, now_ns, self.threshold_ns) {
                            Update::Inserted | Update::Refreshed => {
                                let status = Status::try_from_u8(frame.status)
                                    .expect("Frame::decode validated the status byte");
                                Some(Event::Beat {
                                    pid: frame.pid,
                                    status,
                                    payload: frame.payload,
                                    nonce: frame.nonce,
                                })
                            }
                            Update::OutOfOrder | Update::CapacityExceeded => None,
                        }
                    }
                    Err(e) => Some(Event::Decode(e)),
                }
            }
            RecvResult::WouldBlock => {
                self.drain_stalls();
                if self.stall_cursor < self.stall_queue.len() {
                    let stall = self.stall_queue[self.stall_cursor].take();
                    self.stall_cursor += 1;
                    return stall;
                }
                None
            }
            RecvResult::ShortRead => None,
            RecvResult::IoError(e) => Some(Event::Io(e)),
        }
    }

    fn now_ns(&self) -> u64 {
        let elapsed = self.start.elapsed().as_nanos();
        elapsed.min(u64::MAX as u128) as u64
    }

    fn drain_stalls(&mut self) {
        let now_ns = self.now_ns();
        self.stall_queue.clear();
        self.stall_cursor = 0;
        self.stall_pending.clear();
        for slot in self
            .tracker
            .iter_stalled(now_ns, self.threshold_ns)
            .filter(|slot| !slot.stall_emitted)
        {
            self.stall_pending
                .push((slot.pid, slot.last_nonce, slot.last_ns));
        }
        for &(pid, last_nonce, last_ns) in &self.stall_pending {
            self.stall_queue.push(Some(Event::Stall {
                pid,
                last_nonce,
                last_ns,
            }));
            self.tracker.mark_stall_emitted(pid);
        }
    }

    /// Drain and reset the eviction counter. Returns the number of slots
    /// reclaimed since the last call.
    pub fn drain_evictions(&mut self) -> u64 {
        self.tracker.take_evictions()
    }

    fn finish_bind(sock: UnixDatagram, threshold: Duration) -> io::Result<Self> {
        sock.set_read_timeout(Some(READ_TIMEOUT))?;
        let raw_fd = sock.as_raw_fd();
        peer_cred::enable_credential_passing(raw_fd)?;
        let threshold_ns = threshold.as_nanos().min(u64::MAX as u128) as u64;
        Ok(Observer {
            sock,
            tracker: Tracker::new(),
            threshold_ns,
            start: Instant::now(),
            stall_queue: Vec::new(),
            stall_pending: Vec::with_capacity(CAPACITY),
            stall_cursor: 0,
        })
    }
}

/// Probe whether a live listener is accepting datagrams at `path`.
///
/// Strategy:
/// - Try to connect an unbound datagram socket to the path. On macOS this
///   fails immediately with ECONNREFUSED if no one is listening; on Linux it
///   may succeed (connect only sets default peer) so we fall through to send().
/// - If connect() succeeds, attempt a zero-byte send(). A live listener will
///   accept the datagram. A stale socket file with no listener will cause
///   ECONNREFUSED / ENOENT on send().
///
/// Returns:
/// - `Ok(true)` if we believe another process is listening (send succeeded).
/// - `Ok(false)` if connect() or send() fails in a way that indicates no
///   active listener — the socket file is stale and safe to remove.
/// - `Err` for PermissionDenied — we cannot determine liveness and must not
///   delete the file.
fn probe_live(path: &Path) -> io::Result<bool> {
    let sock = UnixDatagram::unbound()?;

    // On macOS, connect() to a dead UDS DGRAM returns ECONNREFUSED immediately.
    // On Linux, it may succeed (sets default peer only), so we must also check send().
    if let Err(e) = sock.connect(path) {
        return match e.kind() {
            ErrorKind::PermissionDenied => Err(e),
            _ => Ok(false), // ECONNREFUSED / ENOENT — no listener.
        };
    }

    // If connect() succeeded, try to send a zero-byte datagram. A live listener
    // will accept it; a stale socket file with no listener will reject it.
    match sock.send(&[]) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Err(e),
        Err(_) => Ok(false), // ECONNREFUSED / ENOTCONN — stale socket.
    }
}
