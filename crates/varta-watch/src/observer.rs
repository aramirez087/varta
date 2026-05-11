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
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use varta_vlp::{DecodeError, Frame, Status};

use crate::peer_cred::{self, RecvResult};
use crate::tracker::{Tracker, Update, CAPACITY};

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
        /// Observer-local timestamp (ns since [`Observer`] start) when this
        /// event was produced.
        observer_ns: u64,
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
        /// Observer-local timestamp (ns since [`Observer`] start) when this
        /// stall event was produced.
        observer_ns: u64,
    },
    /// A 32-byte payload arrived but failed VLP decoding.
    Decode(DecodeError, u64),
    /// Frame decoded but the `frame.pid` does not match the kernel-verified
    /// peer PID of the sender. The claimed pid is preserved so exporters can
    /// record what the frame *claimed* to be.
    AuthFailure {
        /// The pid the frame on the wire claimed to be.
        claimed_pid: u32,
        /// Observer-local timestamp (ns since [`Observer`] start) when this
        /// event was produced.
        observer_ns: u64,
    },
    /// Receiving from the socket failed with an error other than
    /// `WouldBlock` / `TimedOut`.
    Io(io::Error, u64),
}

/// Owns the responsibility for unlinking the UDS file node when the
/// observer shuts down. Checks device + inode before removing to avoid
/// touching a foreign socket that won a later race.  Errors are swallowed
/// because [`Drop`] must never panic.
///
/// This is a separate type so that observers do not own their own cleanup
/// — a caller (e.g. the daemon binary) can hold a [`Vec<SocketGuard>`]
/// and manage lifecycle explicitly.
pub struct SocketGuard {
    path: PathBuf,
    bound_dev: u64,
    bound_ino: u64,
}

/// Observer process bound to a Unix Domain Socket.
///
/// The observer does **not** own the socket file — the caller receives a
/// [`SocketGuard`] from [`Observer::bind`] and is responsible for cleanup.
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
    /// configured with the given stall `threshold`, together with a
    /// [`SocketGuard`] that unlinks the socket file on drop.
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
    /// The socket is given a read timeout so [`Observer::poll`] cannot
    /// block indefinitely. Pass `read_timeout` to override the default
    /// (100 ms).
    pub fn bind(
        path: impl AsRef<Path>,
        threshold: Duration,
        socket_mode: u32,
        read_timeout: Duration,
    ) -> io::Result<(Self, SocketGuard)> {
        let path = path.as_ref();
        let owned_path: PathBuf = path.to_path_buf();

        match UnixDatagram::bind(path) {
            Ok(sock) => {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(socket_mode))?;
                Self::finish_bind(sock, threshold, owned_path, read_timeout)
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
                        Self::finish_bind(sock, threshold, owned_path, read_timeout)
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

    /// Attempt a single non-blocking read from the socket and return the
    /// corresponding I/O [`Event`].
    ///
    /// This method never returns [`Event::Stall`] — queued stall events must
    /// be retrieved via [`Observer::poll_pending`].  Callers should check
    /// [`Observer::has_pending_stalls`] before calling `poll` to ensure
    /// previously-queued stalls are drained first.
    ///
    /// Returns:
    /// - `Some(Event::Beat)` for an accepted, ordered frame.
    /// - `Some(Event::Decode(_))` if the next 32 bytes fail VLP decoding.
    /// - `Some(Event::Io(_))` for non-`WouldBlock` socket errors.
    /// - `Some(Event::AuthFailure)` if the frame pid does not match the
    ///   kernel-attested sender (Linux only; on macOS this check is
    ///   unavailable for unconnected `SOCK_DGRAM`).
    /// - `None` if no I/O was available (`WouldBlock`), the read was a
    ///   short read, the beat was out-of-order, or capacity was exceeded.
    ///   `WouldBlock` internally triggers [`Observer::drain_stalls`], which
    ///   populates the stall queue for subsequent `poll_pending` calls.
    pub fn poll(&mut self) -> Option<Event> {
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
                                observer_ns: now_ns,
                            });
                        }
                        let _ = peer_pid; // silence unused on macOS
                        match self.tracker.record(&frame, now_ns, self.threshold_ns) {
                            Update::Inserted | Update::Refreshed => Some(Event::Beat {
                                pid: frame.pid,
                                status: frame.status,
                                payload: frame.payload,
                                nonce: frame.nonce,
                                observer_ns: now_ns,
                            }),
                            Update::OutOfOrder | Update::CapacityExceeded => None,
                        }
                    }
                    Err(e) => Some(Event::Decode(e, now_ns)),
                }
            }
            RecvResult::WouldBlock => {
                self.drain_stalls();
                None
            }
            RecvResult::ShortRead => None,
            RecvResult::IoError(e) => Some(Event::Io(e, self.now_ns())),
        }
    }

    /// Return the next queued [`Event::Stall`], if any.
    ///
    /// Stalls are queued internally by [`Observer::drain_stalls`] (which
    /// runs on `WouldBlock` inside [`Observer::poll`]).  Callers should
    /// drain all pending stalls before calling `poll` for new I/O to
    /// minimize stall-latency.
    pub fn poll_pending(&mut self) -> Option<Event> {
        if self.stall_cursor < self.stall_queue.len() {
            let stall = self.stall_queue[self.stall_cursor].take();
            self.stall_cursor += 1;
            return stall;
        }
        None
    }

    /// Whether the stall queue has unconsumed [`Event::Stall`] entries.
    pub fn has_pending_stalls(&self) -> bool {
        self.stall_cursor < self.stall_queue.len()
    }

    fn now_ns(&self) -> u64 {
        let elapsed = self.start.elapsed().as_nanos();
        elapsed.min(u64::MAX as u128) as u64
    }

    fn drain_stalls(&mut self) {
        debug_assert!(
            self.stall_cursor >= self.stall_queue.len(),
            "drain_stalls called with unconsumed stall events"
        );
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
                observer_ns: now_ns,
            }));
            self.tracker.mark_stall_emitted(pid);
        }
    }

    /// Drain and reset the eviction counter. Returns the number of slots
    /// reclaimed since the last call.
    pub fn drain_evictions(&mut self) -> u64 {
        self.tracker.take_evictions()
    }

    /// Drain and reset the capacity-exceeded counter. Returns the number
    /// of beats dropped due to a full tracker since the last call.
    pub fn drain_capacity_exceeded(&mut self) -> u64 {
        self.tracker.take_capacity_exceeded()
    }

    fn finish_bind(
        sock: UnixDatagram,
        threshold: Duration,
        path: PathBuf,
        read_timeout: Duration,
    ) -> io::Result<(Self, SocketGuard)> {
        use std::os::unix::fs::MetadataExt;

        sock.set_read_timeout(Some(read_timeout))?;
        let raw_fd = sock.as_raw_fd();
        peer_cred::enable_credential_passing(raw_fd)?;
        let threshold_ns = threshold.as_nanos().min(u64::MAX as u128) as u64;

        let meta = std::fs::metadata(&path)?;
        let bound_dev = meta.dev();
        let bound_ino = meta.ino();

        let guard = SocketGuard {
            path,
            bound_dev,
            bound_ino,
        };

        Ok((
            Observer {
                sock,
                tracker: Tracker::new(),
                threshold_ns,
                start: Instant::now(),
                stall_queue: Vec::with_capacity(CAPACITY),
                stall_pending: Vec::with_capacity(CAPACITY),
                stall_cursor: 0,
            },
            guard,
        ))
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

impl Drop for SocketGuard {
    /// Unlink the socket file iff the on-disk inode still matches the one
    /// captured at bind time. Errors are swallowed: `drop` must never panic
    /// (including during stack unwinding), the file may have been removed by
    /// another process, and library code must not emit diagnostics.
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.dev() == self.bound_dev && meta.ino() == self.bound_ino {
                let _ = std::fs::remove_file(&self.path);
            }
        }
        // Missing file or foreign inode → silent no-op.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_sock_path() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "varta-observer-drop-{}-{}.sock",
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn drop_unlinks_bound_socket() {
        let path = unique_sock_path();
        let (obs, guard) = Observer::bind(
            &path,
            Duration::from_secs(1),
            0o600,
            Duration::from_millis(100),
        )
        .expect("bind should succeed on a clean temp path");
        assert!(path.exists(), "socket file must exist after bind");
        drop(obs);
        assert!(
            path.exists(),
            "dropping observer must not remove the socket file"
        );
        drop(guard);
        assert!(
            !path.exists(),
            "socket file must be removed after guard drop"
        );
    }
}
