//! Single-threaded observer: bind a Unix datagram socket, decode incoming
//! VLP frames, surface beats / stalls / decode errors via [`Event`].
//!
//! The observer never spawns threads, never allocates after [`Observer::bind`],
//! and surfaces exactly one [`Event`] per call to [`Observer::poll`]. The
//! caller drives the loop — see Session 05 for the daemon entrypoint.

use std::io::{self, ErrorKind};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::{Duration, Instant};

use varta_vlp::{DecodeError, Frame, Status};

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
    /// Any pre-existing file at `path` is removed before bind so a stale
    /// socket from a prior run does not block startup. The socket is given a
    /// fixed read timeout (100 ms) so [`Observer::poll`] cannot block
    /// indefinitely.
    pub fn bind(path: impl AsRef<Path>, threshold: Duration) -> io::Result<Self> {
        let path = path.as_ref();
        let _ = std::fs::remove_file(path);
        let sock = match UnixDatagram::bind(path) {
            Ok(s) => s,
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                let _ = std::fs::remove_file(path);
                UnixDatagram::bind(path)?
            }
            Err(e) => return Err(e),
        };
        sock.set_read_timeout(Some(READ_TIMEOUT))?;
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

        let mut buf = [0u8; 32];
        match self.sock.recv(&mut buf) {
            Ok(32) => {
                let now_ns = self.now_ns();
                match Frame::decode(&buf) {
                    Ok(frame) => match self.tracker.record(&frame, now_ns, self.threshold_ns) {
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
                    },
                    Err(e) => Some(Event::Decode(e)),
                }
            }
            Ok(_) => None,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                self.drain_stalls();
                if self.stall_cursor < self.stall_queue.len() {
                    let stall = self.stall_queue[self.stall_cursor].take();
                    self.stall_cursor += 1;
                    return stall;
                }
                None
            }
            Err(e) => Some(Event::Io(e)),
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
}
