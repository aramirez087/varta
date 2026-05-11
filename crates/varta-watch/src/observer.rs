//! Single-threaded observer: bind a transport listener, decode incoming
//! VLP frames, surface beats / stalls / decode errors via [`Event`].
//!
//! The observer never spawns threads, never allocates after setup,
//! and surfaces exactly one [`Event`] per call to [`Observer::poll`]. The
//! caller drives the loop — see `main.rs` for the daemon entrypoint.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use varta_vlp::{DecodeError, Frame, Status};

use crate::listener::{BeatListener, UdsListener};
use crate::peer_cred::RecvResult;
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
    /// Receiving from the listener failed with an error other than
    /// `WouldBlock` / `TimedOut`.
    Io(io::Error, u64),
}

/// Observer bound to a transport listener.
///
/// The observer owns the listener; cleanup (e.g. socket file unlink) happens
/// when the [`Observer`] is dropped.
pub struct Observer<L: BeatListener = UdsListener> {
    listener: L,
    tracker: Tracker,
    threshold_ns: u64,
    start: Instant,
    stall_queue: Vec<Option<Event>>,
    stall_pending: Vec<(u32, u64, u64)>,
    stall_cursor: usize,
}

impl Observer<UdsListener> {
    /// Bind a Unix datagram socket at `path` and return an [`Observer`]
    /// configured with the given stall `threshold`.
    ///
    /// The socket file permissions are set to `socket_mode` (octal, e.g.
    /// `0o600`) immediately after a successful bind. Credential passing is
    /// enabled on the socket so that [`Observer::poll`] can verify the PID
    /// of every sender against the kernel's `SO_PASSCRED` / `LOCAL_CREDS`
    /// attestation (Linux only).
    ///
    /// If a genuine stale socket exists at `path` (no one listening),
    /// it is cleaned up and the bind succeeds. If another process is
    /// already listening at `path`, the call fails with `AddrInUse`.
    ///
    /// The socket file is unlinked when the [`Observer`] is dropped.
    pub fn bind(
        path: impl AsRef<Path>,
        threshold: Duration,
        socket_mode: u32,
        read_timeout: Duration,
    ) -> io::Result<Self> {
        let listener = UdsListener::bind(path, socket_mode, read_timeout)?;
        Ok(Self::from_listener(listener, threshold))
    }
}

impl<L: BeatListener> Observer<L> {
    /// Create an [`Observer`] from an already-configured listener.
    pub fn from_listener(listener: L, threshold: Duration) -> Self {
        let threshold_ns = threshold.as_nanos().min(u64::MAX as u128) as u64;
        Observer {
            listener,
            tracker: Tracker::new(),
            threshold_ns,
            start: Instant::now(),
            stall_queue: Vec::with_capacity(CAPACITY),
            stall_pending: Vec::with_capacity(CAPACITY),
            stall_cursor: 0,
        }
    }

    /// Attempt a single non-blocking read from the listener and return the
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
    /// - `Some(Event::Io(_))` for non-`WouldBlock` listener errors.
    /// - `Some(Event::AuthFailure)` if the frame pid does not match the
    ///   kernel-attested sender (Linux UDS only; macOS and UDP skip this).
    /// - `None` if no I/O was available (`WouldBlock`), the read was a
    ///   short read, the beat was out-of-order, or capacity was exceeded.
    ///   `WouldBlock` internally triggers [`Observer::drain_stalls`], which
    ///   populates the stall queue for subsequent `poll_pending` calls.
    pub fn poll(&mut self) -> Option<Event> {
        match self.listener.recv() {
            RecvResult::Authenticated { peer_pid, data } => {
                let now_ns = self.now_ns();
                match Frame::decode(&data) {
                    Ok(frame) => {
                        #[cfg(target_os = "linux")]
                        if peer_pid != 0 && frame.pid != peer_pid {
                            return Some(Event::AuthFailure {
                                claimed_pid: frame.pid,
                                observer_ns: now_ns,
                            });
                        }
                        let _ = peer_pid;
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
    ///
    /// Callers should check this before [`Observer::poll`] to ensure
    /// previously-queued stalls are drained first via
    /// [`Observer::poll_pending`].  When `true`, the next
    /// [`Observer::poll_pending`] call is guaranteed to return `Some`.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
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
        let obs = Observer::bind(
            &path,
            Duration::from_secs(1),
            0o600,
            Duration::from_millis(100),
        )
        .expect("bind should succeed on a clean temp path");
        assert!(path.exists(), "socket file must exist after bind");
        drop(obs);
        assert!(
            !path.exists(),
            "socket file must be removed after observer drop"
        );
    }
}
