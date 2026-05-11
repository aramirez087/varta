//! Single-threaded observer: bind one or more transport listeners, decode
//! incoming VLP frames, surface beats / stalls / decode errors via [`Event`].
//!
//! The observer never spawns threads, never allocates after setup,
//! and surfaces at most one [`Event`] per call to [`Observer::poll`]. The
//! caller drives the loop — see `main.rs` for the daemon entrypoint.
//!
//! Multiple listeners (e.g. UDS + UDP) are polled round-robin. Each call to
//! [`Observer::poll`] tries every listener in order; the first successful
//! receive is returned immediately. If all listeners return `WouldBlock`,
//! stalls are drained and `None` is returned.

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
    /// Receiving from a listener failed with an error other than
    /// `WouldBlock` / `TimedOut`.
    Io(io::Error, u64),
}

/// Observer bound to one or more transport listeners.
///
/// The observer owns all listeners; cleanup (e.g. socket file unlink) happens
/// when the [`Observer`] is dropped.
pub struct Observer {
    listeners: Vec<Box<dyn BeatListener>>,
    tracker: Tracker,
    threshold_ns: u64,
    start: Instant,
    stall_queue: Vec<Option<Event>>,
    stall_pending: Vec<(u32, u64, u64)>,
    stall_cursor: usize,
}

impl Observer {
    /// Create an empty observer with no listeners. Use
    /// [`Observer::add_listener`] to attach transports, or call
    /// [`Observer::bind`] for the common single-UDS case.
    pub fn new(threshold: Duration) -> Self {
        let threshold_ns = threshold.as_nanos().min(u64::MAX as u128) as u64;
        Observer {
            listeners: Vec::new(),
            tracker: Tracker::new(),
            threshold_ns,
            start: Instant::now(),
            stall_queue: Vec::with_capacity(CAPACITY),
            stall_pending: Vec::with_capacity(CAPACITY),
            stall_cursor: 0,
        }
    }

    /// Create an observer from a single already-configured listener.
    pub fn from_listener<L: BeatListener + 'static>(listener: L, threshold: Duration) -> Self {
        let mut obs = Self::new(threshold);
        obs.add_listener(Box::new(listener));
        obs
    }

    /// Bind a Unix datagram socket at `path` and return an [`Observer`]
    /// with that single UDS listener.
    ///
    /// This is the backward-compatible convenience constructor for the common
    /// single-UDS case. For multi-transport setups, use [`Observer::new`]
    /// followed by [`Observer::add_listener`].
    pub fn bind(
        path: impl AsRef<Path>,
        threshold: Duration,
        socket_mode: u32,
        read_timeout: Duration,
    ) -> io::Result<Self> {
        let listener = UdsListener::bind(path, socket_mode, read_timeout)?;
        Ok(Self::from_listener(listener, threshold))
    }

    /// Add a listener to the observer. The listener is polled in round-robin
    /// order alongside any existing listeners.
    pub fn add_listener(&mut self, listener: Box<dyn BeatListener>) {
        self.listeners.push(listener);
    }

    /// Attempt a single non-blocking read from each listener and return the
    /// first I/O [`Event`] found.
    ///
    /// Listeners are polled round-robin: if the first listener returns
    /// `WouldBlock`, the next is tried. The first non-`WouldBlock` result
    /// (beat, decode error, auth failure, or I/O error) is returned
    /// immediately. Remaining listeners are not polled until the next call.
    ///
    /// This method never returns [`Event::Stall`] — queued stall events must
    /// be retrieved via [`Observer::poll_pending`].
    pub fn poll(&mut self) -> Option<Event> {
        for i in 0..self.listeners.len() {
            match self.listeners[i].recv() {
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
                                Update::Inserted | Update::Refreshed => {
                                    return Some(Event::Beat {
                                        pid: frame.pid,
                                        status: frame.status,
                                        payload: frame.payload,
                                        nonce: frame.nonce,
                                        observer_ns: now_ns,
                                    });
                                }
                                Update::OutOfOrder | Update::CapacityExceeded => continue,
                            }
                        }
                        Err(e) => return Some(Event::Decode(e, now_ns)),
                    }
                }
                RecvResult::WouldBlock => continue,
                RecvResult::ShortRead => continue,
                RecvResult::IoError(e) => return Some(Event::Io(e, self.now_ns())),
            }
        }
        self.drain_stalls();
        None
    }

    /// Return the next queued [`Event::Stall`], if any.
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

    /// Drain and reset the eviction counter.
    pub fn drain_evictions(&mut self) -> u64 {
        self.tracker.take_evictions()
    }

    /// Drain and reset the capacity-exceeded counter.
    pub fn drain_capacity_exceeded(&mut self) -> u64 {
        self.tracker.take_capacity_exceeded()
    }

    /// Drain and reset the AEAD decryption failure counter across all
    /// listeners.
    pub fn drain_decrypt_failures(&mut self) -> u64 {
        self.listeners
            .iter_mut()
            .map(|l| l.drain_decrypt_failures())
            .sum()
    }

    /// Drain and reset the truncated-datagram counter across all listeners.
    pub fn drain_truncated(&mut self) -> u64 {
        self.listeners.iter_mut().map(|l| l.drain_truncated()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

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
