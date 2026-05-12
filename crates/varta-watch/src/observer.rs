//! Single-threaded observer: bind one or more transport listeners, decode
//! incoming VLP frames, surface beats / stalls / decode errors via [`Event`].
//!
//! The observer never spawns threads, never allocates after setup,
//! and surfaces at most one [`Event`] per call to [`Observer::poll`]. The
//! caller drives the loop — see `main.rs` for the daemon entrypoint.
//!
//! Multiple listeners (e.g. UDS + UDP) are polled round-robin. Each call to
//! [`Observer::poll`] tries every listener once; the first non-`WouldBlock`
//! event is returned but all remaining listeners are still tried, so a
//! busy listener cannot starve co-located listeners. If all listeners return
//! `WouldBlock`, stalls are drained and `None` is returned.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use varta_vlp::{DecodeError, Frame, Status};

use crate::listener::{BeatListener, UdsListener};
use crate::peer_cred::RecvResult;
use crate::tracker::{Tracker, Update};

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
    /// Ancillary data truncated by the kernel (`MSG_CTRUNC` on Linux).
    /// Indicates the kernel's ancillary-data buffer was too small for the
    /// per-message metadata — a kernel-level buffer sizing issue.
    CtrlTruncated(io::Error, u64),
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
    stall_cursor: usize,
    /// Next index to start polling from for fair round-robin across listeners.
    next_listener_start: usize,
    /// Minimum inter-beat interval applied per pid, in nanoseconds.
    /// `None` means no rate limiting (the default).
    rate_limit_interval_ns: Option<u64>,
    /// Total beats dropped by the rate limiter since the last drain.
    rate_limited_total: u64,
}

impl Observer {
    /// Create an empty observer with no listeners. Use
    /// [`Observer::add_listener`] to attach transports, or call
    /// [`Observer::bind`] for the common single-UDS case.
    ///
    /// `tracker_capacity` sets the maximum number of distinct agent pids
    /// tracked concurrently. Beats for new pids beyond this limit are
    /// dropped with [`Update::CapacityExceeded`] (the counter is surfaced
    /// via `varta_tracker_capacity_exceeded_total`).
    ///
    /// `max_beat_rate` is an optional per-pid rate limit in beats per
    /// second.  When set, beats arriving faster than this rate from the
    /// same pid are dropped and counted via [`Observer::drain_rate_limited`].
    /// `None` (the default) disables rate limiting.
    pub fn new(threshold: Duration, tracker_capacity: usize, max_beat_rate: Option<u32>) -> Self {
        let threshold_ns = threshold.as_nanos().min(u64::MAX as u128) as u64;
        let rate_limit_interval_ns = max_beat_rate.and_then(|rps| {
            if rps == 0 {
                None
            } else {
                // Convert beats/sec to nanosecond interval.
                // Saturate at 1 ns (1 GHz rate) to avoid overflow.
                let interval_ns = 1_000_000_000u64.checked_div(rps as u64).unwrap_or(1);
                Some(interval_ns)
            }
        });
        Observer {
            listeners: Vec::new(),
            tracker: Tracker::new(tracker_capacity),
            threshold_ns,
            start: Instant::now(),
            stall_queue: Vec::with_capacity(tracker_capacity),
            stall_cursor: 0,
            next_listener_start: 0,
            rate_limit_interval_ns,
            rate_limited_total: 0,
        }
    }

    /// Create an observer from a single already-configured listener.
    pub fn from_listener<L: BeatListener + 'static>(
        listener: L,
        threshold: Duration,
        tracker_capacity: usize,
        max_beat_rate: Option<u32>,
    ) -> Self {
        let mut obs = Self::new(threshold, tracker_capacity, max_beat_rate);
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
        tracker_capacity: usize,
        max_beat_rate: Option<u32>,
    ) -> io::Result<Self> {
        let listener = UdsListener::bind(path, socket_mode, read_timeout)?;
        Ok(Self::from_listener(
            listener,
            threshold,
            tracker_capacity,
            max_beat_rate,
        ))
    }

    /// Add a listener to the observer. The listener is polled in round-robin
    /// order alongside any existing listeners.
    pub fn add_listener(&mut self, listener: Box<dyn BeatListener>) {
        self.listeners.push(listener);
    }

    /// Poll every listener once round-robin and return the first
    /// non-`WouldBlock` [`Event`] found. Each listener is tried exactly
    /// once per call — a busy listener cannot starve others because the
    /// round-robin advances past it on every successful receive.
    ///
    /// This method never returns [`Event::Stall`] — queued stall events must
    /// be retrieved via [`Observer::poll_pending`].
    pub fn poll(&mut self) -> Option<Event> {
        let len = self.listeners.len();
        let start = self.next_listener_start;
        let mut first_event: Option<Event> = None;
        let mut round = 0;
        while round < len {
            let i = (start + round) % len;
            round += 1;
            match self.listeners[i].recv() {
                RecvResult::Authenticated {
                    peer_pid,
                    peer_uid: _,
                    data,
                } => {
                    let now_ns = self.now_ns();
                    if first_event.is_none() {
                        self.next_listener_start = (i + 1) % len;
                    }
                    match Frame::decode(&data) {
                        Ok(frame) => {
                            // Per-datagram PID verification — works on Linux
                            // (SCM_CREDENTIALS via SO_PASSCRED) and macOS
                            // (LOCAL_PEERTOKEN via getsockopt). For transports
                            // without kernel credential support, peer_pid is 0
                            // and this check is a no-op.
                            if peer_pid != 0 && frame.pid != peer_pid {
                                if first_event.is_none() {
                                    first_event = Some(Event::AuthFailure {
                                        claimed_pid: frame.pid,
                                        observer_ns: now_ns,
                                    });
                                }
                                continue;
                            }
                            // Per-pid rate limiting: if a minimum inter-beat
                            // interval is configured, skip frames that arrive
                            // too soon from the same pid.
                            if let Some(interval_ns) = self.rate_limit_interval_ns {
                                if let Some(last_ns) = self.tracker.last_ns_of(frame.pid) {
                                    if now_ns.saturating_sub(last_ns) < interval_ns {
                                        self.rate_limited_total =
                                            self.rate_limited_total.saturating_add(1);
                                        continue;
                                    }
                                }
                            }
                            match self.tracker.record(&frame, now_ns, self.threshold_ns) {
                                Update::Inserted | Update::Refreshed => {
                                    if first_event.is_none() {
                                        first_event = Some(Event::Beat {
                                            pid: frame.pid,
                                            status: frame.status,
                                            payload: frame.payload,
                                            nonce: frame.nonce,
                                            observer_ns: now_ns,
                                        });
                                    }
                                }
                                Update::OutOfOrder | Update::CapacityExceeded => {}
                            }
                        }
                        Err(e) => {
                            if first_event.is_none() {
                                first_event = Some(Event::Decode(e, now_ns));
                            }
                        }
                    }
                }
                RecvResult::WouldBlock => continue,
                RecvResult::ShortRead => continue,
                RecvResult::CtrlTruncated(e) => {
                    if first_event.is_none() {
                        self.next_listener_start = (i + 1) % len;
                        first_event = Some(Event::CtrlTruncated(e, self.now_ns()));
                    }
                }
                RecvResult::IoError(e) => {
                    if first_event.is_none() {
                        self.next_listener_start = (i + 1) % len;
                        first_event = Some(Event::Io(e, self.now_ns()));
                    }
                }
            }
        }
        self.drain_stalls();
        first_event
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

    /// Observer-local nanosecond timestamp (ns since [`Observer`] start).
    pub fn now_ns(&self) -> u64 {
        let elapsed = self.start.elapsed().as_nanos();
        elapsed.min(u64::MAX as u128) as u64
    }

    fn drain_stalls(&mut self) {
        if self.stall_cursor < self.stall_queue.len() {
            return;
        }
        let now_ns = self.now_ns();
        self.stall_queue.clear();
        self.stall_cursor = 0;
        self.tracker
            .drain_stalled_slots(now_ns, self.threshold_ns, |pid, last_nonce, last_ns| {
                self.stall_queue.push(Some(Event::Stall {
                    pid,
                    last_nonce,
                    last_ns,
                    observer_ns: now_ns,
                }));
            });
    }

    /// Drain and reset the eviction counter.
    pub fn drain_evictions(&mut self) -> u64 {
        self.tracker.take_evictions()
    }

    /// Drain the pid of the most recently evicted slot, if any.
    pub fn drain_evicted_pid(&mut self) -> Option<u32> {
        self.tracker.take_evicted_pid()
    }

    /// Drain and reset the capacity-exceeded counter.
    pub fn drain_capacity_exceeded(&mut self) -> u64 {
        self.tracker.take_capacity_exceeded()
    }

    /// Drain and reset the nonce-wrap counter.
    pub fn drain_nonce_wraps(&mut self) -> u64 {
        self.tracker.take_nonce_wraps()
    }

    /// Drain and reset the rate-limited counter.
    pub fn drain_rate_limited(&mut self) -> u64 {
        let n = self.rate_limited_total;
        self.rate_limited_total = 0;
        n
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

    /// Drain and reset the sender-state-full counter across all listeners.
    pub fn drain_sender_state_full(&mut self) -> u64 {
        self.listeners
            .iter_mut()
            .map(|l| l.drain_sender_state_full())
            .sum()
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
            64,
            None,
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
