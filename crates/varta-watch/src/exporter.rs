//! Exporters for [`crate::observer::Event`] streams.
//!
//! Two concrete implementations ship with v0.1.0:
//!
//! - [`FileExporter`] — appends one tab-separated line per event to a file
//!   on disk. The schema is documented on [`FileExporter`] and is stable
//!   for the v0.1.0 contract.
//! - [`PromExporter`] — exposes per-pid counters via `GET /metrics` over
//!   HTTP/1.0 in the Prometheus text exposition format. The endpoint is
//!   poll-driven by [`PromExporter::serve_pending`]; no background thread
//!   and no shared state.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use varta_vlp::{DecodeError, Status};

use crate::observer::Event;

/// Sink for an [`Event`] stream.
pub trait Exporter {
    /// Record a single observer event. Implementations should never panic
    /// or block the caller for IO; transient failures are returned as
    /// `Err` so the caller can react (log, retry, or fall back).
    fn record(&mut self, ev: &Event) -> io::Result<()>;
    /// Flush any internally buffered output. For network exporters that
    /// hold no per-event buffer this is a no-op that returns `Ok(())`.
    fn flush(&mut self) -> io::Result<()>;
}

/// File-backed exporter. Appends one line per event in the schema:
///
/// ```text
/// <observer_ns>\t<kind>\t<pid>\t<nonce>\t<status>\t<payload>\n
/// ```
///
/// `kind` ∈ `{beat, stall, decode, io, mismatch}`. For `decode`, `io`, and
/// `mismatch` events the pid / nonce / status / payload columns are written
/// as `-` so the line count and column count remain stable.
///
/// `observer_ns` is the observer-local nanosecond timestamp carried by every
/// [`Event`], captured at observer poll time. All exporters sharing an event
/// stream see the same timestamps.
///
/// When `max_bytes` is set, the exporter rotates the file after every write
/// that pushes the size over the limit. Rotation shifts `PATH` → `PATH.1`,
/// `PATH.1` → `PATH.2`, …, up to 5 generations, then re-opens `PATH` in
/// append mode. Without `max_bytes` the file grows unbounded.
pub struct FileExporter {
    sink: BufWriter<File>,
    pending_err: Option<io::Error>,
    path: PathBuf,
    max_bytes: Option<u64>,
    bytes_written: u64,
}

/// Number of rotated file generations kept.
const MAX_ROTATION_GENERATIONS: u32 = 5;

impl FileExporter {
    /// Open `path` in append mode (creating it if necessary) and wrap it
    /// in a [`BufWriter`].
    ///
    /// `max_bytes` is the optional size limit after which the file is
    /// rotated.
    pub fn create(path: impl AsRef<Path>, max_bytes: Option<u64>) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())?;
        let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(FileExporter {
            sink: BufWriter::new(file),
            pending_err: None,
            path: path.as_ref().to_path_buf(),
            max_bytes,
            bytes_written,
        })
    }

    /// Record an evicted pid line into the file export. This is called from
    /// the main loop when a tracker slot is reclaimed, so the operator has
    /// a per-pid trace of eviction events.
    pub fn record_eviction_pid(&mut self, pid: u32, observer_ns: u64) {
        let result = writeln!(self.sink, "{observer_ns}\teviction\t{pid}\t-\t-\t-",);
        if let Err(e) = result {
            self.pending_err = Some(e);
        } else {
            self.pending_err = None;
            let line_len = decimal_digits(observer_ns) as u64
                + 1  // \t
                + 8  // "eviction"
                + 1  // \t
                + decimal_digits(pid as u64) as u64
                + 1  // \t
                + 1  // -
                + 1  // \t
                + 1  // -
                + 1  // \t
                + 1  // -
                + 1; // \n
            self.after_write(line_len);
        }
    }

    /// Called after every successful write. When `max_bytes` is set and
    /// exceeded, rotates the file.
    fn after_write(&mut self, line_len: u64) {
        let Some(max) = self.max_bytes else {
            return;
        };
        self.bytes_written = self.bytes_written.saturating_add(line_len);
        if self.bytes_written < max {
            return;
        }
        // Rotation needed.
        if let Err(e) = self.sink.flush() {
            self.pending_err = Some(e);
            return;
        }
        if let Err(e) = Self::rotate(&self.path) {
            self.pending_err = Some(e);
            return;
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => {
                self.sink = BufWriter::new(file);
                self.bytes_written = 0;
            }
            Err(e) => {
                self.pending_err = Some(e);
            }
        }
    }

    /// Rotate `path`: shift `path` → `path.1`, `path.1` → `path.2`, …
    /// up to [`MAX_ROTATION_GENERATIONS`]. The oldest generation is deleted.
    fn rotate(path: &Path) -> io::Result<()> {
        let path_str = path.to_string_lossy();
        let oldest = format!("{path_str}.{MAX_ROTATION_GENERATIONS}");
        match std::fs::remove_file(&oldest) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        for gen in (1..MAX_ROTATION_GENERATIONS).rev() {
            let src = format!("{path_str}.{gen}");
            let dst = format!("{path_str}.{}", gen + 1);
            match std::fs::rename(&src, &dst) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let first = format!("{path_str}.1");
        match std::fs::rename(path, &first) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
                std::fs::copy(path, &first)?;
                std::fs::remove_file(path)?;
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

impl Exporter for FileExporter {
    fn record(&mut self, ev: &Event) -> io::Result<()> {
        let line_len: u64 = match ev {
            Event::Beat {
                pid,
                status,
                payload,
                nonce,
                observer_ns,
            } => {
                let label = status_label(*status);
                decimal_digits(*observer_ns) as u64
                    + 1  // \t
                    + 4  // "beat"
                    + 1  // \t
                    + decimal_digits(*pid as u64) as u64
                    + 1  // \t
                    + decimal_digits(*nonce) as u64
                    + 1  // \t
                    + label.len() as u64
                    + 1  // \t
                    + decimal_digits(*payload) as u64
                    + 1 // \n
            }
            Event::Stall {
                pid,
                last_nonce,
                observer_ns,
                ..
            } => {
                decimal_digits(*observer_ns) as u64
                + 1  // \t
                + 5  // "stall"
                + 1  // \t
                + decimal_digits(*pid as u64) as u64
                + 1  // \t
                + decimal_digits(*last_nonce) as u64
                + 1  // \t
                + 5  // "stall"
                + 1  // \t
                + 1  // "-"
                + 1
            } // \n
            // Error events with variable-length messages: use a
            // conservative estimate of 256 bytes.  These are rare
            // relative to beats and stalls so the drift is negligible.
            Event::Decode(_, _) | Event::Io(_, _) | Event::CtrlTruncated(_, _) => 256,
            Event::AuthFailure {
                claimed_pid,
                observer_ns,
            } => {
                decimal_digits(*observer_ns) as u64
                + 1  // \t
                + 8  // "mismatch"
                + 1  // \t
                + decimal_digits(*claimed_pid as u64) as u64
                + 1  // \t
                + 1  // "-"
                + 1  // \t
                + 1  // "-"
                + 1  // \t
                + 13 // "auth_failure"
                + 1
            } // \n
        };
        let result = match ev {
            Event::Beat {
                pid,
                status,
                payload,
                nonce,
                observer_ns,
            } => writeln!(
                self.sink,
                "{observer_ns}\tbeat\t{pid}\t{nonce}\t{}\t{payload}",
                status_label(*status),
            ),
            Event::Stall {
                pid,
                last_nonce,
                last_ns: _,
                observer_ns,
            } => writeln!(
                self.sink,
                "{observer_ns}\tstall\t{pid}\t{last_nonce}\tstall\t-",
            ),
            Event::Decode(err, observer_ns) => {
                writeln!(self.sink, "{observer_ns}\tdecode\t-\t-\t-\t{err:?}")
            }
            Event::Io(err, observer_ns) => {
                writeln!(self.sink, "{observer_ns}\tio\t-\t-\t-\t{err}")
            }
            Event::AuthFailure {
                claimed_pid,
                observer_ns,
            } => {
                writeln!(
                    self.sink,
                    "{observer_ns}\tmismatch\t{claimed_pid}\t-\t-\tauth_failure",
                )
            }
            Event::CtrlTruncated(err, observer_ns) => {
                writeln!(self.sink, "{observer_ns}\tctrunc\t-\t-\t-\t{err}")
            }
        };
        if let Err(ref e) = result {
            self.pending_err = Some(io::Error::new(e.kind(), e.to_string()));
        }
        match result {
            Err(e) => Err(e),
            Ok(()) => {
                self.pending_err = None;
                self.after_write(line_len);
                Ok(())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let sink_result = self.sink.flush();
        match (self.pending_err.take(), sink_result) {
            (Some(e), _) => Err(e),
            (None, Err(e)) => Err(e),
            (None, Ok(())) => Ok(()),
        }
    }
}

/// Return the number of decimal digits needed to represent `n`.
fn decimal_digits(mut n: u64) -> usize {
    if n == 0 {
        return 1;
    }
    let mut digits = 0;
    while n > 0 {
        n /= 10;
        digits += 1;
    }
    digits
}

fn status_label(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Degraded => "degraded",
        Status::Critical => "critical",
        Status::Stall => "stall",
        _ => "unknown",
    }
}

/// Prometheus `kind` label values for `varta_decode_errors_total`. Indexed
/// by [`decode_kind_index`]; the array doubles as the canonical ordering
/// for the exposition output, so series remain stable across scrapes.
const DECODE_KIND_LABELS: [&str; 4] = ["bad_magic", "bad_version", "bad_status", "unknown"];

fn decode_kind_index(err: &DecodeError) -> usize {
    match err {
        DecodeError::BadMagic => 0,
        DecodeError::BadVersion => 1,
        DecodeError::BadStatus(_) => 2,
        _ => 3,
    }
}

#[derive(Clone, Copy, Debug)]
struct GaugeRow {
    beats_total: u64,
    stalls_total: u64,
    last_status: Option<u8>,
}

impl GaugeRow {
    const fn new() -> Self {
        GaugeRow {
            beats_total: 0,
            stalls_total: 0,
            last_status: None,
        }
    }
}

/// Per-connection read timeout on the [`PromExporter`]'s accepted streams.
/// Capped so a slow or hostile client cannot stall the observer's poll loop.
const PROM_READ_DEADLINE: Duration = Duration::from_millis(10);
/// Per-connection write timeout for the metrics response body.
const PROM_WRITE_TIMEOUT: Duration = Duration::from_millis(50);
/// Maximum connections accepted per [`PromExporter::serve_pending`] call.
/// Caps the amount of work done before returning control to the observer
/// loop so that stall detection, I/O polling, and reaping are not starved
/// under a storm of slow scrapers. The 100 ms serve deadline still applies
/// as an additional guard.
const PROM_MAX_CONNECTIONS_PER_SERVE: usize = 8;
/// Cap on how many bytes [`PromExporter::serve_pending`] reads from a
/// single request before responding (we discard the request line/headers).
const PROM_REQUEST_CAP: usize = 4096;
/// Minimum interval between accepted scrapes. A scraper hitting faster than
/// once per second cannot starve stall detection in the single-threaded
/// poll loop. Prometheus default scrape intervals are 15–60 s, so this only
/// gates pathological or misconfigured scrapers.
const PROM_MIN_SCRAPE_INTERVAL: Duration = Duration::from_secs(1);

/// Prometheus text-format exporter served over HTTP/1.0.
///
/// The exporter is poll-driven: the daemon main loop calls
/// [`PromExporter::serve_pending`] once per outer tick and the listener
/// is non-blocking, so there is no background thread. Each accepted
/// connection receives a fresh metrics body with `Connection: close`.
pub struct PromExporter {
    listener: TcpListener,
    rows: HashMap<u32, GaugeRow>,
    /// Reused across `/metrics` scrapes to avoid per-scrape allocation.
    body_buf: String,
    /// Timestamp of the most recent scrape served. Enforces
    /// [`PROM_MIN_SCRAPE_INTERVAL`] to protect the single-threaded poll
    /// loop from a fast scraper starving stall detection.
    last_scrape: Option<Instant>,
    evicted_total: u64,
    auth_failures_total: u64,
    /// Per-kind decode failure counters, indexed by [`decode_kind_index`].
    /// Always emitted in full (even at zero) so `absent()` alert rules and
    /// dashboards stay green-on-green instead of disappearing until the
    /// first incident. Size is derived from [`DECODE_KIND_LABELS`] so
    /// adding a label forces the array to grow.
    decode_errors_total: [u64; DECODE_KIND_LABELS.len()],
    io_errors_total: u64,
    ctrl_truncated_total: u64,
    capacity_exceeded_total: u64,
    decrypt_failures_total: u64,
    truncated_total: u64,
    sender_state_full_total: u64,
    rate_limited_total: u64,
    nonce_wrap_total: u64,
    /// Number of `/metrics` scrapes served from cache because
    /// [`PROM_MIN_SCRAPE_INTERVAL`] had not elapsed since the last fresh
    /// render.  Operators can alert on this to detect scrape pressure.
    scrape_skipped_total: u64,
    /// Times [`serve_pending`](Self::serve_pending) exhausted its per-tick
    /// budget (connection cap or wall-clock deadline).  Operators can alert
    /// on this to detect when the exporter cannot serve all incoming scrapes
    /// within a single poll tick.
    scrape_budget_exhausted_total: u64,
    /// Observer startup instant (monotonic). Used to emit
    /// `varta_watch_uptime_seconds`.
    started_at: Instant,
    /// Wall-clock timestamp of the most recent poll loop tick. Used to emit
    /// `varta_watch_last_poll_loop_timestamp_seconds` so operators can
    /// detect observer stalls.
    last_loop_system: SystemTime,
}

impl PromExporter {
    /// Bind a non-blocking TCP listener on `addr` and return the exporter.
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(PromExporter {
            listener,
            rows: HashMap::new(),
            body_buf: String::new(),
            last_scrape: None,
            evicted_total: 0,
            auth_failures_total: 0,
            decode_errors_total: [0; DECODE_KIND_LABELS.len()],
            io_errors_total: 0,
            ctrl_truncated_total: 0,
            capacity_exceeded_total: 0,
            decrypt_failures_total: 0,
            truncated_total: 0,
            sender_state_full_total: 0,
            rate_limited_total: 0,
            nonce_wrap_total: 0,
            scrape_skipped_total: 0,
            scrape_budget_exhausted_total: 0,
            started_at: Instant::now(),
            last_loop_system: SystemTime::now(),
        })
    }

    /// Address the listener is actually bound to. Useful for tests that
    /// bind on port 0 and need to discover the kernel-assigned port.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Record one or more tracker slot evictions.
    pub fn record_eviction(&mut self, count: u64) {
        self.evicted_total = self.evicted_total.saturating_add(count);
    }

    /// Remove the GaugeRow for a pid that was evicted from the tracker.
    /// Prevents unbounded memory growth in the rows HashMap over long-running
    /// deployments with ephemeral processes (CI runners, cron jobs, containers).
    pub fn record_evicted_pid(&mut self, pid: u32) {
        self.rows.remove(&pid);
    }

    /// Record one or more beats dropped due to tracker capacity exceeded.
    pub fn record_capacity_exceeded(&mut self, count: u64) {
        self.capacity_exceeded_total = self.capacity_exceeded_total.saturating_add(count);
    }

    /// Record one or more AEAD decryption (tag verification) failures.
    pub fn record_decrypt_failures(&mut self, count: u64) {
        self.decrypt_failures_total = self.decrypt_failures_total.saturating_add(count);
    }

    /// Record one or more truncated (wrong-size) datagrams received.
    pub fn record_truncated(&mut self, count: u64) {
        self.truncated_total = self.truncated_total.saturating_add(count);
    }

    /// Record one or more times the sender-state map was at capacity,
    /// forcing eviction of the oldest entry.
    pub fn record_sender_state_full(&mut self, count: u64) {
        self.sender_state_full_total = self.sender_state_full_total.saturating_add(count);
    }

    /// Record one or more beats dropped by per-pid rate limiting.
    pub fn record_rate_limited(&mut self, count: u64) {
        self.rate_limited_total = self.rate_limited_total.saturating_add(count);
    }

    /// Record one or more nonce-space wrap events (agent exhausted u64 nonce
    /// space and looped to 0).
    pub fn record_nonce_wraps(&mut self, count: u64) {
        self.nonce_wrap_total = self.nonce_wrap_total.saturating_add(count);
    }

    /// Record one or more scrapes served from cache (scrape arrived before
    /// [`PROM_MIN_SCRAPE_INTERVAL`] elapsed since the last fresh render).
    pub fn record_scrape_skipped(&mut self, count: u64) {
        self.scrape_skipped_total = self.scrape_skipped_total.saturating_add(count);
    }

    /// Record that the observer poll loop has completed another tick.
    /// Called once per outer loop iteration so that
    /// `varta_watch_last_poll_loop_timestamp_seconds` stays fresh.
    pub fn record_loop_tick(&mut self) {
        self.last_loop_system = SystemTime::now();
    }

    /// Record one or more `MSG_CTRUNC` ancillary-data truncation events.
    /// Indicates the kernel's per-message metadata buffer is too small —
    /// a separate signal from generic I/O errors so operators can size
    /// `ANCILLARY_BUFFER_SIZE` appropriately.
    pub fn record_ctrl_truncated(&mut self, count: u64) {
        self.ctrl_truncated_total = self.ctrl_truncated_total.saturating_add(count);
    }

    /// Accept ready connections on the listener and write a metrics
    /// response back to each. Returns `Ok(())` when the accept queue
    /// drains cleanly; returns the first non-`WouldBlock` error otherwise.
    ///
    /// Service budget per call is bounded by two limits (whichever hits
    /// first): a 100 ms wall-clock deadline and
    /// [`PROM_MAX_CONNECTIONS_PER_SERVE`] accepted connections. Both
    /// exist to prevent a storm of slow scrapers from starving the
    /// observer poll loop (stall detection, I/O polling, reaping).
    pub fn serve_pending(&mut self) -> io::Result<()> {
        // Rate-limit: if a scrape was already served within
        // PROM_MIN_SCRAPE_INTERVAL, additional scrapes still receive a
        // response (the cached body from the last fresh render) but
        // render_body() is skipped.  This prevents a fast / misconfigured
        // scraper from starving the single-threaded poll loop while keeping
        // all Prometheus scrapes successful.
        let render_fresh = self
            .last_scrape
            .is_none_or(|last| last.elapsed() >= PROM_MIN_SCRAPE_INTERVAL);
        let serve_deadline = Instant::now() + Duration::from_millis(100);
        let mut served = 0;
        let result = loop {
            if Instant::now() >= serve_deadline {
                self.scrape_budget_exhausted_total =
                    self.scrape_budget_exhausted_total.saturating_add(1);
                break Ok(());
            }
            if served >= PROM_MAX_CONNECTIONS_PER_SERVE {
                self.scrape_budget_exhausted_total =
                    self.scrape_budget_exhausted_total.saturating_add(1);
                break Ok(());
            }
            match self.listener.accept() {
                Ok((stream, _)) => {
                    self.serve_one(stream, render_fresh)?;
                    served += 1;
                    if !render_fresh {
                        self.scrape_skipped_total = self.scrape_skipped_total.saturating_add(1);
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        if served > 0 && render_fresh {
            self.last_scrape = Some(Instant::now());
        }
        result
    }

    fn serve_one(&mut self, mut stream: TcpStream, render_fresh: bool) -> io::Result<()> {
        // Accepted streams inherit the listener's non-blocking flag on both
        // Linux (via `accept4(SOCK_NONBLOCK)` in libstd) and macOS (libstd
        // calls `fcntl(F_SETFL, O_NONBLOCK)` post-accept). We intentionally
        // do *not* set a blocking read/write timeout here: a blocking socket
        // would let a slow peer hold the observer poll loop hostage for up
        // to the timeout per request. The PROM_READ_DEADLINE /
        // PROM_WRITE_TIMEOUT below are wall-clock budgets enforced by the
        // loops themselves, not socket-level timeouts.
        let deadline = Instant::now() + PROM_READ_DEADLINE;
        let mut buf = [0u8; 512];
        let mut total = 0;
        loop {
            if Instant::now() >= deadline {
                break;
            }
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    let preview = &buf[..n];
                    if preview.windows(4).any(|w| w == b"\r\n\r\n") || total >= PROM_REQUEST_CAP {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        if total < 4 || buf[..4] != *b"GET " {
            let response = b"HTTP/1.0 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ =
                write_all_nonblocking(&mut stream, response, Instant::now() + PROM_WRITE_TIMEOUT);
            drain_read_to_would_block(&mut stream);
            let _ = stream.shutdown(Shutdown::Write);
            return Ok(());
        }

        if render_fresh {
            self.render_body();
        }
        let body_len = self.body_buf.len();
        let write_deadline = Instant::now() + PROM_WRITE_TIMEOUT;
        // Write headers and body in two parts to avoid allocating a
        // combined response String.
        let _ = write_headers_with_len(&mut stream, body_len, write_deadline);
        let _ = write_all_nonblocking(&mut stream, self.body_buf.as_bytes(), write_deadline);
        drain_read_to_would_block(&mut stream);
        let _ = stream.shutdown(Shutdown::Write);
        Ok(())
    }

    fn render_body(&mut self) {
        self.body_buf.clear();
        const BODY_BUF_MAX_CAPACITY: usize = 65_536;
        if self.body_buf.capacity() > BODY_BUF_MAX_CAPACITY {
            self.body_buf = String::with_capacity(BODY_BUF_MAX_CAPACITY);
        }

        let mut pids: Vec<u32> = self.rows.keys().copied().collect();
        pids.sort_unstable();

        self.body_buf
            .push_str("# HELP varta_beats_total Total accepted beats per agent pid.\n");
        self.body_buf.push_str("# TYPE varta_beats_total counter\n");
        for pid in &pids {
            let row = &self.rows[pid];
            let _ = writeln!(
                self.body_buf,
                "varta_beats_total{{pid=\"{pid}\"}} {}",
                row.beats_total
            );
        }
        self.body_buf
            .push_str("# HELP varta_stalls_total Total observer-detected stalls per agent pid.\n");
        self.body_buf
            .push_str("# TYPE varta_stalls_total counter\n");
        for pid in &pids {
            let row = &self.rows[pid];
            let _ = writeln!(
                self.body_buf,
                "varta_stalls_total{{pid=\"{pid}\"}} {}",
                row.stalls_total
            );
        }
        self.body_buf.push_str("# HELP varta_status Last reported status code per agent pid (0=ok,1=degraded,2=critical,3=stall).\n");
        self.body_buf.push_str("# TYPE varta_status gauge\n");
        for pid in &pids {
            let row = &self.rows[pid];
            if let Some(code) = row.last_status {
                let _ = writeln!(self.body_buf, "varta_status{{pid=\"{pid}\"}} {code}");
            }
        }
        self.body_buf.push_str(
            "# HELP varta_tracker_evicted_total Total tracker slots reclaimed from dead agents.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_tracker_evicted_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_evicted_total {}",
            self.evicted_total
        );
        // Security counter — always emitted, even at 0.  Otherwise dashboards
        // and `absent()` alert rules silently produce no series until the
        // first spoof attempt, which defeats the purpose of an alert.
        self.body_buf.push_str(
            "# HELP varta_frame_auth_failures_total Frames rejected due to PID spoofing or authentication failure.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_frame_auth_failures_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_frame_auth_failures_total {}",
            self.auth_failures_total
        );
        // Always emit one series per kind so dashboards and `absent()` rules
        // stay green-on-green instead of disappearing until the first incident.
        self.body_buf
            .push_str("# HELP varta_decode_errors_total Total VLP decode failures by kind.\n");
        self.body_buf
            .push_str("# TYPE varta_decode_errors_total counter\n");
        for (idx, kind) in DECODE_KIND_LABELS.iter().enumerate() {
            let _ = writeln!(
                self.body_buf,
                "varta_decode_errors_total{{kind=\"{kind}\"}} {}",
                self.decode_errors_total[idx]
            );
        }
        self.body_buf
            .push_str("# HELP varta_io_errors_total Total socket receive errors.\n");
        self.body_buf
            .push_str("# TYPE varta_io_errors_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_io_errors_total {}",
            self.io_errors_total
        );
        self.body_buf
            .push_str("# HELP varta_ctrl_truncated_total Total ancillary-data truncation events (MSG_CTRUNC on Linux).\n");
        self.body_buf
            .push_str("# TYPE varta_ctrl_truncated_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_ctrl_truncated_total {}",
            self.ctrl_truncated_total
        );
        self.body_buf.push_str("# HELP varta_tracker_capacity_exceeded_total Total beats dropped because tracker is full.\n");
        self.body_buf
            .push_str("# TYPE varta_tracker_capacity_exceeded_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_tracker_capacity_exceeded_total {}",
            self.capacity_exceeded_total
        );
        self.body_buf.push_str(
            "# HELP varta_frame_decrypt_failures_total Total AEAD decryption/tag-verification failures.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_frame_decrypt_failures_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_frame_decrypt_failures_total {}",
            self.decrypt_failures_total
        );
        self.body_buf.push_str(
            "# HELP varta_truncated_datagrams_total Total datagrams received with wrong size.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_truncated_datagrams_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_truncated_datagrams_total {}",
            self.truncated_total
        );
        self.body_buf.push_str(
            "# HELP varta_sender_state_full_total Total times the sender-state map was full and an entry was force-evicted.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_sender_state_full_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_sender_state_full_total {}",
            self.sender_state_full_total
        );
        self.body_buf.push_str(
            "# HELP varta_rate_limited_total Total beats dropped by per-pid rate limiting.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_rate_limited_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_rate_limited_total {}",
            self.rate_limited_total
        );
        self.body_buf.push_str(
            "# HELP varta_scrape_skipped_total Number of /metrics scrapes served from cache (rate-limited).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_scrape_skipped_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_scrape_skipped_total {}",
            self.scrape_skipped_total
        );
        self.body_buf.push_str(
            "# HELP varta_scrape_budget_exhausted_total Times the serve budget (max connections or deadline) was exhausted during a poll tick.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_scrape_budget_exhausted_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_scrape_budget_exhausted_total {}",
            self.scrape_budget_exhausted_total
        );
        self.body_buf.push_str(
            "# HELP varta_nonce_wrap_total Total nonce-space wrap events detected (agent exhausted u64 nonces).\n",
        );
        self.body_buf
            .push_str("# TYPE varta_nonce_wrap_total counter\n");
        let _ = writeln!(
            self.body_buf,
            "varta_nonce_wrap_total {}",
            self.nonce_wrap_total
        );
        // --- Observer self-health metrics ---------------------------------
        self.body_buf
            .push_str("# HELP varta_watch_uptime_seconds Observer process uptime in seconds.\n");
        self.body_buf
            .push_str("# TYPE varta_watch_uptime_seconds gauge\n");
        let uptime = self.started_at.elapsed().as_secs_f64();
        let _ = writeln!(self.body_buf, "varta_watch_uptime_seconds {uptime:.3}");
        self.body_buf.push_str(
            "# HELP varta_watch_last_poll_loop_timestamp_seconds Unix timestamp of the most recent poll loop iteration.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_watch_last_poll_loop_timestamp_seconds gauge\n");
        let loop_ts = self
            .last_loop_system
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let _ = writeln!(
            self.body_buf,
            "varta_watch_last_poll_loop_timestamp_seconds {loop_ts:.3}"
        );
        self.body_buf.push_str(
            "# HELP varta_watch_pids_tracked Current number of agent PIDs in the tracker.\n",
        );
        self.body_buf
            .push_str("# TYPE varta_watch_pids_tracked gauge\n");
        let _ = writeln!(
            self.body_buf,
            "varta_watch_pids_tracked {}",
            self.rows.len()
        );
    }
}

impl Exporter for PromExporter {
    fn record(&mut self, ev: &Event) -> io::Result<()> {
        match ev {
            Event::Beat {
                pid,
                status,
                observer_ns: _,
                ..
            } => {
                let row = self.rows.entry(*pid).or_insert_with(GaugeRow::new);
                row.beats_total = row.beats_total.saturating_add(1);
                row.last_status = Some(*status as u8);
            }
            Event::Stall {
                pid,
                observer_ns: _,
                ..
            } => {
                let row = self.rows.entry(*pid).or_insert_with(GaugeRow::new);
                row.stalls_total = row.stalls_total.saturating_add(1);
                row.last_status = Some(Status::Stall as u8);
            }
            Event::AuthFailure { observer_ns: _, .. } => {
                self.auth_failures_total = self.auth_failures_total.saturating_add(1);
            }
            Event::Decode(err, _) => {
                let idx = decode_kind_index(err);
                self.decode_errors_total[idx] = self.decode_errors_total[idx].saturating_add(1);
            }
            Event::Io(_, _) => {
                self.io_errors_total = self.io_errors_total.saturating_add(1);
            }
            Event::CtrlTruncated(_, _) => {
                self.ctrl_truncated_total = self.ctrl_truncated_total.saturating_add(1);
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Write the HTTP 200 response line and headers (including Content-Length)
/// into `stream` using a stack buffer so no heap allocation occurs on the
/// `/metrics` scrape path.
fn write_headers_with_len(
    stream: &mut TcpStream,
    body_len: usize,
    deadline: Instant,
) -> io::Result<()> {
    let mut buf = [0u8; 128];
    let prefix = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: ";
    let suffix = b"\r\nConnection: close\r\n\r\n";
    let len_str_len = write_usize(&mut buf[prefix.len()..], body_len);
    let total = prefix.len() + len_str_len + suffix.len();
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len() + len_str_len..total].copy_from_slice(suffix);
    write_all_nonblocking(stream, &buf[..total], deadline)
}

/// Write `n` as decimal ASCII into `buf` and return the number of bytes
/// written.
///
/// `usize` on 64-bit can require up to 20 decimal digits.  The caller must
/// ensure `buf` is large enough; the debug assertion catches undersized
/// buffers at test time and has zero overhead in release builds.
fn write_usize(buf: &mut [u8], mut n: usize) -> usize {
    debug_assert!(
        buf.len() >= 20,
        "write_usize: buffer too small ({})",
        buf.len()
    );
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut pos = buf.len();
    while n > 0 {
        pos -= 1;
        buf[pos] = (n % 10) as u8 + b'0';
        n /= 10;
    }
    let len = buf.len() - pos;
    buf.copy_within(pos.., 0);
    len
}

/// Maximum number of `yield_now()` calls per `write_all_nonblocking`
/// invocation.  At ~100 µs per yield (macOS) and 10 yields this bounds
/// scheduler concessions to ~1 ms, well within the 50 ms
/// [`PROM_WRITE_TIMEOUT`].
const MAX_WRITE_YIELDS: usize = 10;

/// Non-blocking `write_all` with a wall-clock deadline. Returns `Ok(())`
/// whether the full buffer was written or the deadline expired; the caller
/// is responsible for deciding whether a short write is an error.
///
/// On `WouldBlock` the loop yields the thread to the OS scheduler rather
/// than busy-spinning.  To prevent a persistently-full TCP send buffer from
/// starving the observer poll loop, the function yields at most
/// [`MAX_WRITE_YIELDS`] times before giving up on the current buffer.
///
/// `yield_now()` can be surprisingly long on macOS (~100 µs).  With the
/// 50 ms [`PROM_WRITE_TIMEOUT`] a 10-yield budget is safe.
fn write_all_nonblocking(stream: &mut TcpStream, buf: &[u8], deadline: Instant) -> io::Result<()> {
    let mut written = 0;
    let mut yields = 0;
    while written < buf.len() {
        if Instant::now() >= deadline {
            break;
        }
        match stream.write(&buf[written..]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if yields >= MAX_WRITE_YIELDS {
                    break;
                }
                yields += 1;
                std::thread::yield_now();
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Drain any unread data from the peer's send buffer so that
/// `shutdown(SHUT_WR)` sends a graceful FIN instead of RST.
///
/// On macOS, calling `shutdown(SHUT_WR)` on a non-blocking socket that has
/// unread data in the receive buffer triggers an RST rather than a TCP FIN.
/// This non-blocking drain empties the receive buffer, letting
/// `shutdown(SHUT_WR)` complete cleanly on all platforms.
fn drain_read_to_would_block(stream: &mut TcpStream) {
    let mut buf = [0u8; 128];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_body_sorts_pids_numerically() {
        let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
        prom.record(&Event::Beat {
            pid: 30,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 0,
        })
        .unwrap();
        prom.record(&Event::Beat {
            pid: 2,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 0,
        })
        .unwrap();
        prom.record(&Event::Beat {
            pid: 11,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 0,
        })
        .unwrap();
        prom.render_body();
        let body = &prom.body_buf;
        let pos2 = body.find("pid=\"2\"").expect("pid 2");
        let pos11 = body.find("pid=\"11\"").expect("pid 11");
        let pos30 = body.find("pid=\"30\"").expect("pid 30");
        assert!(pos2 < pos11 && pos11 < pos30, "sort order broken:\n{body}");
    }

    #[test]
    fn decode_and_io_events_do_not_create_rows() {
        let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
        prom.record(&Event::Decode(varta_vlp::DecodeError::BadMagic, 0))
            .unwrap();
        prom.record(&Event::Io(io::Error::other("x"), 0)).unwrap();
        assert!(prom.rows.is_empty());
    }

    #[test]
    fn decode_errors_emit_kind_label_for_every_variant_even_at_zero() {
        let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
        // Bump bad_magic twice, bad_status once, leave bad_version at zero.
        prom.record(&Event::Decode(DecodeError::BadMagic, 0))
            .unwrap();
        prom.record(&Event::Decode(DecodeError::BadMagic, 0))
            .unwrap();
        prom.record(&Event::Decode(DecodeError::BadStatus(0xff), 0))
            .unwrap();

        prom.render_body();
        let body = &prom.body_buf;
        // All three kind series must be present so `absent()` rules don't
        // silently disappear before the first incident of that kind.
        assert!(
            body.contains("varta_decode_errors_total{kind=\"bad_magic\"} 2"),
            "missing or wrong bad_magic series:\n{body}"
        );
        assert!(
            body.contains("varta_decode_errors_total{kind=\"bad_version\"} 0"),
            "missing zero-valued bad_version series:\n{body}"
        );
        assert!(
            body.contains("varta_decode_errors_total{kind=\"bad_status\"} 1"),
            "missing or wrong bad_status series:\n{body}"
        );
    }

    #[test]
    fn non_get_request_returns_405() {
        let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
        let addr = prom.local_addr().expect("local_addr");
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        stream
            .write_all(b"POST /metrics HTTP/1.0\r\n\r\n")
            .expect("write");
        prom.serve_pending().expect("serve_pending");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read");
        assert!(
            response.starts_with("HTTP/1.0 405 Method Not Allowed"),
            "expected 405, got: {response}"
        );
        assert!(
            response.contains("Allow: GET"),
            "missing Allow header: {response}"
        );
    }

    #[test]
    fn record_evicted_pid_removes_row() {
        let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
        prom.record(&Event::Beat {
            pid: 42,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 0,
        })
        .unwrap();
        assert!(prom.rows.contains_key(&42), "row should exist after beat");
        prom.record_evicted_pid(42);
        assert!(
            !prom.rows.contains_key(&42),
            "row should be removed after eviction"
        );
    }

    #[test]
    fn record_evicted_pid_ignores_unknown_pid() {
        let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
        // Should not panic when called for a pid that was never tracked.
        prom.record_evicted_pid(99);
        // Verify rows is still empty.
        assert!(prom.rows.is_empty());
    }

    #[test]
    fn self_health_metrics_are_emitted() {
        let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
        // Add a tracked PID so pids_tracked > 0
        prom.record(&Event::Beat {
            pid: 7,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 1,
        })
        .unwrap();
        prom.record_loop_tick();
        prom.render_body();
        let body = &prom.body_buf;
        assert!(
            body.contains("varta_watch_uptime_seconds"),
            "missing varta_watch_uptime_seconds:\n{body}"
        );
        assert!(
            body.contains("varta_watch_last_poll_loop_timestamp_seconds"),
            "missing varta_watch_last_poll_loop_timestamp_seconds:\n{body}"
        );
        assert!(
            body.contains("varta_watch_pids_tracked 1"),
            "missing/incorrect varta_watch_pids_tracked:\n{body}"
        );
        // Uptime should be small (just created)
        let needle = "varta_watch_uptime_seconds 0.";
        assert!(body.contains(needle), "uptime should start near 0:\n{body}");
        // pids_tracked after eviction
        prom.record_evicted_pid(7);
        prom.render_body();
        let body2 = &prom.body_buf;
        assert!(
            body2.contains("varta_watch_pids_tracked 0"),
            "pids_tracked should be 0 after eviction:\n{body2}"
        );
    }
}
