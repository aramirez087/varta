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
use std::path::Path;
use std::time::{Duration, Instant};

use varta_vlp::{DecodeError, Status};

use crate::observer::Event;

/// Sink for an [`Event`] stream.
pub trait Exporter {
    /// Record a single observer event. Implementations should never panic
    /// or block the caller for IO; transient failures are absorbed and
    /// surfaced via [`Exporter::flush`].
    fn record(&mut self, ev: &Event);
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
pub struct FileExporter {
    sink: BufWriter<File>,
    pending_err: Option<io::Error>,
}

impl FileExporter {
    /// Open `path` in append mode (creating it if necessary) and wrap it
    /// in a [`BufWriter`].
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())?;
        Ok(FileExporter {
            sink: BufWriter::new(file),
            pending_err: None,
        })
    }
}

impl Exporter for FileExporter {
    fn record(&mut self, ev: &Event) {
        if self.pending_err.is_some() {
            return;
        }
        let line = match ev {
            Event::Beat {
                pid,
                status,
                payload,
                nonce,
                observer_ns,
            } => format!(
                "{observer_ns}\tbeat\t{pid}\t{nonce}\t{status}\t{payload}\n",
                status = status_label(*status),
            ),
            Event::Stall {
                pid,
                last_nonce,
                last_ns: _,
                observer_ns,
            } => format!("{observer_ns}\tstall\t{pid}\t{last_nonce}\tstall\t-\n"),
            Event::Decode(err, observer_ns) => {
                format!("{observer_ns}\tdecode\t-\t-\t-\t{err:?}\n")
            }
            Event::Io(err, observer_ns) => {
                format!("{observer_ns}\tio\t-\t-\t-\t{err}\n")
            }
            Event::AuthFailure {
                claimed_pid,
                observer_ns,
            } => {
                format!("{observer_ns}\tmismatch\t{claimed_pid}\t-\t-\tauth_failure\n")
            }
        };
        if let Err(e) = self.sink.write_all(line.as_bytes()) {
            self.pending_err = Some(e);
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

fn status_label(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Degraded => "degraded",
        Status::Critical => "critical",
        Status::Stall => "stall",
    }
}

/// Prometheus `kind` label values for `varta_decode_errors_total`. Indexed
/// by [`decode_kind_index`]; the array doubles as the canonical ordering
/// for the exposition output, so series remain stable across scrapes.
const DECODE_KIND_LABELS: [&str; 3] = ["bad_magic", "bad_version", "bad_status"];

fn decode_kind_index(err: &DecodeError) -> usize {
    match err {
        DecodeError::BadMagic => 0,
        DecodeError::BadVersion => 1,
        DecodeError::BadStatus(_) => 2,
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
/// Cap on how many bytes [`PromExporter::serve_pending`] reads from a
/// single request before responding (we discard the request line/headers).
const PROM_REQUEST_CAP: usize = 4096;

/// Prometheus text-format exporter served over HTTP/1.0.
///
/// The exporter is poll-driven: the daemon main loop calls
/// [`PromExporter::serve_pending`] once per outer tick and the listener
/// is non-blocking, so there is no background thread. Each accepted
/// connection receives a fresh metrics body with `Connection: close`.
pub struct PromExporter {
    listener: TcpListener,
    rows: HashMap<u32, GaugeRow>,
    evicted_total: u64,
    auth_failures_total: u64,
    /// Per-kind decode failure counters, indexed by [`decode_kind_index`].
    /// Always emitted in full (even at zero) so `absent()` alert rules and
    /// dashboards stay green-on-green instead of disappearing until the
    /// first incident.
    decode_errors_total: [u64; 3],
    io_errors_total: u64,
    capacity_exceeded_total: u64,
}

impl PromExporter {
    /// Bind a non-blocking TCP listener on `addr` and return the exporter.
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        Ok(PromExporter {
            listener,
            rows: HashMap::new(),
            evicted_total: 0,
            auth_failures_total: 0,
            decode_errors_total: [0; 3],
            io_errors_total: 0,
            capacity_exceeded_total: 0,
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

    /// Record one or more beats dropped due to tracker capacity exceeded.
    pub fn record_capacity_exceeded(&mut self, count: u64) {
        self.capacity_exceeded_total = self.capacity_exceeded_total.saturating_add(count);
    }

    /// Accept every connection currently ready on the listener and write a
    /// metrics response back. Returns `Ok(())` when the accept queue
    /// drains cleanly; returns the first non-`WouldBlock` error otherwise.
    ///
    /// Total service time per call is bounded to avoid starving the
    /// observer poll loop under a storm of slow scrapers.
    pub fn serve_pending(&mut self) -> io::Result<()> {
        let serve_deadline = Instant::now() + Duration::from_millis(100);
        loop {
            if Instant::now() >= serve_deadline {
                return Ok(());
            }
            match self.listener.accept() {
                Ok((stream, _)) => self.serve_one(stream)?,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    fn serve_one(&self, mut stream: TcpStream) -> io::Result<()> {
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
                    if contains_subsequence(preview, b"\r\n\r\n") || total >= PROM_REQUEST_CAP {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        if total < 4 || buf[..4] != *b"GET " {
            let response = b"HTTP/1.0 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let mut written = 0;
            let write_deadline = Instant::now() + PROM_WRITE_TIMEOUT;
            while written < response.len() {
                if Instant::now() >= write_deadline {
                    break;
                }
                match stream.write(&response[written..]) {
                    Ok(0) => break,
                    Ok(n) => written += n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        std::hint::spin_loop();
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            let _ = stream.shutdown(Shutdown::Both);
            return Ok(());
        }

        let body = self.render_body();
        let response = format!(
            "HTTP/1.0 200 OK\r\n\
             Content-Type: text/plain; version=0.0.4\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            len = body.len(),
        );
        let buf = response.as_bytes();
        let mut written = 0;
        let write_deadline = Instant::now() + PROM_WRITE_TIMEOUT;
        while written < buf.len() {
            if Instant::now() >= write_deadline {
                break;
            }
            match stream.write(&buf[written..]) {
                Ok(0) => break,
                Ok(n) => written += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // Peer's recv buffer is full. The deadline check at the
                    // top of the loop caps the worst case; hint the CPU we
                    // are in a short busy-wait so it can back off internally
                    // instead of burning a full core for PROM_WRITE_TIMEOUT.
                    std::hint::spin_loop();
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
        Ok(())
    }

    fn render_body(&self) -> String {
        let mut pids: Vec<u32> = self.rows.keys().copied().collect();
        pids.sort_unstable();

        let mut out = String::with_capacity(256 + pids.len() * 96);
        out.push_str("# HELP varta_beats_total Total accepted beats per agent pid.\n");
        out.push_str("# TYPE varta_beats_total counter\n");
        for pid in &pids {
            let row = &self.rows[pid];
            let _ = writeln!(
                out,
                "varta_beats_total{{pid=\"{pid}\"}} {}",
                row.beats_total
            );
        }
        out.push_str("# HELP varta_stalls_total Total observer-detected stalls per agent pid.\n");
        out.push_str("# TYPE varta_stalls_total counter\n");
        for pid in &pids {
            let row = &self.rows[pid];
            let _ = writeln!(
                out,
                "varta_stalls_total{{pid=\"{pid}\"}} {}",
                row.stalls_total
            );
        }
        out.push_str("# HELP varta_status Last reported status code per agent pid (0=ok,1=degraded,2=critical,3=stall).\n");
        out.push_str("# TYPE varta_status gauge\n");
        for pid in &pids {
            let row = &self.rows[pid];
            if let Some(code) = row.last_status {
                let _ = writeln!(out, "varta_status{{pid=\"{pid}\"}} {code}");
            }
        }
        if self.evicted_total > 0 {
            out.push_str("# HELP varta_tracker_evicted_total Total tracker slots reclaimed from dead agents.\n");
            out.push_str("# TYPE varta_tracker_evicted_total counter\n");
            let _ = writeln!(out, "varta_tracker_evicted_total {}", self.evicted_total);
        }
        // Security counter — always emitted, even at 0.  Otherwise dashboards
        // and `absent()` alert rules silently produce no series until the
        // first spoof attempt, which defeats the purpose of an alert.
        out.push_str(
            "# HELP varta_frame_auth_failures_total Frames rejected due to PID spoofing or authentication failure.\n",
        );
        out.push_str("# TYPE varta_frame_auth_failures_total counter\n");
        let _ = writeln!(
            out,
            "varta_frame_auth_failures_total {}",
            self.auth_failures_total
        );
        // Always emit one series per kind so dashboards and `absent()` rules
        // stay green-on-green instead of disappearing until the first incident.
        out.push_str("# HELP varta_decode_errors_total Total VLP decode failures by kind.\n");
        out.push_str("# TYPE varta_decode_errors_total counter\n");
        for (idx, kind) in DECODE_KIND_LABELS.iter().enumerate() {
            let _ = writeln!(
                out,
                "varta_decode_errors_total{{kind=\"{kind}\"}} {}",
                self.decode_errors_total[idx]
            );
        }
        out.push_str("# HELP varta_io_errors_total Total socket receive errors.\n");
        out.push_str("# TYPE varta_io_errors_total counter\n");
        let _ = writeln!(out, "varta_io_errors_total {}", self.io_errors_total);
        if self.capacity_exceeded_total > 0 {
            out.push_str("# HELP varta_tracker_capacity_exceeded_total Total beats dropped because tracker is full.\n");
            out.push_str("# TYPE varta_tracker_capacity_exceeded_total counter\n");
            let _ = writeln!(
                out,
                "varta_tracker_capacity_exceeded_total {}",
                self.capacity_exceeded_total
            );
        }
        out
    }
}

impl Exporter for PromExporter {
    fn record(&mut self, ev: &Event) {
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
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
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
        });
        prom.record(&Event::Beat {
            pid: 2,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 0,
        });
        prom.record(&Event::Beat {
            pid: 11,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
            observer_ns: 0,
        });
        let body = prom.render_body();
        let pos2 = body.find("pid=\"2\"").expect("pid 2");
        let pos11 = body.find("pid=\"11\"").expect("pid 11");
        let pos30 = body.find("pid=\"30\"").expect("pid 30");
        assert!(pos2 < pos11 && pos11 < pos30, "sort order broken:\n{body}");
    }

    #[test]
    fn decode_and_io_events_do_not_create_rows() {
        let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
        prom.record(&Event::Decode(varta_vlp::DecodeError::BadMagic, 0));
        prom.record(&Event::Io(io::Error::other("x"), 0));
        assert!(prom.rows.is_empty());
    }

    #[test]
    fn decode_errors_emit_kind_label_for_every_variant_even_at_zero() {
        let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
        // Bump bad_magic twice, bad_status once, leave bad_version at zero.
        prom.record(&Event::Decode(DecodeError::BadMagic, 0));
        prom.record(&Event::Decode(DecodeError::BadMagic, 0));
        prom.record(&Event::Decode(DecodeError::BadStatus(0xff), 0));

        let body = prom.render_body();
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
}
