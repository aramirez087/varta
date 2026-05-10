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

use varta_vlp::Status;

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
/// `kind` ∈ `{beat, stall, decode, io}`. For `decode` and `io` events the
/// pid / nonce / status / payload columns are written as `-` so the line
/// count and column count remain stable.
///
/// `observer_ns` is the elapsed nanoseconds since this exporter was
/// created, captured at `record()` time. The `Event` enum carries no
/// per-event timestamp, so each exporter snapshots its own monotonic
/// clock — values are comparable within a single observer process.
pub struct FileExporter {
    sink: BufWriter<File>,
    start: Instant,
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
            start: Instant::now(),
            pending_err: None,
        })
    }

    fn elapsed_ns(&self) -> u128 {
        self.start.elapsed().as_nanos()
    }
}

impl Exporter for FileExporter {
    fn record(&mut self, ev: &Event) {
        if self.pending_err.is_some() {
            return;
        }
        let ns = self.elapsed_ns();
        let line = match ev {
            Event::Beat {
                pid,
                status,
                payload,
                nonce,
            } => format!(
                "{ns}\tbeat\t{pid}\t{nonce}\t{status}\t{payload}\n",
                status = status_label(*status),
            ),
            Event::Stall {
                pid,
                last_nonce,
                last_ns: _,
            } => format!("{ns}\tstall\t{pid}\t{last_nonce}\tstall\t-\n"),
            Event::Decode(err) => format!("{ns}\tdecode\t-\t-\t-\t{err:?}\n"),
            Event::Io(err) => format!("{ns}\tio\t-\t-\t-\t{err}\n"),
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

fn status_code(s: Status) -> u8 {
    match s {
        Status::Ok => 0,
        Status::Degraded => 1,
        Status::Critical => 2,
        Status::Stall => 3,
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

    /// Accept every connection currently ready on the listener and write a
    /// metrics response back. Returns `Ok(())` when the accept queue
    /// drains cleanly; returns the first non-`WouldBlock` error otherwise.
    pub fn serve_pending(&mut self) -> io::Result<()> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => self.serve_one(stream)?,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    fn serve_one(&self, mut stream: TcpStream) -> io::Result<()> {
        // Stream is already non-blocking (inherited from the listener).
        // A short write timeout bounds the response phase.
        stream.set_write_timeout(Some(PROM_WRITE_TIMEOUT))?;

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

        let body = self.render_body();
        let response = format!(
            "HTTP/1.0 200 OK\r\n\
             Content-Type: text/plain; version=0.0.4\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            len = body.len(),
            body = body,
        );
        stream.write_all(response.as_bytes())?;
        stream.shutdown(Shutdown::Both)?;
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
        out
    }
}

impl Exporter for PromExporter {
    fn record(&mut self, ev: &Event) {
        match ev {
            Event::Beat { pid, status, .. } => {
                let row = self.rows.entry(*pid).or_insert_with(GaugeRow::new);
                row.beats_total = row.beats_total.saturating_add(1);
                row.last_status = Some(status_code(*status));
            }
            Event::Stall { pid, .. } => {
                let row = self.rows.entry(*pid).or_insert_with(GaugeRow::new);
                row.stalls_total = row.stalls_total.saturating_add(1);
                row.last_status = Some(status_code(Status::Stall));
            }
            Event::Decode(_) | Event::Io(_) => {}
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.serve_pending()
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
        });
        prom.record(&Event::Beat {
            pid: 2,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
        });
        prom.record(&Event::Beat {
            pid: 11,
            status: Status::Ok,
            nonce: 1,
            payload: 0,
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
        prom.record(&Event::Decode(varta_vlp::DecodeError::BadMagic));
        prom.record(&Event::Io(io::Error::other("x")));
        assert!(prom.rows.is_empty());
    }
}
