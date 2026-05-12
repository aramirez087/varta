//! Session 05 acceptance contract tests for `varta-watch::exporter`.
//!
//! Each test name here is verbatim from `docs/acceptance/varta-v0-1-0.md`.
//! The CI gate (Session 08) greps these names — do not rename without
//! updating the contract.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::Duration;

use varta_vlp::{DecodeError, Status};
use varta_watch::{Event, Exporter, FileExporter, PromExporter};

static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_tmp(tag: &str) -> TempPath {
    let pid = std::process::id();
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("varta-watch-s05-{tag}-{pid}-{n}"));
    let _ = std::fs::remove_file(&p);
    TempPath(p)
}

struct TempPath(PathBuf);

impl TempPath {
    fn as_path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Drive `serve_pending` from the test thread while a client transaction
/// (connect → write request → read response) completes against `addr`.
/// Returns the response body (everything after the first `\r\n\r\n`).
fn http_get(prom: &mut PromExporter, addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect to prom exporter");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("write timeout");

    let req = format!("GET {path} HTTP/1.0\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .expect("write http request");

    // Yield so the kernel can deliver the bytes to the server's receive
    // buffer before serve_pending accepts and reads the connection.
    thread::sleep(Duration::from_millis(5));

    prom.serve_pending().expect("serve_pending");

    let mut buf = Vec::with_capacity(2048);
    stream.read_to_end(&mut buf).expect("read response");
    let raw = String::from_utf8(buf).expect("utf8 response");
    let split = raw
        .find("\r\n\r\n")
        .unwrap_or_else(|| panic!("response missing header/body delimiter:\n{raw}"));
    raw[split + 4..].to_string()
}

#[test]
fn prom_exporter_reports_beats_total_per_pid() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    for n in 1..=3 {
        prom.record(&Event::Beat {
            pid: 7,
            status: Status::Ok,
            payload: 0,
            nonce: n,
            observer_ns: 0,
        });
    }
    let body = http_get(&mut prom, addr, "/metrics");
    assert!(
        body.contains("varta_beats_total{pid=\"7\"} 3"),
        "missing beats_total counter:\n{body}"
    );
}

#[test]
fn prom_exporter_reports_stalls_total_per_pid() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    prom.record(&Event::Beat {
        pid: 9,
        status: Status::Ok,
        payload: 0,
        nonce: 1,
        observer_ns: 0,
    });
    prom.record(&Event::Stall {
        pid: 9,
        last_nonce: 1,
        last_ns: 0,
        observer_ns: 0,
    });
    let body = http_get(&mut prom, addr, "/metrics");
    assert!(
        body.contains("varta_stalls_total{pid=\"9\"} 1"),
        "missing stalls_total counter:\n{body}"
    );
}

#[test]
fn file_exporter_appends_one_line_per_event() {
    let path = unique_tmp("export");
    let mut fe = FileExporter::create(path.as_path(), None).expect("create file exporter");
    let events = [
        Event::Beat {
            pid: 1,
            status: Status::Ok,
            payload: 0,
            nonce: 1,
            observer_ns: 0,
        },
        Event::Beat {
            pid: 1,
            status: Status::Degraded,
            payload: 0,
            nonce: 2,
            observer_ns: 0,
        },
        Event::Stall {
            pid: 1,
            last_nonce: 2,
            last_ns: 0,
            observer_ns: 0,
        },
        Event::Decode(DecodeError::BadMagic, 0),
    ];
    for ev in &events {
        fe.record(ev);
    }
    fe.flush().expect("flush");
    let body = std::fs::read_to_string(path.as_path()).expect("read export file");
    assert_eq!(
        body.lines().count(),
        events.len(),
        "file exporter line count mismatch:\n{body}"
    );
}
