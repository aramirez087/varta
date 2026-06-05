//! Session 05 acceptance contract tests for `varta-watch::exporter`.
//!
//! Each test name here is verbatim from `docs/acceptance/varta-v0-1-0.md`.
//! The CI gate (Session 08) greps these names — do not rename without
//! updating the contract.
//!
//! Requires `--features prometheus-exporter` — exercises the HTTP /metrics
//! surface that the Class-A safety-critical profile intentionally excludes.

#![cfg(feature = "prometheus-exporter")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::Duration;

use varta_vlp::crypto::BearerToken;
use varta_vlp::{DecodeError, Status};
use varta_watch::{Event, Exporter, FileExporter, PromExporter};

static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Shared bearer token across the integration suite.  Bytes are arbitrary;
/// `TEST_TOKEN_HEX` is the lowercase 64-char hex form for the
/// `Authorization: Bearer` header.
const TEST_TOKEN: [u8; 32] = [0xcd; 32];
const TEST_TOKEN_HEX: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn make_token() -> BearerToken {
    BearerToken::from_bytes(TEST_TOKEN)
}

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

    let req = format!("GET {path} HTTP/1.0\r\nAuthorization: Bearer {TEST_TOKEN_HEX}\r\n\r\n");
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
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    for n in 1..=3 {
        prom.record(&Event::Beat {
            pid: 7,
            status: Status::Ok,
            payload: 0,
            nonce: n,
            observer_ns: 0,
            origin: varta_watch::BeatOrigin::KernelAttested,
            pid_ns_inode: None,
        })
        .unwrap();
    }
    let body = http_get(&mut prom, addr, "/metrics");
    assert!(
        body.contains("varta_beats_total{pid=\"7\"} 3"),
        "missing beats_total counter:\n{body}"
    );
}

#[test]
fn prom_exporter_reports_stalls_total_per_pid() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    prom.record(&Event::Beat {
        pid: 9,
        status: Status::Ok,
        payload: 0,
        nonce: 1,
        observer_ns: 0,
        origin: varta_watch::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    })
    .unwrap();
    prom.record(&Event::Stall {
        pid: 9,
        last_nonce: 1,
        last_ns: 0,
        observer_ns: 0,
        origin: varta_watch::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
        generation: None,
    })
    .unwrap();
    let body = http_get(&mut prom, addr, "/metrics");
    assert!(
        body.contains("varta_stalls_total{pid=\"9\"} 1"),
        "missing stalls_total counter:\n{body}"
    );
}

/// Bucket boundaries duplicated locally because the constant is private to
/// the exporter module.  If these drift, update both sites — the doc and
/// the alert recipes in `observer-liveness.md` also reference these
/// boundaries by value.
const EXPECTED_BUCKET_LE: &[&str] = &[
    "0.001", "0.005", "0.01", "0.05", "0.1", "0.25", "0.5", "1", "+Inf",
];

#[test]
fn prom_exporter_emits_serve_pending_seconds_buckets_at_zero_on_first_scrape() {
    // Contract: every bucket label (including `+Inf`, literally — not `inf`)
    // must appear on the first scrape with count zero so `absent()` alert
    // rules and `histogram_quantile()` queries stay green from the first
    // observation.  Same discipline as `iteration_seconds`,
    // `decode_errors_total`, and `prom_connections_dropped_total`.
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    let body = http_get(&mut prom, addr, "/metrics");
    for le in EXPECTED_BUCKET_LE {
        let needle = format!("varta_observer_serve_pending_seconds_bucket{{le=\"{le}\"}} 0");
        assert!(
            body.contains(&needle),
            "missing serve_pending bucket `le={le}` at zero:\n{body}"
        );
    }
    assert!(
        body.contains("varta_observer_serve_pending_seconds_count 0"),
        "missing serve_pending_seconds_count:\n{body}"
    );
    assert!(
        body.contains("varta_observer_serve_pending_seconds_sum 0.000000000"),
        "missing serve_pending_seconds_sum at zero:\n{body}"
    );
}

#[test]
fn prom_exporter_emits_scrape_budget_exceeded_at_zero_on_first_scrape() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    let body = http_get(&mut prom, addr, "/metrics");
    assert!(
        body.contains("varta_observer_scrape_budget_exceeded_total 0"),
        "missing scrape_budget_exceeded_total at zero:\n{body}"
    );
}

#[test]
fn prom_exporter_serve_pending_histogram_records_observed_durations() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token()).expect("bind");
    let addr = prom.local_addr().expect("local_addr");
    // Record three observations directly — http_get itself calls
    // serve_pending() but the test helper does NOT call
    // record_serve_pending_duration (only the daemon's main loop does).
    // So the histogram count should be exactly 3.
    prom.record_serve_pending_duration(Duration::from_micros(50));
    prom.record_serve_pending_duration(Duration::from_micros(150));
    prom.record_serve_pending_duration(Duration::from_micros(300));
    let body = http_get(&mut prom, addr, "/metrics");
    assert!(
        body.contains("varta_observer_serve_pending_seconds_count 3"),
        "expected count=3:\n{body}"
    );
    // All three observations are well below 1 ms, so they should all land
    // in the first bucket and be cumulative-counted in every higher bucket.
    assert!(
        body.contains("varta_observer_serve_pending_seconds_bucket{le=\"0.001\"} 3"),
        "expected `le=\"0.001\"` bucket = 3:\n{body}"
    );
    assert!(
        body.contains("varta_observer_serve_pending_seconds_bucket{le=\"+Inf\"} 3"),
        "expected +Inf bucket = 3 (cumulative):\n{body}"
    );
}

#[test]
fn prom_exporter_scrape_budget_exceeded_increments_when_observation_exceeds_budget() {
    let mut prom = PromExporter::bind("127.0.0.1:0".parse().unwrap(), make_token())
        .expect("bind")
        .with_scrape_budget(Duration::from_millis(10));
    let addr = prom.local_addr().expect("local_addr");
    // One in-budget, two over-budget.
    prom.record_serve_pending_duration(Duration::from_millis(1));
    prom.record_serve_pending_duration(Duration::from_millis(20));
    prom.record_serve_pending_duration(Duration::from_millis(50));
    let body = http_get(&mut prom, addr, "/metrics");
    assert!(
        body.contains("varta_observer_scrape_budget_exceeded_total 2"),
        "expected scrape_budget_exceeded_total = 2:\n{body}"
    );
}

#[test]
fn file_exporter_appends_one_line_per_event() {
    let path = unique_tmp("export");
    let mut fe = FileExporter::create(path.as_path(), None, 0).expect("create file exporter");
    let events = [
        Event::Beat {
            pid: 1,
            status: Status::Ok,
            payload: 0,
            nonce: 1,
            observer_ns: 0,
            origin: varta_watch::BeatOrigin::KernelAttested,
            pid_ns_inode: None,
        },
        Event::Beat {
            pid: 1,
            status: Status::Degraded,
            payload: 0,
            nonce: 2,
            observer_ns: 0,
            origin: varta_watch::BeatOrigin::KernelAttested,
            pid_ns_inode: None,
        },
        Event::Stall {
            pid: 1,
            last_nonce: 2,
            last_ns: 0,
            observer_ns: 0,
            origin: varta_watch::BeatOrigin::KernelAttested,
            pid_ns_inode: None,
            generation: None,
        },
        Event::Decode(DecodeError::BadMagic, 0),
    ];
    for ev in &events {
        fe.record(ev).unwrap();
    }
    fe.flush().expect("flush");
    let body = std::fs::read_to_string(path.as_path()).expect("read export file");
    assert_eq!(
        body.lines().count(),
        events.len(),
        "file exporter line count mismatch:\n{body}"
    );
}

#[test]
fn file_exporter_sync_every_one_durable_without_flush() {
    // sync_every = 1 forces fdatasync on every record. Reading the file
    // back through a fresh open (no shared BufWriter state) must see the
    // line on disk before the exporter is dropped or flushed.
    let path = unique_tmp("export-sync");
    let mut fe = FileExporter::create(path.as_path(), None, 1).expect("create file exporter");
    let ev = Event::Beat {
        pid: 1,
        status: Status::Ok,
        payload: 0,
        nonce: 1,
        observer_ns: 0,
        origin: varta_watch::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    };
    fe.record(&ev).unwrap();
    // Crucially: NO `fe.flush()` and NO `drop(fe)` before reading. The
    // fdatasync inside `after_write` is what proves durability.
    let body = std::fs::read_to_string(path.as_path()).expect("read export file");
    assert_eq!(
        body.lines().count(),
        1,
        "sync_every=1 must persist every record on disk:\n{body}"
    );
}

#[test]
fn file_exporter_sync_every_zero_is_buffered_until_flush() {
    // sync_every = 0 (default) keeps the old behavior — writes stay in
    // the BufWriter until flush()/drop. Reading the file mid-stream sees
    // an empty file even though `record()` returned Ok.
    let path = unique_tmp("export-buffered");
    let mut fe = FileExporter::create(path.as_path(), None, 0).expect("create file exporter");
    let ev = Event::Beat {
        pid: 1,
        status: Status::Ok,
        payload: 0,
        nonce: 1,
        observer_ns: 0,
        origin: varta_watch::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    };
    fe.record(&ev).unwrap();
    let mid = std::fs::read_to_string(path.as_path()).expect("read export file");
    assert!(
        mid.is_empty(),
        "without sync_every, a one-event write must still be buffered:\n{mid}"
    );
    fe.flush().expect("flush");
    let after = std::fs::read_to_string(path.as_path()).expect("read export file");
    assert_eq!(
        after.lines().count(),
        1,
        "after flush the buffered event must be on disk:\n{after}"
    );
}

#[test]
fn file_exporter_sync_every_n_batches_durability() {
    // sync_every = 3 — first two records stay buffered, the third
    // triggers an fdatasync that brings all three on disk together.
    let path = unique_tmp("export-batched");
    let mut fe = FileExporter::create(path.as_path(), None, 3).expect("create file exporter");
    let make = |nonce: u64| Event::Beat {
        pid: 1,
        status: Status::Ok,
        payload: 0,
        nonce,
        observer_ns: 0,
        origin: varta_watch::BeatOrigin::KernelAttested,
        pid_ns_inode: None,
    };

    fe.record(&make(1)).unwrap();
    fe.record(&make(2)).unwrap();
    let after_two = std::fs::read_to_string(path.as_path()).expect("read export file");
    assert!(
        after_two.is_empty(),
        "below the sync threshold the file should still be empty:\n{after_two}"
    );

    fe.record(&make(3)).unwrap();
    let after_three = std::fs::read_to_string(path.as_path()).expect("read export file");
    assert_eq!(
        after_three.lines().count(),
        3,
        "the Nth record must flush every preceding buffered record too:\n{after_three}"
    );
}
