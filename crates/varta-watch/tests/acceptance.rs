//! Session 03 acceptance contract tests for `varta-watch`.
//!
//! Each test name here is verbatim from `docs/acceptance/varta-v0-1-0.md`.
//! The CI gate (Session 08) greps these names — do not rename without
//! updating the contract.

use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use varta_vlp::{DecodeError, Frame, Status, MAGIC, VERSION};
use varta_watch::{Event, Observer, Tracker, Update};

static UDS_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Mint a unique socket path for the duration of one test. The path lives
/// under `std::env::temp_dir()` and is removed by the returned [`UdsPath`]
/// guard on drop, so failed test runs do not leave orphans behind.
fn unique_uds_path(tag: &str) -> UdsPath {
    let pid = std::process::id();
    let n = UDS_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("varta-watch-s03-{tag}-{pid}-{n}.sock"));
    let _ = std::fs::remove_file(&p);
    UdsPath(p)
}

struct UdsPath(PathBuf);

impl UdsPath {
    fn as_path(&self) -> &Path {
        &self.0
    }
}

impl Drop for UdsPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Build a canonical 32-byte VLP frame for the given pid/nonce/status.
fn make_frame(pid: u32, nonce: u64, status: Status, payload: u64) -> Frame {
    Frame {
        magic: MAGIC,
        version: VERSION,
        status: status as u8,
        pid,
        timestamp: nonce,
        nonce,
        payload,
    }
}

/// Open a connected client datagram socket pointing at `target`.
fn client_socket(target: &Path) -> UnixDatagram {
    let sock = UnixDatagram::unbound().expect("client unbound");
    sock.connect(target).expect("client connect");
    sock
}

/// Send `frame` as 32 wire bytes through `sock`.
fn send_frame(sock: &UnixDatagram, frame: &Frame) {
    let mut buf = [0u8; 32];
    frame.encode(&mut buf);
    sock.send(&buf).expect("send frame");
}

/// Poll the observer until `pred` returns `Some(_)` or the deadline expires.
/// Replaces raw sleeps with a bounded retry that yields between empty polls.
fn poll_until_match<F, T>(observer: &mut Observer, deadline: Duration, mut pred: F) -> Option<T>
where
    F: FnMut(Event) -> Result<T, ()>,
{
    let stop = Instant::now() + deadline;
    while Instant::now() < stop {
        if let Some(ev) = observer.poll() {
            if let Ok(value) = pred(ev) {
                return Some(value);
            }
            continue;
        }
        thread::sleep(Duration::from_millis(1));
    }
    None
}

#[test]
fn observer_emits_beat_per_received_frame() {
    let path = unique_uds_path("beats");
    let mut observer =
        Observer::bind(path.as_path(), Duration::from_secs(60)).expect("bind observer");
    let client = client_socket(path.as_path());

    let frames = [
        make_frame(101, 1, Status::Ok, 0xA1),
        make_frame(101, 2, Status::Ok, 0xA2),
        make_frame(101, 3, Status::Degraded, 0xA3),
    ];
    for f in &frames {
        send_frame(&client, f);
    }

    let deadline = Duration::from_secs(2);
    let mut got: Vec<(u32, u64, Status, u64)> = Vec::with_capacity(3);
    let stop = Instant::now() + deadline;
    while got.len() < 3 && Instant::now() < stop {
        if let Some(ev) = observer.poll() {
            match ev {
                Event::Beat {
                    pid,
                    nonce,
                    status,
                    payload,
                } => got.push((pid, nonce, status, payload)),
                Event::Decode(e) => panic!("unexpected decode error: {e}"),
                Event::Io(e) => panic!("unexpected io error: {e}"),
                Event::Stall { .. } => panic!("unexpected stall during beat test"),
            }
        } else {
            thread::sleep(Duration::from_millis(1));
        }
    }

    assert_eq!(got.len(), 3, "expected 3 beats, got {got:?}");
    assert_eq!(got[0], (101, 1, Status::Ok, 0xA1));
    assert_eq!(got[1], (101, 2, Status::Ok, 0xA2));
    assert_eq!(got[2], (101, 3, Status::Degraded, 0xA3));
}

#[test]
fn observer_emits_stall_after_threshold_elapses() {
    let path = unique_uds_path("stall");
    let threshold = Duration::from_millis(150);
    let mut observer = Observer::bind(path.as_path(), threshold).expect("bind observer");
    let client = client_socket(path.as_path());

    send_frame(&client, &make_frame(202, 1, Status::Ok, 0xB1));

    // Drain the beat first.
    let beat = poll_until_match(&mut observer, Duration::from_secs(2), |ev| match ev {
        Event::Beat { pid, nonce, .. } if pid == 202 && nonce == 1 => Ok(()),
        _ => Err(()),
    });
    assert!(beat.is_some(), "did not observe initial beat for pid 202");

    // Now expect a Stall event for pid 202 within threshold + budget.
    let stall = poll_until_match(
        &mut observer,
        threshold + Duration::from_secs(1),
        |ev| match ev {
            Event::Stall {
                pid, last_nonce, ..
            } if pid == 202 && last_nonce == 1 => Ok(()),
            _ => Err(()),
        },
    );
    assert!(stall.is_some(), "no Stall event surfaced for pid 202");

    // It must fire exactly once — confirm no second stall arrives shortly after.
    let extra = poll_until_match(&mut observer, Duration::from_millis(300), |ev| match ev {
        Event::Stall { pid: 202, .. } => Ok(()),
        _ => Err(()),
    });
    assert!(
        extra.is_none(),
        "Stall must fire exactly once per silence run"
    );
}

#[test]
fn observer_reports_decode_error_for_bad_magic() {
    let path = unique_uds_path("decode");
    let mut observer =
        Observer::bind(path.as_path(), Duration::from_secs(60)).expect("bind observer");
    let client = client_socket(path.as_path());

    let bogus = [0xFFu8; 32];
    client.send(&bogus).expect("send bogus payload");

    let got = poll_until_match(&mut observer, Duration::from_secs(2), |ev| match ev {
        Event::Decode(DecodeError::BadMagic) => Ok(()),
        Event::Decode(other) => panic!("wrong decode error variant: {other:?}"),
        _ => Err(()),
    });
    assert!(got.is_some(), "expected Event::Decode(BadMagic)");
}

#[test]
fn tracker_capacity_bounded_to_64_pids() {
    let mut tracker = Tracker::new();
    let now_ns: u64 = 1_000;
    let threshold_ns: u64 = 100;

    for pid in 1u32..=64 {
        let f = make_frame(pid, 1, Status::Ok, 0);
        let update = tracker.record(&f, now_ns, threshold_ns);
        assert_eq!(update, Update::Inserted, "pid {pid} should insert");
    }
    assert_eq!(tracker.len(), 64, "tracker should be full at 64 pids");

    // Without any stalled slots, overflow should still be CapacityExceeded
    let overflow = make_frame(65, 1, Status::Ok, 0);
    let result = tracker.record(&overflow, now_ns, threshold_ns);
    assert_eq!(result, Update::CapacityExceeded);
    assert_eq!(tracker.len(), 64, "len must not grow past capacity");
}
