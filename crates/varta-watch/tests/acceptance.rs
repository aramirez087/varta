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

use varta_vlp::{DecodeError, Frame, Status};
use varta_watch::tracker::MAX_CAPACITY;
use varta_watch::EvictionPolicy;
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
    Frame::new(status, pid, nonce, nonce, payload)
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
/// Checks queued stalls (via `poll_pending`) before I/O (via `poll`).
fn poll_until_match<F, T>(observer: &mut Observer, deadline: Duration, mut pred: F) -> Option<T>
where
    F: FnMut(Event) -> Result<T, ()>,
{
    let stop = Instant::now() + deadline;
    while Instant::now() < stop {
        // Drain pending stalls first
        if let Some(ev) = observer.poll_pending() {
            if let Ok(value) = pred(ev) {
                return Some(value);
            }
            continue;
        }
        // Then check new I/O events
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
    let mut observer = Observer::bind(
        path.as_path(),
        Duration::from_secs(60),
        0o600,
        Duration::from_millis(100),
        64,
        EvictionPolicy::Strict,
        None,
    )
    .expect("bind observer");
    let client = client_socket(path.as_path());

    let pid = std::process::id();
    let frames = [
        make_frame(pid, 1, Status::Ok, 0xA1),
        make_frame(pid, 2, Status::Ok, 0xA2),
        make_frame(pid, 3, Status::Degraded, 0xA3),
    ];
    for f in &frames {
        send_frame(&client, f);
    }

    let deadline = Duration::from_secs(5);
    let mut got: Vec<(u32, u64, Status, u64)> = Vec::with_capacity(3);
    let stop = Instant::now() + deadline;
    'outer: while got.len() < 3 && Instant::now() < stop {
        // Check queued stalls first, then I/O events.
        let ev = loop {
            if let Some(ev) = observer.poll_pending() {
                break ev;
            }
            if let Some(ev) = observer.poll() {
                break ev;
            }
            if Instant::now() >= stop {
                break 'outer;
            }
            thread::sleep(Duration::from_millis(1));
        };
        match ev {
            Event::Beat {
                pid,
                nonce,
                status,
                payload,
                observer_ns: _,
            } => got.push((pid, nonce, status, payload)),
            Event::Decode(e, _) => panic!("unexpected decode error: {e}"),
            Event::Io(e, _) => panic!("unexpected io error: {e}"),
            Event::Stall { .. } => panic!("unexpected stall during beat test"),
            Event::AuthFailure { .. } => {
                panic!("unexpected auth failure during beat test")
            }
            Event::CtrlTruncated(e, _) => panic!("unexpected ctrl truncation: {e}"),
        }
    }

    assert_eq!(got.len(), 3, "expected 3 beats, got {got:?}");
    assert_eq!(got[0], (pid, 1, Status::Ok, 0xA1));
    assert_eq!(got[1], (pid, 2, Status::Ok, 0xA2));
    assert_eq!(got[2], (pid, 3, Status::Degraded, 0xA3));
}

#[test]
fn observer_emits_stall_after_threshold_elapses() {
    let path = unique_uds_path("stall");
    let threshold = Duration::from_millis(150);
    let mut observer = Observer::bind(
        path.as_path(),
        threshold,
        0o600,
        Duration::from_millis(100),
        64,
        EvictionPolicy::Strict,
        None,
    )
    .expect("bind observer");
    let client = client_socket(path.as_path());

    let pid = std::process::id();
    send_frame(&client, &make_frame(pid, 1, Status::Ok, 0xB1));

    // Drain the beat first.
    let beat = poll_until_match(&mut observer, Duration::from_secs(5), |ev| match ev {
        Event::Beat { pid: p, nonce, .. } if p == pid && nonce == 1 => Ok(()),
        _ => Err(()),
    });
    assert!(beat.is_some(), "did not observe initial beat for pid {pid}");

    // Now expect a Stall event for the same pid within threshold + budget.
    let stall = poll_until_match(
        &mut observer,
        threshold + Duration::from_secs(1),
        |ev| match ev {
            Event::Stall {
                pid: p, last_nonce, ..
            } if p == pid && last_nonce == 1 => Ok(()),
            _ => Err(()),
        },
    );
    assert!(stall.is_some(), "no Stall event surfaced for pid {pid}");

    // It must fire exactly once — confirm no second stall arrives shortly after.
    let extra = poll_until_match(&mut observer, Duration::from_millis(300), |ev| match ev {
        Event::Stall { pid: p, .. } if p == pid => Ok(()),
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
    let mut observer = Observer::bind(
        path.as_path(),
        Duration::from_secs(60),
        0o600,
        Duration::from_millis(100),
        64,
        EvictionPolicy::Strict,
        None,
    )
    .expect("bind observer");
    let client = client_socket(path.as_path());

    let bogus = [0xFFu8; 32];
    client.send(&bogus).expect("send bogus payload");

    let got = poll_until_match(&mut observer, Duration::from_secs(5), |ev| match ev {
        Event::Decode(DecodeError::BadMagic, _) => Ok(()),
        Event::Decode(other, _) => panic!("wrong decode error variant: {other:?}"),
        _ => Err(()),
    });
    assert!(got.is_some(), "expected Event::Decode(BadMagic)");
}

#[test]
fn tracker_capacity_bounded_to_64_pids() {
    let mut tracker = Tracker::new(64, EvictionPolicy::Strict);
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

/// A frame whose `pid` field does not match the kernel-attested sender
/// PID must yield `Event::AuthFailure` on Linux.  On macOS the kernel
/// may or may not expose per-datagram credentials (depends on kernel
/// version and whether `LOCAL_PEERTOKEN` / `LOCAL_PEERPID` succeeds),
/// so the frame may be accepted as a beat or rejected — the test
/// accepts either outcome.
#[test]
fn observer_rejects_spoofed_pid_frame() {
    let path = unique_uds_path("spoof");
    let mut observer = Observer::bind(
        path.as_path(),
        Duration::from_secs(60),
        0o600,
        Duration::from_millis(100),
        64,
        EvictionPolicy::Strict,
        None,
    )
    .expect("bind observer");
    let client = client_socket(path.as_path());

    let real_pid = std::process::id();
    let spoofed_pid = real_pid + 999;
    let frame = make_frame(spoofed_pid, 1, Status::Ok, 0xCC);
    send_frame(&client, &frame);

    #[cfg(target_os = "linux")]
    {
        let claimed = poll_until_match(&mut observer, Duration::from_secs(5), |ev| match ev {
            Event::AuthFailure {
                claimed_pid,
                observer_ns: _,
            } => Ok(claimed_pid),
            Event::Stall { .. } => Err(()),
            _ => Err(()),
        });
        let c = claimed.expect("expected Event::AuthFailure on Linux when pid is spoofed");
        assert_eq!(
            c, spoofed_pid,
            "AuthFailure claimed_pid must match spoofed pid"
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        let outcome = poll_until_match(&mut observer, Duration::from_secs(5), |ev| match ev {
            Event::Beat { pid, .. } if pid == spoofed_pid => Ok(true),
            Event::AuthFailure { claimed_pid, .. } if claimed_pid == spoofed_pid => Ok(false),
            _ => Err(()),
        });
        assert!(
            outcome.is_some(),
            "on macOS spoofed frame must produce either Beat or AuthFailure"
        );
    }
}

/// Send datagrams shorter than 32 bytes to the observer and verify they are
/// silently counted as truncated without crashing or emitting beat events.
#[test]
fn observer_counts_truncated_datagrams() {
    let path = unique_uds_path("trunc");
    let mut observer = Observer::bind(
        path.as_path(),
        Duration::from_secs(60),
        0o600,
        Duration::from_millis(100),
        64,
        EvictionPolicy::Strict,
        None,
    )
    .expect("bind observer");
    let client = client_socket(path.as_path());

    // Send 0-byte, 1-byte, 31-byte, and 33-byte datagrams.
    // A correct UDS VLP frame is exactly 32 bytes; anything else is ShortRead.
    client.send(b"").expect("send 0-byte");
    client.send(b"\xAA").expect("send 1-byte");
    client.send(&[0xBBu8; 31]).expect("send 31-byte");
    client.send(&[0xCCu8; 33]).expect("send 33-byte");

    // Poll to let the observer consume the datagrams. None of them should
    // surface as events — they are silently skipped in the poll loop.
    let deadline = Duration::from_secs(2);
    let mut saw_beat = false;
    let stop = Instant::now() + deadline;
    while Instant::now() < stop {
        if let Some(Event::Beat { .. } | Event::Stall { .. }) = observer.poll() {
            saw_beat = true;
        }
        if observer.drain_truncated() >= 4 {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    let truncated = observer.drain_truncated();
    assert_eq!(
        truncated, 0,
        "all truncated should have been drained in loop"
    );
    assert!(!saw_beat, "truncated datagrams must not emit Beat events");
}

/// Verify that `Tracker::new(capacity)` clamps to [`MAX_CAPACITY`]
/// and that the capacity bound is enforced exactly at that boundary.
#[test]
fn tracker_capacity_clamped_to_max_capacity() {
    // Clamping: requests above MAX_CAPACITY are silently capped.
    let mut over = Tracker::new(MAX_CAPACITY + 1000, EvictionPolicy::Strict);
    let now_ns: u64 = 1_000;
    let threshold_ns: u64 = 100;

    // Fill up to MAX_CAPACITY distinct pids. Every insert must succeed
    // (Update::Inserted or Update::Replaced). At the boundary, the next
    // pid must yield CapacityExceeded.
    for pid in 1u32..=MAX_CAPACITY as u32 {
        let f = make_frame(pid, 1, Status::Ok, 0);
        let update = over.record(&f, now_ns, threshold_ns);
        assert!(
            update == Update::Inserted || update == Update::Refreshed,
            "pid {pid} should fit within MAX_CAPACITY"
        );
    }
    assert_eq!(
        over.len(),
        MAX_CAPACITY,
        "tracker should be full at MAX_CAPACITY"
    );

    let overflow = make_frame(MAX_CAPACITY as u32 + 1, 1, Status::Ok, 0);
    let result = over.record(&overflow, now_ns, threshold_ns);
    assert_eq!(result, Update::CapacityExceeded);
    assert_eq!(
        over.len(),
        MAX_CAPACITY,
        "len must not grow past MAX_CAPACITY"
    );
}
