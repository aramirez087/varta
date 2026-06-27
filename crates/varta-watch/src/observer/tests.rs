use super::*;
use crate::listener::BeatListener;
use crate::peer_cred::{BeatOrigin, RecvResult};
use crate::tracker::{DEFAULT_EVICTION_SCAN_WINDOW, MAX_CAPACITY};
use std::collections::VecDeque;
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

#[cfg(target_os = "linux")]
fn nonexistent_pid_below_pid_max(obs: &Observer) -> u32 {
    let upper = obs.pid_max().min(1_000_000);
    for pid in (2..=upper).rev() {
        if crate::peer_cred::read_pid_start_time(pid).is_none() {
            return pid;
        }
    }
    panic!("could not find an unused pid <= pid_max for observer regression test");
}

#[test]
fn new_caps_untrusted_tracker_capacity_before_auxiliary_allocations() {
    let obs = Observer::new(
        Duration::from_secs(1),
        usize::MAX,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("observer construction should cap capacity before allocation");

    assert_eq!(obs.stall_queue.capacity(), MAX_CAPACITY);
}

#[test]
#[allow(unsafe_code)]
fn drop_unlinks_bound_socket() {
    // SAFETY: unit-test runner may be multi-threaded; the umask window is
    // benign since no concurrent thread creates files at our temp path.
    let pre = unsafe { PreThreadAttestation::new_unchecked() };
    let path = unique_sock_path();
    let obs = Observer::bind(
        &path,
        Duration::from_secs(1),
        0o600,
        Duration::from_millis(100),
        0,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
        &pre,
    )
    .expect("bind should succeed on a clean temp path");
    assert!(path.exists(), "socket file must exist after bind");
    drop(obs);
    assert!(
        !path.exists(),
        "socket file must be removed after observer drop"
    );
}

#[test]
fn maybe_refresh_pid_max_respects_interval() {
    // Drive the cadence gate without exercising the /proc read itself —
    // the value `read_pid_max` returns is host-dependent (kernel default
    // 4_194_304 on Linux, u32::MAX elsewhere); we assert the gate's
    // *timing* contract, not the value.
    //
    // The observer's monotonic clock is anchored to `Observer::new` (see
    // `Clock::new`), so `now_ns()` starts near zero and only crosses
    // PID_MAX_REFRESH_INTERVAL_NS after ~60 s of real uptime. The test
    // advances the observer's `last_now_ns` directly via the forward
    // clamp to simulate elapsed time without sleeping.
    let mut obs = Observer::new(
        Duration::from_secs(1),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    let initial = obs.pid_max();
    assert_eq!(
        obs.last_pid_max_refresh_ns, 0,
        "fresh Observer has not yet run a periodic refresh"
    );

    // Immediately after construction the observer clock is still inside
    // the startup window. `now_ns() - 0 < INTERVAL`, so the gate skips:
    // `Observer::new` has already read pid_max, no need to re-read yet.
    let refreshed_at_startup = obs.maybe_refresh_pid_max();
    assert!(
        !refreshed_at_startup,
        "first call within startup window must skip (Observer::new already read pid_max)"
    );
    assert_eq!(
        obs.last_pid_max_refresh_ns, 0,
        "skip must leave the timestamp untouched"
    );

    // Simulate >60 s of observer uptime by pushing the forward-clamped
    // monotonic anchor past the interval. The next `now_ns()` reading
    // will be clamped to at least this value.
    obs.last_now_ns = PID_MAX_REFRESH_INTERVAL_NS + 1_000_000_000;
    // The forward clamp registers the real raw clock as a regression
    // when computing now_ns; drain it so unrelated tests stay clean.
    let refreshed_after_interval = obs.maybe_refresh_pid_max();
    assert!(
        refreshed_after_interval,
        "refresh must fire once the interval has elapsed since startup"
    );
    let first_ts = obs.last_pid_max_refresh_ns;
    assert!(
        first_ts >= PID_MAX_REFRESH_INTERVAL_NS,
        "post-interval refresh stamps a fresh timestamp >= INTERVAL"
    );
    assert_eq!(
        obs.pid_max(),
        initial,
        "refresh re-reads the same host value within a single test process"
    );

    // Immediate follow-up: the gate must close again until another full
    // interval elapses.
    let refreshed_again = obs.maybe_refresh_pid_max();
    assert!(
        !refreshed_again,
        "second call within new interval must skip"
    );
    assert_eq!(
        obs.last_pid_max_refresh_ns, first_ts,
        "skip must leave the new timestamp untouched"
    );

    // Rewind the recorded timestamp by more than the interval and confirm
    // the gate opens again.
    obs.last_pid_max_refresh_ns = first_ts.saturating_sub(PID_MAX_REFRESH_INTERVAL_NS + 1);
    let refreshed_after_rewind = obs.maybe_refresh_pid_max();
    assert!(
        refreshed_after_rewind,
        "refresh must fire after rewinding the recorded timestamp"
    );
    assert!(
        obs.last_pid_max_refresh_ns >= first_ts,
        "rewind-driven refresh records a fresh timestamp"
    );

    // Test produced clock regressions as a side effect of pushing
    // `last_now_ns` past the real raw clock; drain so subsequent suite
    // state stays neutral. The count is non-deterministic (depends on
    // how many `now_ns()` calls were issued by `maybe_refresh_pid_max`).
    let _ = obs.drain_clock_regressions();
}

#[test]
fn clock_regression_counter_increments_on_backward_clock() {
    let mut obs = Observer::new(
        Duration::from_secs(1),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    // Baseline reading — the forward clamp seeds `last_now_ns` from the
    // current monotonic value. No regression yet.
    let _ = obs.now_ns();
    assert_eq!(
        obs.drain_clock_regressions(),
        0,
        "no regressions after the first reading"
    );

    // Simulate the kernel clock having previously reported a value far
    // in the future (e.g. before a VM live migration that rewound the
    // TSC). The next `now_ns()` call reads a real value strictly less
    // than `last_now_ns`, so the forward clamp absorbs it AND the
    // regression counter must increment.
    obs.last_now_ns = u64::MAX / 2;
    let clamped = obs.now_ns();
    assert_eq!(
        clamped,
        u64::MAX / 2,
        "forward clamp preserves the larger value"
    );
    assert_eq!(
        obs.drain_clock_regressions(),
        1,
        "exactly one regression observed"
    );

    // Drain resets — a second drain reads zero.
    assert_eq!(
        obs.drain_clock_regressions(),
        0,
        "drain must reset the counter"
    );

    // A second backward excursion bumps the counter again.
    obs.last_now_ns = u64::MAX / 2;
    let _ = obs.now_ns();
    obs.last_now_ns = u64::MAX / 2;
    let _ = obs.now_ns();
    assert_eq!(
        obs.drain_clock_regressions(),
        2,
        "counter is saturating-add cumulative until drained"
    );
}

#[test]
fn clock_jump_forward_counter_increments_on_large_advance() {
    let mut obs = Observer::new(
        Duration::from_secs(1),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    // Feed synthetic timestamps via apply_raw_clock_test so we don't need
    // to wait real time. Simulate a baseline reading then a 10 s jump.
    let _ = obs.apply_raw_clock_test(1_000_000); // prime: 1 ms from baseline
    let _ = obs.apply_raw_clock_test(11_000_000_000); // +10 s jump
    assert_eq!(
        obs.drain_clock_jumps_forward(),
        1,
        "forward jump exceeding threshold must increment the counter"
    );
    assert_eq!(
        obs.drain_clock_regressions(),
        0,
        "a forward jump must not also count as a regression"
    );

    // Drain resets — second drain reads zero.
    assert_eq!(
        obs.drain_clock_jumps_forward(),
        0,
        "drain must reset the forward-jump counter"
    );

    // A sub-threshold advance (2 s) must not be counted.
    let _ = obs.apply_raw_clock_test(13_000_000_000); // +2 s — below 5 s sentinel
    assert_eq!(
        obs.drain_clock_jumps_forward(),
        0,
        "advance below threshold must not be counted as a jump"
    );

    // Bootstrap case: last_now_ns == 0 must not trigger a jump (startup).
    obs.last_now_ns = 0;
    let _ = obs.apply_raw_clock_test(10_000_000_000); // 10 s from zero
    assert_eq!(
        obs.drain_clock_jumps_forward(),
        0,
        "initial read from last_now_ns==0 must not count as a forward jump"
    );
}

#[test]
fn global_rate_limit_refills_at_configured_rate() {
    let mut rl = GlobalRateLimit::new(100, 1);

    assert!(
        rl.try_consume(0),
        "initial burst token should allow the first beat"
    );
    assert!(
        !rl.try_consume(9_999_999),
        "100 bps allows one token every 10 ms; 9.999999 ms is too early"
    );
    assert!(
        rl.try_consume(10_000_000),
        "fractional refill remainder must carry the bucket to one full token at 10 ms"
    );
}

struct ScriptedListener {
    results: VecDeque<RecvResult>,
}

impl ScriptedListener {
    fn with_frame(pid: u32, nonce: u64, payload: u32) -> Self {
        Self::with_frames(&[(pid, nonce, payload)])
    }

    fn with_frames(frames: &[(u32, u64, u32)]) -> Self {
        let mut results = VecDeque::new();
        for &(pid, nonce, payload) in frames {
            let frame = Frame::new(Status::Ok, pid, 1, nonce, payload);
            let mut data = [0u8; 32];
            frame.encode(&mut data);
            results.push_back(RecvResult::Authenticated {
                peer_pid: pid,
                peer_uid: 0,
                peer_pid_ns_inode: None,
                peer_pidfd: None,
                origin: BeatOrigin::KernelAttested,
                data,
            });
        }
        Self { results }
    }

    fn with_status_frames(frames: &[(u32, Status, u64, u64, u32)]) -> Self {
        let mut results = VecDeque::new();
        for &(pid, status, timestamp, nonce, payload) in frames {
            let frame = Frame::new(status, pid, timestamp, nonce, payload);
            let mut data = [0u8; 32];
            frame.encode(&mut data);
            results.push_back(RecvResult::Authenticated {
                peer_pid: pid,
                peer_uid: 0,
                peer_pid_ns_inode: None,
                peer_pidfd: None,
                origin: BeatOrigin::KernelAttested,
                data,
            });
        }
        Self { results }
    }

    /// A regular beat (`nonce 1`, `Ok`) immediately followed by the pid's
    /// terminal dying-gasp (`NONCE_TERMINAL`, decode-enforced `Critical`),
    /// both kernel-attested. The two frames are microseconds apart, so the
    /// terminal beat falls inside any realistic per-pid interval.
    fn with_terminal_after_regular(pid: u32) -> Self {
        let mut results = VecDeque::new();
        for (status, nonce, payload) in [
            (Status::Ok, 1u64, 100u32),
            (Status::Critical, NONCE_TERMINAL, 0xDEAD),
        ] {
            let frame = Frame::new(status, pid, 1, nonce, payload);
            let mut data = [0u8; 32];
            frame.encode(&mut data);
            results.push_back(RecvResult::Authenticated {
                peer_pid: pid,
                peer_uid: 0,
                peer_pid_ns_inode: None,
                peer_pidfd: None,
                origin: BeatOrigin::KernelAttested,
                data,
            });
        }
        Self { results }
    }

    fn with_origin_frames(frames: &[(u32, u64, u32, BeatOrigin)]) -> Self {
        let mut results = VecDeque::new();
        for &(pid, nonce, payload, origin) in frames {
            let frame = Frame::new(Status::Ok, pid, 1, nonce, payload);
            let mut data = [0u8; 32];
            frame.encode(&mut data);
            let peer_pid = if origin == BeatOrigin::KernelAttested {
                pid
            } else {
                0
            };
            results.push_back(RecvResult::Authenticated {
                peer_pid,
                peer_uid: 0,
                peer_pid_ns_inode: None,
                peer_pidfd: None,
                origin,
                data,
            });
        }
        Self { results }
    }

    fn with_authenticated_invalid_frames(count: usize) -> Self {
        let mut results = VecDeque::new();
        for nonce in 1..=count as u64 {
            let frame = Frame::new(Status::Stall, 10, 1, nonce, 0);
            let mut data = [0u8; 32];
            frame.encode(&mut data);
            results.push_back(RecvResult::Authenticated {
                peer_pid: 0,
                peer_uid: 0,
                peer_pid_ns_inode: None,
                peer_pidfd: None,
                origin: BeatOrigin::OperatorAttestedTransport,
                data,
            });
        }
        Self { results }
    }

    fn with_auth_failures(count: usize) -> Self {
        let mut results = VecDeque::new();
        for nonce in 1..=count as u64 {
            let frame = Frame::new(Status::Ok, 10, 1, nonce, 0);
            let mut data = [0u8; 32];
            frame.encode(&mut data);
            results.push_back(RecvResult::Authenticated {
                peer_pid: 20,
                peer_uid: 0,
                peer_pid_ns_inode: None,
                peer_pidfd: None,
                origin: BeatOrigin::KernelAttested,
                data,
            });
        }
        Self { results }
    }

    fn with_ctrl_truncated(count: usize) -> Self {
        let mut results = VecDeque::new();
        for _ in 0..count {
            results.push_back(RecvResult::CtrlTruncated(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "test ancillary truncation",
            )));
        }
        Self { results }
    }
}

impl BeatListener for ScriptedListener {
    fn recv(&mut self, _now_ns: u64) -> RecvResult {
        self.results.pop_front().unwrap_or(RecvResult::WouldBlock)
    }
}

#[test]
fn linux_effective_origin_requires_namespace_for_unpinned_kernel_authority() {
    assert_eq!(
        linux_effective_origin_for_identity(
            BeatOrigin::KernelAttested,
            None,
            Some(123),
            None,
            None,
        ),
        BeatOrigin::SocketModeOnly,
        "first-contact Linux UDS recovery authority needs both generation and namespace proof"
    );
}

#[test]
fn linux_effective_origin_accepts_complete_first_contact_identity() {
    assert_eq!(
        linux_effective_origin_for_identity(
            BeatOrigin::KernelAttested,
            Some(4026531836),
            Some(123),
            None,
            None,
        ),
        BeatOrigin::KernelAttested
    );
}

#[test]
fn linux_effective_origin_preserves_already_pinned_kernel_slot() {
    assert_eq!(
        linux_effective_origin_for_identity(
            BeatOrigin::KernelAttested,
            None,
            None,
            Some(Some(4026531836)),
            Some(Some(123)),
        ),
        BeatOrigin::KernelAttested,
        "already-pinned agents may lose /proc metadata while emitting a terminal frame"
    );
}

#[test]
fn linux_effective_origin_does_not_upgrade_slot_with_generation_but_no_namespace() {
    assert_eq!(
        linux_effective_origin_for_identity(
            BeatOrigin::KernelAttested,
            None,
            Some(123),
            Some(None),
            Some(Some(123)),
        ),
        BeatOrigin::SocketModeOnly,
        "generation-only identity is not enough to mint recovery authority"
    );
}

#[test]
fn poll_returns_multi_listener_events_one_at_a_time() {
    let mut obs = Observer::new(
        Duration::from_secs(1),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    obs.add_listener(Box::new(ScriptedListener::with_frame(10, 1, 100)));
    obs.add_listener(Box::new(ScriptedListener::with_frame(20, 1, 200)));

    let first = obs.poll();
    assert!(
        matches!(
            first,
            Some(Event::Beat {
                pid: 10,
                payload: 100,
                ..
            })
        ),
        "first poll must return the first listener's beat, got {first:?}"
    );

    let second = obs.poll();
    assert!(
        matches!(
            second,
            Some(Event::Beat {
                pid: 20,
                payload: 200,
                ..
            })
        ),
        "second poll must return the second listener's beat, got {second:?}"
    );
}

#[test]
fn per_pid_limited_frame_does_not_spend_global_token() {
    let mut obs = Observer::new(
        Duration::from_secs(60),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        Some(1),
        1,
        2,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    obs.add_listener(Box::new(ScriptedListener::with_frames(&[
        (10, 1, 100),
        (10, 2, 101),
        (20, 1, 200),
    ])));

    let first = obs.poll();
    assert!(
        matches!(
            first,
            Some(Event::Beat {
                pid: 10,
                payload: 100,
                ..
            })
        ),
        "first beat should be accepted, got {first:?}"
    );

    let second = obs.poll();
    assert!(
        second.is_none(),
        "too-fast same-pid beat should be dropped by per-pid limiter, got {second:?}"
    );
    assert_eq!(
        obs.drain_per_pid_rate_limited(),
        1,
        "same-pid burst should increment only the per-pid limiter"
    );

    let third = obs.poll();
    assert!(
        matches!(
            third,
            Some(Event::Beat {
                pid: 20,
                payload: 200,
                ..
            })
        ),
        "per-pid-limited beat must not consume the remaining global token; got {third:?}"
    );
    assert_eq!(
        obs.drain_global_rate_limited(),
        0,
        "no frame should have exhausted the global bucket"
    );
}

#[test]
fn authenticated_decode_errors_pay_global_rate_limit() {
    let mut obs = Observer::new(
        Duration::from_secs(60),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        1,
        1,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    obs.add_listener(Box::new(
        ScriptedListener::with_authenticated_invalid_frames(2),
    ));

    let first = obs.poll();
    assert!(
        matches!(first, Some(Event::Decode(DecodeError::StallOnWire, _))),
        "the first authenticated decode error should consume the burst token, got {first:?}"
    );
    assert_eq!(obs.drain_global_rate_limited(), 0);

    let second = obs.poll();
    assert!(
        second.is_none(),
        "the exhausted global bucket must shed repeated authenticated decode errors, got {second:?}"
    );
    assert_eq!(
        obs.drain_global_rate_limited(),
        1,
        "the shed malformed frame must be visible in global limiter metrics"
    );
    assert!(
        obs.last_poll_consumed(),
        "a rate-limited malformed datagram is still consumed I/O"
    );
}

#[test]
fn authenticated_pid_mismatches_pay_global_rate_limit() {
    let mut obs = Observer::new(
        Duration::from_secs(60),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        1,
        1,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    obs.add_listener(Box::new(ScriptedListener::with_auth_failures(2)));

    let first = obs.poll();
    assert!(
        matches!(
            first,
            Some(Event::AuthFailure {
                claimed_pid: 10,
                ..
            })
        ),
        "the first authenticated PID mismatch should consume the burst token, got {first:?}"
    );
    assert_eq!(obs.drain_global_rate_limited(), 0);

    let second = obs.poll();
    assert!(
        second.is_none(),
        "the exhausted global bucket must shed repeated PID-mismatch events, got {second:?}"
    );
    assert_eq!(
        obs.drain_global_rate_limited(),
        1,
        "the shed PID mismatch must be visible in global limiter metrics"
    );
    assert!(
        obs.last_poll_consumed(),
        "a rate-limited PID mismatch is still consumed I/O"
    );
}

#[test]
fn ctrl_truncated_events_pay_global_rate_limit() {
    let mut obs = Observer::new(
        Duration::from_secs(60),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        1,
        1,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    obs.add_listener(Box::new(ScriptedListener::with_ctrl_truncated(2)));

    let first = obs.poll();
    assert!(
        matches!(first, Some(Event::CtrlTruncated(_, _))),
        "the first control-truncation event should consume the burst token, got {first:?}"
    );
    assert_eq!(obs.drain_global_rate_limited(), 0);

    let second = obs.poll();
    assert!(
        second.is_none(),
        "the exhausted global bucket must shed repeated control-truncation events, got {second:?}"
    );
    assert_eq!(
        obs.drain_global_rate_limited(),
        1,
        "the shed control-truncation event must be visible in global limiter metrics"
    );
    assert!(
        obs.last_poll_consumed(),
        "a rate-limited control-truncation datagram is still consumed I/O"
    );
}

#[test]
fn pid_above_max_rejections_pay_global_rate_limit() {
    let mut obs = Observer::new(
        Duration::from_secs(60),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        1,
        1,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");
    obs.pid_max = 100;

    obs.add_listener(Box::new(ScriptedListener::with_origin_frames(&[
        (101, 1, 0, BeatOrigin::OperatorAttestedTransport),
        (102, 1, 0, BeatOrigin::OperatorAttestedTransport),
    ])));

    let first = obs.poll();
    assert!(
        first.is_none(),
        "the first above-pid_max frame should be locally rejected, got {first:?}"
    );
    assert_eq!(
        obs.drain_pid_above_max_drops(),
        1,
        "the first above-pid_max frame should reach the local rejection counter"
    );
    assert_eq!(obs.drain_global_rate_limited(), 0);

    let second = obs.poll();
    assert!(
        second.is_none(),
        "the exhausted global bucket must shed repeated above-pid_max frames, got {second:?}"
    );
    assert_eq!(
        obs.drain_global_rate_limited(),
        1,
        "the shed above-pid_max frame must be visible in global limiter metrics"
    );
    assert_eq!(
        obs.drain_pid_above_max_drops(),
        0,
        "a globally shed above-pid_max frame must not also count as a local pid_max drop"
    );
    assert!(
        obs.last_poll_consumed(),
        "a rate-limited above-pid_max datagram is still consumed I/O"
    );
}

#[test]
fn terminal_gasp_bypasses_per_pid_rate_limiter() {
    // Regression: a panic hook's terminal beat (`NONCE_TERMINAL` => `Critical`)
    // is the agent's single dying gasp and almost always arrives within the
    // per-pid interval of the last regular beat. The tracker is built to never
    // drop a terminal frame (it records it even when the namespace inode has
    // read back `None`), but the per-pid rate limiter runs FIRST. Pre-fix it
    // shed exactly that beat, so the observer lost the Critical status + panic
    // payload and fell back to slow silence-based stall detection.
    //
    // max_beat_rate = 1/s (interval 1 s); the two frames are microseconds
    // apart, so a regular second beat WOULD be dropped here.
    let mut obs = Observer::new(
        Duration::from_secs(60),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        Some(1),
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    obs.add_listener(Box::new(ScriptedListener::with_terminal_after_regular(10)));

    let first = obs.poll();
    assert!(
        matches!(first, Some(Event::Beat { pid: 10, .. })),
        "first regular beat should be accepted, got {first:?}"
    );

    // THE FIX: the terminal gasp must be admitted despite arriving inside the
    // per-pid interval, surfacing its Critical status to the tracker/recovery.
    let second = obs.poll();
    assert!(
        matches!(
            second,
            Some(Event::Beat {
                pid: 10,
                status: Status::Critical,
                payload: 0xDEAD,
                nonce: NONCE_TERMINAL,
                ..
            })
        ),
        "terminal gasp must bypass the per-pid limiter and surface Critical, got {second:?}"
    );
    assert_eq!(
        obs.drain_per_pid_rate_limited(),
        0,
        "the terminal beat must NOT be counted as a per-pid drop"
    );
}

#[test]
fn terminal_gasp_bypasses_global_limiter_once_for_tracked_kernel_agent() {
    // Regression: the terminal panic frame was protected from the per-pid
    // limiter but still paid the global bucket. A single unrelated burst could
    // exhaust that bucket first, dropping the dying agent's only Critical beat
    // and leaving operators to infer the panic later from silence.
    let mut obs = Observer::new(
        Duration::from_secs(60),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        1,
        1,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    obs.add_listener(Box::new(ScriptedListener::with_status_frames(&[
        (10, Status::Ok, 1, 1, 100),
        (20, Status::Ok, 1, 1, 200),
        (10, Status::Critical, 2, NONCE_TERMINAL, 0xDEAD),
        (10, Status::Critical, 3, NONCE_TERMINAL, 0xBEEF),
    ])));

    let first = obs.poll();
    assert!(
        matches!(
            first,
            Some(Event::Beat {
                pid: 10,
                payload: 100,
                ..
            })
        ),
        "first tracked beat should consume the only global token, got {first:?}"
    );

    let second = obs.poll();
    assert!(
        second.is_none(),
        "unrelated beat should be dropped after the global bucket is empty, got {second:?}"
    );
    assert_eq!(
        obs.drain_global_rate_limited(),
        1,
        "the unrelated beat should account as the global drop"
    );

    let third = obs.poll();
    assert!(
        matches!(
            third,
            Some(Event::Beat {
                pid: 10,
                status: Status::Critical,
                payload: 0xDEAD,
                nonce: NONCE_TERMINAL,
                ..
            })
        ),
        "tracked kernel-attested terminal gasp must bypass the exhausted global bucket once, got {third:?}"
    );
    assert_eq!(
        obs.drain_global_rate_limited(),
        0,
        "the terminal gasp must not be counted as a global drop"
    );

    let fourth = obs.poll();
    assert!(
        fourth.is_none(),
        "repeated terminal frames must not get an unlimited global-limiter bypass, got {fourth:?}"
    );
    assert_eq!(
        obs.drain_global_rate_limited(),
        1,
        "the repeated terminal frame should pay the exhausted global bucket"
    );
}

#[test]
fn repeated_terminal_gasp_pays_per_pid_rate_limiter() {
    // The terminal-frame carve-out exists for exactly one case: a process
    // beats normally, panics, and emits one Critical dying gasp inside the
    // ordinary per-pid interval. Once that terminal frame is recorded,
    // repeated terminal frames are no longer a dying-gasp edge; they are a
    // same-pid hot loop and must pay --max-beat-rate.
    let mut obs = Observer::new(
        Duration::from_secs(60),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        Some(1),
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    obs.add_listener(Box::new(ScriptedListener::with_status_frames(&[
        (10, Status::Ok, 1, 1, 100),
        (10, Status::Critical, 2, NONCE_TERMINAL, 0xDEAD),
        (10, Status::Critical, 3, NONCE_TERMINAL, 0xBEEF),
    ])));

    let first = obs.poll();
    assert!(
        matches!(
            first,
            Some(Event::Beat {
                pid: 10,
                payload: 100,
                ..
            })
        ),
        "regular beat should be accepted, got {first:?}"
    );

    let second = obs.poll();
    assert!(
        matches!(
            second,
            Some(Event::Beat {
                pid: 10,
                status: Status::Critical,
                payload: 0xDEAD,
                nonce: NONCE_TERMINAL,
                ..
            })
        ),
        "first terminal beat after a regular beat must still bypass the per-pid limiter, got {second:?}"
    );
    assert_eq!(
        obs.drain_per_pid_rate_limited(),
        0,
        "the first terminal edge must not count as a per-pid drop"
    );

    let third = obs.poll();
    assert!(
        third.is_none(),
        "repeated terminal frame inside the interval must be per-pid limited, got {third:?}"
    );
    assert_eq!(
        obs.drain_per_pid_rate_limited(),
        1,
        "repeated terminal frames should pay the per-pid limiter"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn first_contact_without_generation_is_recovery_ineligible() {
    let mut obs = Observer::new(
        Duration::ZERO,
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");
    let pid = nonexistent_pid_below_pid_max(&obs);

    obs.add_listener(Box::new(ScriptedListener::with_frame(pid, 1, 0xCAFE)));

    let beat = obs.poll();
    assert!(
        matches!(
            beat,
            Some(Event::Beat {
                pid: got_pid,
                payload: 0xCAFE,
                origin: BeatOrigin::SocketModeOnly,
                ..
            }) if got_pid == pid
        ),
        "first-contact Linux UDS beat with no start-time generation must stay \
         observable but recovery-ineligible, got {beat:?}"
    );

    let stall = obs.poll_pending();
    assert!(
        matches!(
            stall,
            Some(Event::Stall {
                pid: got_pid,
                origin: BeatOrigin::SocketModeOnly,
                generation: None,
                ..
            }) if got_pid == pid
        ),
        "stall from an unpinned first-contact beat must carry SocketModeOnly \
         so Recovery::on_stall refuses it, got {stall:?}"
    );
    assert_eq!(obs.drain_origin_conflicts(), 0);
}

#[test]
fn consumed_but_dropped_datagram_reports_io_so_loop_does_not_idle_sleep() {
    // Regression: the main loop throttles with a 10 ms sleep only when the
    // observer is "truly idle". A datagram that is dequeued and then dropped
    // (here, by the per-pid rate limiter) yields no Event, so poll() returns
    // None — but it IS I/O, and the socket may still hold queued beats.
    // `last_poll_consumed()` must report it so the loop keeps draining; pre-
    // fix the loop slept after every dropped datagram, capping drain at
    // ~100 datagrams/s and head-of-line-blocking real beats -> false stalls.
    let mut obs = Observer::new(
        Duration::from_secs(60),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        Some(1),
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    obs.add_listener(Box::new(ScriptedListener::with_frames(&[
        (10, 1, 100),
        (10, 2, 101),
    ])));

    // First beat is accepted and returned as an Event — clearly I/O.
    let first = obs.poll();
    assert!(
        matches!(first, Some(Event::Beat { pid: 10, .. })),
        "first beat should be accepted, got {first:?}"
    );
    assert!(obs.last_poll_consumed(), "an accepted beat is consumed I/O");

    // Second beat is dequeued but dropped by the per-pid limiter: poll()
    // returns None, yet a datagram WAS consumed off the socket.
    let second = obs.poll();
    assert!(
        second.is_none(),
        "too-fast same-pid beat should be dropped, got {second:?}"
    );
    assert_eq!(
        obs.drain_per_pid_rate_limited(),
        1,
        "the second datagram was dequeued and dropped by the per-pid limiter"
    );
    assert!(
        obs.last_poll_consumed(),
        "THE FIX: a consumed-but-dropped datagram must still report I/O so \
         the main loop keeps draining instead of sleeping 10 ms"
    );

    // Negative control: the socket is now empty (recv -> WouldBlock). poll()
    // returns None AND reports no consumption, so the loop correctly sleeps.
    let third = obs.poll();
    assert!(
        third.is_none(),
        "empty socket yields no event, got {third:?}"
    );
    assert!(
        !obs.last_poll_consumed(),
        "a truly idle poll (WouldBlock) must report no I/O so the throttle \
         sleep still fires when there is genuinely nothing to drain"
    );
}

#[test]
fn higher_trust_origin_repairs_untrusted_preemption_before_rate_limit() {
    let mut obs = Observer::new(
        Duration::from_secs(60),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        Some(1),
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    let pid = std::process::id();
    obs.add_listener(Box::new(ScriptedListener::with_origin_frames(&[
        (pid, 99, 100, BeatOrigin::NetworkUnverified),
        (pid, 1, 200, BeatOrigin::KernelAttested),
    ])));

    let first = obs.poll();
    assert!(
        matches!(
            first,
            Some(Event::Beat {
                pid: got_pid,
                payload: 100,
                origin: BeatOrigin::NetworkUnverified,
                ..
            }) if got_pid == pid
        ),
        "untrusted preemption frame should be recorded first, got {first:?}"
    );

    let second = obs.poll();
    assert!(
        matches!(
            second,
            Some(Event::Beat {
                pid: got_pid,
                payload: 200,
                nonce: 1,
                origin: BeatOrigin::KernelAttested,
                ..
            }) if got_pid == pid
        ),
        "kernel-attested beat should replace the weaker slot immediately, got {second:?}"
    );
    assert_eq!(
        obs.drain_per_pid_rate_limited(),
        0,
        "trust-upgrade beats must not be dropped by the stale weak slot timestamp"
    );
    assert_eq!(
        obs.drain_origin_conflicts(),
        0,
        "a higher-trust replacement is not an origin conflict"
    );
}

#[test]
fn predrain_loop_observes_all_buffered_resumes_before_deferred_stalls_fire() {
    // Regression for the DrainPending ingress pre-drain (main.rs step 1a).
    // The fire-time freshness gate can only see resumptions the tracker has
    // recorded, and poll() returns on the first exported Event — one
    // returnable beat per call. A mass stall whose agents have since resumed
    // leaves their resume-beats buffered on the socket while up to
    // RECOVERY_SPAWN_MAX_PER_TICK deferred recoveries fire per tick; without
    // draining ingress first, stall_freshness reads stale `stall_emitted`
    // state and recovery kills a healthy, already-recovered fleet ~16:1.
    // This locks the contract the pre-drain relies on: looping poll() until
    // `last_poll_consumed()` is false consumes EVERY buffered resume and
    // flips each queued stall to AgentResumed, while the stall queue itself
    // stays intact for the eval loop to skip.
    let mut obs = Observer::new(
        Duration::from_secs(1),
        64,
        EvictionPolicy::Strict,
        DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("Observer::new should succeed");

    const PIDS: [u32; 3] = [40, 41, 42];
    obs.add_listener(Box::new(ScriptedListener::with_origin_frames(&[
        (PIDS[0], 1, 100, BeatOrigin::SocketModeOnly),
        (PIDS[1], 1, 101, BeatOrigin::SocketModeOnly),
        (PIDS[2], 1, 102, BeatOrigin::SocketModeOnly),
    ])));

    // Consume the three initial beats (one returnable Event per poll()).
    let _ = obs.apply_raw_clock_test(1_000_000);
    for _ in 0..PIDS.len() {
        let ev = obs.poll();
        assert!(
            matches!(ev, Some(Event::Beat { .. })),
            "initial beat should be observed, got {ev:?}"
        );
    }

    // Cross the silence threshold; the empty poll's drain_stalls pass queues
    // a stall for every pid and latches `stall_emitted`.
    let _ = obs.apply_raw_clock_test(5_000_000_000);
    assert!(obs.poll().is_none());
    assert!(obs.has_pending_stalls(), "mass stall should queue events");
    for pid in PIDS {
        assert_eq!(
            obs.stall_freshness(pid, None),
            StallFreshness::Warranted,
            "queued stall for pid {pid} starts warranted"
        );
    }

    // The whole fleet resumes; its beats sit buffered (a second listener
    // stands in for the socket queue).
    obs.add_listener(Box::new(ScriptedListener::with_origin_frames(&[
        (PIDS[0], 2, 100, BeatOrigin::SocketModeOnly),
        (PIDS[1], 2, 101, BeatOrigin::SocketModeOnly),
        (PIDS[2], 2, 102, BeatOrigin::SocketModeOnly),
    ])));

    // The main loop's pre-drain shape: poll until the sockets are empty.
    let mut drained = 0usize;
    loop {
        drained += 1;
        assert!(drained <= 16, "pre-drain loop did not terminate");
        let _ = obs.poll();
        if !obs.last_poll_consumed() {
            break;
        }
    }

    // Every buffered resume was observed: each queued stall must now be
    // judged stale, and the queue itself remains for the eval loop to skip.
    assert!(
        obs.has_pending_stalls(),
        "pre-drain must not consume the stall queue"
    );
    for pid in PIDS {
        assert_eq!(
            obs.stall_freshness(pid, None),
            StallFreshness::AgentResumed,
            "buffered resume for pid {pid} must flip its deferred stall stale"
        );
    }
}

#[test]
fn cross_namespace_gate_is_fail_closed_when_observer_inode_unknown() {
    // Same namespace -> accepted (not refused).
    assert!(!cross_namespace_refused(Some(42), Some(42)));
    // Different namespace -> refused.
    assert!(cross_namespace_refused(Some(42), Some(7)));
    // No peer inode (UDP transport / non-Linux / unreadable peer /proc): there
    // is nothing to compare, so it is NOT a cross-namespace conflict.
    assert!(!cross_namespace_refused(Some(42), None));
    assert!(!cross_namespace_refused(None, None));

    // Regression (bug-483): the observer's own namespace inode is unknown
    // (`observer_pid_namespace_inode` memoized `None` after a startup
    // `/proc/self/ns/pid` race) but the peer presents an inode. The gate MUST
    // fail closed and refuse the cross-namespace peer, not silently accept it
    // for the rest of the process lifetime. The previous
    // `matches!((observer, peer), (Some(a), Some(b)) if a != b)` returned
    // `false` here (accept), disabling the gate without the operator's
    // `--allow-cross-namespace-agents` opt-in.
    assert!(cross_namespace_refused(None, Some(7)));
}
