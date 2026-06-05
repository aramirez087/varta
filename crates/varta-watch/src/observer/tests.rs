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
}

impl BeatListener for ScriptedListener {
    fn recv(&mut self) -> RecvResult {
        self.results.pop_front().unwrap_or(RecvResult::WouldBlock)
    }
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

    obs.add_listener(Box::new(ScriptedListener::with_origin_frames(&[
        (42, 99, 100, BeatOrigin::NetworkUnverified),
        (42, 1, 200, BeatOrigin::KernelAttested),
    ])));

    let first = obs.poll();
    assert!(
        matches!(
            first,
            Some(Event::Beat {
                pid: 42,
                payload: 100,
                origin: BeatOrigin::NetworkUnverified,
                ..
            })
        ),
        "untrusted preemption frame should be recorded first, got {first:?}"
    );

    let second = obs.poll();
    assert!(
        matches!(
            second,
            Some(Event::Beat {
                pid: 42,
                payload: 200,
                nonce: 1,
                origin: BeatOrigin::KernelAttested,
                ..
            })
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
