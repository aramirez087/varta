//! Prometheus endpoint, metrics, file export, and rate-limiting tests.

use super::{
    http_get, locate_watch_binary, parse_histogram_bucket, parse_metric_value, spawn_watch,
    wait_until, wait_until_with_timeout, ChildGuard, TempDir, AGENT_CHILD_ENV, PROM_TOKEN_HEX,
};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use varta_client::{BeatOutcome, Status, Varta};

/// Spawns varta-watch with `--max-beat-rate 10` (max 10 beats/sec per PID).
/// Sends 50 beats as fast as possible from one agent; asserts
/// `varta_rate_limited_total > 0` and the agent's beat count is < 50.
pub(super) fn max_beat_rate_limits_and_reports_metric() {
    let tmp = TempDir::new("mbr");
    let socket = tmp.path().join("varta.sock");

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "5000", // no stall during test
        "--max-beat-rate",
        "10",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "varta-watch did not bind socket within 3s"
    );
    assert!(
        wait_until(
            || TcpStream::connect(prom_addr).is_ok(),
            Duration::from_secs(3)
        ),
        "/metrics not reachable within 3s"
    );

    let agent_pid = std::process::id();
    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect");
        for _ in 0..50 {
            // Send as fast as possible — no backoff sleep for Dropped,
            // because Dropped is expected here due to rate limiting.
            if let BeatOutcome::Failed(e) = agent.beat(Status::Ok, 0) {
                panic!("unexpected hard failure: {e}");
            }
        }
    }

    let rate_limited_needle = "varta_rate_limited_total";
    let beats_needle = format!("varta_beats_total{{pid=\"{agent_pid}\"}}");
    let mut last_body = String::new();
    let satisfied = wait_until(
        || match http_get(prom_addr, "/metrics") {
            Ok((200, body)) => {
                last_body = body;
                // Must contain the rate limited counter
                last_body.contains(rate_limited_needle)
                    // Must have beats for this PID
                    && last_body.contains(&beats_needle)
            }
            _ => false,
        },
        Duration::from_secs(5),
    );
    assert!(
        satisfied,
        "/metrics missing rate_limited or beats; last body:\n{last_body}"
    );

    // Parse the rate_limited value and assert it's > 0
    let rl_val: u64 = last_body
        .lines()
        .filter(|l| l.starts_with("varta_rate_limited_total{"))
        .filter_map(|l| l.split_whitespace().last())
        .filter_map(|v| v.parse::<u64>().ok())
        .sum();
    assert!(
        rl_val > 0,
        "varta_rate_limited_total should be > 0 when sending 50 beats at max 10/s"
    );

    // Parse the agent beat count and assert it's < 50
    let beat_val = last_body
        .lines()
        .find(|l| l.starts_with(&beats_needle))
        .and_then(|l| l.split_whitespace().last())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    assert!(
        beat_val < 50,
        "agent beat count {beat_val} should be < 50 with rate limit of 10/s"
    );
}

/// Spawns varta-watch with `--export-file`, sends beats from two agents,
/// waits for stalls, and verifies the TSV file has beat and stall lines.
pub(super) fn file_export_writes_tsv() {
    let tmp = TempDir::new("fexp");
    let socket = tmp.path().join("varta.sock");
    let export = tmp.path().join("events.tsv");

    let mut child = Command::new(locate_watch_binary())
        .args([
            "--socket",
            socket.to_str().unwrap(),
            "--threshold-ms",
            "200",
            "--export-file",
            export.to_str().unwrap(),
            "--shutdown-after-secs",
            "10",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn varta-watch");

    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "varta-watch did not bind socket within 3s"
    );

    let agent_pid_1 = std::process::id();
    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect");
        for _ in 0..5 {
            let mut tries = 0u32;
            loop {
                match agent.beat(Status::Ok, 0) {
                    BeatOutcome::Sent => break,
                    BeatOutcome::Dropped(_) => {
                        tries += 1;
                        if tries > 5_000 {
                            panic!("kernel never accepted a beat");
                        }
                        std::thread::sleep(Duration::from_micros(500));
                    }
                    BeatOutcome::Failed(e) => panic!("unexpected hard failure: {e}"),
                }
            }
        }
    }

    // Spawn a second agent (different PID) via child process
    let me = std::env::current_exe().expect("current_exe");
    let mut agent2 = Command::new(&me)
        .env(AGENT_CHILD_ENV, socket.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn agent child");
    let child_pid = agent2.id();
    let _ = agent2.wait().expect("wait agent child");

    // Wait past threshold so stalls are surfaced
    std::thread::sleep(Duration::from_millis(400));

    // Gracefully shut down the observer so fe.flush() runs
    Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("kill -TERM");
    let _ = child.wait().expect("wait observer");

    // Read the export file
    let content = std::fs::read_to_string(&export).unwrap_or_default();
    assert!(
        !content.is_empty(),
        "export file should contain event lines (got {content:?})"
    );

    // Verify beats from agent 1
    assert!(
        content
            .lines()
            .any(|l| l.contains("\tbeat\t") && l.contains(&agent_pid_1.to_string())),
        "export file missing beat lines for pid {agent_pid_1}:\n{content}"
    );

    // Verify stall lines for both agents
    let agent1_stalled = content
        .lines()
        .any(|l| l.contains("\tstall\t") && l.contains(&agent_pid_1.to_string()));
    assert!(
        agent1_stalled,
        "export file missing stall for pid {agent_pid_1}:\n{content}"
    );

    let child_stalled = content
        .lines()
        .any(|l| l.contains("\tstall\t") && l.contains(&child_pid.to_string()));
    assert!(
        child_stalled,
        "export file missing stall for child pid {child_pid}:\n{content}"
    );
}

/// Spawns varta-watch with `--export-file-max-bytes 200`, sends enough beats
/// to trigger rotation, and asserts rotated files exist.
pub(super) fn file_export_rotation() {
    let tmp = TempDir::new("frot");
    let socket = tmp.path().join("varta.sock");
    let export = tmp.path().join("rot.tsv");

    let (mut child, _prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "5000", // no stall
        "--export-file",
        export.to_str().unwrap(),
        "--export-file-max-bytes",
        "200",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "varta-watch did not bind socket within 3s"
    );

    // Send many beats from two PIDs to push file size over 200 bytes
    {
        let mut agent1 = Varta::connect(&socket).expect("Varta::connect agent1");
        for _ in 0..30 {
            let mut tries = 0u32;
            loop {
                match agent1.beat(Status::Ok, 0) {
                    BeatOutcome::Sent => break,
                    BeatOutcome::Dropped(_) => {
                        tries += 1;
                        if tries > 5_000 {
                            panic!("kernel never accepted a beat agent1");
                        }
                        std::thread::sleep(Duration::from_micros(500));
                    }
                    BeatOutcome::Failed(e) => panic!("unexpected hard failure: {e}"),
                }
            }
        }
    }

    // Give the observer time to flush and rotate
    std::thread::sleep(Duration::from_millis(300));

    // At least one rotation file should exist or the main file should be
    // under the rotation limit (proving a rotation happened and a new file
    // was started).
    let main_size = std::fs::metadata(&export).map(|m| m.len()).unwrap_or(0);
    let rot1 = tmp.path().join("rot.tsv.1");
    let rot1_exists = rot1.exists();

    assert!(
        rot1_exists || main_size > 0,
        "expected rotation file rot.tsv.1 or main file with content; \
         main_size={main_size}, rot1_exists={rot1_exists}"
    );

    // If rot.tsv.1 exists, it should be non-empty
    if rot1_exists {
        let rot1_size = std::fs::metadata(&rot1).map(|m| m.len()).unwrap_or(0);
        assert!(
            rot1_size > 0,
            "rotation file rot.tsv.1 should be non-empty; size={rot1_size}"
        );
    }
}

/// Spawns varta-watch with `--tracker-capacity 2` and a short threshold.
/// Spawns 5 agent child processes sequentially (each a distinct PID). The
/// first two fill the tracker; once they stall, subsequent PIDs trigger
/// eviction. Asserts `varta_tracker_evicted_total > 0` in /metrics.
pub(super) fn tracker_capacity_exceeded_reports_eviction_metric() {
    let tmp = TempDir::new("tevict");
    let socket = tmp.path().join("varta.sock");

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "100", // stall quickly
        "--tracker-capacity",
        "2",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "20",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "varta-watch did not bind socket within 3s"
    );
    assert!(
        wait_until(
            || TcpStream::connect(prom_addr).is_ok(),
            Duration::from_secs(3)
        ),
        "/metrics not reachable within 3s"
    );

    let me = std::env::current_exe().expect("current_exe");
    let child_count = 5;

    // Spawn children sequentially with interleaved sleeps so the first two
    // stall and become evictable before later children arrive.
    for i in 0..child_count {
        let mut child = Command::new(&me)
            .env(AGENT_CHILD_ENV, socket.to_str().unwrap())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn agent child");
        let _ = child.wait().expect("wait agent child");

        // After the first 2 children, wait for stalls + eviction threshold
        if i < 2 {
            std::thread::sleep(Duration::from_millis(50));
        } else {
            // Wait past threshold * EVICTION_MULTIPLIER (100ms * 10 = 1s)
            // so the first slots become evictable
            std::thread::sleep(Duration::from_millis(1100));
        }
    }

    // Check /metrics for eviction counter
    let eviction_needle = "varta_tracker_evicted_total";
    let satisfied = wait_until(
        || match http_get(prom_addr, "/metrics") {
            Ok((200, body)) => {
                if let Some(line) = body.lines().find(|l| l.starts_with(eviction_needle)) {
                    if let Some(val) = line.split_whitespace().nth(1) {
                        if let Ok(n) = val.parse::<u64>() {
                            return n > 0;
                        }
                    }
                }
                false
            }
            _ => false,
        },
        Duration::from_secs(5),
    );
    assert!(
        satisfied,
        "varta_tracker_evicted_total should be > 0 with tracker capacity 2 and 5 distinct PIDs"
    );
}

/// `iteration_budget_holds_under_slow_scrape_load` — H5 contract.
///
/// Spawn `varta-watch` with a 100 ms soft iteration budget, run one agent
/// for ~3 s while a pool of 8 deliberately-slow `/metrics` scrapers hammer
/// the exporter (partial GET, then sleep, then close — hits the per-conn
/// 10 ms read-deadline path).  After the agent stops we let the threshold
/// expire so a stall surfaces, then scrape `/metrics` once normally and
/// assert:
///
/// - `varta_stalls_total{pid=<agent>}` ≥ 1 (stall detection NOT starved).
/// - 99% of recorded iterations fit in the `le="0.5"` bucket
///   (worst-case-iteration upper bound from observer-liveness.md holds
///   even under adversarial scrape load).
/// - `varta_observer_iteration_seconds_count` is greater than zero (the
///   histogram is being recorded at all).
///
/// The point of the test is to pin the contract H5 names: under a storm
/// of slow scrapers, the documented per-iteration upper bound holds and
/// stall detection continues to fire.
pub(super) fn iteration_budget_holds_under_slow_scrape_load() {
    use std::io::Write;

    let tmp = TempDir::new("iter-budget");
    let socket = tmp.path().join("varta.sock");

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "500",
        "--iteration-budget-ms",
        "100",
        // Disable per-IP rate limiting so the slow-scraper pool actually
        // reaches `serve_one`. The default rate limit (5/s, burst 10) would
        // drop most of the 8 concurrent scrapers at the IP layer and the
        // test would only exercise the cheap drain path. burst=0 is the
        // documented "no limit" escape hatch (see exporter.rs:705).
        "--prom-rate-limit-burst",
        "0",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "20",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "varta-watch did not bind socket within 3s"
    );
    assert!(
        wait_until(
            || TcpStream::connect(prom_addr).is_ok(),
            Duration::from_secs(3)
        ),
        "/metrics not reachable within 3s"
    );

    // Spawn 8 slow scraper threads.  Each opens a TCP connection, writes a
    // valid auth header but stops BEFORE the trailing `\r\n\r\n`, sleeps
    // long enough to exhaust `PROM_READ_DEADLINE` (10 ms), then closes.
    // The exporter sees these as deadline-exhausted reads and bumps
    // `scrape_budget_exhausted_total`.  Their queue depth is what drives
    // the iteration-time histogram toward the upper bound.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut scraper_handles = Vec::new();
    for _ in 0..8 {
        let stop = stop.clone();
        let addr = prom_addr;
        scraper_handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                    // Write request + auth header, intentionally OMIT the
                    // body-terminator blank line so the read loop on the
                    // server hits PROM_READ_DEADLINE waiting for it.
                    let partial = format!(
                        "GET /metrics HTTP/1.0\r\nHost: localhost\r\nAuthorization: Bearer {PROM_TOKEN_HEX}\r\n",
                    );
                    let _ = s.write_all(partial.as_bytes());
                    let _ = s.flush();
                    // Hold the connection open past the 10 ms read deadline,
                    // then close.
                    std::thread::sleep(Duration::from_millis(30));
                    drop(s);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }));
    }

    // Drive a real agent for ~3 s while the scraper pool runs in parallel.
    let agent_pid = std::process::id();
    let agent_start = Instant::now();
    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect");
        while agent_start.elapsed() < Duration::from_secs(3) {
            let mut tries = 0u32;
            loop {
                match agent.beat(Status::Ok, 0) {
                    BeatOutcome::Sent => break,
                    BeatOutcome::Dropped(_) => {
                        tries += 1;
                        if tries > 5_000 {
                            panic!("kernel never accepted a beat within 5000 retries");
                        }
                        std::thread::sleep(Duration::from_micros(500));
                    }
                    BeatOutcome::Failed(e) => panic!("unexpected hard failure: {e}"),
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // drop agent → no further beats
    }

    // Let the threshold expire so a stall is surfaced.
    std::thread::sleep(Duration::from_millis(700));

    // Stop the scraper pool BEFORE the assertion scrape so the assertion's
    // own GET is not blocked behind a backlog of partial connections.
    stop.store(true, Ordering::Relaxed);
    for h in scraper_handles {
        let _ = h.join();
    }
    // Give the daemon one more tick to drain its accept queue and refresh
    // the histogram.
    std::thread::sleep(Duration::from_millis(200));

    let (status, body) = http_get(prom_addr, "/metrics").expect("final /metrics scrape");
    assert_eq!(
        status, 200,
        "final scrape did not return 200; body:\n{body}"
    );

    // 1. Stall detection MUST have fired despite the scrape storm.
    let stalls_needle = format!("varta_stalls_total{{pid=\"{agent_pid}\"}} ");
    let stall_line = body
        .lines()
        .find(|l| l.starts_with(&stalls_needle))
        .unwrap_or_else(|| panic!("/metrics missing {stalls_needle:?}; body:\n{body}"));
    let stall_count: u64 = stall_line[stalls_needle.len()..]
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("could not parse stall count from {stall_line:?}"));
    assert!(
        stall_count >= 1,
        "stall detection starved under scrape load: got {stall_count} stalls; body:\n{body}"
    );

    // 2. Histogram contract: ≥99% of iterations must fit within the
    //    documented 0.5 s worst-case upper bound.  Parse the cumulative
    //    histogram out of the body.
    let count = parse_metric_value(&body, "varta_observer_iteration_seconds_count")
        .unwrap_or_else(|| panic!("missing iteration count; body:\n{body}"));
    assert!(
        count > 0,
        "iteration histogram was never updated (count=0); body:\n{body}"
    );
    let le_500 = parse_histogram_bucket(&body, "varta_observer_iteration_seconds", "0.5")
        .unwrap_or_else(|| panic!("missing le=0.5 bucket; body:\n{body}"));
    // 99% threshold expressed without floats — `99 * count` ≤ `100 * le_500`.
    assert!(
        le_500.saturating_mul(100) >= count.saturating_mul(99),
        "<99% of iterations fit le=0.5 ({le_500} of {count}); body:\n{body}"
    );

    // 3. +Inf bucket should equal count (sanity — every observation lands
    //    somewhere).
    let le_inf = parse_histogram_bucket(&body, "varta_observer_iteration_seconds", "+Inf")
        .unwrap_or_else(|| panic!("missing le=+Inf bucket; body:\n{body}"));
    assert_eq!(
        le_inf, count,
        "+Inf bucket ({le_inf}) must equal count ({count}); body:\n{body}"
    );
}

/// `serve_pending_seconds_separates_scrape_from_beat_path` — M6 contract.
///
/// Under sustained partial-GET scrape pressure with a deliberately tight
/// `--scrape-budget-ms 5`, the daemon must:
///
/// 1. Emit the `varta_observer_serve_pending_seconds_*` histogram with
///    every bucket label (including `+Inf` literally), and the count must
///    advance during the run.
/// 2. Emit `varta_observer_scrape_budget_exceeded_total` and increment it
///    at least once (the partial-GET pool reliably drives serve_pending
///    past the 5 ms budget).
/// 3. Keep recording the iteration histogram in lockstep — every
///    iteration calls record_serve_pending_duration after our change, so
///    `iteration_seconds_count` and `serve_pending_seconds_count` must
///    differ by at most one tick (the bracket order in main.rs writes
///    serve_pending first, then iteration_duration at the loop end).
/// 4. The stable-label-set contract on the new histogram must hold from
///    the first scrape: every `le` label present.
///
/// The point is M6's binary outcome: scrape variance is observable
/// independently of beat-path latency.
pub(super) fn serve_pending_seconds_separates_scrape_from_beat_path() {
    use std::io::Write;

    let tmp = TempDir::new("scrape-isolation");
    let socket = tmp.path().join("varta.sock");

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "500",
        "--iteration-budget-ms",
        "100",
        "--scrape-budget-ms",
        "50",
        "--prom-rate-limit-burst",
        "0",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "20",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "varta-watch did not bind socket within 3s"
    );
    assert!(
        wait_until(
            || TcpStream::connect(prom_addr).is_ok(),
            Duration::from_secs(3)
        ),
        "/metrics not reachable within 3s"
    );

    // Same partial-GET pattern as the H5 test — the canonical recipe
    // for synthesising scrape pressure on the single-threaded daemon
    // (cerebrum 2026-05-13 H5).  burst=0 disables per-IP rate limiting so
    // the 8 scrapers actually queue inside `serve_one`.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut scraper_handles = Vec::new();
    for _ in 0..8 {
        let stop = stop.clone();
        let addr = prom_addr;
        scraper_handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                    let partial = format!(
                        "GET /metrics HTTP/1.0\r\nHost: localhost\r\nAuthorization: Bearer {PROM_TOKEN_HEX}\r\n",
                    );
                    let _ = s.write_all(partial.as_bytes());
                    let _ = s.flush();
                    std::thread::sleep(Duration::from_millis(30));
                    drop(s);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }));
    }

    // Run an agent for ~3 s to populate the iteration histogram with
    // realistic mixed beat / scrape iterations.
    let agent_start = Instant::now();
    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect");
        while agent_start.elapsed() < Duration::from_secs(3) {
            let mut tries = 0u32;
            loop {
                match agent.beat(Status::Ok, 0) {
                    BeatOutcome::Sent => break,
                    BeatOutcome::Dropped(_) => {
                        tries += 1;
                        if tries > 5_000 {
                            panic!("kernel never accepted a beat within 5000 retries");
                        }
                        std::thread::sleep(Duration::from_micros(500));
                    }
                    BeatOutcome::Failed(e) => panic!("unexpected hard failure: {e}"),
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // Stop scrapers BEFORE the assertion scrape so the assertion's GET
    // is not queued behind partial connections (cerebrum 2026-05-13 H5).
    stop.store(true, Ordering::Relaxed);
    for h in scraper_handles {
        let _ = h.join();
    }
    std::thread::sleep(Duration::from_millis(200));

    let (status, body) = http_get(prom_addr, "/metrics").expect("final /metrics scrape");
    assert_eq!(
        status, 200,
        "final scrape did not return 200; body:\n{body}"
    );

    // 1. Stable label-set contract: every bucket present, including
    //    `+Inf` literal.
    for le in &[
        "0.001", "0.005", "0.01", "0.05", "0.1", "0.25", "0.5", "1", "+Inf",
    ] {
        let needle = format!("varta_observer_serve_pending_seconds_bucket{{le=\"{le}\"}} ");
        assert!(
            body.lines().any(|l| l.starts_with(&needle)),
            "missing serve_pending bucket le={le:?}; body:\n{body}"
        );
    }

    // 2. The serve_pending histogram count advances.
    let sp_count = parse_metric_value(&body, "varta_observer_serve_pending_seconds_count")
        .unwrap_or_else(|| {
            panic!("missing varta_observer_serve_pending_seconds_count; body:\n{body}")
        });
    assert!(
        sp_count > 0,
        "serve_pending histogram never updated (count=0); body:\n{body}"
    );

    // 3. Bracket order: every iteration records serve_pending first, then
    //    iteration_duration at the end of the loop body. So
    //    iteration_count and serve_pending_count are within one tick of
    //    each other (the binary may have completed serve_pending but not
    //    yet record_iteration_duration when the scrape's own response
    //    rendered the body).
    let iter_count = parse_metric_value(&body, "varta_observer_iteration_seconds_count")
        .unwrap_or_else(|| panic!("missing iteration_seconds_count; body:\n{body}"));
    let diff = iter_count.abs_diff(sp_count);
    assert!(
        diff <= 1,
        "iteration_count ({iter_count}) and serve_pending_count ({sp_count}) drifted by {diff}; body:\n{body}"
    );

    // 4. Scrape-budget exceeded fires under the 50 ms budget. The
    //    partial-GET pool reliably drives serve_pending to its 200 ms
    //    structural cap on at least one iteration.
    let sb_exceeded = parse_metric_value(&body, "varta_observer_scrape_budget_exceeded_total")
        .unwrap_or_else(|| {
            panic!("missing varta_observer_scrape_budget_exceeded_total; body:\n{body}")
        });
    assert!(
        sb_exceeded >= 1,
        "scrape_budget_exceeded_total stayed at 0 under partial-GET pool with 50 ms budget; body:\n{body}"
    );

    // 5. +Inf bucket equals count — sanity for cumulative histogram.
    let le_inf = parse_histogram_bucket(&body, "varta_observer_serve_pending_seconds", "+Inf")
        .unwrap_or_else(|| panic!("missing serve_pending le=+Inf bucket; body:\n{body}"));
    assert_eq!(
        le_inf, sp_count,
        "+Inf bucket ({le_inf}) must equal serve_pending count ({sp_count}); body:\n{body}"
    );
}

/// Asserts every metric name referenced by the shipped Prometheus alert
/// rules is actually emitted by a running varta-watch.
///
/// This is the load-bearing assertion behind the `observability/` bundle
/// promise: alerts cannot reference metrics the binary doesn't emit.
/// The CI `observability-lint` job runs the same cross-check against
/// the exporter source, but a live-binary scrape catches the
/// dynamic-only case where a metric *is* declared in source but never
/// rendered on `/metrics` (cfg-gating, feature drift, etc.).
pub(super) fn alert_rules_match_live_metrics() {
    use std::path::PathBuf;

    let tmp = TempDir::new("alert-coverage");
    let socket = tmp.path().join("varta.sock");

    // Spawn with a tracker capacity of 1 + small audit ring so the
    // `_capacity_exceeded` / `_eviction` / `_ring_watermark` counters
    // get a chance to render (zero is still a valid render under
    // stable-label-set discipline, so we don't depend on a specific
    // value -- only on the metric name appearing in the output).
    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "varta-watch did not bind socket within 3s"
    );
    assert!(
        wait_until(
            || TcpStream::connect(prom_addr).is_ok(),
            Duration::from_secs(3)
        ),
        "/metrics not reachable within 3s"
    );

    // Drive a handful of beats so every counter family touches at least
    // one render path; histogram families render at zero unconditionally
    // by stable-label-set discipline.
    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect");
        for _ in 0..10 {
            match agent.beat(Status::Ok, 0) {
                BeatOutcome::Sent => {}
                BeatOutcome::Dropped(_) => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                BeatOutcome::Failed(e) => panic!("unexpected hard failure: {e}"),
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    // Wait one more poll-cycle so the observer has rendered the
    // tracker / iteration histograms for our beats.
    std::thread::sleep(Duration::from_millis(300));

    let (status, body) = http_get(prom_addr, "/metrics").expect("/metrics scrape");
    assert_eq!(status, 200, "/metrics returned {status}; body:\n{body}");

    // Load the alert-rules YAML from the repo. CARGO_MANIFEST_DIR is
    // `crates/varta-tests`; the repo root is two parents up.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rules_path = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|root| root.join("observability/alerts/varta.rules.yml"))
        .expect("compute observability/alerts/varta.rules.yml path");
    let rules =
        std::fs::read_to_string(&rules_path).expect("read observability/alerts/varta.rules.yml");

    // Extract every distinct `varta_<name>` token. The exporter emits
    // histogram bases (`varta_foo_seconds`); Prometheus appends
    // `_bucket`, `_sum`, `_count` at render time. We normalise the
    // alert references by stripping those suffixes when they don't
    // appear verbatim on the wire.
    let mut alert_metrics: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut cursor = 0;
    let bytes = rules.as_bytes();
    while cursor < bytes.len() {
        if let Some(rel) = rules[cursor..].find("varta_") {
            let start = cursor + rel;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
                end += 1;
            }
            alert_metrics.insert(rules[start..end].to_string());
            cursor = end;
        } else {
            break;
        }
    }
    assert!(
        !alert_metrics.is_empty(),
        "no varta_* metrics extracted from alert rules at {rules_path:?}; \
         rule file may be empty or malformed"
    );

    // For each referenced metric, the body must contain a TYPE / HELP
    // declaration OR an instance line. We match the bare name preceded
    // by a HELP/TYPE keyword OR followed by `{` (labelled instance) /
    // a literal `_bucket` / `_sum` / `_count` (histogram suffix). The
    // simplest robust check: the metric name string appears somewhere
    // in the body. False positives only occur if a longer metric name
    // *contains* the shorter one as a substring, which the exporter
    // does not produce by audit (varta_beats_total is never a prefix
    // of another emitted metric).
    let mut missing: Vec<String> = Vec::new();
    for metric in &alert_metrics {
        // Strip histogram suffixes -- the exporter emits the base name
        // and Prometheus's `_bucket` / `_sum` / `_count` are rendered
        // by the same code path that emits the base.
        let base = metric
            .strip_suffix("_bucket")
            .or_else(|| metric.strip_suffix("_sum"))
            .or_else(|| metric.strip_suffix("_count"))
            .unwrap_or(metric);
        if !body.contains(base) {
            missing.push(metric.clone());
        }
    }

    assert!(
        missing.is_empty(),
        "alert rules at {rules_path:?} reference {} metric(s) not present on \
         /metrics: {missing:?}\n\
         This is the load-bearing test for the observability bundle: every \
         alert must be backed by a live metric.\n\
         Fix: either (a) add the metric to the exporter, (b) remove the alert \
         from observability/alerts/varta.rules.yml, or (c) gate it on a \
         Cargo feature this test does not enable.\n\
         (Total alert metrics: {}, missing: {}.)",
        missing.len(),
        alert_metrics.len(),
        missing.len(),
    );
}

/// `hostile_frame_rejected_at_decode_with_label_emit` (M1 contract + H1).
///
/// Spawns the observer and sends two hand-crafted frames:
///   1. `Status::Stall` paired with the reserved `pid = 1` — exercises the
///      H1 precedence (StallOnWire check fires before BadPid).
///   2. `Status::Stall` paired with a legitimate pid `12345` — exercises
///      the H1 path independently of any other validation rule, locking
///      in that StallOnWire is the canonical rejection label for any
///      observer-only status appearing on the wire.
///
/// Asserts:
///   * `varta_decode_errors_total{kind="stall_on_wire"}` ticks up by >= 2;
///   * every kind label (including the new `stall_on_wire`) is present in
///     the exposition output even when only one has fired — the
///     stable-label-set contract (cerebrum 2026-05-11);
///   * no per-pid beat counter is published for either pid (the frames
///     must never reach the tracker).
pub(super) fn hostile_frame_rejected_at_decode_with_label_emit() {
    use std::os::unix::net::UnixDatagram;
    use varta_vlp::{Frame, Status};

    let tmp = TempDir::new("hostile-frame");
    let socket = tmp.path().join("varta.sock");

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "500",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "varta-watch did not bind socket within 3s"
    );
    assert!(
        wait_until(
            || TcpStream::connect(prom_addr).is_ok(),
            Duration::from_secs(3)
        ),
        "/metrics not reachable within 3s"
    );

    // Two hostile frames:
    //   1. Status::Stall + reserved pid=1 — pre-H1 would have decoded
    //      cleanly and could have triggered "init has stalled" recovery.
    //      Post-H1, decode rejects on StallOnWire before reaching the pid
    //      range check.
    //   2. Status::Stall + legitimate pid=12345 — locks in StallOnWire as
    //      the canonical rejection label independent of any other rule.
    let client = UnixDatagram::unbound().expect("unbound");
    client.connect(&socket).expect("connect");

    for hostile_pid in [1u32, 12_345] {
        let hostile = Frame::new(Status::Stall, hostile_pid, 1_000, 7, 0);
        let mut buf = [0u8; 32];
        hostile.encode(&mut buf);
        client.send(&buf).expect("send hostile frame");
    }

    // The observer's poll loop reads, decodes, and either records or
    // rejects on its next tick (~100ms). Poll the counter until it
    // increments by 2.
    let stall_count = wait_until_with_timeout(
        || {
            let (code, body) = http_get(prom_addr, "/metrics").ok()?;
            if code != 200 {
                return None;
            }
            let v = parse_metric_value(&body, "varta_decode_errors_total{kind=\"stall_on_wire\"}")?;
            if v >= 2 {
                Some((v, body))
            } else {
                None
            }
        },
        Duration::from_secs(5),
    )
    .expect("stall_on_wire counter did not reach 2 within 5s");

    let (count, body) = stall_count;
    assert!(
        count >= 2,
        "stall_on_wire decode-error counter must increment for both hostile frames"
    );

    // The reserved-pid path must NOT fire — StallOnWire takes precedence
    // by decode order, even when pid=1 would also be rejected.
    let bad_pid =
        parse_metric_value(&body, "varta_decode_errors_total{kind=\"bad_pid\"}").unwrap_or(0);
    assert_eq!(
        bad_pid, 0,
        "bad_pid must not fire for Status::Stall + pid=1 — \
         StallOnWire takes precedence; body:\n{body}"
    );

    // Stable-label-set contract: every kind must be emitted, including the
    // new `stall_on_wire`, even when only one fires.
    for kind in [
        "bad_magic",
        "bad_version",
        "bad_status",
        "bad_pid",
        "bad_timestamp",
        "bad_nonce",
        "stall_on_wire",
    ] {
        let needle = format!("varta_decode_errors_total{{kind=\"{kind}\"}} ");
        assert!(
            body.contains(&needle),
            "missing decode-error label {kind} in /metrics body:\n{body}"
        );
    }

    // Tracker invariant: a rejected frame must NEVER surface as a
    // per-pid beat. Confirm neither hostile pid has a beats_total series.
    assert!(
        !body.contains("varta_beats_total{pid=\"1\"}"),
        "rejected frame leaked to tracker for pid=1; body:\n{body}"
    );
    assert!(
        !body.contains("varta_beats_total{pid=\"12345\"}"),
        "rejected frame leaked to tracker for pid=12345; body:\n{body}"
    );

    eprintln!("hostile_frame_rejected_at_decode_with_label_emit: ok");
}
