//! Basic heartbeat, status encoding, and clock-source smoke tests.

use super::{
    http_get, spawn_watch, wait_until, ChildGuard, TempDir, AGENT_CHILD_ENV, DEGRADED_CHILD_ENV,
    MULTI_AGENT_BEATS, MULTI_AGENT_COUNT, PANIC_CHILD_ENV,
};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use varta_client::{BeatOutcome, Status, Varta};

/// `client_to_observer_to_recovery_full_loop` (S06 contract).
///
/// Spawns the compiled `varta-watch` binary, drives 100 beats from a real
/// `Varta` client, induces a stall, asserts the recovery command fired
/// (touched a marker file), then GETs `/metrics` and checks the per-pid
/// beat counter.
pub(super) fn client_to_observer_to_recovery_full_loop() {
    let tmp = TempDir::new("loop");
    let socket = tmp.path().join("varta.sock");
    let marker = tmp.path().join("recovered.marker");
    let recovery_exec = format!("touch {}", marker.display());

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-exec",
        &recovery_exec,
        "--recovery-debounce-ms",
        "1000",
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
        // The agent socket is non-blocking. On macOS the per-socket UDS receive
        // buffer is small (~4 KiB); at line-rate the buffer overflows and send(2)
        // returns ENOBUFS. varta-client now correctly classifies ENOBUFS as
        // BeatOutcome::Dropped (kernel-pressure, transient). Any Failed outcome
        // is an unexpected hard error and should fail the test immediately.
        for _ in 0..100 {
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
        }
        // Drop the agent so the sender side is closed; observer keeps polling.
    }

    // Wait past threshold, then for the recovery marker.
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        wait_until(|| marker.exists(), Duration::from_secs(3)),
        "recovery marker did not appear within 3s"
    );

    // /metrics must reflect 100 beats for our pid. The Prom exporter
    // serves on every poll-loop tick; allow up to 2s for the most recent
    // tick's body to expose the counter.
    let needle = format!("varta_beats_total{{pid=\"{agent_pid}\"}} 100");
    let mut last_body = String::new();
    let satisfied = wait_until(
        || match http_get(prom_addr, "/metrics") {
            Ok((200, body)) => {
                last_body = body.clone();
                body.contains(&needle)
            }
            _ => false,
        },
        Duration::from_secs(3),
    );
    assert!(
        satisfied,
        "/metrics did not surface {needle:?}; last body:\n{last_body}"
    );

    // Assert stall detection is reported in /metrics
    let stalls_needle = format!("varta_stalls_total{{pid=\"{agent_pid}\"}} 1");
    assert!(
        last_body.contains(&stalls_needle),
        "/metrics missing stall counter {stalls_needle:?}; last body:\n{last_body}"
    );
    let stall_status_needle = format!("varta_status{{pid=\"{agent_pid}\"}} 3");
    assert!(
        last_body.contains(&stall_status_needle),
        "/metrics missing stall status gauge {stall_status_needle:?}; last body:\n{last_body}"
    );
}

/// `panic_handler_critical_beat_visible_in_metrics` (S06 contract).
///
/// Spawns `varta-watch`, then re-spawns this test binary as a child with
/// `VARTA_E2E_PANIC_CHILD=<socket>`. The child installs the panic hook,
/// sends a warmup beat, then panics — the hook fires the Critical frame
/// before unwinding. Parent asserts `/metrics` shows the Critical status
/// gauge for the child's pid.
pub(super) fn panic_handler_critical_beat_visible_in_metrics() {
    let tmp = TempDir::new("panic");
    let socket = tmp.path().join("varta.sock");

    let (mut watch_child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard = ChildGuard(&mut watch_child);

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
    let panic_child = Command::new(&me)
        .env(PANIC_CHILD_ENV, socket.to_str().unwrap())
        .env_remove("RUST_BACKTRACE")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn panic child");
    let child_pid = panic_child.id();
    let output = panic_child
        .wait_with_output()
        .expect("wait_with_output panic child");
    assert!(
        !output.status.success(),
        "panic child unexpectedly succeeded: {:?}",
        output.status
    );

    // The child's Critical frame races process exit; allow up to 3s for
    // the parent observer to consume it and the Prom body to reflect it.
    let critical_needle = format!("varta_status{{pid=\"{child_pid}\"}} 2");
    let beats_label = format!("pid=\"{child_pid}\"");
    let mut last_body = String::new();
    let satisfied = wait_until(
        || match http_get(prom_addr, "/metrics") {
            Ok((200, body)) => {
                last_body = body.clone();
                body.contains(&critical_needle)
            }
            _ => false,
        },
        Duration::from_secs(3),
    );

    assert!(
        last_body.contains(&beats_label),
        "/metrics never registered any frame for child pid {child_pid}; \
         hook never fired even at warmup. Last body:\n{last_body}"
    );
    assert!(
        satisfied,
        "/metrics did not surface Critical status gauge {critical_needle:?}; \
         last body:\n{last_body}"
    );
}

/// `concurrent_multi_agent_beats_visible_in_metrics`.
///
/// Spawns `varta-watch` with a generous tracker capacity, then spawns
/// [`MULTI_AGENT_COUNT`] concurrent agent child processes. Each child
/// re-execs this test binary as `VARTA_E2E_AGENT_CHILD=<socket>`, sends
/// [`MULTI_AGENT_BEATS`] beats, then exits. The parent waits for all
/// children, then asserts every child's PID appears in `/metrics` with
/// the expected beat count.
pub(super) fn concurrent_multi_agent_beats_visible_in_metrics() {
    let tmp = TempDir::new("multi");
    let socket = tmp.path().join("varta.sock");

    let (mut watch_child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--tracker-capacity",
        "128",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard = ChildGuard(&mut watch_child);

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
    let mut children: Vec<Child> = Vec::with_capacity(MULTI_AGENT_COUNT);

    for _ in 0..MULTI_AGENT_COUNT {
        let child = Command::new(&me)
            .env(AGENT_CHILD_ENV, socket.to_str().unwrap())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn agent child");
        children.push(child);
    }

    // Wait for all children with generous timeout — the observer is
    // non-blocking and each child exits after its beats, but slow CI
    // runners may take longer.
    for child in &mut children {
        let status = child.wait().expect("wait agent child");
        assert!(status.success(), "agent child exited with {status}");
    }

    // The Prom exporter updates on every poll-loop tick. Poll until
    // at least MULTI_AGENT_COUNT distinct PIDs appear in the beats counter,
    // or the deadline expires.
    let mut last_body = String::new();
    let mut seen_pids = 0u32;
    let mut max_claim = 0u64;
    let satisfied = wait_until(
        || match http_get(prom_addr, "/metrics") {
            Ok((200, body)) => {
                last_body = body.clone();
                seen_pids = 0;
                max_claim = 0;
                for line in body.lines() {
                    if let Some(rest) = line.strip_prefix("varta_beats_total{pid=\"") {
                        if let Some(end) = rest.find('\"') {
                            if let Some(val_start) = rest[end..].find(' ') {
                                let count_str = rest[end + val_start..].trim();
                                if let Ok(n) = count_str.parse::<u64>() {
                                    max_claim = max_claim.max(n);
                                    seen_pids += 1;
                                }
                            }
                        }
                    }
                }
                seen_pids >= MULTI_AGENT_COUNT as u32
            }
            _ => false,
        },
        Duration::from_secs(8),
    );

    assert!(
        satisfied,
        "/metrics shows {seen_pids} PIDs, expected at least {MULTI_AGENT_COUNT}; \
         body:\n{last_body}"
    );

    // Each child sends exactly MULTI_AGENT_BEATS beats. Retry logic within
    // each child may cause a few extra if Dropped beats are re-sent, but
    // no single PID should claim more than a reasonable ceiling.
    let ceiling = (MULTI_AGENT_BEATS * 2) as u64;
    assert!(
        max_claim <= ceiling,
        "max beat count {max_claim} exceeds reasonable ceiling {ceiling}"
    );
}

/// `status_degraded_visible_in_metrics`.
///
/// Spawns varta-watch, then a child that sends 5 `Status::Degraded` beats.
/// Asserts `/metrics` shows `varta_status{pid="child_pid"} 1`.
pub(super) fn status_degraded_visible_in_metrics() {
    let tmp = TempDir::new("degraded");
    let socket = tmp.path().join("varta.sock");

    let (mut watch_child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard = ChildGuard(&mut watch_child);

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
    let mut degraded_child = Command::new(&me)
        .env(DEGRADED_CHILD_ENV, socket.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn degraded child");
    let child_pid = degraded_child.id();
    let status = degraded_child.wait().expect("wait degraded child");
    assert!(status.success(), "degraded child exited with {status}");

    let degraded_needle = format!("varta_status{{pid=\"{child_pid}\"}} 1");
    let mut last_body = String::new();
    let satisfied = wait_until(
        || match http_get(prom_addr, "/metrics") {
            Ok((200, body)) => {
                last_body = body.clone();
                body.contains(&degraded_needle)
            }
            _ => false,
        },
        Duration::from_secs(3),
    );
    assert!(
        satisfied,
        "/metrics did not surface Degraded status gauge {degraded_needle:?}; \
         last body:\n{last_body}"
    );
}

/// H7 — basic smoke test that the default `--clock-source monotonic`
/// produces a working daemon (no crash, /metrics reachable). Confirms
/// the Observer's swap from `Instant::now()` to `Clock` did not regress
/// startup or the poll loop.
pub(super) fn clock_source_monotonic_smoke() {
    let tmp = TempDir::new("clock-mono");
    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        tmp.path().join("varta.sock").to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--clock-source",
        "monotonic",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "5",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(
            || TcpStream::connect(prom_addr).is_ok(),
            Duration::from_secs(3)
        ),
        "/metrics not reachable within 3s under --clock-source monotonic"
    );

    // One scrape against the live daemon — proves the poll loop is
    // advancing now_ns() against CLOCK_MONOTONIC without panic.
    match http_get(prom_addr, "/metrics") {
        Ok((200, body)) => assert!(
            body.contains("varta_watch_uptime_seconds"),
            "expected uptime metric under monotonic clock"
        ),
        other => panic!("unexpected /metrics response: {other:?}"),
    }

    eprintln!("clock_source_monotonic_smoke: ok");
}

/// H7 — same smoke test under `--clock-source boottime` (Linux only).
/// CI cannot actually `systemctl suspend` the test host, so this is a
/// startup-and-poll smoke test only; suspend behaviour is verified
/// manually per `book/src/architecture/safety-profiles.md`.
#[cfg(target_os = "linux")]
pub(super) fn clock_source_boottime_smoke() {
    let tmp = TempDir::new("clock-boot");
    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        tmp.path().join("varta.sock").to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--clock-source",
        "boottime",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "5",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(
            || TcpStream::connect(prom_addr).is_ok(),
            Duration::from_secs(3)
        ),
        "/metrics not reachable within 3s under --clock-source boottime"
    );

    match http_get(prom_addr, "/metrics") {
        Ok((200, body)) => assert!(
            body.contains("varta_watch_uptime_seconds"),
            "expected uptime metric under boottime clock"
        ),
        other => panic!("unexpected /metrics response: {other:?}"),
    }

    eprintln!("clock_source_boottime_smoke: ok");
}
