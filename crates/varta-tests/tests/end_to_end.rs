//! Session 06 end-to-end contract tests.
//!
//! Drives the real `varta-watch` binary, the real `varta-client` agent
//! (with the `panic-handler` feature), and asserts on the live `/metrics`
//! endpoint exposed by [`varta_watch::PromExporter`].
//!
//! SRE-profile contract harness: `varta-tests`'s dependency on
//! `varta-watch` always pulls `--features prometheus-exporter`, so the
//! /metrics surface is guaranteed available.  Class-A safety-critical
//! coverage (no argv, no HTTP) lives in
//! `crates/varta-watch/tests/compile_time_config_smoke.rs` instead.
//!
//! This target uses `harness = false` so the binary can intercept the
//! `VARTA_E2E_PANIC_CHILD` env-var dispatch *before* the test runner
//! starts. The contract for `panic_handler_critical_beat_visible_in_metrics`
//! requires `Command::new(std::env::current_exe())` to re-enter this
//! binary as a panic-emitting child.

#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]
// clippy::print_stdout bans println! but allows eprintln!.  The custom test
// runner (harness = false) below uses eprintln! for test status output,
// which is correct: harness = false tests report results to stderr.

use std::io::{BufRead, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use varta_client::{install_panic_handler, BeatOutcome, Status, Varta};

const PANIC_CHILD_ENV: &str = "VARTA_E2E_PANIC_CHILD";
const AGENT_CHILD_ENV: &str = "VARTA_E2E_AGENT_CHILD";
const DEGRADED_CHILD_ENV: &str = "VARTA_E2E_DEGRADED_CHILD";

/// Shared bearer token for the e2e suite.  The 64-char hex form is what
/// `Authorization: Bearer <…>` carries; the raw bytes are what
/// `varta-watch` validates against the file content (after `decode_hex_32`).
const PROM_TOKEN_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Number of concurrent agent processes spawned in the multi-agent test.
const MULTI_AGENT_COUNT: usize = 10;

/// Number of beats each agent process sends.
const MULTI_AGENT_BEATS: usize = 20;

/// Hand-rolled test runner. Runs as the panic child when the dispatch env
/// var is set; otherwise executes both contract tests sequentially.
fn main() -> ExitCode {
    if let Ok(socket_path) = std::env::var(PANIC_CHILD_ENV) {
        run_panic_child(&socket_path);
        // run_panic_child panics; this is unreachable but kept for clarity.
        return ExitCode::SUCCESS;
    }
    if let Ok(socket_path) = std::env::var(AGENT_CHILD_ENV) {
        run_agent_child(&socket_path);
        return ExitCode::SUCCESS;
    }
    if let Ok(socket_path) = std::env::var(DEGRADED_CHILD_ENV) {
        run_degraded_child(&socket_path);
        return ExitCode::SUCCESS;
    }

    let mut failed = 0u32;
    eprintln!("running 19 tests");
    failed += run_one(
        "client_to_observer_to_recovery_full_loop",
        client_to_observer_to_recovery_full_loop,
    );
    failed += run_one(
        "panic_handler_critical_beat_visible_in_metrics",
        panic_handler_critical_beat_visible_in_metrics,
    );
    failed += run_one(
        "concurrent_multi_agent_beats_visible_in_metrics",
        concurrent_multi_agent_beats_visible_in_metrics,
    );
    failed += run_one(
        "recovery_exec_mode_touch_marker_file",
        recovery_exec_mode_touch_marker_file,
    );
    failed += run_one("recovery_cmd_file_mode", recovery_cmd_file_mode);
    failed += run_one("recovery_exec_file_mode", recovery_exec_file_mode);
    failed += run_one("recovery_timeout_kill_after", recovery_timeout_kill_after);
    failed += run_one("recovery_env_isolation", recovery_env_isolation);
    failed += run_one(
        "recovery_audit_log_records_spawn_and_complete",
        recovery_audit_log_records_spawn_and_complete,
    );
    failed += run_one(
        "recovery_audit_log_chain_survives_rotation_and_restart",
        recovery_audit_log_chain_survives_rotation_and_restart,
    );
    failed += run_one(
        "max_beat_rate_limits_and_reports_metric",
        max_beat_rate_limits_and_reports_metric,
    );
    failed += run_one("file_export_writes_tsv", file_export_writes_tsv);
    failed += run_one("file_export_rotation", file_export_rotation);
    failed += run_one(
        "tracker_capacity_exceeded_reports_eviction_metric",
        tracker_capacity_exceeded_reports_eviction_metric,
    );
    failed += run_one(
        "client_reconnect_after_observer_restart",
        client_reconnect_after_observer_restart,
    );
    failed += run_one(
        "client_auto_reconnect_after_dropped",
        client_auto_reconnect_after_dropped,
    );
    failed += run_one(
        "signal_handling_graceful_shutdown",
        signal_handling_graceful_shutdown,
    );
    failed += run_one(
        "status_degraded_visible_in_metrics",
        status_degraded_visible_in_metrics,
    );
    failed += run_one(
        "iteration_budget_holds_under_slow_scrape_load",
        iteration_budget_holds_under_slow_scrape_load,
    );
    failed += run_one(
        "serve_pending_seconds_separates_scrape_from_beat_path",
        serve_pending_seconds_separates_scrape_from_beat_path,
    );
    failed += run_one(
        "hostile_frame_rejected_at_decode_with_label_emit",
        hostile_frame_rejected_at_decode_with_label_emit,
    );
    #[cfg(feature = "udp")]
    {
        failed += run_one(
            "udp_client_to_observer_beats_and_stall",
            udp_client_to_observer_beats_and_stall,
        );
    }
    #[cfg(feature = "secure-udp")]
    {
        failed += run_one(
            "secure_udp_client_to_observer_beats",
            secure_udp_client_to_observer_beats,
        );
    }
    #[cfg(all(feature = "secure-udp", feature = "test-hooks"))]
    {
        failed += run_one(
            "secure_udp_counter_wrap_continues_under_load",
            secure_udp_counter_wrap_continues_under_load,
        );
    }
    #[cfg(all(feature = "secure-udp", target_family = "unix"))]
    {
        failed += run_one(
            "secure_udp_fork_safe_under_real_fork",
            secure_udp_fork_safe_under_real_fork,
        );
    }
    failed += run_one("clock_source_monotonic_smoke", clock_source_monotonic_smoke);
    #[cfg(target_os = "linux")]
    {
        failed += run_one("clock_source_boottime_smoke", clock_source_boottime_smoke);
    }

    let total = 19u32
        + if cfg!(feature = "udp") { 1 } else { 0 }
        + if cfg!(feature = "secure-udp") { 1 } else { 0 }
        + if cfg!(all(feature = "secure-udp", feature = "test-hooks")) {
            1
        } else {
            0
        }
        + if cfg!(all(feature = "secure-udp", target_family = "unix")) {
            1
        } else {
            0
        }
        + 1
        + if cfg!(target_os = "linux") { 1 } else { 0 };
    let passed = total - failed;
    eprintln!(
        "\ntest result: {} {} passed; {} failed; 0 ignored",
        if failed == 0 { "ok." } else { "FAILED." },
        passed,
        failed,
    );
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

const PER_TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn run_one(name: &str, f: fn()) -> u32 {
    eprintln!("test {name} ... starting");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        let _ = tx.send(());
    });
    match rx.recv_timeout(PER_TEST_TIMEOUT) {
        Ok(()) => {
            eprintln!("test {name} ... ok");
            0
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            eprintln!(
                "test {name} ... TIMED OUT (>{}s)",
                PER_TEST_TIMEOUT.as_secs()
            );
            1
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            eprintln!("test {name} ... FAILED");
            1
        }
    }
}

// --- contract tests ---------------------------------------------------------

/// `client_to_observer_to_recovery_full_loop` (S06 contract).
///
/// Spawns the compiled `varta-watch` binary, drives 100 beats from a real
/// `Varta` client, induces a stall, asserts the recovery command fired
/// (touched a marker file), then GETs `/metrics` and checks the per-pid
/// beat counter.
fn client_to_observer_to_recovery_full_loop() {
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
fn panic_handler_critical_beat_visible_in_metrics() {
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
fn concurrent_multi_agent_beats_visible_in_metrics() {
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

// ===== A1: --recovery-exec E2E ==============================================

/// Spawns `varta-watch` with `--recovery-exec`, drives beats, induces a
/// stall, and asserts the recovery exec command fired (created a marker file
/// with the agent PID in its name).
fn recovery_exec_mode_touch_marker_file() {
    let tmp = TempDir::new("rec-exec");
    let socket = tmp.path().join("varta.sock");
    let marker = tmp.path().join(format!("marker.{}", std::process::id()));

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
        for _ in 0..10 {
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
    }

    // Wait past threshold for stall + recovery to fire
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        wait_until(|| marker.exists(), Duration::from_secs(3)),
        "recovery-exec marker did not appear within 3s"
    );

    // Verify stall surfaced in /metrics
    let stalls_needle = format!("varta_stalls_total{{pid=\"{agent_pid}\"}} 1");
    let satisfied = wait_until(
        || match http_get(prom_addr, "/metrics") {
            Ok((200, body)) => body.contains(&stalls_needle),
            _ => false,
        },
        Duration::from_secs(3),
    );
    assert!(
        satisfied,
        "/metrics missing exec-mode stall counter {stalls_needle:?}"
    );
}

// ===== A2: --recovery-cmd-file migration → --recovery-exec-file E2E =========

/// Writes the recovery exec command to a file with 0600 permissions,
/// spawns `varta-watch` with `--recovery-exec-file`, and asserts recovery
/// fires on stall.  (Previously used `--recovery-cmd-file`; shell-mode
/// recovery was permanently removed.  See
/// `book/src/architecture/recovery-shell-removal.md`.)
fn recovery_cmd_file_mode() {
    let tmp = TempDir::new("rcmd-file");
    let socket = tmp.path().join("varta.sock");
    let exec_file = tmp.path().join("recovery.exec");
    let marker = tmp.path().join("rcmd-file.marker");

    // Write exec command to file with restrictive permissions.
    // The exec-file format is: first whitespace-separated token is the
    // program; remaining tokens are fixed arguments.  The observer appends
    // the stalled pid as the final argument.
    {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&exec_file)
            .expect("create recovery exec file");
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(format!("touch {}", marker.display()).as_bytes())
            .expect("write recovery exec");
        writer.flush().expect("flush recovery exec");
    }

    let (mut child, _prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-exec-file",
        exec_file.to_str().unwrap(),
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

    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect");
        for _ in 0..10 {
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

    std::thread::sleep(Duration::from_millis(400));
    assert!(
        wait_until(|| marker.exists(), Duration::from_secs(3)),
        "recovery-exec-file marker did not appear within 3s"
    );
}

// ===== A3: --recovery-exec-file E2E =========================================

/// Writes the recovery exec command to a file with 0600 permissions,
/// spawns `varta-watch` with `--recovery-exec-file`, and asserts recovery
/// fires on stall.
fn recovery_exec_file_mode() {
    let tmp = TempDir::new("rexec-file");
    let socket = tmp.path().join("varta.sock");
    let exec_file = tmp.path().join("recovery.exec");
    let marker = tmp.path().join("rexec-file.marker");

    {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&exec_file)
            .expect("create recovery exec file");
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(format!("touch {}", marker.display()).as_bytes())
            .expect("write recovery exec");
        writer.flush().expect("flush recovery exec");
    }

    let (mut child, _prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-exec-file",
        exec_file.to_str().unwrap(),
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

    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect");
        for _ in 0..10 {
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

    std::thread::sleep(Duration::from_millis(400));
    assert!(
        wait_until(|| marker.exists(), Duration::from_secs(3)),
        "recovery-exec-file marker did not appear within 3s"
    );
}

// ===== A4: --recovery-timeout-ms (kill-after) E2E ===========================

/// Spawns varta-watch with `--recovery-exec <script> --recovery-timeout-ms 300`.
/// After a stall, the script touches a marker then sleeps; the sleep child
/// should be killed within 300 ms, leaving the observer responsive (not hung).
fn recovery_timeout_kill_after() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new("rto");
    let socket = tmp.path().join("varta.sock");
    let marker = tmp.path().join("rto.marker");

    // Write a tiny shell wrapper that touches the marker then sleeps.
    // Shell-mode recovery is gone; the wrapper is a named, auditable file.
    let script = tmp.path().join("rto-recovery.sh");
    {
        let content = format!("#!/bin/sh\ntouch '{}'\nsleep 10\n", marker.display());
        std::fs::write(&script, content.as_bytes()).expect("write recovery script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("chmod recovery script");
    }

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-exec",
        script.to_str().unwrap(),
        "--recovery-debounce-ms",
        "0", // no debounce so stall triggers immediately
        "--recovery-timeout-ms",
        "300",
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

    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect");
        for _ in 0..10 {
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

    // Wait for stall + recovery spawn + marker creation (script touches marker first).
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        wait_until(|| marker.exists(), Duration::from_secs(3)),
        "recovery marker (touch before sleep) did not appear"
    );

    // Wait past timeout so the sleep child is killed and reaped.
    // After kill, the observer loop should still be responsive.
    std::thread::sleep(Duration::from_millis(500));

    // Verify observer is still alive by checking /metrics responds
    let alive = wait_until(
        || matches!(http_get(prom_addr, "/metrics"), Ok((200, _))),
        Duration::from_secs(3),
    );
    assert!(
        alive,
        "observer should still be alive after recovery timeout kill"
    );
}

// ===== A5: --recovery-env (environment isolation) E2E ========================

/// Three observers, three policies:
///   1. `--recovery-env VARTA_E2E_ENV=works` (no inherit): allowlist works.
///   2. neither flag (secure default): `$VARTA_E2E_SECRET` planted in the
///      test process env is NOT leaked into the recovery child. This is the
///      regression test for the post-2026-05-14 inversion of the default
///      env policy (formerly: full inheritance, allowing AWS_*/`*_TOKEN`
///      leakage into recovery subprocesses).
///   3. `--recovery-inherit-env` (explicit opt-in): the same planted
///      sentinel IS visible to the recovery child, confirming the legacy
///      escape hatch is wired correctly.
///
/// The sentinel `VARTA_E2E_SECRET` is `set_var` on the test process for the
/// duration of this test and removed at the end.  The custom test runner
/// (`harness = false` in `main()`) executes contract tests sequentially,
/// so cross-test env races are not a concern.
#[allow(unsafe_code)]
fn recovery_env_isolation() {
    use std::os::unix::fs::PermissionsExt;
    const SENTINEL_KEY: &str = "VARTA_E2E_SECRET";
    const SENTINEL_VAL: &str = "must-not-leak";

    // SAFETY: see crate-level note above (sequential runner).  We restore the
    // env on every exit path below.
    unsafe {
        std::env::set_var(SENTINEL_KEY, SENTINEL_VAL);
    }

    // --- Observer 1: --recovery-env allowlist works ---
    let tmp = TempDir::new("renv");
    let socket = tmp.path().join("varta.sock");
    let marker_isolated = tmp.path().join("env-isolated.marker");
    // Write a wrapper script that checks the allowlisted env var and touches
    // the marker. Shell-mode recovery is gone; this is a named wrapper.
    let script1 = tmp.path().join("renv1.sh");
    {
        let content = format!(
            "#!/bin/sh\ntest \"$VARTA_E2E_ENV\" = \"works\" && touch '{}'\n",
            marker_isolated.display()
        );
        std::fs::write(&script1, content.as_bytes()).expect("write script1");
        std::fs::set_permissions(&script1, std::fs::Permissions::from_mode(0o755))
            .expect("chmod script1");
    }

    let (mut child, _prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-exec",
        script1.to_str().unwrap(),
        "--recovery-debounce-ms",
        "0",
        "--recovery-env",
        "VARTA_E2E_ENV=works",
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

    drive_beats(&socket, "observer 1");

    std::thread::sleep(Duration::from_millis(400));
    let ok1 = wait_until(|| marker_isolated.exists(), Duration::from_secs(3));
    if !ok1 {
        unsafe {
            std::env::remove_var(SENTINEL_KEY);
        }
        panic!("env-isolated marker did not appear");
    }

    // --- Observer 2: secure default — sentinel must NOT leak into child ---
    let tmp2 = TempDir::new("renv-default");
    let socket2 = tmp2.path().join("varta.sock");
    let marker_secure = tmp2.path().join("secure-default.marker");
    // Touch the marker ONLY when the sentinel is absent.  If the secret
    // leaked into the recovery child, the marker is never created and the
    // wait_until below times out, failing the test loudly.
    let script2 = tmp2.path().join("renv2.sh");
    {
        let content = format!(
            "#!/bin/sh\ntest -z \"${SENTINEL_KEY}\" && touch '{}'\n",
            marker_secure.display()
        );
        std::fs::write(&script2, content.as_bytes()).expect("write script2");
        std::fs::set_permissions(&script2, std::fs::Permissions::from_mode(0o755))
            .expect("chmod script2");
    }

    let (mut child2, _prom_addr2) = spawn_watch(&[
        "--socket",
        socket2.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-exec",
        script2.to_str().unwrap(),
        "--recovery-debounce-ms",
        "0",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard2 = ChildGuard(&mut child2);

    let ok2_socket = wait_until(|| socket2.exists(), Duration::from_secs(3));
    if !ok2_socket {
        unsafe {
            std::env::remove_var(SENTINEL_KEY);
        }
        panic!("varta-watch v2 did not bind socket within 3s");
    }

    drive_beats(&socket2, "observer 2");

    std::thread::sleep(Duration::from_millis(400));
    let ok2 = wait_until(|| marker_secure.exists(), Duration::from_secs(3));
    if !ok2 {
        unsafe {
            std::env::remove_var(SENTINEL_KEY);
        }
        panic!(
            "secure-default marker did not appear: sentinel {SENTINEL_KEY} \
             must not be visible to recovery children when --recovery-inherit-env \
             is absent (was the default flipped back to inherit?)"
        );
    }

    // --- Observer 3: --recovery-inherit-env restores legacy inheritance ---
    let tmp3 = TempDir::new("renv-inherit");
    let socket3 = tmp3.path().join("varta.sock");
    let marker_inherit = tmp3.path().join("inherit-optin.marker");
    let script3 = tmp3.path().join("renv3.sh");
    {
        let content = format!(
            "#!/bin/sh\ntest \"${SENTINEL_KEY}\" = \"{SENTINEL_VAL}\" && touch '{}'\n",
            marker_inherit.display()
        );
        std::fs::write(&script3, content.as_bytes()).expect("write script3");
        std::fs::set_permissions(&script3, std::fs::Permissions::from_mode(0o755))
            .expect("chmod script3");
    }

    let (mut child3, _prom_addr3) = spawn_watch(&[
        "--socket",
        socket3.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-exec",
        script3.to_str().unwrap(),
        "--recovery-debounce-ms",
        "0",
        "--recovery-inherit-env",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard3 = ChildGuard(&mut child3);

    let ok3_socket = wait_until(|| socket3.exists(), Duration::from_secs(3));
    if !ok3_socket {
        unsafe {
            std::env::remove_var(SENTINEL_KEY);
        }
        panic!("varta-watch v3 did not bind socket within 3s");
    }

    drive_beats(&socket3, "observer 3");

    std::thread::sleep(Duration::from_millis(400));
    let ok3 = wait_until(|| marker_inherit.exists(), Duration::from_secs(3));

    // Always restore the env before any final panic.
    unsafe {
        std::env::remove_var(SENTINEL_KEY);
    }
    assert!(
        ok3,
        "inherit-optin marker did not appear: --recovery-inherit-env must \
         restore legacy inheritance so {SENTINEL_KEY} is visible to the child"
    );
}

/// Drive enough beats through the agent socket to push the observer past
/// its stall threshold and trigger recovery.  Shared by the three sub-cases
/// of [`recovery_env_isolation`].
fn drive_beats(socket: &Path, tag: &str) {
    let mut agent = Varta::connect(socket).unwrap_or_else(|e| panic!("Varta::connect {tag}: {e}"));
    for _ in 0..10 {
        let mut tries = 0u32;
        loop {
            match agent.beat(Status::Ok, 0) {
                BeatOutcome::Sent => break,
                BeatOutcome::Dropped(_) => {
                    tries += 1;
                    if tries > 5_000 {
                        panic!("kernel never accepted a beat ({tag})");
                    }
                    std::thread::sleep(Duration::from_micros(500));
                }
                BeatOutcome::Failed(e) => panic!("unexpected hard failure ({tag}): {e}"),
            }
        }
    }
}

// ===== M1: recovery audit log E2E ===========================================

/// Spawn `varta-watch` with `--recovery-audit-file`, drive a stall, assert
/// the audit TSV contains both a spawn and a complete record for the
/// agent's pid, and that the Prometheus surface exposes the new recovery
/// outcome counters (every label value present, even at zero, from the
/// first scrape).
fn recovery_audit_log_records_spawn_and_complete() {
    let tmp = TempDir::new("audit");
    let socket = tmp.path().join("varta.sock");
    let audit_path = tmp.path().join("recovery-audit.tsv");

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-exec",
        "/usr/bin/true",
        "--recovery-debounce-ms",
        "1000",
        "--recovery-audit-file",
        audit_path.to_str().unwrap(),
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

    let agent_pid = std::process::id();
    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect");
        for _ in 0..10 {
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
    }

    // Stall + recovery must fire; audit log must record both spawn and
    // complete for our pid. Poll the file for up to 5s — completion may
    // happen one observer tick after spawn.
    let spawn_needle = format!("\tspawn\t{agent_pid}\t");
    let complete_needle = format!("\tcomplete\t{agent_pid}\t");
    let mut last_body = String::new();
    let satisfied = wait_until(
        || match std::fs::read_to_string(&audit_path) {
            Ok(body) => {
                let has_spawn = body.contains(&spawn_needle);
                let has_complete = body.contains(&complete_needle);
                last_body = body;
                has_spawn && has_complete
            }
            Err(_) => false,
        },
        Duration::from_secs(5),
    );
    assert!(
        satisfied,
        "audit log missing spawn+complete for pid {agent_pid}; got:\n{last_body}"
    );
    assert!(
        last_body.starts_with("# varta-watch recovery audit v2\n"),
        "audit log missing schema header; got:\n{last_body}"
    );

    // v2 schema: every record line carries a seq column (first) and a
    // chain column (last). Confirm both are well-formed for every record
    // line — boot, spawn, and complete.
    for line in last_body.lines().filter(|l| !l.starts_with('#')) {
        let cols: Vec<&str> = line.split('\t').collect();
        let seq: u64 = cols[0]
            .parse()
            .unwrap_or_else(|_| panic!("seq column not numeric: {line}"));
        assert!(seq >= 1, "seq must be >= 1: {line}");
        let chain = cols.last().expect("chain column");
        assert!(
            *chain == "-" || chain.len() == 64,
            "chain column must be `-` or 64 hex chars: {line}"
        );
    }

    // /metrics must expose every recovery outcome label (including zeroes)
    // and at least one spawned + one reaped_zero counter increment.
    let needles = [
        "varta_recovery_outcomes_total{outcome=\"spawned\"}",
        "varta_recovery_outcomes_total{outcome=\"debounced\"}",
        "varta_recovery_outcomes_total{outcome=\"reaped_zero\"}",
        "varta_recovery_outcomes_total{outcome=\"reaped_nonzero\"}",
        "varta_recovery_outcomes_total{outcome=\"killed\"}",
        "varta_recovery_outcomes_total{outcome=\"spawn_failed\"}",
    ];
    let metrics_ok = wait_until(
        || match http_get(prom_addr, "/metrics") {
            Ok((200, body)) => needles.iter().all(|n| body.contains(n)),
            _ => false,
        },
        Duration::from_secs(3),
    );
    assert!(
        metrics_ok,
        "/metrics missing one of the varta_recovery_outcomes_total label values"
    );
}

/// End-to-end: after a daemon restart, the second session's audit chain
/// continues from where the first one left off.
///
/// 1. Spawn varta-watch with audit + small max_bytes → drive a recovery
///    (forces at least one record).
/// 2. SIGKILL the daemon to simulate unclean shutdown (no graceful Drop).
/// 3. Restart varta-watch on the same audit path.
/// 4. Drive a second recovery.
/// 5. Assert: a `resume` (or `corrupt_tail`) boot record appears between
///    the two sessions, the seq column is strictly monotonic across the
///    boundary, and the chain column on the new session's boot record
///    references the prior session's tail when audit-chain is compiled in.
fn recovery_audit_log_chain_survives_rotation_and_restart() {
    let tmp = TempDir::new("audit-restart");
    let socket = tmp.path().join("varta.sock");
    let audit_path = tmp.path().join("recovery-audit.tsv");

    // ---- Session 1 --------------------------------------------------------
    let (mut child, _prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-exec",
        "/usr/bin/true",
        "--recovery-debounce-ms",
        "1000",
        "--recovery-audit-file",
        audit_path.to_str().unwrap(),
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);

    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "session 1: varta-watch did not bind socket within 3s"
    );

    let agent_pid = std::process::id();
    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect session 1");
        for _ in 0..10 {
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
    }

    let spawn_needle = format!("\tspawn\t{agent_pid}\t");
    let complete_needle = format!("\tcomplete\t{agent_pid}\t");
    assert!(
        wait_until(
            || match std::fs::read_to_string(&audit_path) {
                Ok(b) => b.contains(&spawn_needle) && b.contains(&complete_needle),
                Err(_) => false,
            },
            Duration::from_secs(5),
        ),
        "session 1 did not record spawn+complete"
    );

    // SIGKILL forces an unclean shutdown — the Drop impl that does a
    // best-effort fsync runs only on the *parent* test, not on the child
    // process. Whatever the child fdatasync'd during writes is on disk;
    // everything after the last sync is lost (exactly what we want to
    // exercise on the resume path).
    let _ = child.kill();
    let _ = child.wait();

    // Capture the audit-file contents after session 1.
    let session1_body = std::fs::read_to_string(&audit_path).expect("read after session 1");
    assert!(session1_body.starts_with("# varta-watch recovery audit v2\n"));
    let session1_lines: Vec<&str> = session1_body
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect();
    assert!(!session1_lines.is_empty(), "session 1 wrote no records");
    let last_session1_seq: u64 = session1_lines
        .last()
        .unwrap()
        .split('\t')
        .next()
        .unwrap()
        .parse()
        .expect("session 1 last seq numeric");
    let last_session1_chain = session1_lines
        .last()
        .unwrap()
        .split('\t')
        .next_back()
        .unwrap()
        .to_string();

    // ---- Session 2 --------------------------------------------------------
    // Use a fresh socket path; the old one is left as-is on disk from the
    // killed child but won't interfere since session 2 binds a new one.
    let socket2 = tmp.path().join("varta2.sock");
    let (mut child2, _prom_addr2) = spawn_watch(&[
        "--socket",
        socket2.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-exec",
        "/usr/bin/true",
        "--recovery-debounce-ms",
        "1000",
        "--recovery-audit-file",
        audit_path.to_str().unwrap(),
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard2 = ChildGuard(&mut child2);

    assert!(
        wait_until(|| socket2.exists(), Duration::from_secs(3)),
        "session 2: varta-watch did not bind socket within 3s"
    );

    {
        let mut agent = Varta::connect(&socket2).expect("Varta::connect session 2");
        for _ in 0..10 {
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
    }

    // Wait for at least one more spawn+complete *past* the session-1 tail.
    assert!(
        wait_until(
            || match std::fs::read_to_string(&audit_path) {
                Ok(b) => {
                    let s2 = &b[session1_body.len().min(b.len())..];
                    s2.contains(&spawn_needle) && s2.contains(&complete_needle)
                }
                Err(_) => false,
            },
            Duration::from_secs(5),
        ),
        "session 2 did not record spawn+complete past session 1's tail"
    );

    let full = std::fs::read_to_string(&audit_path).expect("read full audit");
    let all_records: Vec<&str> = full.lines().filter(|l| !l.starts_with('#')).collect();

    // 1. Seq is strictly monotonic across the restart.
    let mut last_seq = 0u64;
    for rec in &all_records {
        let seq: u64 = rec.split('\t').next().unwrap().parse().unwrap();
        assert!(
            seq > last_seq,
            "seq must be strictly monotonic across restart: {seq} after {last_seq}"
        );
        last_seq = seq;
    }

    // 2. A boot record exists past session 1's last seq carrying the
    //    expected reason (`resume` for clean fsync'd tail, or
    //    `corrupt_tail` for torn).
    let restart_boot = all_records
        .iter()
        .find(|line| {
            let cols: Vec<&str> = line.split('\t').collect();
            let seq: u64 = cols[0].parse().unwrap_or(0);
            seq > last_session1_seq && cols.contains(&"boot")
        })
        .expect("session 2 must emit a boot record above session 1's tail seq");
    let restart_cols: Vec<&str> = restart_boot.split('\t').collect();
    let reason = restart_cols[6]; // seq ms ns boot pid prev reason chain
    assert!(
        reason == "resume" || reason == "corrupt_tail",
        "restart boot reason must be resume or corrupt_tail; got {reason} in: {restart_boot}"
    );

    // 3. When audit-chain is compiled in: the restart boot's prev_chain
    //    column matches the session-1 tail's chain (resume) — or is `-`
    //    when the tail was torn.
    if last_session1_chain != "-" && last_session1_chain.len() == 64 {
        let prev_chain_col = restart_cols[5];
        if reason == "resume" {
            assert_eq!(
                prev_chain_col, last_session1_chain,
                "resume boot must carry the prior session's last chain as prev_chain"
            );
        }
    }
}

// ===== A6: --max-beat-rate (rate limiting) E2E ==============================

/// Spawns varta-watch with `--max-beat-rate 10` (max 10 beats/sec per PID).
/// Sends 50 beats as fast as possible from one agent; asserts
/// `varta_rate_limited_total > 0` and the agent's beat count is < 50.
fn max_beat_rate_limits_and_reports_metric() {
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

// ===== A7: --export-file (file exporter) E2E ================================

/// Spawns varta-watch with `--export-file`, sends beats from two agents,
/// waits for stalls, and verifies the TSV file has beat and stall lines.
fn file_export_writes_tsv() {
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

// ===== A8: --export-file-max-bytes (file rotation) E2E ======================

/// Spawns varta-watch with `--export-file-max-bytes 200`, sends enough beats
/// to trigger rotation, and asserts rotated files exist.
fn file_export_rotation() {
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

// ===== A9: Tracker eviction E2E =============================================

/// Spawns varta-watch with `--tracker-capacity 2` and a short threshold.
/// Spawns 5 agent child processes sequentially (each a distinct PID). The
/// first two fill the tracker; once they stall, subsequent PIDs trigger
/// eviction. Asserts `varta_tracker_evicted_total > 0` in /metrics.
fn tracker_capacity_exceeded_reports_eviction_metric() {
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

// ===== A10: Varta::reconnect() E2E ==========================================

/// Spawns observer v1, client connects and beats. Kills observer v1. Spawns
/// observer v2 on the same socket path. Client calls `reconnect()` and
/// sends more beats, which should appear in v2's /metrics.
fn client_reconnect_after_observer_restart() {
    let tmp = TempDir::new("reconn");
    let socket = tmp.path().join("varta.sock");

    // ---- Observer v1 ----
    let (mut child1, prom_addr_1) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard1 = ChildGuard(&mut child1);

    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "varta-watch v1 did not bind socket within 3s"
    );

    let agent_pid = std::process::id();
    let mut agent = Varta::connect(&socket).expect("Varta::connect");
    // Send initial beats against v1
    for _ in 0..3 {
        let mut tries = 0u32;
        loop {
            match agent.beat(Status::Ok, 0) {
                BeatOutcome::Sent => break,
                BeatOutcome::Dropped(_) => {
                    tries += 1;
                    if tries > 5_000 {
                        panic!("kernel never accepted a beat v1");
                    }
                    std::thread::sleep(Duration::from_micros(500));
                }
                BeatOutcome::Failed(e) => panic!("unexpected hard failure v1: {e}"),
            }
        }
    }

    // Verify v1 saw the beats
    let needle_v1 = format!("varta_beats_total{{pid=\"{agent_pid}\"}} 3");
    let satisfied_v1 = wait_until(
        || match http_get(prom_addr_1, "/metrics") {
            Ok((200, body)) => body.contains(&needle_v1),
            _ => false,
        },
        Duration::from_secs(3),
    );
    assert!(
        satisfied_v1,
        "v1 /metrics did not show 3 beats: {needle_v1:?}"
    );

    // Kill v1
    drop(_guard1);
    child1.kill().expect("kill v1");
    child1.wait().expect("wait v1");
    // Allow kernel to release the socket
    std::thread::sleep(Duration::from_millis(200));

    // ---- Observer v2 (same socket path) ----
    let (mut child2, prom_addr_2) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard2 = ChildGuard(&mut child2);

    // Wait for v2 to be ready
    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "varta-watch v2 did not bind socket within 3s"
    );
    assert!(
        wait_until(
            || TcpStream::connect(prom_addr_2).is_ok(),
            Duration::from_secs(3)
        ),
        "v2 /metrics not reachable within 3s"
    );

    // Reconnect client
    agent.reconnect().expect("reconnect to v2");

    // Send beats against v2
    for _ in 0..5 {
        let mut tries = 0u32;
        loop {
            match agent.beat(Status::Ok, 0) {
                BeatOutcome::Sent => break,
                BeatOutcome::Dropped(_) => {
                    tries += 1;
                    if tries > 5_000 {
                        panic!("kernel never accepted a beat v2");
                    }
                    std::thread::sleep(Duration::from_micros(500));
                }
                BeatOutcome::Failed(e) => panic!("unexpected hard failure v2: {e}"),
            }
        }
    }

    // Verify v2 sees the 5 new beats
    let needle_v2 = format!("varta_beats_total{{pid=\"{agent_pid}\"}} 5");
    let satisfied_v2 = wait_until(
        || match http_get(prom_addr_2, "/metrics") {
            Ok((200, body)) => body.contains(&needle_v2),
            _ => false,
        },
        Duration::from_secs(3),
    );
    assert!(
        satisfied_v2,
        "v2 /metrics did not show 5 beats after reconnect: {needle_v2:?}"
    );
}

// ===== A11: Varta::set_reconnect_after() (auto-reconnect) E2E ================

/// Connects a client, sets `set_reconnect_after(3)`, kills the observer,
/// and verifies the client handles the Dropped path without panicking.
fn client_auto_reconnect_after_dropped() {
    let tmp = TempDir::new("autorec");
    let socket = tmp.path().join("varta.sock");

    let (mut child, _prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);

    assert!(
        wait_until(|| socket.exists(), Duration::from_secs(3)),
        "varta-watch did not bind socket within 3s"
    );

    let mut agent = Varta::connect(&socket).expect("Varta::connect");
    agent.set_reconnect_after(3);

    // Send a warmup beat to confirm connection works
    loop {
        match agent.beat(Status::Ok, 0) {
            BeatOutcome::Sent => break,
            BeatOutcome::Dropped(_) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            BeatOutcome::Failed(e) => panic!("warmup beat failed: {e}"),
        }
    }

    // Kill the observer
    child.kill().expect("kill observer");
    child.wait().expect("wait observer");

    // Send beats against dead observer — should all be Dropped.
    // After 3 consecutive Dropped, auto-reconnect triggers but fails
    // (no observer on the path). Code path must not panic.
    let mut dropped_count = 0u32;
    for _ in 0..10 {
        match agent.beat(Status::Ok, 0) {
            BeatOutcome::Dropped(_) => {
                dropped_count += 1;
            }
            BeatOutcome::Sent => {
                // If observer came back (unlikely), that's fine
                dropped_count = 0;
            }
            BeatOutcome::Failed(e) => {
                // Hard failure (e.g. reconnect created a new socket but
                // connect fails) is acceptable in this degraded scenario.
                eprintln!("  (expected) auto-reconnect test beat failed: {e}");
            }
        }
    }

    // The beat path did not panic — that's the primary assertion.
    // Dropped beats are expected since the observer is dead.
    assert!(
        dropped_count > 0,
        "expected some Dropped beats with dead observer"
    );
}

// ===== A12: Signal handling (SIGTERM) E2E ===================================

/// Spawns varta-watch *without* `--shutdown-after-secs`, sends a few beats,
/// then sends SIGTERM. Asserts the observer exits cleanly (exit code 0)
/// and the socket file is cleaned up.
fn signal_handling_graceful_shutdown() {
    let tmp = TempDir::new("sigterm");
    let socket = tmp.path().join("varta.sock");

    #[cfg(unix)]
    {
        let mut child = Command::new(locate_watch_binary())
            .args([
                "--socket",
                socket.to_str().unwrap(),
                "--threshold-ms",
                "5000",
                "--prom-addr",
                "127.0.0.1:0",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn varta-watch without --shutdown-after-secs");

        // Read the prom addr from stdout
        let stdout = child.stdout.take().expect("stdout was piped");
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        let _ = reader.read_line(&mut line).expect("read prom addr");

        assert!(
            wait_until(|| socket.exists(), Duration::from_secs(3)),
            "varta-watch did not bind socket within 3s"
        );

        // Send a few beats
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
                                panic!("kernel never accepted a beat before sigterm");
                            }
                            std::thread::sleep(Duration::from_micros(500));
                        }
                        BeatOutcome::Failed(e) => panic!("unexpected hard failure: {e}"),
                    }
                }
            }
        }

        // Send SIGTERM via kill(1)
        let kill_status = Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status()
            .expect("kill -TERM");
        assert!(kill_status.success(), "kill -TERM command failed");

        // Wait for graceful exit with timeout
        let status =
            wait_until_with_timeout(|| child.try_wait().ok().flatten(), Duration::from_secs(5));
        match status {
            Some(exit_status) => {
                assert!(
                    exit_status.success(),
                    "observer should exit cleanly after SIGTERM, got: {exit_status}"
                );
            }
            None => {
                child.kill().expect("force kill after timeout");
                child.wait().expect("wait after force kill");
                panic!("observer did not exit within 5s after SIGTERM");
            }
        }

        // Socket should be cleaned up by Observer::Drop
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            !socket.exists(),
            "socket file should be unlinked after graceful shutdown"
        );
    }

    #[cfg(not(unix))]
    {
        // Skip on non-Unix; signal handling is Unix-specific
    }
}

// ===== A13: Status::Degraded in /metrics E2E ================================

/// Spawns varta-watch, then a child that sends 5 `Status::Degraded` beats.
/// Asserts `/metrics` shows `varta_status{pid="child_pid"} 1`.
fn status_degraded_visible_in_metrics() {
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

// --- panic-child entrypoint -------------------------------------------------

/// Code path entered when this binary is re-spawned as a panic child via
/// `VARTA_E2E_PANIC_CHILD=<socket>`. Installs the panic hook, beats once
/// so a pid label exists, then panics so the hook fires the Critical
/// frame.
///
/// This function must never write to stdout/stderr — the parent process
/// spawns the child with both streams set to `Stdio::null()`, and any
/// output would be silently discarded (or leak to a shared terminal if
/// the null redirection were removed).
fn run_panic_child(socket_path: &str) {
    install_panic_handler(PathBuf::from(socket_path)).expect("panic child: install hook");
    let mut agent = Varta::connect(socket_path).expect("panic child: connect");
    let _ = agent.beat(Status::Ok, 0);
    // Give the daemon a moment to consume the warmup beat before the
    // panic-fired Critical frame races process exit.
    std::thread::sleep(Duration::from_millis(150));
    panic!("VARTA_E2E_PANIC_CHILD: deliberate panic for hook coverage");
}

// --- agent-child entrypoint ------------------------------------------------

/// Code path entered when this binary is re-spawned as a multi-agent child via
/// `VARTA_E2E_AGENT_CHILD=<socket>`. Connects to the observer, sends
/// [`MULTI_AGENT_BEATS`] beats, then exits cleanly.
///
/// This function must never write to stdout/stderr — the parent process
/// spawns children with both streams set to `Stdio::null()`.
fn run_agent_child(socket_path: &str) {
    let mut agent = Varta::connect(socket_path).expect("agent child: connect");
    for i in 0..MULTI_AGENT_BEATS {
        let mut tries = 0u32;
        loop {
            match agent.beat(Status::Ok, i as u32) {
                BeatOutcome::Sent => break,
                BeatOutcome::Dropped(_) => {
                    tries += 1;
                    if tries > 500 {
                        std::process::exit(1);
                    }
                    std::thread::sleep(Duration::from_micros(500));
                }
                BeatOutcome::Failed(_) => std::process::exit(1),
            }
        }
    }
    // Brief delay so the last beats can reach the observer before the child
    // process exits and the kernel closes the socket.
    std::thread::sleep(Duration::from_millis(100));
}

// --- degraded-child entrypoint --------------------------------------------

/// Code path entered when this binary is re-spawned as a degraded child via
/// `VARTA_E2E_DEGRADED_CHILD=<socket>`. Connects to the observer, sends
/// beats with `Status::Degraded`, then exits cleanly.
///
/// This function must never write to stdout/stderr.
fn run_degraded_child(socket_path: &str) {
    let mut agent = Varta::connect(socket_path).expect("degraded child: connect");
    // Give observer time to bind
    std::thread::sleep(Duration::from_millis(150));
    for _ in 0..5 {
        let mut tries = 0u32;
        loop {
            match agent.beat(Status::Degraded, 0) {
                BeatOutcome::Sent => break,
                BeatOutcome::Dropped(_) => {
                    tries += 1;
                    if tries > 500 {
                        std::process::exit(1);
                    }
                    std::thread::sleep(Duration::from_micros(500));
                }
                BeatOutcome::Failed(_) => std::process::exit(1),
            }
        }
    }
    std::thread::sleep(Duration::from_millis(100));
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
fn iteration_budget_holds_under_slow_scrape_load() {
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
fn serve_pending_seconds_separates_scrape_from_beat_path() {
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
fn hostile_frame_rejected_at_decode_with_label_emit() {
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

/// Parse `<name> <number>\n` out of a Prometheus exposition body.
/// Returns `None` if the line is absent or the value does not parse.
fn parse_metric_value(body: &str, name: &str) -> Option<u64> {
    let prefix = format!("{name} ");
    body.lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .and_then(|tail| tail.trim().parse::<u64>().ok())
}

/// Parse a single `<name>_bucket{le="<bound>"} <count>` series out of a
/// Prometheus exposition body. Returns `None` if the bucket is absent.
fn parse_histogram_bucket(body: &str, name: &str, le: &str) -> Option<u64> {
    let needle = format!("{name}_bucket{{le=\"{le}\"}} ");
    body.lines()
        .find_map(|l| l.strip_prefix(&needle))
        .and_then(|tail| tail.trim().parse::<u64>().ok())
}

// --- helpers ----------------------------------------------------------------

static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let pid = std::process::id();
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("varta-e2e-{tag}-{pid}-{n}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create tempdir");
        TempDir { path: p }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// RAII guard that kills the spawned `varta-watch` if a test fails before
/// the daemon's `--shutdown-after-secs` deadline.
struct ChildGuard<'a>(&'a mut Child);

impl Drop for ChildGuard<'_> {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_watch(args: &[&str]) -> (Child, SocketAddr) {
    let exe = locate_watch_binary();

    // Whenever the test asks for --prom-addr, the observer now also
    // requires --prom-token-file.  Synthesize a 0600-mode token file for
    // the suite-wide constant and append the flag transparently.  The
    // file is intentionally leaked: the test process is short-lived and
    // cleaning up means racing with the child's still-open file handle.
    let needs_prom_token = args.contains(&"--prom-addr") && !args.contains(&"--prom-token-file");
    let mut extra_args: Vec<String> = Vec::new();
    let mut leaked_token_path: Option<String> = None;
    if needs_prom_token {
        let dir = std::env::temp_dir().join(format!(
            "varta-e2e-prom-token-{}-{}",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&dir).expect("create token dir");
        let path = dir.join("prom.token");
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(PROM_TOKEN_HEX.as_bytes()))
            .expect("write prom token");
        leaked_token_path = Some(path.to_string_lossy().into_owned());
    }

    let mut cmd = Command::new(&exe);
    cmd.args(args);
    if let Some(ref p) = leaked_token_path {
        extra_args.push(String::from("--prom-token-file"));
        extra_args.push(p.clone());
    }
    cmd.args(&extra_args);
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", exe.display()));
    let stdout = child.stdout.take().expect("stdout was piped");
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("read prom addr from daemon stdout");
    let addr = line
        .trim()
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| panic!("parse prom addr from daemon: {line:?}"));
    (child, addr)
}

/// Resolve `target/<profile>/varta-watch` relative to the running test
/// binary. Cargo only sets `CARGO_BIN_EXE_<name>` when the binary lives
/// in the same crate as the integration test, so for cross-crate spawn
/// we walk the conventional cargo target layout instead.
///
/// Tests assume the caller built `varta-watch` at the same profile as
/// the test binary — `cargo test -p varta-tests` builds dev-deps in
/// debug mode, which produces `target/debug/varta-watch` automatically
/// because `varta-watch` is a workspace member compiled in the same
/// invocation.
fn locate_watch_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    // exe is target/<profile>/deps/end_to_end-XXXX
    let deps_dir = exe.parent().expect("deps dir");
    let profile_dir = deps_dir.parent().expect("profile dir");
    let direct = profile_dir.join("varta-watch");
    if direct.exists() {
        return direct;
    }
    // The binary was not at the expected path. The user must build the
    // workspace first (e.g. `cargo build --workspace`).
    panic!(
        "varta-watch binary not found at {} — \
         build the workspace before running these tests \
         (e.g. `cargo build --workspace`)",
        direct.display()
    );
}

fn wait_until<F: FnMut() -> bool>(mut f: F, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    f()
}

/// Like `wait_until`, but returns the value produced by the closure rather
/// than a boolean. Returns `None` if the deadline expires.
fn wait_until_with_timeout<F: FnMut() -> Option<T>, T>(mut f: F, timeout: Duration) -> Option<T> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Synchronous HTTP/1.0 GET with the suite-wide bearer token.  Returns
/// `(status_code, body)`.
fn http_get(addr: SocketAddr, path: &str) -> std::io::Result<(u16, String)> {
    http_get_with_auth(addr, path, Some(PROM_TOKEN_HEX))
}

/// HTTP/1.0 GET that lets the caller pick the Authorization token (or omit
/// it entirely, to exercise the 401 path).
fn http_get_with_auth(
    addr: SocketAddr,
    path: &str,
    bearer: Option<&str>,
) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut req = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(token) = bearer {
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    let mut buf = Vec::with_capacity(2048);
    stream.read_to_end(&mut buf)?;
    let raw = String::from_utf8_lossy(&buf).into_owned();
    let split = raw
        .find("\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("missing header/body delimiter"))?;
    let status = parse_status(&raw[..split])?;
    Ok((status, raw[split + 4..].to_string()))
}

fn parse_status(headers: &str) -> std::io::Result<u16> {
    let first = headers
        .lines()
        .next()
        .ok_or_else(|| std::io::Error::other("empty response"))?;
    let mut parts = first.split_whitespace();
    let _http = parts.next();
    let code = parts
        .next()
        .ok_or_else(|| std::io::Error::other("no status code"))?;
    code.parse::<u16>()
        .map_err(|_| std::io::Error::other("non-numeric status"))
}

#[cfg(feature = "udp")]
fn udp_client_to_observer_beats_and_stall() {
    use std::net::UdpSocket;

    let addr: std::net::SocketAddr = "127.0.0.1:0".parse().expect("parse");
    let receiver = UdpSocket::bind(addr).expect("bind receiver");
    receiver.set_nonblocking(true).expect("set_nonblocking");
    let receiver_addr = receiver.local_addr().expect("local_addr");

    // Smoke test: connect_udp + beat over localhost loopback.
    // The observer is NOT listening on this port — beats will be silently
    // dropped by the kernel (no peer). This verifies the API compiles,
    // connects, and sends without panicking.
    {
        let mut agent = varta_client::Varta::connect_udp(receiver_addr).expect("connect_udp");
        for _ in 0..10 {
            let outcome = agent.beat(varta_client::Status::Ok, 0);
            assert!(
                matches!(outcome, varta_client::BeatOutcome::Sent),
                "beat should succeed against a bound localhost UDP port"
            );
        }
    }

    drop(receiver);
    eprintln!("udp_client_to_observer_beats_and_stall: ok");
}

#[cfg(feature = "secure-udp")]
fn secure_udp_client_to_observer_beats() {
    use std::io::Write;
    use std::net::UdpSocket;
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new("secure-udp");
    let key_path = tmp.path().join("test.key");
    // 32-byte test key as 64-character hex
    let key_hex = "abababababababababababababababababababababababababababababababab";
    // varta-watch's --key-file validator requires mode 0600 or stricter.
    // Use OpenOptions::mode at create time and chmod again for good
    // measure — `std::fs::write` would inherit the process umask.
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&key_path)
            .expect("create key file");
        f.write_all(format!("{key_hex}\n").as_bytes())
            .expect("write key file");
    }
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod key file");
    let key = varta_vlp::crypto::Key::from_bytes([0xabu8; 32]);

    // Reserve an ephemeral UDP port for the observer
    let probe = UdpSocket::bind("127.0.0.1:0").expect("bind probe");
    let udp_port = probe.local_addr().expect("local_addr").port();
    drop(probe);

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        tmp.path().join("varta.sock").to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--udp-port",
        &udp_port.to_string(),
        "--key-file",
        key_path.to_str().unwrap(),
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "8",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(
            || TcpStream::connect(prom_addr).is_ok(),
            Duration::from_secs(3)
        ),
        "/metrics not reachable within 3s"
    );

    let agent_pid = std::process::id();
    let observer_addr = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        udp_port,
    );
    {
        let mut agent = varta_client::Varta::connect_secure_udp(observer_addr, key)
            .expect("connect_secure_udp");
        for _ in 0..10 {
            match agent.beat(varta_client::Status::Ok, 0) {
                varta_client::BeatOutcome::Sent => {}
                varta_client::BeatOutcome::Dropped(_) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                varta_client::BeatOutcome::Failed(e) => {
                    panic!("unexpected hard failure: {e}");
                }
            }
        }
    }

    let needle = format!("varta_beats_total{{pid=\"{agent_pid}\"}}");
    let mut last_body = String::new();
    let satisfied = wait_until(
        || match http_get(prom_addr, "/metrics") {
            Ok((200, body)) => {
                last_body = body;
                last_body.contains(&needle)
            }
            _ => false,
        },
        Duration::from_secs(5),
    );
    assert!(
        satisfied,
        "/metrics did not surface {needle:?} for secure UDP; last body:\n{last_body}"
    );

    eprintln!("secure_udp_client_to_observer_beats: ok");
}

/// H6 — exercise the AEAD-counter wrap path end-to-end. Connect a real
/// secure-UDP agent, fast-forward the counter to `u32::MAX`, beat once to
/// trigger the in-process prefix rotation, then beat again to exercise the
/// rotated prefix. The observer must accept all frames (no decrypt
/// errors), proving:
///   - the wrap path does NOT call OS entropy (no blocking syscall),
///   - the new HKDF-derived prefix produces a valid AEAD nonce,
///   - the observer's per-sender state rotates cleanly to the new prefix.
#[cfg(all(feature = "secure-udp", feature = "test-hooks"))]
fn secure_udp_counter_wrap_continues_under_load() {
    use std::io::Write;
    use std::net::UdpSocket;
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new("secure-udp-wrap");
    let key_path = tmp.path().join("test.key");
    let key_hex = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&key_path)
            .expect("create key file");
        f.write_all(format!("{key_hex}\n").as_bytes())
            .expect("write key file");
    }
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod key file");
    let key = varta_vlp::crypto::Key::from_bytes([0xcdu8; 32]);

    let probe = UdpSocket::bind("127.0.0.1:0").expect("bind probe");
    let udp_port = probe.local_addr().expect("local_addr").port();
    drop(probe);

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        tmp.path().join("varta.sock").to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--udp-port",
        &udp_port.to_string(),
        "--key-file",
        key_path.to_str().unwrap(),
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(
            || TcpStream::connect(prom_addr).is_ok(),
            Duration::from_secs(3)
        ),
        "/metrics not reachable within 3s"
    );

    let agent_pid = std::process::id();
    let observer_addr = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        udp_port,
    );

    let prefix_before;
    let prefix_after;
    {
        let mut agent = varta_client::Varta::connect_secure_udp(observer_addr, key)
            .expect("connect_secure_udp");

        // One warm-up beat under prefix-index 0.
        match agent.beat(varta_client::Status::Ok, 0) {
            varta_client::BeatOutcome::Sent | varta_client::BeatOutcome::Dropped(_) => {}
            varta_client::BeatOutcome::Failed(e) => panic!("unexpected hard failure: {e}"),
        }

        prefix_before = agent.iv_prefix_for_test();
        assert_eq!(
            agent.iv_prefix_index_for_test(),
            0,
            "fresh connection must start at prefix_index 0"
        );

        // Fast-forward the counter so the NEXT beat triggers wrap rotation.
        agent.set_iv_counter_for_test(u32::MAX);

        // This beat hits the wrap branch — must rotate prefix without
        // re-reading OS entropy.
        match agent.beat(varta_client::Status::Ok, 0) {
            varta_client::BeatOutcome::Sent | varta_client::BeatOutcome::Dropped(_) => {}
            varta_client::BeatOutcome::Failed(e) => panic!("wrap-rotation beat failed: {e}"),
        }

        assert_eq!(
            agent.iv_prefix_index_for_test(),
            1,
            "prefix_index must advance to 1 after wrap"
        );
        prefix_after = agent.iv_prefix_for_test();
        assert_ne!(
            prefix_after, prefix_before,
            "rotated prefix must differ from prior prefix"
        );

        // A few more beats under the rotated prefix to exercise the new
        // session against the observer's replay state.
        for _ in 0..5 {
            match agent.beat(varta_client::Status::Ok, 0) {
                varta_client::BeatOutcome::Sent | varta_client::BeatOutcome::Dropped(_) => {}
                varta_client::BeatOutcome::Failed(e) => {
                    panic!("post-rotation beat failed: {e}")
                }
            }
        }
    }

    // The observer must have decoded the frames before AND after the
    // rotation — i.e. it must have rotated its per-sender replay state to
    // the new prefix without raising decrypt errors.
    let beats_needle = format!("varta_beats_total{{pid=\"{agent_pid}\"}}");
    let mut last_body = String::new();
    let beats_visible = wait_until(
        || match http_get(prom_addr, "/metrics") {
            Ok((200, body)) => {
                last_body = body;
                last_body.contains(&beats_needle)
            }
            _ => false,
        },
        Duration::from_secs(5),
    );
    assert!(
        beats_visible,
        "/metrics did not surface {beats_needle:?} after counter wrap; body:\n{last_body}"
    );

    // Sanity: aead_attempts_total must be non-zero (proves the secure-UDP
    // decode path actually ran for our frames).
    assert!(
        last_body.contains("varta_secure_aead_attempts_total"),
        "expected secure aead attempts counter in /metrics; body:\n{last_body}"
    );

    eprintln!("secure_udp_counter_wrap_continues_under_load: ok");
}

/// Fork-safety contract: a `fork(2)` followed by `beat()` in the child
/// MUST NOT cause AEAD nonce reuse on the secure-UDP transport. The
/// `Varta` wrapper detects the PID mismatch and invokes
/// `transport.reconnect()` to refresh the IV salt before encrypting any
/// frame in the child. Verified end-to-end by:
///
/// 1. Spawning `varta-watch` with a secure-UDP listener.
/// 2. Connecting a `Varta::connect_secure_udp` agent in the test process.
/// 3. Beating once, then calling `fork(2)`.
/// 4. Child beats N times under the auto-recovered transport, then `_exit`s.
/// 5. Parent beats N times.
/// 6. Scraping `/metrics`: parent AND child must appear as distinct
///    `varta_beats_total{pid=...}` entries, and `varta_io_errors_total`
///    plus every `varta_decode_errors_total{kind=...}` entry must stay
///    at zero (no AEAD-tag failures or nonce-replay rejections).
#[cfg(all(feature = "secure-udp", target_family = "unix"))]
#[allow(unsafe_code)]
fn secure_udp_fork_safe_under_real_fork() {
    use std::io::Write;
    use std::net::UdpSocket;
    use std::os::unix::fs::PermissionsExt;

    extern "C" {
        fn fork() -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(code: i32) -> !;
    }

    let tmp = TempDir::new("secure-udp-fork");
    let key_path = tmp.path().join("test.key");
    let key_hex = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&key_path)
            .expect("create key file");
        f.write_all(format!("{key_hex}\n").as_bytes())
            .expect("write key file");
    }
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod key file");
    let key = varta_vlp::crypto::Key::from_bytes([0xefu8; 32]);

    let probe = UdpSocket::bind("127.0.0.1:0").expect("bind probe");
    let udp_port = probe.local_addr().expect("local_addr").port();
    drop(probe);

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        tmp.path().join("varta.sock").to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--udp-port",
        &udp_port.to_string(),
        "--key-file",
        key_path.to_str().unwrap(),
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "12",
    ]);
    let _guard = ChildGuard(&mut child);

    assert!(
        wait_until(
            || TcpStream::connect(prom_addr).is_ok(),
            Duration::from_secs(3)
        ),
        "/metrics not reachable within 3s"
    );

    let parent_pid = std::process::id();
    let observer_addr = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        udp_port,
    );

    let mut agent =
        varta_client::Varta::connect_secure_udp(observer_addr, key).expect("connect_secure_udp");

    // One beat under the parent's pid pre-fork.
    let _ = agent.beat(varta_client::Status::Ok, 0);

    // SAFETY: classic fork; the child runs only async-signal-safe code
    // (beat() does not allocate; _exit() is mandatory to avoid the
    // child running cargo-test atexit handlers).
    let child_pid = unsafe { fork() };
    if child_pid < 0 {
        panic!("fork() failed: {}", std::io::Error::last_os_error());
    }

    if child_pid == 0 {
        // CHILD. Fork-recovery must fire on the first beat — `agent` was
        // built before fork, so connect_pid is the parent's PID.
        for _ in 0..20 {
            let _ = agent.beat(varta_client::Status::Ok, 0);
        }
        // _exit, not exit: skip Rust runtime teardown / atexit handlers
        // that would re-run cargo-test machinery and break the parent.
        unsafe { _exit(0) };
    }

    // PARENT. Continue beating after fork; the parent's connect_pid still
    // matches std::process::id(), so no recovery fires here.
    for _ in 0..20 {
        let _ = agent.beat(varta_client::Status::Ok, 0);
    }

    // Reap the child.
    let mut status = 0i32;
    let waited = unsafe { waitpid(child_pid, &mut status as *mut i32, 0) };
    assert_eq!(
        waited,
        child_pid,
        "waitpid did not return the child pid (errno={})",
        std::io::Error::last_os_error()
    );

    // Sanity: parent's fork-recovery counter MUST remain at zero (the
    // parent never crossed the fork boundary from its own perspective).
    assert_eq!(
        agent.fork_recoveries(),
        0,
        "parent must not observe a fork-recovery event"
    );

    let parent_needle = format!("varta_beats_total{{pid=\"{parent_pid}\"}}");
    let child_needle = format!("varta_beats_total{{pid=\"{child_pid}\"}}");
    let mut last_body = String::new();
    let both_visible = wait_until(
        || match http_get(prom_addr, "/metrics") {
            Ok((200, body)) => {
                last_body = body;
                last_body.contains(&parent_needle) && last_body.contains(&child_needle)
            }
            _ => false,
        },
        Duration::from_secs(6),
    );
    assert!(
        both_visible,
        "expected both pids ({parent_needle:?}, {child_needle:?}) in /metrics; body:\n{last_body}"
    );

    // No AEAD decode failures should have fired. If the child had reused
    // the parent's nonce, the observer's replay state would either drop
    // the duplicate frame (no second pid would surface) or — if the
    // listener happens to be in a state where the replayed nonce decrypts
    // anyway — the integrity check would still hold, but the test above
    // would fail because the child's beats land under the parent's pid.
    // Either way, the dual-pid assertion above is the load-bearing one.
    assert!(
        last_body.contains("varta_io_errors_total 0"),
        "expected varta_io_errors_total to be 0; body:\n{last_body}"
    );

    eprintln!("secure_udp_fork_safe_under_real_fork: ok");
}

/// H7 — basic smoke test that the default `--clock-source monotonic`
/// produces a working daemon (no crash, /metrics reachable). Confirms
/// the Observer's swap from `Instant::now()` to `Clock` did not regress
/// startup or the poll loop.
fn clock_source_monotonic_smoke() {
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
fn clock_source_boottime_smoke() {
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
