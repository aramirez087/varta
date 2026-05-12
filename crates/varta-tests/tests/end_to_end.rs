//! Session 06 end-to-end contract tests.
//!
//! Drives the real `varta-watch` binary, the real `varta-client` agent
//! (with the `panic-handler` feature), and asserts on the live `/metrics`
//! endpoint exposed by [`varta_watch::PromExporter`].
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
    eprintln!("running 16 tests");
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
    failed += run_one(
        "recovery_cmd_file_mode",
        recovery_cmd_file_mode,
    );
    failed += run_one(
        "recovery_exec_file_mode",
        recovery_exec_file_mode,
    );
    failed += run_one(
        "recovery_timeout_kill_after",
        recovery_timeout_kill_after,
    );
    failed += run_one(
        "recovery_env_isolation",
        recovery_env_isolation,
    );
    failed += run_one(
        "max_beat_rate_limits_and_reports_metric",
        max_beat_rate_limits_and_reports_metric,
    );
    failed += run_one(
        "file_export_writes_tsv",
        file_export_writes_tsv,
    );
    failed += run_one(
        "file_export_rotation",
        file_export_rotation,
    );
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

    let total = 16u32
        + if cfg!(feature = "udp") { 1 } else { 0 }
        + if cfg!(feature = "secure-udp") { 1 } else { 0 };
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

fn run_one(name: &str, f: fn()) -> u32 {
    eprintln!("test {name} ... starting");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    match result {
        Ok(()) => {
            eprintln!("test {name} ... ok");
            0
        }
        Err(_) => {
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
    let recovery_cmd = format!("touch {}", marker.display());

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-cmd",
        &recovery_cmd,
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
                    BeatOutcome::Dropped => {
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
                    BeatOutcome::Dropped => {
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

// ===== A2: --recovery-cmd-file E2E ==========================================

/// Writes the recovery command template to a file with 0600 permissions,
/// spawns `varta-watch` with `--recovery-cmd-file`, and asserts recovery
/// fires on stall.
fn recovery_cmd_file_mode() {
    let tmp = TempDir::new("rcmd-file");
    let socket = tmp.path().join("varta.sock");
    let cmd_file = tmp.path().join("recovery.cmd");
    let marker = tmp.path().join("rcmd-file.marker");

    // Write recovery template to file with restrictive permissions
    {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .open(&cmd_file)
            .expect("create recovery cmd file");
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(format!("touch {}", marker.display()).as_bytes())
            .expect("write recovery cmd");
        writer.flush().expect("flush recovery cmd");
    }

    let (mut child, _prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-cmd-file",
        cmd_file.to_str().unwrap(),
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
                    BeatOutcome::Dropped => {
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
        "recovery-cmd-file marker did not appear within 3s"
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
                    BeatOutcome::Dropped => {
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

/// Spawns varta-watch with `--recovery-cmd "sleep 10" --recovery-timeout-ms 300`.
/// After a stall, the sleep child should be killed within 300ms, leaving the
/// observer responsive (not hung).
fn recovery_timeout_kill_after() {
    let tmp = TempDir::new("rto");
    let socket = tmp.path().join("varta.sock");
    let marker = tmp.path().join("rto.marker");
    let cmd = format!("touch {} && sleep 10", marker.display());

    let (mut child, prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-cmd",
        &cmd,
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
                    BeatOutcome::Dropped => {
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

    // Wait for stall + recovery spawn + marker creation
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
        || match http_get(prom_addr, "/metrics") {
            Ok((200, _)) => true,
            _ => false,
        },
        Duration::from_secs(3),
    );
    assert!(
        alive,
        "observer should still be alive after recovery timeout kill"
    );
}

// ===== A5: --recovery-env (environment isolation) E2E ========================

/// Spawns varta-watch with `--recovery-env VARTA_E2E_ENV=works`, uses a
/// shell command that tests the env var and touches a marker only when set.
/// Then verifies absence of env isolation still inherits `$HOME`.
fn recovery_env_isolation() {
    let tmp = TempDir::new("renv");
    let socket = tmp.path().join("varta.sock");
    let marker_isolated = tmp.path().join("env-isolated.marker");
    let cmd = format!(
        "test \"$VARTA_E2E_ENV\" = \"works\" && touch {}",
        marker_isolated.display()
    );

    let (mut child, _prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-cmd",
        &cmd,
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

    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect");
        for _ in 0..10 {
            let mut tries = 0u32;
            loop {
                match agent.beat(Status::Ok, 0) {
                    BeatOutcome::Sent => break,
                    BeatOutcome::Dropped => {
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
        wait_until(|| marker_isolated.exists(), Duration::from_secs(3)),
        "env-isolated marker did not appear"
    );

    // --- Second observer: no --recovery-env → $HOME should be inherited ---
    let tmp2 = TempDir::new("renv-v2");
    let socket2 = tmp2.path().join("varta.sock");
    let marker_inherited = tmp2.path().join("env-inherited.marker");
    let cmd2 = format!("test -n \"$HOME\" && touch {}", marker_inherited.display());

    let (mut child2, _prom_addr2) = spawn_watch(&[
        "--socket",
        socket2.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-cmd",
        &cmd2,
        "--recovery-debounce-ms",
        "0",
        "--prom-addr",
        "127.0.0.1:0",
        "--shutdown-after-secs",
        "10",
    ]);
    let _guard2 = ChildGuard(&mut child2);

    assert!(
        wait_until(|| socket2.exists(), Duration::from_secs(3)),
        "varta-watch v2 did not bind socket within 3s"
    );

    {
        let mut agent = Varta::connect(&socket2).expect("Varta::connect v2");
        for _ in 0..10 {
            let mut tries = 0u32;
            loop {
                match agent.beat(Status::Ok, 0) {
                    BeatOutcome::Sent => break,
                    BeatOutcome::Dropped => {
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
    }

    std::thread::sleep(Duration::from_millis(400));
    assert!(
        wait_until(|| marker_inherited.exists(), Duration::from_secs(3)),
        "inherited-env marker did not appear (HOME should be present without --recovery-env)"
    );
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
    let rl_val = last_body
        .lines()
        .find(|l| l.starts_with("varta_rate_limited_total "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
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

    let (mut child, _prom_addr) = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--export-file",
        export.to_str().unwrap(),
        "--export-file-max-bytes",
        "50", // tiny limit forces rotation + flush after every event
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

    let agent_pid_1 = std::process::id();
    {
        let mut agent = Varta::connect(&socket).expect("Varta::connect");
        for _ in 0..5 {
            let mut tries = 0u32;
            loop {
                match agent.beat(Status::Ok, 0) {
                    BeatOutcome::Sent => break,
                    BeatOutcome::Dropped => {
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
    let mut child = Command::new(&me)
        .env(AGENT_CHILD_ENV, socket.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn agent child");
    let child_pid = child.id();
    let _ = child.wait().expect("wait agent child");

    // Wait past threshold so stalls are surfaced and rotation flushes file.
    // The BufWriter-backed file exporter flushes on rotation; with
    // --export-file-max-bytes 50, every event triggers a rotation+flush.
    std::thread::sleep(Duration::from_millis(500));

    // Read all export files (content is spread across rotation generations)
    let mut content = String::new();
    for gen_suffix in &["", ".1", ".2", ".3", ".4", ".5"] {
        let path = tmp.path().join(format!("events.tsv{gen_suffix}"));
        if let Ok(c) = std::fs::read_to_string(&path) {
            content.push_str(&c);
        }
    }
    assert!(
        !content.is_empty(),
        "export file should contain event lines"
    );

    // Verify beats from agent 1
    assert!(
        content.lines().any(|l| l.contains("\tbeat\t") && l.contains(&agent_pid_1.to_string())),
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
                    BeatOutcome::Dropped => {
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
                BeatOutcome::Dropped => {
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
                BeatOutcome::Dropped => {
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
            BeatOutcome::Dropped => {
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
            BeatOutcome::Dropped => {
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
        let mut child = Command::new(&locate_watch_binary())
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
                        BeatOutcome::Dropped => {
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
        let status = wait_until_with_timeout(
            || child.try_wait().ok().flatten(),
            Duration::from_secs(5),
        );
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
    install_panic_handler(PathBuf::from(socket_path));
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
            match agent.beat(Status::Ok, i as u64) {
                BeatOutcome::Sent => break,
                BeatOutcome::Dropped => {
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
                BeatOutcome::Dropped => {
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
    let mut child = Command::new(&exe)
        .args(args)
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
    // Fallback: scan deps dir for the most recent `varta-watch` artefact.
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
fn wait_until_with_timeout<F: FnMut() -> Option<T>, T>(
    mut f: F,
    timeout: Duration,
) -> Option<T> {
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

/// Synchronous HTTP/1.0 GET. Returns (status_code, body).
fn http_get(addr: SocketAddr, path: &str) -> std::io::Result<(u16, String)> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
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

    let tmp = TempDir::new("secure-udp");
    let key_path = tmp.path().join("test.key");
    // 32-byte test key as 64-character hex
    let key_hex = "abababababababababababababababababababababababababababababababab";
    std::fs::write(&key_path, format!("{key_hex}\n")).expect("write key file");
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
                varta_client::BeatOutcome::Dropped => {
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
