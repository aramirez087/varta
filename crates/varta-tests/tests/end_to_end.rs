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

// Scenario-based submodules — implementations migrated in session 04.
// `#[path]` is required because end_to_end.rs is the crate root; without it,
// `mod basic;` would resolve to tests/basic.rs (sibling), not tests/end_to_end/basic.rs.
#[path = "end_to_end/basic.rs"]
mod basic;
#[path = "end_to_end/observability.rs"]
mod observability;
#[path = "end_to_end/reconnect.rs"]
mod reconnect;
#[path = "end_to_end/recovery.rs"]
mod recovery;
#[path = "end_to_end/secure_udp.rs"]
mod secure_udp;

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

struct TestCase {
    name: &'static str,
    run: fn(),
}

static TESTS: &[TestCase] = &[
    TestCase {
        name: "client_to_observer_to_recovery_full_loop",
        run: basic::client_to_observer_to_recovery_full_loop,
    },
    TestCase {
        name: "panic_handler_critical_beat_visible_in_metrics",
        run: basic::panic_handler_critical_beat_visible_in_metrics,
    },
    TestCase {
        name: "concurrent_multi_agent_beats_visible_in_metrics",
        run: basic::concurrent_multi_agent_beats_visible_in_metrics,
    },
    TestCase {
        name: "recovery_exec_mode_touch_marker_file",
        run: recovery::recovery_exec_mode_touch_marker_file,
    },
    TestCase {
        name: "recovery_cmd_file_mode",
        run: recovery::recovery_cmd_file_mode,
    },
    TestCase {
        name: "recovery_exec_file_mode",
        run: recovery::recovery_exec_file_mode,
    },
    TestCase {
        name: "recovery_timeout_kill_after",
        run: recovery::recovery_timeout_kill_after,
    },
    TestCase {
        name: "recovery_env_isolation",
        run: recovery::recovery_env_isolation,
    },
    TestCase {
        name: "recovery_audit_log_records_spawn_and_complete",
        run: recovery::recovery_audit_log_records_spawn_and_complete,
    },
    TestCase {
        name: "recovery_audit_log_chain_survives_rotation_and_restart",
        run: recovery::recovery_audit_log_chain_survives_rotation_and_restart,
    },
    TestCase {
        name: "max_beat_rate_limits_and_reports_metric",
        run: observability::max_beat_rate_limits_and_reports_metric,
    },
    TestCase {
        name: "file_export_writes_tsv",
        run: observability::file_export_writes_tsv,
    },
    TestCase {
        name: "file_export_rotation",
        run: observability::file_export_rotation,
    },
    TestCase {
        name: "tracker_capacity_exceeded_reports_eviction_metric",
        run: observability::tracker_capacity_exceeded_reports_eviction_metric,
    },
    TestCase {
        name: "client_reconnect_after_observer_restart",
        run: reconnect::client_reconnect_after_observer_restart,
    },
    TestCase {
        name: "client_auto_reconnect_after_dropped",
        run: reconnect::client_auto_reconnect_after_dropped,
    },
    TestCase {
        name: "signal_handling_graceful_shutdown",
        run: reconnect::signal_handling_graceful_shutdown,
    },
    TestCase {
        name: "status_degraded_visible_in_metrics",
        run: basic::status_degraded_visible_in_metrics,
    },
    TestCase {
        name: "iteration_budget_holds_under_slow_scrape_load",
        run: observability::iteration_budget_holds_under_slow_scrape_load,
    },
    TestCase {
        name: "serve_pending_seconds_separates_scrape_from_beat_path",
        run: observability::serve_pending_seconds_separates_scrape_from_beat_path,
    },
    TestCase {
        name: "hostile_frame_rejected_at_decode_with_label_emit",
        run: observability::hostile_frame_rejected_at_decode_with_label_emit,
    },
    TestCase {
        name: "alert_rules_match_live_metrics",
        run: observability::alert_rules_match_live_metrics,
    },
    #[cfg(feature = "udp")]
    TestCase {
        name: "udp_client_to_observer_beats_and_stall",
        run: secure_udp::udp_client_to_observer_beats_and_stall,
    },
    #[cfg(feature = "secure-udp")]
    TestCase {
        name: "secure_udp_client_to_observer_beats",
        run: secure_udp::secure_udp_client_to_observer_beats,
    },
    #[cfg(all(feature = "secure-udp", feature = "test-hooks"))]
    TestCase {
        name: "secure_udp_counter_wrap_continues_under_load",
        run: secure_udp::secure_udp_counter_wrap_continues_under_load,
    },
    #[cfg(all(feature = "secure-udp", target_family = "unix"))]
    TestCase {
        name: "secure_udp_fork_safe_under_real_fork",
        run: secure_udp::secure_udp_fork_safe_under_real_fork,
    },
    TestCase {
        name: "clock_source_monotonic_smoke",
        run: basic::clock_source_monotonic_smoke,
    },
    #[cfg(target_os = "linux")]
    TestCase {
        name: "clock_source_boottime_smoke",
        run: basic::clock_source_boottime_smoke,
    },
];

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

    let total = expected_test_count();
    let mut failed = 0u32;
    eprintln!("running {total} tests");
    for test in TESTS {
        failed += run_one(test.name, test.run);
    }

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

fn expected_test_count() -> u32 {
    TESTS.len() as u32
}

fn run_one(name: &str, f: fn()) -> u32 {
    eprintln!("test {name} ... starting");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        let _ = tx.send(result);
    });
    match rx.recv_timeout(PER_TEST_TIMEOUT) {
        Ok(Ok(())) => {
            eprintln!("test {name} ... ok");
            0
        }
        Ok(Err(payload)) => {
            eprintln!(
                "test {name} ... FAILED ({})",
                panic_payload_message(payload.as_ref())
            );
            1
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

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.as_str()
    } else {
        "non-string panic payload"
    }
}

/// Drive enough beats through the agent socket to push the observer past
/// its stall threshold and trigger recovery.  Shared by the three sub-cases
/// of recovery_env_isolation.
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

fn uds_recovery_supported() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris",
    ))
}

fn skip_if_uds_recovery_unsupported(test_name: &str) -> bool {
    if uds_recovery_supported() {
        return false;
    }
    eprintln!(
        "skipping {test_name}: this target's pathname Unix datagram sockets are socket-mode-only, so recovery is intentionally refused"
    );
    true
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
