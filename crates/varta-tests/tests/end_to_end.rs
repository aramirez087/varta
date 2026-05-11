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

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use varta_client::{install_panic_handler, BeatOutcome, Status, Varta};

const PANIC_CHILD_ENV: &str = "VARTA_E2E_PANIC_CHILD";

/// Hand-rolled test runner. Runs as the panic child when the dispatch env
/// var is set; otherwise executes both contract tests sequentially.
fn main() -> ExitCode {
    if let Ok(socket_path) = std::env::var(PANIC_CHILD_ENV) {
        run_panic_child(&socket_path);
        // run_panic_child panics; this is unreachable but kept for clarity.
        return ExitCode::SUCCESS;
    }

    let mut failed = 0u32;
    eprintln!("running 2 tests");
    failed += run_one(
        "client_to_observer_to_recovery_full_loop",
        client_to_observer_to_recovery_full_loop,
    );
    failed += run_one(
        "panic_handler_critical_beat_visible_in_metrics",
        panic_handler_critical_beat_visible_in_metrics,
    );

    let total = 2u32;
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
    let prom_addr = probe_port();
    let recovery_cmd = format!("touch {}", marker.display());

    let mut child = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "200",
        "--recovery-cmd",
        &recovery_cmd,
        "--recovery-debounce-ms",
        "1000",
        "--prom-addr",
        &prom_addr.to_string(),
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
    let prom_addr = probe_port();

    let mut watch_child = spawn_watch(&[
        "--socket",
        socket.to_str().unwrap(),
        "--threshold-ms",
        "5000",
        "--prom-addr",
        &prom_addr.to_string(),
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

// --- panic-child entrypoint -------------------------------------------------

/// Code path entered when this binary is re-spawned as a panic child via
/// `VARTA_E2E_PANIC_CHILD=<socket>`. Installs the panic hook, beats once
/// so a pid label exists, then panics so the hook fires the Critical
/// frame.
fn run_panic_child(socket_path: &str) {
    install_panic_handler(PathBuf::from(socket_path));
    let mut agent = Varta::connect(socket_path).expect("panic child: connect");
    let _ = agent.beat(Status::Ok, 0);
    // Give the daemon a moment to consume the warmup beat before the
    // panic-fired Critical frame races process exit.
    std::thread::sleep(Duration::from_millis(150));
    panic!("VARTA_E2E_PANIC_CHILD: deliberate panic for hook coverage");
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

fn spawn_watch(args: &[&str]) -> Child {
    let exe = locate_watch_binary();
    Command::new(&exe)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", exe.display()))
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

/// Bind a fresh ephemeral port, capture its address, then drop the
/// listener so the daemon can take it. Tiny TOCTOU window on a non-
/// hostile test host — documented in the session handoff.
fn probe_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    addr
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
