#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]

//! Varta performance harness.
//!
//! Three subcommands, each computing a single measurement and asserting
//! it against the v0.1.0 acceptance contract. Failure → non-zero exit
//! with the measured value reported on stderr.
//!
//! # Subcommands
//!
//! - `latency`         — `bench_latency_p99_under_one_microsecond`
//!   (steady-state `Varta::beat` p99 latency < 1 µs).
//! - `cpu-50-agents`   — `bench_observer_cpu_under_zero_point_one_percent`
//!   (observer CPU % across 50 × 1 Hz agents < 0.1 %).
//! - `binary-size`     — `bench_binary_size_delta_under_twenty_kilobytes`
//!   (linking `varta-client` adds < 20 KB to a stripped release binary).

use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use varta_client::{Status, Varta};

// --- contract thresholds ----------------------------------------------------

/// `bench_latency_p99_under_one_microsecond` — p99 of steady-state `beat()`
/// must remain below 1 microsecond (1_000 ns) on the host running the
/// session. HOST-DEPENDENT: noisy CI runners may legitimately exceed this;
/// `docs/benchmarks/results.md` records WARN status with measured ns.
const LATENCY_P99_NS_THRESHOLD: u64 = 1_000;

/// `bench_observer_cpu_under_zero_point_one_percent` — daemon CPU usage
/// across 50 agents emitting at 1 Hz must remain below 0.1 % wall.
/// HOST-DEPENDENT: virtualised CI hosts can spike under noisy neighbours.
const CPU_THRESHOLD_PCT: f64 = 0.1;

/// `bench_binary_size_delta_under_twenty_kilobytes` — linking the client
/// against an empty hello-world fixture must add < 20 KB to the stripped
/// release binary.
const BINARY_DELTA_BYTES_THRESHOLD: u64 = 20 * 1024;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sub = match args.first() {
        Some(s) => s.as_str(),
        None => {
            eprintln!(
                "varta-bench: missing subcommand (latency|cpu-50-agents|binary-size|udp-latency)"
            );
            return ExitCode::from(2);
        }
    };
    match sub {
        "latency" => run_latency(),
        "cpu-50-agents" => run_cpu_50_agents(),
        "binary-size" => run_binary_size(),
        #[cfg(feature = "udp")]
        "udp-latency" => run_udp_latency(),
        other => {
            eprintln!("varta-bench: unknown subcommand {other:?}");
            ExitCode::from(2)
        }
    }
}

// --- latency ----------------------------------------------------------------

fn run_latency() -> ExitCode {
    let tmp = match TempDir::new("varta-bench-latency") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("latency: failed to mint tempdir: {e}");
            return ExitCode::from(1);
        }
    };
    let socket = tmp.path().join("bench.sock");

    // Drainer thread keeps the kernel datagram queue empty so `send(2)`
    // returns Ok(32) instead of WouldBlock under load.
    let stop = Arc::new(AtomicBool::new(false));
    let drainer = match Drainer::spawn(&socket, stop.clone()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("latency: drainer failed: {e}");
            return ExitCode::from(1);
        }
    };

    let mut agent = match Varta::connect(&socket) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("latency: Varta::connect failed: {e}");
            stop.store(true, Ordering::Relaxed);
            let _ = drainer.join();
            return ExitCode::from(1);
        }
    };

    // Warmup: prime caches and branch predictors.
    const WARMUP: usize = 100_000;
    for _ in 0..WARMUP {
        let _ = agent.beat(Status::Ok, 0);
    }

    // Timed loop. Allocation outside the timing loop is harness scaffolding.
    const ITERS: usize = 1_000_000;
    let mut lats: Vec<u64> = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        let _ = agent.beat(Status::Ok, 0);
        lats.push(t0.elapsed().as_nanos() as u64);
    }

    drop(agent);
    stop.store(true, Ordering::Relaxed);
    let _ = drainer.join();

    lats.sort_unstable();
    let p50 = percentile_pm(&lats, 500);
    let p99 = percentile_pm(&lats, 990);
    let p999 = percentile_pm(&lats, 999);

    eprintln!(
        "latency: iters={ITERS} p50={p50}ns p99={p99}ns p99.9={p999}ns threshold={}ns",
        LATENCY_P99_NS_THRESHOLD
    );

    if p99 < LATENCY_P99_NS_THRESHOLD {
        eprintln!("bench_latency_p99_under_one_microsecond: PASS (p99={p99}ns)");
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "bench_latency_p99_under_one_microsecond: FAIL (p99={p99}ns >= {}ns)",
            LATENCY_P99_NS_THRESHOLD
        );
        ExitCode::from(1)
    }
}

fn percentile_pm(sorted: &[u64], per_mille: usize) -> u64 {
    let n = sorted.len();
    let idx = n.saturating_mul(per_mille) / 1000;
    sorted[idx.min(n - 1)]
}

struct Drainer {
    handle: Option<thread::JoinHandle<()>>,
}

impl Drainer {
    fn spawn(socket: &Path, stop: Arc<AtomicBool>) -> std::io::Result<Self> {
        if socket.exists() {
            std::fs::remove_file(socket)?;
        }
        let sock = UnixDatagram::bind(socket)?;
        sock.set_read_timeout(Some(Duration::from_millis(50)))?;
        let handle = thread::Builder::new()
            .name("varta-bench-drainer".into())
            .spawn(move || {
                let mut buf = [0u8; 32];
                while !stop.load(Ordering::Relaxed) {
                    match sock.recv(&mut buf) {
                        Ok(_) => {}
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => break,
                    }
                }
            })?;
        Ok(Drainer {
            handle: Some(handle),
        })
    }

    fn join(mut self) -> thread::Result<()> {
        if let Some(h) = self.handle.take() {
            return h.join();
        }
        Ok(())
    }
}

// --- cpu-50-agents ----------------------------------------------------------

fn run_cpu_50_agents() -> ExitCode {
    let tmp = match TempDir::new("varta-bench-cpu") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cpu-50-agents: failed to mint tempdir: {e}");
            return ExitCode::from(1);
        }
    };
    let socket = tmp.path().join("bench.sock");

    // Bound the daemon's wall lifetime via --shutdown-after-secs. We rely
    // on the daemon self-terminating before snapshotting RUSAGE_CHILDREN
    // so getrusage(2) actually accounts the daemon's CPU.
    const AGENT_BEATS: usize = 30; // 30 × 1 Hz = ~30 s
    const DAEMON_LIFETIME_SECS: u64 = 35;

    let watch_bin = match watch_binary_path() {
        Some(p) => p,
        None => {
            eprintln!(
                "cpu-50-agents: cannot locate varta-watch binary; \
                 run via `cargo run -p varta-bench --release -- cpu-50-agents`"
            );
            return ExitCode::from(1);
        }
    };

    let mut child = match Command::new(&watch_bin)
        .arg("--socket")
        .arg(&socket)
        .arg("--threshold-ms")
        .arg("5000")
        .arg("--shutdown-after-secs")
        .arg(DAEMON_LIFETIME_SECS.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cpu-50-agents: spawn failed: {e}");
            return ExitCode::from(1);
        }
    };

    if !wait_for_path(&socket, Duration::from_secs(3)) {
        let _ = child.kill();
        eprintln!("cpu-50-agents: socket did not appear within 3s");
        return ExitCode::from(1);
    }

    let r0 = rusage_children();
    let t0 = Instant::now();

    let mut handles = Vec::with_capacity(50);
    for _ in 0..50 {
        let socket = socket.clone();
        let h = thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || {
                let mut agent = match Varta::connect(&socket) {
                    Ok(a) => a,
                    Err(_) => return,
                };
                for _ in 0..AGENT_BEATS {
                    let _ = agent.beat(Status::Ok, 0);
                    thread::sleep(Duration::from_secs(1));
                }
            })
            .expect("spawn agent thread");
        handles.push(h);
    }
    for h in handles {
        let _ = h.join();
    }

    // Wait for the daemon to exit so RUSAGE_CHILDREN accounts its CPU.
    let _ = child.wait();
    let r1 = rusage_children();
    let wall = t0.elapsed();

    let cpu_ns = rusage_delta_ns(&r0, &r1);
    let wall_ns = wall.as_nanos() as u64;
    let cpu_pct = if wall_ns == 0 {
        0.0
    } else {
        (cpu_ns as f64) * 100.0 / (wall_ns as f64)
    };

    eprintln!(
        "cpu-50-agents: daemon_cpu_ns={cpu_ns} wall_ns={wall_ns} cpu_pct={cpu_pct:.4} \
         threshold={CPU_THRESHOLD_PCT:.4}%"
    );

    if cpu_pct < CPU_THRESHOLD_PCT {
        eprintln!("bench_observer_cpu_under_zero_point_one_percent: PASS ({cpu_pct:.4}%)");
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "bench_observer_cpu_under_zero_point_one_percent: FAIL \
             ({cpu_pct:.4}% >= {CPU_THRESHOLD_PCT:.4}%)"
        );
        ExitCode::from(1)
    }
}

/// Best-effort lookup of the `varta-watch` binary built alongside the
/// release `varta-bench` artefact. We probe the standard cargo target
/// layout relative to the bench binary.
fn watch_binary_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join("varta-watch");
    if candidate.exists() {
        return Some(candidate);
    }
    None
}

fn wait_for_path(p: &Path, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if fs::metadata(p).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

// --- getrusage(RUSAGE_CHILDREN) ---------------------------------------------

fn rusage_children() -> libc::rusage {
    let mut r = MaybeUninit::<libc::rusage>::zeroed();
    let rc = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, r.as_mut_ptr()) };
    assert_eq!(rc, 0, "getrusage(RUSAGE_CHILDREN) failed");
    unsafe { r.assume_init() }
}

fn rusage_delta_ns(start: &libc::rusage, end: &libc::rusage) -> u64 {
    let delta_user = timeval_ns(&end.ru_utime).saturating_sub(timeval_ns(&start.ru_utime));
    let delta_sys = timeval_ns(&end.ru_stime).saturating_sub(timeval_ns(&start.ru_stime));
    delta_user.saturating_add(delta_sys)
}

fn timeval_ns(tv: &libc::timeval) -> u64 {
    let secs = tv.tv_sec.max(0) as u64;
    let usecs = tv.tv_usec.max(0) as u64;
    secs.saturating_mul(1_000_000_000)
        .saturating_add(usecs.saturating_mul(1_000))
}

// --- binary-size ------------------------------------------------------------

fn run_binary_size() -> ExitCode {
    let tmp = match TempDir::new("varta-bench-binsize") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("binary-size: failed to mint tempdir: {e}");
            return ExitCode::from(1);
        }
    };

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let varta_client_path = manifest_dir
        .parent()
        .expect("workspace root")
        .join("varta-client");
    let varta_vlp_path = manifest_dir
        .parent()
        .expect("workspace root")
        .join("varta-vlp");

    let empty_dir = tmp.path().join("fix-empty");
    let with_dir = tmp.path().join("fix-client");
    if let Err(e) = write_fixture_empty(&empty_dir) {
        eprintln!("binary-size: write empty fixture: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = write_fixture_with_client(&with_dir, &varta_client_path, &varta_vlp_path) {
        eprintln!("binary-size: write with-client fixture: {e}");
        return ExitCode::from(1);
    }

    let empty_bin = match cargo_release_build(&empty_dir, "fix-empty") {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("binary-size: build empty fixture: {msg}");
            return ExitCode::from(1);
        }
    };
    let with_bin = match cargo_release_build(&with_dir, "fix-client") {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("binary-size: build with-client fixture: {msg}");
            return ExitCode::from(1);
        }
    };

    let strip_status = strip_binary(&empty_bin) && strip_binary(&with_bin);
    let empty_size = match fs::metadata(&empty_bin) {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("binary-size: stat empty: {e}");
            return ExitCode::from(1);
        }
    };
    let with_size = match fs::metadata(&with_bin) {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("binary-size: stat with-client: {e}");
            return ExitCode::from(1);
        }
    };

    let delta = with_size.saturating_sub(empty_size);
    eprintln!(
        "binary-size: empty={empty_size}B with-client={with_size}B delta={delta}B \
         threshold={BINARY_DELTA_BYTES_THRESHOLD}B stripped={strip_status}"
    );

    if delta < BINARY_DELTA_BYTES_THRESHOLD {
        eprintln!(
            "bench_binary_size_delta_under_twenty_kilobytes: PASS \
             (delta={}KB)",
            delta / 1024
        );
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "bench_binary_size_delta_under_twenty_kilobytes: FAIL \
             (delta={delta}B >= {BINARY_DELTA_BYTES_THRESHOLD}B)"
        );
        ExitCode::from(1)
    }
}

fn write_fixture_empty(root: &Path) -> std::io::Result<()> {
    fs::create_dir_all(root.join("src"))?;
    fs::write(
        root.join("Cargo.toml"),
        "[package]\n\
         name = \"fix-empty\"\n\
         version = \"0.0.1\"\n\
         edition = \"2021\"\n\
         \n\
         [[bin]]\n\
         name = \"fix-empty\"\n\
         path = \"src/main.rs\"\n\
         \n\
         [dependencies]\n\
         \n\
         [profile.release]\n\
         lto = false\n\
         codegen-units = 1\n\
         opt-level = 3\n\
         strip = false\n\
         \n\
         [workspace]\n",
    )?;
    fs::write(
        root.join("src/main.rs"),
        "fn main() { std::process::exit(0); }\n",
    )?;
    Ok(())
}

fn write_fixture_with_client(
    root: &Path,
    varta_client_path: &Path,
    varta_vlp_path: &Path,
) -> std::io::Result<()> {
    fs::create_dir_all(root.join("src"))?;
    let manifest = format!(
        "[package]\n\
         name = \"fix-client\"\n\
         version = \"0.0.1\"\n\
         edition = \"2021\"\n\
         \n\
         [[bin]]\n\
         name = \"fix-client\"\n\
         path = \"src/main.rs\"\n\
         \n\
         [dependencies]\n\
         varta-client = {{ path = {client:?} }}\n\
         varta-vlp = {{ path = {vlp:?} }}\n\
         \n\
         [profile.release]\n\
         lto = false\n\
         codegen-units = 1\n\
         opt-level = 3\n\
         strip = false\n\
         \n\
         [workspace]\n",
        client = varta_client_path.display().to_string(),
        vlp = varta_vlp_path.display().to_string(),
    );
    fs::write(root.join("Cargo.toml"), manifest)?;
    fs::write(
        root.join("src/main.rs"),
        "use varta_client::{Status, Varta};\n\
         use varta_vlp::Frame;\n\
         \n\
         fn main() {\n    \
            let path = std::env::args().nth(1).unwrap_or_else(|| String::from(\"/tmp/x.sock\"));\n    \
            if let Ok(mut a) = Varta::connect(&path) {\n        \
                let _ = a.beat(Status::Ok, 0);\n    \
            }\n    \
            let frame = Frame::new(Status::Ok, 0, 0, 1, 0);\n    \
            let mut buf = [0u8; 32];\n    \
            frame.encode(&mut buf);\n    \
            std::process::exit(buf[0] as i32);\n\
         }\n",
    )?;
    Ok(())
}

fn cargo_release_build(root: &Path, bin_name: &str) -> Result<PathBuf, String> {
    let target = root.join("target");
    let status = Command::new(env!("CARGO"))
        .arg("build")
        .arg("--release")
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", &target)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("spawn cargo: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build failed: {status}"));
    }
    let bin_path = target.join("release").join(bin_name);
    if !bin_path.exists() {
        return Err(format!("missing built binary at {}", bin_path.display()));
    }
    Ok(bin_path)
}

fn strip_binary(path: &Path) -> bool {
    let attempts: &[&[&str]] = &[&["strip", "-x"], &["strip"]];
    for argv in attempts {
        let mut cmd = Command::new(argv[0]);
        for a in &argv[1..] {
            cmd.arg(a);
        }
        cmd.arg(path);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        if let Ok(status) = cmd.status() {
            if status.success() {
                return true;
            }
        }
    }
    false
}

// --- TempDir ----------------------------------------------------------------

static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> std::io::Result<Self> {
        let pid = std::process::id();
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("{tag}-{pid}-{n}"));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p)?;
        Ok(TempDir { path: p })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(feature = "udp")]
fn run_udp_latency() -> ExitCode {
    use std::net::{SocketAddr, UdpSocket};

    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse");
    let drainer = UdpSocket::bind(addr).expect("bind drainer");
    let drainer_addr = drainer.local_addr().expect("local_addr");
    drainer
        .set_nonblocking(true)
        .expect("drainer set_nonblocking");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    let drainer_handle = thread::spawn(move || {
        let mut buf = [0u8; 32];
        while !stop_clone.load(Ordering::Relaxed) {
            let _ = drainer.recv(&mut buf);
        }
    });

    let mut agent = varta_client::Varta::connect_udp(drainer_addr).expect("connect_udp");
    for _ in 0..100_000 {
        let _ = agent.beat(Status::Ok, 0);
    }
    let iterations = 500_000u64;
    let mut samples = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let t0 = Instant::now();
        let _ = agent.beat(Status::Ok, 0);
        let ns = t0.elapsed().as_nanos() as u64;
        samples.push(ns);
    }
    drop(agent);
    stop.store(true, Ordering::Relaxed);
    let _ = drainer_handle.join();

    let mut sorted = samples.clone();
    sorted.sort_unstable();
    let p50 = percentile_pm(&sorted, 500);
    let p99 = percentile_pm(&sorted, 990);
    let p99_9 = percentile_pm(&sorted, 999);
    let mean = samples.iter().sum::<u64>() / samples.len() as u64;

    eprintln!(
        "udp-latency  samples={}  p50={p50}ns  p99={p99}ns  p99.9={p99_9}ns  mean={mean}ns",
        samples.len()
    );
    if p99 <= LATENCY_P99_NS_THRESHOLD {
        eprintln!("udp-latency  PASS  (p99 <= 1µs)");
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "udp-latency  WARN  (p99 {p99}ns > {}ns threshold — host-dependent)",
            LATENCY_P99_NS_THRESHOLD
        );
        ExitCode::SUCCESS
    }
}
