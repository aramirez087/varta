//! Linux signal-restorer trampoline regression tests.
//!
//! The Linux build of `varta-watch` ships a hand-rolled `rt_sigreturn`
//! trampoline (`varta_signal_restorer`) and a kernel-ABI `KernelSigAction`
//! struct in `crates/varta-watch/src/main.rs`. If a future Linux kernel
//! silently changes the `rt_sigreturn` syscall convention, the
//! `rt_sigframe` layout, or `SA_RESTORER` semantics, the observer would
//! `SIGSEGV` on the first SIGTERM / SIGINT delivery.
//!
//! These tests are the userspace regression check for that failure mode.
//! Each test spawns the real `varta-watch` binary, sends a signal that
//! exercises the trampoline path, and asserts:
//!
//!   1. The process exits within a tight deadline (the trampoline path is
//!      either fine or wedged — slow shutdown is also a regression).
//!   2. The process was **not** terminated by a signal — specifically not
//!      `SIGSEGV` (11), which is the symptom of a broken trampoline.
//!
//! The CI workflow `kernel-rc.yml` runs this file inside a virtme-ng VM
//! booted on the latest mainline / -rc kernel to surface kernel-ABI
//! regressions before they hit production distros.
//!
//! Linux-only (the trampoline only exists on Linux). On other Unixes the
//! file compiles to an empty module.

#![deny(rust_2018_idioms)]

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    /// Hard upper bound on shutdown latency. Trampoline-broken kernels
    /// SIGSEGV immediately; healthy kernels exit cleanly well under this.
    /// 2 s is tight enough to catch a poll-loop wedge, loose enough to
    /// absorb GitHub Actions runner jitter.
    const SHUTDOWN_BUDGET: Duration = Duration::from_secs(2);

    /// Time window for the daemon to bind its socket before we start
    /// signalling it. Mirrors the budget used by `end_to_end.rs`.
    const SOCKET_BIND_BUDGET: Duration = Duration::from_secs(3);

    /// Monotonic suffix counter so concurrent tests cannot share a socket
    /// path. Same shape as `TMP_COUNTER` in `end_to_end.rs`.
    static TMP_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Resolve `target/<profile>/varta-watch` relative to the current test
    /// binary. Identical strategy to `locate_watch_binary` in `end_to_end.rs`
    /// — kept private here so this test file stands alone.
    fn locate_watch_binary() -> PathBuf {
        let exe = std::env::current_exe().expect("current_exe");
        // exe is `target/<profile>/deps/signal_trampoline-XXXX`.
        let deps_dir = exe.parent().expect("deps dir");
        let profile_dir = deps_dir.parent().expect("profile dir");
        let direct = profile_dir.join("varta-watch");
        assert!(
            direct.exists(),
            "varta-watch binary not found at {} — \
             build the workspace before running these tests \
             (e.g. `cargo build --workspace`)",
            direct.display(),
        );
        direct
    }

    /// Self-cleaning scratch directory. Same shape as the `end_to_end.rs`
    /// helper; replicated locally to keep this file self-contained.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            let pid = std::process::id();
            let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let mut p = std::env::temp_dir();
            p.push(format!("varta-signal-trampoline-{tag}-{pid}-{n}"));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).expect("create tempdir");
            TempDir { path: p }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Spawn `varta-watch` without `--shutdown-after-secs` and without
    /// `--prom-addr` (the trampoline tests do not scrape `/metrics`).
    /// Waits until the daemon binds its socket so the signal lands on a
    /// fully-initialised process.
    fn spawn_observer(tag: &str) -> (Child, TempDir) {
        let tmp = TempDir::new(tag);
        let socket = tmp.path.join("varta.sock");
        let child = Command::new(locate_watch_binary())
            .args([
                "--socket",
                socket.to_str().expect("utf-8 socket path"),
                "--threshold-ms",
                "5000",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn varta-watch");

        let deadline = Instant::now() + SOCKET_BIND_BUDGET;
        while Instant::now() < deadline {
            if socket.exists() {
                return (child, tmp);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // Socket never appeared. Best-effort cleanup before failing.
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "varta-watch did not bind socket within {SOCKET_BIND_BUDGET:?} — \
             test environment problem, not a trampoline regression"
        );
    }

    /// Send `signal` to `pid` via `kill(1)`. Shelling out keeps this file
    /// dependency-free (no `libc` import in the test harness).
    fn kill(pid: u32, signal: &str) {
        let status = Command::new("kill")
            .arg(signal)
            .arg(pid.to_string())
            .status()
            .unwrap_or_else(|e| panic!("invoke kill {signal} {pid}: {e}"));
        assert!(status.success(), "kill {signal} {pid} failed: {status}",);
    }

    /// Wait for `child` to exit within `SHUTDOWN_BUDGET`. Returns the exit
    /// status, or force-kills + panics on timeout (which is itself a
    /// regression — a wedged poll loop is just as bad as a SIGSEGV).
    fn wait_for_exit(child: &mut Child, case: &str) -> ExitStatus {
        let deadline = Instant::now() + SHUTDOWN_BUDGET;
        loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "{case}: varta-watch did not exit within {SHUTDOWN_BUDGET:?} \
                     after signal — possible trampoline wedge or shutdown regression"
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Assert: clean `exit(0)` and **no terminating signal**. A `Some(11)`
    /// (`SIGSEGV`) from `ExitStatusExt::signal()` is the canonical symptom
    /// of a broken `rt_sigreturn` trampoline, so we name it in the message.
    fn assert_clean_exit(status: ExitStatus, case: &str) {
        if let Some(sig) = status.signal() {
            panic!(
                "{case}: trampoline regression — process killed by signal {sig} \
                 (SIGSEGV=11 indicates broken rt_sigreturn). Full status: {status}"
            );
        }
        assert!(
            status.success(),
            "{case}: observer exited non-zero after signal: {status}"
        );
    }

    /// T1: SIGTERM immediately after socket bind. Exercises the trampoline
    /// path during early steady-state poll.
    #[test]
    fn sigterm_immediately_after_bind_exits_cleanly() {
        let case = "T1 sigterm_immediately_after_bind";
        let (mut child, _tmp) = spawn_observer("t1");
        kill(child.id(), "-TERM");
        let status = wait_for_exit(&mut child, case);
        assert_clean_exit(status, case);
    }

    /// T2: SIGINT after some real beat traffic. Covers the other installed
    /// signal — SIGINT and SIGTERM share the trampoline path but go through
    /// distinct `rt_sigaction` installs, so a per-signal readback bug would
    /// catch one and miss the other.
    #[test]
    fn sigint_after_beats_exits_cleanly() {
        let case = "T2 sigint_after_beats";
        let (mut child, tmp) = spawn_observer("t2");

        // Send 5 beats from an in-process client so the observer is doing
        // real work (recvfrom in its poll loop) when the signal arrives.
        let socket = tmp.path.join("varta.sock");
        {
            let mut agent = varta_client::Varta::connect(&socket).expect("Varta::connect");
            for _ in 0..5 {
                let mut tries = 0u32;
                loop {
                    match agent.beat(varta_client::Status::Ok, 0) {
                        varta_client::BeatOutcome::Sent => break,
                        varta_client::BeatOutcome::Dropped(_) => {
                            tries += 1;
                            assert!(
                                tries <= 5_000,
                                "{case}: kernel never accepted a beat before signal",
                            );
                            std::thread::sleep(Duration::from_micros(500));
                        }
                        varta_client::BeatOutcome::Failed(e) => {
                            panic!("{case}: unexpected hard failure: {e}")
                        }
                    }
                }
            }
        }

        kill(child.id(), "-INT");
        let status = wait_for_exit(&mut child, case);
        assert_clean_exit(status, case);
    }

    /// T3: SIGTERM × 3 in rapid succession. Two extra signals after the
    /// first one races against the handler / shutdown path. Catches
    /// regressions where the trampoline works on the first delivery but
    /// fails when the kernel re-enters it on a redelivered signal, and
    /// would catch any future doubled-install bug in the readback rewrite.
    #[test]
    fn sigterm_burst_exits_cleanly() {
        let case = "T3 sigterm_burst";
        let (mut child, _tmp) = spawn_observer("t3");
        let pid = child.id();
        for _ in 0..3 {
            kill(pid, "-TERM");
        }
        let status = wait_for_exit(&mut child, case);
        assert_clean_exit(status, case);
    }
}
