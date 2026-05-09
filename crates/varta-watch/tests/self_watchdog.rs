//! Integration test for the in-process self-watchdog (L1 observer liveness).
//!
//! Requires `--features test-hooks`: the `--inject-wedge-ms <MS>` flag stalls
//! the poll loop on the first iteration, causing `LAST_TICK_NS` to stop
//! advancing.  The watchdog thread detects the stall and calls
//! `process::abort()`, which produces SIGABRT (signal 6 on every Unix Varta
//! targets).
//!
//! Without `test-hooks` this file compiles to an empty crate — no test
//! functions are defined outside the cfg gate.
//!
//! Also excluded from the Class-A `compile-time-config` profile: the
//! harness drives the binary with `--inject-wedge-ms`, which is rejected
//! by a Class-A binary that accepts no argv tokens.

#![cfg(not(feature = "compile-time-config"))]

#[cfg(feature = "test-hooks")]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{Duration, Instant};

    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new(tag: &str) -> Self {
            let pid = std::process::id();
            let mut p = std::env::temp_dir();
            p.push(format!("varta-selfwdt-{tag}-{pid}"));
            std::fs::create_dir_all(&p).expect("create tempdir");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))
                .expect("chmod tempdir");
            Self(p)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `varta-watch --self-watchdog-secs 1 --inject-wedge-ms 3000` must abort
    /// (SIGABRT) within the watchdog deadline rather than running for the
    /// full `--shutdown-after-secs 10` lifetime.
    ///
    /// SIGABRT is signal 6 on Linux, macOS, FreeBSD, NetBSD, OpenBSD,
    /// DragonFly BSD — every Unix platform Varta targets.  We inline the
    /// constant to avoid pulling in `libc` (project zero-dep rule).
    #[cfg(unix)]
    #[test]
    fn self_watchdog_aborts_on_wedged_poll_loop() {
        use std::os::unix::process::ExitStatusExt;

        let dir = TmpDir::new("wedge");
        let socket_path = dir.0.join("agents.sock");

        let mut child = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
            .args([
                "--socket",
                socket_path.to_str().unwrap(),
                "--threshold-ms",
                "100",
                "--self-watchdog-secs",
                "1",
                // Stall the first poll iteration for 3 s — longer than the
                // 1 s watchdog deadline.  The watchdog thread wakes at 500 ms
                // intervals and fires after ~1.5 s of stall.
                "--inject-wedge-ms",
                "3000",
                // Safety net: if the watchdog somehow doesn't fire, exit
                // cleanly after 10 s so the test doesn't hang indefinitely.
                "--shutdown-after-secs",
                "10",
            ])
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn varta-watch with --inject-wedge-ms");

        // Wait up to 6 s for the child to exit (watchdog should fire ~1.5–2 s
        // after start).
        let test_deadline = Instant::now() + Duration::from_secs(6);
        let status = loop {
            if let Ok(Some(s)) = child.try_wait() {
                break s;
            }
            if Instant::now() >= test_deadline {
                child.kill().ok();
                let _ = child.wait();
                panic!("self-watchdog did not abort within 6 s");
            }
            std::thread::sleep(Duration::from_millis(100));
        };

        // process::abort() raises SIGABRT (6).  On Linux this gives exit code
        // 134 (128 + 6); on macOS the signal is preserved in the wait status.
        // Check the signal directly for portability.
        //
        // SIGABRT == 6 on:
        //   Linux   <asm/signal.h>: #define SIGABRT 6
        //   macOS   <sys/signal.h>: #define SIGABRT 6
        //   FreeBSD <sys/signal.h>: #define SIGABRT 6
        //   NetBSD  <sys/signal.h>: #define SIGABRT 6
        const SIGABRT: i32 = 6;

        assert_eq!(
            status.signal(),
            Some(SIGABRT),
            "self-watchdog must abort via SIGABRT (6); got status: {:?}",
            status
        );
    }
}
