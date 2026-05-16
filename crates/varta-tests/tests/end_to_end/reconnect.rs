//! Client reconnect and signal handling tests.

use super::{
    locate_watch_binary, spawn_watch, wait_until, wait_until_with_timeout, ChildGuard, TempDir,
};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Duration;
use varta_client::{BeatOutcome, Status, Varta};

/// Spawns observer v1, client connects and beats. Kills observer v1. Spawns
/// observer v2 on the same socket path. Client calls `reconnect()` and
/// sends more beats, which should appear in v2's /metrics.
pub(super) fn client_reconnect_after_observer_restart() {
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
        || match super::http_get(prom_addr_1, "/metrics") {
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
        || match super::http_get(prom_addr_2, "/metrics") {
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

/// Connects a client, sets `set_reconnect_after(3)`, kills the observer,
/// and verifies the client handles the Dropped path without panicking.
pub(super) fn client_auto_reconnect_after_dropped() {
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

/// Spawns varta-watch *without* `--shutdown-after-secs`, sends a few beats,
/// then sends SIGTERM. Asserts the observer exits cleanly (exit code 0)
/// and the socket file is cleaned up.
pub(super) fn signal_handling_graceful_shutdown() {
    use std::io::{BufRead, BufReader};

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
        let mut reader = BufReader::new(stdout);
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
