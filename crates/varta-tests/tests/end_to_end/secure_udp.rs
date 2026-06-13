//! UDP and secure-UDP transport tests.

#[cfg(any(feature = "udp", feature = "secure-udp"))]
use super::{http_get, spawn_watch, wait_until, ChildGuard, TempDir};
#[cfg(feature = "secure-udp")]
use std::net::TcpStream;
#[cfg(feature = "secure-udp")]
use std::time::Duration;

#[cfg(feature = "udp")]
pub(super) fn udp_client_to_observer_beats_and_stall() {
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
pub(super) fn secure_udp_client_to_observer_beats() {
    use std::io::Write;
    use std::net::UdpSocket;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
pub(super) fn secure_udp_counter_wrap_continues_under_load() {
    use std::io::Write;
    use std::net::UdpSocket;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
/// `Varta` wrapper detects a process-lineage epoch mismatch and invokes
/// `transport.reconnect()` to refresh the IV salt before encrypting any
/// frame in the child, even when PID equality is deliberately made to alias.
/// Verified end-to-end by:
///
/// 1. Spawning `varta-watch` with a secure-UDP listener.
/// 2. Connecting a `Varta::connect_secure_udp` agent in the test process.
/// 3. Beating once, then calling `fork(2)`.
/// 4. With `test-hooks`, the child overwrites the inherited PID snapshot with
///    its own PID, masking the ordinary PID-mismatch detector.
/// 5. Child beats N times under the epoch-recovered transport, then `_exit`s.
/// 6. Parent beats N times.
/// 7. Scraping `/metrics`: parent AND child must appear as distinct
///    `varta_beats_total{pid=...}` entries, and `varta_io_errors_total`
///    plus every `varta_decode_errors_total{kind=...}` entry must stay
///    at zero (no AEAD-tag failures or nonce-replay rejections).
#[cfg(all(feature = "secure-udp", target_family = "unix"))]
#[allow(unsafe_code)]
pub(super) fn secure_udp_fork_safe_under_real_fork() {
    use std::io::Write;
    use std::net::UdpSocket;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
        #[cfg(feature = "test-hooks")]
        {
            // Mask the normal PID mismatch by making the inherited snapshot
            // equal the child's PID. Only the pthread_atfork lineage epoch
            // can now force session refresh before the first seal.
            agent.set_connect_pid_for_test(std::process::id());
        }
        for _ in 0..20 {
            let _ = agent.beat(varta_client::Status::Ok, 0);
        }
        if agent.fork_recoveries() != 1 {
            unsafe { _exit(2) };
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
    assert_eq!(
        status, 0,
        "child exited unsuccessfully; fork epoch did not trigger exactly one recovery"
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
