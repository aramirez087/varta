//! Integration tests for the `sd_notify` wire protocol.
//!
//! Binds a real `UnixDatagram` listener, spawns `varta-watch` with
//! `$NOTIFY_SOCKET` set to the listener path (or abstract name on Linux),
//! and asserts the message sequence: `READY=1\n` first, at least one
//! `WATCHDOG=1\n`, then `STOPPING=1\n` last.

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicU32 = AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct TmpDir(PathBuf);

impl TmpDir {
    fn new(tag: &str) -> Self {
        let pid = std::process::id();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("varta-notify-{tag}-{pid}-{n}"));
        std::fs::create_dir_all(&p).expect("create tempdir");
        // chmod 0o755 — parallel test runs can set a restrictive umask
        // (see cerebrum.md 2026-05-13: UnixDatagram::bind sets umask !0o600).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))
                .expect("chmod tempdir 0755");
        }
        Self(p)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Collect messages from `sock` until `child` exits or `timeout` elapses.
/// Returns all messages received as UTF-8 strings.
fn collect_messages(
    sock: &UnixDatagram,
    child: &mut std::process::Child,
    timeout: Duration,
) -> Vec<String> {
    let deadline = Instant::now() + timeout;
    let mut msgs = Vec::new();
    let mut buf = [0u8; 256];

    loop {
        // Check if child exited.
        if let Ok(Some(_)) = child.try_wait() {
            // Drain any final messages with a short window.
            sock.set_read_timeout(Some(Duration::from_millis(50))).ok();
            loop {
                match sock.recv(&mut buf) {
                    Ok(n) if n > 0 => {
                        if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                            msgs.push(s.to_owned());
                        }
                    }
                    _ => break,
                }
            }
            break;
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            break;
        }

        match sock.recv(&mut buf) {
            Ok(n) if n > 0 => {
                if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                    msgs.push(s.to_owned());
                }
            }
            _ => {}
        }
    }

    // Ensure child is reaped.
    let _ = child.wait();
    msgs
}

// ---------------------------------------------------------------------------
// Tests: path-based socket (Linux + macOS)
// ---------------------------------------------------------------------------

/// `varta-watch` must send `READY=1\n`, at least one `WATCHDOG=1\n`, and
/// `STOPPING=1\n` in that order when `$NOTIFY_SOCKET` is a path-based UDS.
#[test]
fn sd_notify_emits_ready_watchdog_stopping_on_clean_exit() {
    let dir = TmpDir::new("sd");
    let notify_path = dir.path("notify.sock");
    let agent_sock = dir.path("agents.sock");

    let listener = UnixDatagram::bind(&notify_path).expect("bind notify listener");
    listener
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("set read timeout");

    let mut child = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            agent_sock.to_str().unwrap(),
            "--threshold-ms",
            "100",
            "--shutdown-after-secs",
            "1",
        ])
        .env("NOTIFY_SOCKET", notify_path.to_str().unwrap())
        .env("WATCHDOG_USEC", "200000") // 200 ms → half-interval 100 ms
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn varta-watch");

    let msgs = collect_messages(&listener, &mut child, Duration::from_secs(5));

    assert!(
        !msgs.is_empty(),
        "no sd_notify messages received; is the binary running?"
    );

    assert_eq!(
        msgs.first().map(String::as_str),
        Some("READY=1\n"),
        "first message must be READY=1; got: {:?}",
        msgs
    );

    assert!(
        msgs.iter().any(|m| m == "WATCHDOG=1\n"),
        "expected at least one WATCHDOG=1 message; got: {:?}",
        msgs
    );

    assert_eq!(
        msgs.last().map(String::as_str),
        Some("STOPPING=1\n"),
        "last message must be STOPPING=1; got: {:?}",
        msgs
    );
}

/// H5: with `--self-watchdog-secs` explicitly set, the watchdog thread is
/// solely responsible for emitting `WATCHDOG=1`.  Asserts that at least one
/// arrives — proves the take/spawn handoff in `main.rs` wires the cloned
/// socket into the thread.
#[test]
fn watchdog_thread_emits_watchdog_when_self_watchdog_secs_set() {
    let dir = TmpDir::new("h5-explicit");
    let notify_path = dir.path("notify.sock");
    let agent_sock = dir.path("agents.sock");

    let listener = UnixDatagram::bind(&notify_path).expect("bind notify listener");
    listener
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("set read timeout");

    let mut child = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            agent_sock.to_str().unwrap(),
            "--threshold-ms",
            "100",
            "--self-watchdog-secs",
            "4",
            "--shutdown-after-secs",
            "1",
        ])
        .env("NOTIFY_SOCKET", notify_path.to_str().unwrap())
        // WATCHDOG_USEC=200000 → half-interval 100 ms; the watchdog thread
        // sleeps min(half/2, 500ms).max(50ms) = 50 ms and emits every tick.
        .env("WATCHDOG_USEC", "200000")
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn varta-watch");

    let msgs = collect_messages(&listener, &mut child, Duration::from_secs(5));

    assert!(
        msgs.iter().any(|m| m == "WATCHDOG=1\n"),
        "watchdog thread must emit WATCHDOG=1 when --self-watchdog-secs is set; got: {:?}",
        msgs
    );
    // READY must precede; STOPPING must terminate.
    assert_eq!(msgs.first().map(String::as_str), Some("READY=1\n"));
    assert_eq!(msgs.last().map(String::as_str), Some("STOPPING=1\n"));
}

/// H5 auto-enable: when `$WATCHDOG_USEC` is present but `--self-watchdog-secs`
/// is omitted, the watchdog thread must still be spawned (with the
/// auto-derived 4 s deadline) and WATCHDOG=1 must still be emitted.
#[test]
fn watchdog_auto_enable_emits_watchdog_without_self_watchdog_flag() {
    let dir = TmpDir::new("h5-auto");
    let notify_path = dir.path("notify.sock");
    let agent_sock = dir.path("agents.sock");

    let listener = UnixDatagram::bind(&notify_path).expect("bind notify listener");
    listener
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("set read timeout");

    let mut child = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            agent_sock.to_str().unwrap(),
            "--threshold-ms",
            "100",
            // Deliberately NO --self-watchdog-secs.  WATCHDOG_USEC alone must
            // be enough to trigger auto-enable.
            "--shutdown-after-secs",
            "1",
        ])
        .env("NOTIFY_SOCKET", notify_path.to_str().unwrap())
        .env("WATCHDOG_USEC", "200000")
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn varta-watch (auto-enable)");

    let msgs = collect_messages(&listener, &mut child, Duration::from_secs(5));

    assert!(
        msgs.iter().any(|m| m == "WATCHDOG=1\n"),
        "auto-enabled watchdog must emit WATCHDOG=1; got: {:?}",
        msgs
    );
}

/// `varta-watch` must start and exit cleanly even when `$NOTIFY_SOCKET` is
/// unset — sd_notify failures are non-fatal.
#[test]
fn sd_notify_no_op_when_env_unset() {
    let dir = TmpDir::new("noop");
    let agent_sock = dir.path("agents.sock");

    let out = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            agent_sock.to_str().unwrap(),
            "--threshold-ms",
            "100",
            "--shutdown-after-secs",
            "0",
        ])
        .env_remove("NOTIFY_SOCKET")
        .env_remove("WATCHDOG_USEC")
        .output()
        .expect("spawn varta-watch without NOTIFY_SOCKET");

    assert!(
        out.status.success(),
        "binary must exit cleanly without NOTIFY_SOCKET; got {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Tests: abstract-namespace socket (Linux only)
// ---------------------------------------------------------------------------

/// Build a `sockaddr_un` for an abstract socket and call `bind(2)` via FFI.
/// Mirrors `connect_abstract` in `notify.rs` for the receiving side.
#[cfg(target_os = "linux")]
fn bind_abstract(sock: &UnixDatagram, name: &str) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let name_bytes = name.as_bytes();
    if name_bytes.len() >= 108 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "abstract name too long",
        ));
    }

    // sun_family (u16 LE, AF_UNIX=1) at bytes 0..2,
    // sun_path[0]=NUL (abstract marker) at byte 2,
    // then name bytes starting at byte 3.
    let mut addr_buf = [0u8; 110];
    addr_buf[0] = 1; // AF_UNIX LSB
    addr_buf[1] = 0;
    addr_buf[2] = 0; // leading NUL = abstract namespace
    addr_buf[3..3 + name_bytes.len()].copy_from_slice(name_bytes);
    let addrlen: u32 = (2 + 1 + name_bytes.len()) as u32;

    extern "C" {
        fn bind(
            sockfd: std::ffi::c_int,
            addr: *const std::ffi::c_void,
            addrlen: u32,
        ) -> std::ffi::c_int;
    }

    // SAFETY: fd is valid (just created), addr_buf is fully initialised,
    // addrlen is the exact populated byte count.
    let rc = unsafe {
        bind(
            sock.as_raw_fd(),
            addr_buf.as_ptr() as *const std::ffi::c_void,
            addrlen,
        )
    };

    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// On Linux, `varta-watch` must handle `$NOTIFY_SOCKET=@abstract-name`
/// (the format systemd uses for abstract-namespace sockets).
#[cfg(target_os = "linux")]
#[test]
fn sd_notify_works_with_abstract_socket_name() {
    let dir = TmpDir::new("abs");
    let agent_sock = dir.path("agents.sock");

    // Abstract-namespace socket name must be unique per test invocation.
    let abstract_name = format!("varta-test-notify-{}", std::process::id());
    let notify_socket_env = format!("@{abstract_name}");

    let listener = UnixDatagram::unbound().expect("create unbound socket");
    bind_abstract(&listener, &abstract_name).expect("bind abstract socket");
    listener
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("set read timeout");

    let mut child = Command::new(env!("CARGO_BIN_EXE_varta-watch"))
        .args([
            "--socket",
            agent_sock.to_str().unwrap(),
            "--threshold-ms",
            "100",
            "--shutdown-after-secs",
            "1",
        ])
        .env("NOTIFY_SOCKET", &notify_socket_env)
        .env("WATCHDOG_USEC", "200000")
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn varta-watch with abstract NOTIFY_SOCKET");

    let msgs = collect_messages(&listener, &mut child, Duration::from_secs(5));

    assert_eq!(
        msgs.first().map(String::as_str),
        Some("READY=1\n"),
        "first message via abstract socket must be READY=1; got: {:?}",
        msgs
    );
    assert!(
        msgs.iter().any(|m| m == "WATCHDOG=1\n"),
        "expected at least one WATCHDOG=1 via abstract socket; got: {:?}",
        msgs
    );
    assert_eq!(
        msgs.last().map(String::as_str),
        Some("STOPPING=1\n"),
        "last message via abstract socket must be STOPPING=1; got: {:?}",
        msgs
    );
}
