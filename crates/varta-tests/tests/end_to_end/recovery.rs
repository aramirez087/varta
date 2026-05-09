//! Recovery command execution and audit log tests.

use super::{
    drive_beats, http_get, skip_if_uds_recovery_unsupported, spawn_watch, wait_until, ChildGuard,
    TempDir,
};
use std::time::Duration;
use varta_client::{BeatOutcome, Status, Varta};

/// Spawns `varta-watch` with `--recovery-exec`, drives beats, induces a
/// stall, and asserts the recovery exec command fired (created a marker file
/// with the agent PID in its name).
pub(super) fn recovery_exec_mode_touch_marker_file() {
    if skip_if_uds_recovery_unsupported("recovery_exec_mode_touch_marker_file") {
        return;
    }

    use std::net::TcpStream;

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

/// Writes the recovery exec command to a file with 0600 permissions,
/// spawns `varta-watch` with `--recovery-exec-file`, and asserts recovery
/// fires on stall.  (Previously used `--recovery-cmd-file`; shell-mode
/// recovery was permanently removed.  See
/// `book/src/architecture/recovery-shell-removal.md`.)
pub(super) fn recovery_cmd_file_mode() {
    if skip_if_uds_recovery_unsupported("recovery_cmd_file_mode") {
        return;
    }

    use std::io::{BufWriter, Write};
    use std::os::unix::fs::OpenOptionsExt;

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
        let mut writer = BufWriter::new(file);
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

/// Writes the recovery exec command to a file with 0600 permissions,
/// spawns `varta-watch` with `--recovery-exec-file`, and asserts recovery
/// fires on stall.
pub(super) fn recovery_exec_file_mode() {
    if skip_if_uds_recovery_unsupported("recovery_exec_file_mode") {
        return;
    }

    use std::io::{BufWriter, Write};
    use std::os::unix::fs::OpenOptionsExt;

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
        let mut writer = BufWriter::new(file);
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

/// Spawns varta-watch with `--recovery-exec <script> --recovery-timeout-ms 300`.
/// After a stall, the script touches a marker then sleeps; the sleep child
/// should be killed within 300 ms, leaving the observer responsive (not hung).
pub(super) fn recovery_timeout_kill_after() {
    if skip_if_uds_recovery_unsupported("recovery_timeout_kill_after") {
        return;
    }

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
pub(super) fn recovery_env_isolation() {
    if skip_if_uds_recovery_unsupported("recovery_env_isolation") {
        return;
    }

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

/// Spawn `varta-watch` with `--recovery-audit-file`, drive a stall, assert
/// the audit TSV contains both a spawn and a complete record for the
/// agent's pid, and that the Prometheus surface exposes the new recovery
/// outcome counters (every label value present, even at zero, from the
/// first scrape).
pub(super) fn recovery_audit_log_records_spawn_and_complete() {
    if skip_if_uds_recovery_unsupported("recovery_audit_log_records_spawn_and_complete") {
        return;
    }

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
pub(super) fn recovery_audit_log_chain_survives_rotation_and_restart() {
    if skip_if_uds_recovery_unsupported("recovery_audit_log_chain_survives_rotation_and_restart") {
        return;
    }

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
