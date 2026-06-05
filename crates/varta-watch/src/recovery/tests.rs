use std::time::{Duration, Instant};

use crate::audit;
use crate::peer_cred::BeatOrigin;
use crate::probe_table::{mix32, BoundedIndex};

use super::debounce::{InsertOutcome, LastFiredTable, MAX_LAST_FIRED_CAPACITY};
use super::reaper::{CAPTURE_DRAIN_BYTES_PER_TICK, POST_EXIT_CAPTURE_DRAIN_GRACE};
use super::{Recovery, RecoveryMode, RecoveryOutcome};

#[test]
fn capacity_builders_cap_untrusted_values() {
    let rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::ZERO,
    )
    .with_reap_scratch_capacity(usize::MAX)
    .with_outstanding_capacity(usize::MAX);

    assert_eq!(rec.reap_scratch.capacity(), crate::tracker::MAX_CAPACITY);
}

#[test]
fn exec_mode_spawns_command_via_execvp() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::ZERO,
    );
    match rec.on_stall(42, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {
            std::thread::sleep(Duration::from_millis(50));
            let outcomes = rec.try_reap(0);
            let reaped = outcomes.into_iter().find_map(|o| match o {
                RecoveryOutcome::Reaped { status, .. } => Some(status),
                _ => None,
            });
            assert!(
                matches!(reaped, Some(s) if s.success()),
                "expected exec mode to spawn and reap true; got {reaped:?}"
            );
        }
        other => panic!("expected Spawned in exec mode, got {other:?}"),
    }
}

#[test]
fn reaped_outcome_carries_duration_for_metrics() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::ZERO,
    );

    match rec.on_stall(43, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned in exec mode, got {other:?}"),
    }

    std::thread::sleep(Duration::from_millis(20));
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if Instant::now() >= deadline {
            panic!("timed out waiting for Reaped");
        }
        let outcomes = rec.try_reap(0);
        if let Some(duration_ns) = outcomes.into_iter().find_map(|o| match o {
            RecoveryOutcome::Reaped { duration_ns, .. } => Some(duration_ns),
            _ => None,
        }) {
            assert!(
                duration_ns > 0,
                "reaped outcome must carry non-zero duration for metrics"
            );
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn exec_mode_substitutes_pid_in_args() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "test \"$1\" = \"42\"".to_string(),
                "varta-recovery".to_string(),
                "{pid}".to_string(),
            ],
        },
        Duration::ZERO,
    );
    match rec.on_stall(42, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {
            std::thread::sleep(Duration::from_millis(100));
            let outcomes = rec.try_reap(0);
            let reaped = outcomes.into_iter().find_map(|o| match o {
                RecoveryOutcome::Reaped { status, .. } => Some(status),
                _ => None,
            });
            assert!(
                matches!(reaped, Some(s) if s.success()),
                "expected {{pid}} substitution in exec mode; got {reaped:?}"
            );
        }
        other => panic!("expected Spawned, got {other:?}"),
    }
}

#[test]
fn exec_mode_no_shell_injection_via_pid_substitution() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec!["{pid}".to_string()],
        },
        Duration::ZERO,
    );
    match rec.on_stall(42, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {
            std::thread::sleep(Duration::from_millis(50));
            let outcomes = rec.try_reap(0);
            assert!(
                outcomes.iter().any(
                    |o| matches!(o, RecoveryOutcome::Reaped { status, .. } if status.success())
                ),
                "exec mode with {{pid}} in args should succeed: {outcomes:?}"
            );
        }
        other => panic!("expected Spawned, got {other:?}"),
    }
}

#[test]
fn exec_mode_env_isolation_clears_environment() {
    let mut rec = Recovery::with_timeout(
        RecoveryMode::Exec {
            program: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "test -z \"$HOME\" && test \"$E1\" = \"a\" && test \"$E2\" = \"b\"".to_string(),
            ],
        },
        Duration::ZERO,
        None,
    )
    .with_recovery_env(vec!["E1=a".to_string(), "E2=b".to_string()]);
    match rec.on_stall(1, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {
            std::thread::sleep(Duration::from_millis(100));
            let outcomes = rec.try_reap(0);
            let reaped = outcomes.into_iter().find_map(|o| match o {
                RecoveryOutcome::Reaped { status, .. } => Some(status),
                _ => None,
            });
            assert!(
                matches!(reaped, Some(s) if s.success()),
                "exec mode env isolation failed; got {reaped:?}"
            );
        }
        other => panic!("expected Spawned, got {other:?}"),
    }
}

fn audit_tmpdir(tag: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "varta-rec-audit-{tag}-{}-{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir(&dir).expect("create tempdir");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod tempdir");
    dir
}

fn pids_for_same_probe_cluster(capacity: usize, count: usize) -> Vec<u32> {
    let table_size = capacity.saturating_mul(2).max(2).next_power_of_two();
    let mask = table_size - 1;
    let mut pids = Vec::with_capacity(count);
    let mut pid = 2u32;
    while pids.len() < count {
        if (mix32(pid) as usize & mask) == 0 {
            pids.push(pid);
        }
        pid = pid.checked_add(1).expect("enough u32 pids for test");
    }
    pids
}

#[test]
fn audit_sink_records_spawn_and_complete_for_exec_mode() {
    let dir = audit_tmpdir("audit-rt");
    let path = dir.join("audit.log");
    let (sink, _) = audit::RecoveryAuditLog::create(&path, audit::AuditConfig::default())
        .expect("create audit");

    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::ZERO,
    )
    .with_audit_sink(Some(sink));

    match rec.on_stall(123, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned, got {other:?}"),
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if Instant::now() >= deadline {
            panic!("timed out waiting for Reaped");
        }
        let outcomes = rec.try_reap(0);
        if outcomes
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(rec);

    let body = std::fs::read_to_string(&path).expect("read audit");
    let lines: Vec<&str> = body.lines().collect();
    assert!(lines[0].starts_with("# varta-watch recovery audit v2"));
    assert!(
        lines.iter().any(|l| l.contains("\tspawn\t123\t")),
        "expected spawn line for pid 123: {body}"
    );
    assert!(
        lines.iter().any(|l| l.contains("\tcomplete\t123\t")),
        "expected complete line for pid 123: {body}"
    );
    for line in lines.iter().filter(|l| !l.starts_with('#')) {
        let cols: Vec<&str> = line.split('\t').collect();
        let seq: u64 = cols[0].parse().expect("seq column parses");
        assert!(seq >= 1, "seq must be >= 1");
        let chain = cols.last().expect("chain column");
        assert!(
            *chain == "-" || chain.len() == 64,
            "chain column must be `-` or 64 hex chars; got {chain:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: a `complete` audit record must carry the completion-time
/// `observer_ns` passed to `try_reap`, not a hardcoded `0`. Before the fix,
/// `emit_complete_audit` pinned the field to 0 (while spawn/refused records
/// carried the real value), breaking correlation of recovery completions
/// against the observer event stream. TSV layout is
/// `seq · wallclock_ms · observer_ns · "complete" · agent_pid · …`, so the
/// `observer_ns` value lives at column index 2.
#[test]
fn complete_record_carries_completion_observer_ns() {
    const OBSERVER_NS: u64 = 1_234_567_890;
    let dir = audit_tmpdir("complete-obs-ns");
    let path = dir.join("audit.log");
    let (sink, _) = audit::RecoveryAuditLog::create(&path, audit::AuditConfig::default())
        .expect("create audit");

    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::ZERO,
    )
    .with_audit_sink(Some(sink));

    match rec.on_stall(321, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned, got {other:?}"),
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if Instant::now() >= deadline {
            panic!("timed out waiting for Reaped");
        }
        let outcomes = rec.try_reap(OBSERVER_NS);
        if outcomes
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(rec);

    let body = std::fs::read_to_string(&path).expect("read audit");
    let complete = body
        .lines()
        .find(|l| l.contains("\tcomplete\t321\t"))
        .expect("complete line for pid 321");
    let cols: Vec<&str> = complete.split('\t').collect();
    assert_eq!(cols[3], "complete", "column-layout sanity: {complete}");
    assert_eq!(
        cols[2],
        OBSERVER_NS.to_string(),
        "complete record observer_ns must be the completion-time value, not 0: {complete}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn capture_records_nonzero_length_for_chatty_child() {
    let dir = audit_tmpdir("capture");
    let path = dir.join("audit.log");
    let (sink, _) = audit::RecoveryAuditLog::create(&path, audit::AuditConfig::default())
        .expect("create audit");

    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "sh".to_string(),
            args: vec!["-c".to_string(), "printf '%64s' '' | tr ' ' X".to_string()],
        },
        Duration::ZERO,
    )
    .with_capture(4096)
    .with_audit_sink(Some(sink));

    match rec.on_stall(77, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned, got {other:?}"),
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        if Instant::now() >= deadline {
            panic!("timed out waiting for Reaped");
        }
        let outcomes = rec.try_reap(0);
        if outcomes
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(rec);

    let body = std::fs::read_to_string(&path).expect("read audit");
    let complete = body
        .lines()
        .find(|l| l.contains("\tcomplete\t77\t"))
        .expect("complete line");
    let cols: Vec<&str> = complete.split('\t').collect();
    let stdout_len: u32 = cols[10].parse().expect("stdout_len");
    assert!(
        stdout_len >= 64,
        "expected stdout_len ≥ 64, got {stdout_len}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn capture_truncates_at_per_child_cap() {
    let dir = audit_tmpdir("truncate");
    let path = dir.join("audit.log");
    let (sink, _) = audit::RecoveryAuditLog::create(&path, audit::AuditConfig::default())
        .expect("create audit");

    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                "head -c 10000 /dev/zero | tr '\\0' X".to_string(),
            ],
        },
        Duration::ZERO,
    )
    .with_capture(64)
    .with_audit_sink(Some(sink));

    match rec.on_stall(8, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned, got {other:?}"),
    }
    let deadline = Instant::now() + Duration::from_millis(2_000);
    loop {
        if Instant::now() >= deadline {
            panic!("timed out waiting for Reaped");
        }
        let outcomes = rec.try_reap(0);
        if outcomes
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(rec);

    let body = std::fs::read_to_string(&path).expect("read audit");
    let complete = body
        .lines()
        .find(|l| l.contains("\tcomplete\t8\t"))
        .expect("complete line");
    let cols: Vec<&str> = complete.split('\t').collect();
    let truncated = cols[12];
    assert_eq!(
        truncated, "true",
        "expected truncated=true, got: {complete}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: a recovery command that exits immediately but backgrounds a
/// grandchild inheriting the capture pipe write-end must not pin its
/// outstanding slot forever. The immediate child is reaped (`completed_status`
/// set), but the read-end never reaches EOF (the grandchild holds the
/// write-end) and stays below the cap (never `truncated`), so the two original
/// `capture_drained` terminal conditions are never met. The post-exit grace
/// is the only thing that reclaims the slot; without it, `on_stall` returns
/// `Debounced` for this pid forever and the leak can starve other pids.
#[test]
#[cfg_attr(miri, ignore)]
fn exited_child_with_open_inherited_pipe_is_reclaimed_after_grace() {
    const PID: u32 = 991;

    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            // The `sh` exits 0 immediately; the backgrounded `sleep` inherits
            // the piped stdout/stderr fds and keeps the write-end open well
            // past the grace window, so the read-end never sees EOF.
            program: "sh".to_string(),
            args: vec!["-c".to_string(), "sleep 10 & exit 0".to_string()],
        },
        Duration::ZERO,
    )
    .with_capture(8192);

    match rec.on_stall(PID, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned, got {other:?}"),
    }

    // Let the immediate `sh` exit, then reap once: this observes the exit and
    // stamps `completed_at`. Capture is NOT drained (pipe open, below cap), so
    // the slot must remain outstanding — this is exactly the wedged state.
    std::thread::sleep(Duration::from_millis(250));
    let early = rec.try_reap(0);
    assert!(
        !early
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Reaped { .. })),
        "must not reap before the post-exit grace elapses"
    );
    assert!(
        rec.outstanding.contains(PID),
        "exited child with an open inherited pipe must stay outstanding while draining"
    );

    // Past the grace the slot is reclaimed even though the pipe never reached
    // EOF — proving the leak is bounded rather than permanent.
    std::thread::sleep(POST_EXIT_CAPTURE_DRAIN_GRACE + Duration::from_millis(500));
    let mut reaped = false;
    for _ in 0..10 {
        if rec
            .try_reap(0)
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
        {
            reaped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        reaped,
        "slot must be reclaimed after the post-exit grace despite no pipe EOF"
    );
    assert!(
        !rec.outstanding.contains(PID),
        "outstanding slot must be freed after the grace-driven reap"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn capture_cap_closes_pipes_so_chatty_child_can_exit() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "yes".to_string(),
            args: vec!["X".to_string()],
        },
        Duration::ZERO,
    )
    .with_capture(64);

    match rec.on_stall(9, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned, got {other:?}"),
    }

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if Instant::now() >= deadline {
            panic!("chatty child stayed outstanding after capture cap");
        }
        let outcomes = rec.try_reap(0);
        if outcomes
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn completed_child_capture_drain_is_bounded_per_tick() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "head".to_string(),
            args: vec![
                "-c".to_string(),
                "6000".to_string(),
                "/dev/zero".to_string(),
            ],
        },
        Duration::ZERO,
    )
    .with_capture(8192);

    match rec.on_stall(10, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned, got {other:?}"),
    }

    std::thread::sleep(Duration::from_millis(100));
    let outcomes = rec.try_reap(0);
    assert!(
        !outcomes
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Reaped { .. })),
        "completed child should stay pending until bounded capture drain finishes"
    );
    let entry = rec
        .outstanding
        .get(10)
        .expect("completed child should remain outstanding during deferred capture drain");
    assert!(
        entry.stdout_len as usize <= CAPTURE_DRAIN_BYTES_PER_TICK,
        "one tick drained {} bytes, above budget {}",
        entry.stdout_len,
        CAPTURE_DRAIN_BYTES_PER_TICK
    );

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if Instant::now() >= deadline {
            panic!("timed out waiting for deferred capture drain");
        }
        let outcomes = rec.try_reap(0);
        if outcomes
            .iter()
            .any(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn audit_disabled_does_not_create_audit_file() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::ZERO,
    );
    match rec.on_stall(1, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned, got {other:?}"),
    }
}

#[test]
fn refuses_recovery_on_unauthenticated_origin_always() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::ZERO,
    );

    match rec.on_stall(42, BeatOrigin::NetworkUnverified, false, None, 0) {
        RecoveryOutcome::RefusedUnauthenticatedSource { pid } => assert_eq!(pid, 42),
        other => panic!("expected RefusedUnauthenticatedSource, got {other:?}"),
    }
    assert_eq!(rec.take_refused_unauthenticated_source(), 1);
    assert_eq!(rec.take_refused_unauthenticated_source(), 0);
}

#[test]
fn operator_attested_transport_fires_recovery() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::ZERO,
    );

    match rec.on_stall(42, BeatOrigin::OperatorAttestedTransport, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned, got {other:?}"),
    }
    assert_eq!(rec.take_refused_unauthenticated_source(), 0);
}

#[test]
fn refusal_does_not_burn_debounce_window() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::from_secs(60),
    );

    let _ = rec.on_stall(7, BeatOrigin::NetworkUnverified, false, None, 0);

    match rec.on_stall(7, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned, got {other:?}"),
    }
}

#[test]
fn spawn_failure_does_not_burn_debounce_window() {
    let dir = audit_tmpdir("spawn-failure-debounce");
    let missing = dir.join("missing-recovery-command");
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: missing.display().to_string(),
            args: vec![],
        },
        Duration::from_secs(60),
    );

    match rec.on_stall(7, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::SpawnFailed(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        other => panic!("expected SpawnFailed for missing command, got {other:?}"),
    }

    rec.mode = RecoveryMode::Exec {
        program: "true".to_string(),
        args: vec![],
    };

    match rec.on_stall(7, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("failed spawn must not debounce a later valid recovery, got {other:?}"),
    }

    drop(rec);
    let _ = std::fs::remove_dir_all(&dir);
}

/// PID-recycle regression (sibling of tracker bug-341/342): when the OS
/// recycles a recently-recovered PID to a *different* process within the
/// debounce window, the debounce ledger must NOT suppress the new process's
/// recovery. The fix keys the ledger on `(pid, generation)`; a `Some != Some`
/// generation proves the recycle and drops the stale window.
#[test]
fn recycled_pid_within_debounce_window_spawns_new_recovery() {
    const GEN_A: u64 = 111;
    const GEN_B: u64 = 222;
    let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(60));

    // Generation A stalls and recovers; ledger pins (42, GEN_A).
    match rec.on_stall(42, BeatOrigin::KernelAttested, false, Some(GEN_A), 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned for first generation, got {other:?}"),
    }
    // Reap A's child so the outstanding gate is clear; isolates the
    // last-fired (debounce) ledger as the sole remaining gate.
    std::thread::sleep(Duration::from_millis(50));
    let _ = rec.try_reap(0);

    // Within the SAME debounce window the kernel recycles PID 42 to an
    // unrelated process (generation B) that genuinely stalls. The old
    // bare-PID ledger returned Debounced here; the fix must spawn.
    match rec.on_stall(42, BeatOrigin::KernelAttested, false, Some(GEN_B), 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("recycled PID must not be debounced, got {other:?}"),
    }
    assert_eq!(
        rec.take_last_fired_recycle_resets(),
        1,
        "the recycle must be counted exactly once"
    );

    // The ledger is now re-pinned to generation B: a second B stall inside
    // the window is correctly debounced (proves the slot was overwritten,
    // not merely bypassed).
    std::thread::sleep(Duration::from_millis(50));
    let _ = rec.try_reap(0);
    match rec.on_stall(42, BeatOrigin::KernelAttested, false, Some(GEN_B), 0) {
        RecoveryOutcome::Debounced => {}
        other => panic!("same generation within window must debounce, got {other:?}"),
    }
    assert_eq!(rec.take_last_fired_recycle_resets(), 0);
}

/// Control: with no generation token (`OperatorAttestedTransport`, non-Linux)
/// or the *same* generation, the debounce ledger preserves its prior
/// bare-PID behaviour — a repeat stall within the window is suppressed.
#[test]
fn same_or_unknown_generation_within_debounce_window_is_debounced() {
    // Same generation.
    let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(60));
    let _ = rec.on_stall(5, BeatOrigin::KernelAttested, false, Some(111), 0);
    std::thread::sleep(Duration::from_millis(50));
    let _ = rec.try_reap(0);
    match rec.on_stall(5, BeatOrigin::KernelAttested, false, Some(111), 0) {
        RecoveryOutcome::Debounced => {}
        other => panic!("same generation must debounce, got {other:?}"),
    }

    // Unknown generation on both sides (lenient — never a recycle signal).
    let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(60));
    let _ = rec.on_stall(6, BeatOrigin::KernelAttested, false, None, 0);
    std::thread::sleep(Duration::from_millis(50));
    let _ = rec.try_reap(0);
    match rec.on_stall(6, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::Debounced => {}
        other => panic!("unknown generation must preserve bare-PID debounce, got {other:?}"),
    }
    assert_eq!(rec.take_last_fired_recycle_resets(), 0);
}

#[test]
fn refuses_recovery_on_cross_namespace_agent() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::ZERO,
    );

    match rec.on_stall(42, BeatOrigin::KernelAttested, true, None, 0) {
        RecoveryOutcome::RefusedCrossNamespace { pid } => assert_eq!(pid, 42),
        other => panic!("expected RefusedCrossNamespace, got {other:?}"),
    }
    assert_eq!(rec.take_refused_cross_namespace(), 1);
    assert_eq!(rec.take_refused_cross_namespace(), 0);
}

#[test]
fn opt_in_allows_recovery_on_cross_namespace_agent() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::ZERO,
    )
    .with_allow_cross_namespace(true);

    match rec.on_stall(42, BeatOrigin::KernelAttested, true, None, 0) {
        RecoveryOutcome::Spawned { .. } => {}
        other => panic!("expected Spawned with opt-in, got {other:?}"),
    }
    assert_eq!(rec.take_refused_cross_namespace(), 0);
}

#[test]
fn cross_namespace_gate_precedes_unauth_gate() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::ZERO,
    );

    match rec.on_stall(42, BeatOrigin::NetworkUnverified, true, None, 0) {
        RecoveryOutcome::RefusedCrossNamespace { pid } => assert_eq!(pid, 42),
        other => panic!("expected RefusedCrossNamespace, got {other:?}"),
    }
    assert_eq!(rec.take_refused_cross_namespace(), 1);
    assert_eq!(rec.take_refused_unauthenticated_source(), 0);
}

#[test]
fn last_fired_table_at_capacity_with_fresh_entries_refuses() {
    let mut table = LastFiredTable::with_capacity(4);
    let debounce = Duration::from_secs(10);
    let t0 = Instant::now();
    for pid in 10..14 {
        assert_eq!(
            table.try_insert(pid, None, t0, debounce),
            InsertOutcome::Inserted,
            "pid {pid} should fill an empty slot"
        );
    }
    assert_eq!(table.len(), 4);

    let result = table.try_insert(99, None, t0 + Duration::from_millis(1), debounce);
    assert_eq!(result, InsertOutcome::RefusedCapacity);
    assert!(table.get(99, None).is_none());
    assert_eq!(table.len(), 4);
}

#[test]
fn last_fired_table_at_capacity_evicts_oldest_past_debounce() {
    let mut table = LastFiredTable::with_capacity(4);
    let debounce = Duration::from_millis(100);
    let t0 = Instant::now();
    table.try_insert(10, None, t0, debounce);
    table.try_insert(11, None, t0 + Duration::from_millis(10), debounce);
    table.try_insert(12, None, t0 + Duration::from_millis(20), debounce);
    table.try_insert(13, None, t0 + Duration::from_millis(30), debounce);

    let now = t0 + Duration::from_millis(200);
    let outcome = table.try_insert(99, None, now, debounce);
    assert_eq!(outcome, InsertOutcome::EvictedOldest { evicted_pid: 10 });
    assert!(table.get(10, None).is_none());
    assert_eq!(table.get(99, None), Some(now));
    assert_eq!(table.get(11, None), Some(t0 + Duration::from_millis(10)));
    assert_eq!(table.get(12, None), Some(t0 + Duration::from_millis(20)));
    assert_eq!(table.get(13, None), Some(t0 + Duration::from_millis(30)));
}

#[test]
fn last_fired_table_refusal_does_not_burn_debounce_window() {
    let mut table = LastFiredTable::with_capacity(2);
    let debounce = Duration::from_millis(100);
    let t0 = Instant::now();
    table.try_insert(1, None, t0, debounce);
    table.try_insert(2, None, t0, debounce);

    let refused = table.try_insert(99, None, t0 + Duration::from_millis(50), debounce);
    assert_eq!(refused, InsertOutcome::RefusedCapacity);
    assert!(
        table.get(99, None).is_none(),
        "refusal must not leave a record"
    );

    let later = t0 + Duration::from_millis(200);
    let outcome = table.try_insert(99, None, later, debounce);
    assert!(matches!(
        outcome,
        InsertOutcome::EvictedOldest { .. } | InsertOutcome::Inserted
    ));
    assert_eq!(table.get(99, None), Some(later));
}

#[test]
fn last_fired_reservation_does_not_mutate_until_commit() {
    let mut table = LastFiredTable::with_capacity(1);
    let now = Instant::now();

    let reservation = table
        .try_reserve(99, None, now, Duration::from_secs(1))
        .expect("reservation should fit");

    assert_eq!(table.len(), 0);
    assert!(table.get(99, None).is_none());

    assert_eq!(table.commit_reserved(reservation), InsertOutcome::Inserted);
    assert_eq!(table.len(), 1);
    assert_eq!(table.get(99, None), Some(now));
}

#[test]
fn last_fired_eviction_reservation_preserves_old_slot_until_commit() {
    let mut table = LastFiredTable::with_capacity(1);
    let debounce = Duration::from_millis(100);
    let t0 = Instant::now();
    assert_eq!(
        table.try_insert(10, None, t0, debounce),
        InsertOutcome::Inserted
    );

    let later = t0 + Duration::from_millis(200);
    let reservation = table
        .try_reserve(99, None, later, debounce)
        .expect("old entry should be reservable for eviction");

    assert_eq!(table.get(10, None), Some(t0));
    assert!(table.get(99, None).is_none());

    assert_eq!(
        table.commit_reserved(reservation),
        InsertOutcome::EvictedOldest { evicted_pid: 10 }
    );
    assert!(table.get(10, None).is_none());
    assert_eq!(table.get(99, None), Some(later));
    assert_eq!(table.take_evictions(), 1);
}

#[test]
fn last_fired_table_prune_bounded_wcet() {
    let mut table = LastFiredTable::with_capacity(MAX_LAST_FIRED_CAPACITY);
    let t0 = Instant::now();
    for pid in 0..MAX_LAST_FIRED_CAPACITY as u32 {
        table.try_insert(pid.saturating_add(2), None, t0, Duration::ZERO);
    }
    assert_eq!(table.len(), MAX_LAST_FIRED_CAPACITY);

    let later = t0 + Duration::from_secs(60);
    let start = Instant::now();
    table.prune_expired(later, Duration::from_secs(1));
    let elapsed = start.elapsed();
    assert_eq!(table.len(), 0, "every entry exceeded the prune threshold");
    assert!(
        elapsed < Duration::from_millis(5),
        "prune_expired took {elapsed:?} — expected < 5 ms"
    );
}

#[test]
fn on_stall_refuses_when_debounce_table_at_capacity_with_fresh_entries() {
    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "true".to_string(),
            args: vec![],
        },
        Duration::from_secs(10),
    );
    rec.shrink_last_fired_for_test(2);

    for pid in 10..12u32 {
        match rec.on_stall(pid, BeatOrigin::KernelAttested, false, None, 0) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned for pid {pid}, got {other:?}"),
        }
    }

    match rec.on_stall(99, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::RefusedDebounceCapacity { pid } => assert_eq!(pid, 99),
        other => panic!("expected RefusedDebounceCapacity, got {other:?}"),
    }
    assert_eq!(rec.take_refused_debounce_capacity(), 1);
    assert_eq!(rec.take_refused_unauthenticated_source(), 0);
    assert_eq!(rec.take_refused_cross_namespace(), 0);
}

#[test]
#[cfg_attr(miri, ignore)]
fn outstanding_probe_exhaustion_refuses_before_spawning_child() {
    const CAPACITY: usize = 128;
    let cluster = pids_for_same_probe_cluster(CAPACITY, BoundedIndex::<u32>::MAX_PROBE + 1);
    let refused_pid = *cluster.last().expect("cluster contains refused pid");
    let dir = audit_tmpdir("outstanding-probe");
    let marker = dir.join("refused-child-spawned");
    let script = format!(r#"if [ "$1" = "{refused_pid}" ]; then : > "$2"; fi"#);

    let mut rec = Recovery::with_mode(
        RecoveryMode::Exec {
            program: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                script,
                "varta-recovery".to_string(),
                "{pid}".to_string(),
                marker.display().to_string(),
            ],
        },
        Duration::ZERO,
    )
    .with_outstanding_capacity(CAPACITY);

    for &pid in cluster.iter().take(BoundedIndex::<u32>::MAX_PROBE) {
        match rec.on_stall(pid, BeatOrigin::KernelAttested, false, None, 0) {
            RecoveryOutcome::Spawned { .. } => {}
            other => panic!("expected Spawned for clustered pid {pid}, got {other:?}"),
        }
    }

    match rec.on_stall(refused_pid, BeatOrigin::KernelAttested, false, None, 0) {
        RecoveryOutcome::RefusedOutstandingCapacity { pid } => assert_eq!(pid, refused_pid),
        other => panic!("expected RefusedOutstandingCapacity, got {other:?}"),
    }

    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !marker.exists(),
        "probe-exhaustion refusal must happen before spawning the recovery child"
    );
    assert_eq!(rec.take_refused_outstanding_capacity(), 1);
    assert_eq!(rec.take_outstanding_probe_exhausted(), 1);
    drop(rec);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg_attr(miri, ignore)]
fn try_reap_no_truncation_within_cap() {
    let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(10));
    for pid in 1u32..=3 {
        rec.on_stall(pid, BeatOrigin::KernelAttested, false, None, 0);
    }
    std::thread::sleep(Duration::from_millis(50));
    let outcomes = rec.try_reap(0);
    assert_eq!(rec.take_reap_truncated(), 0, "no truncation expected");
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
            .count(),
        3,
        "all 3 children should be reaped"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn try_reap_caps_and_cursor_advances() {
    let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(10));
    for pid in 1u32..=5 {
        rec.on_stall(pid, BeatOrigin::KernelAttested, false, None, 0);
    }
    rec.shrink_reap_max_for_test(2);
    std::thread::sleep(Duration::from_millis(100));

    let mut total_reaped = 0;
    let mut total_ticks = 0;
    for _ in 0..3 {
        let outcomes = rec.try_reap(0);
        total_reaped += outcomes
            .iter()
            .filter(|o| matches!(o, RecoveryOutcome::Reaped { .. }))
            .count();
        total_ticks += 1;
        if rec.outstanding.len() == 0 {
            break;
        }
    }
    assert_eq!(total_reaped, 5, "all 5 children eventually reaped");
    assert!(total_ticks <= 3, "at most 3 ticks to drain 5 with cap=2");
}

#[test]
#[cfg_attr(miri, ignore)]
fn try_reap_truncation_counter_increments_and_resets() {
    let mut rec = Recovery::new_exec("true".to_string(), vec![], Duration::from_secs(10));
    for pid in 1u32..=4 {
        rec.on_stall(pid, BeatOrigin::KernelAttested, false, None, 0);
    }
    rec.shrink_reap_max_for_test(2);
    std::thread::sleep(Duration::from_millis(100));

    rec.try_reap(0);
    assert_eq!(rec.take_reap_truncated(), 1, "one truncated tick");
    assert_eq!(rec.take_reap_truncated(), 0, "counter reset after drain");
}
