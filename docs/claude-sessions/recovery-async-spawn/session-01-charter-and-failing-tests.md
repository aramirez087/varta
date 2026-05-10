---
session: 01
title: "Charter, API contract, failing tests"
depends_on: []
touches:
  - "docs/acceptance/varta-v0-1-0.md"
  - "docs/architecture/recovery-async-spawn.md"
  - "crates/varta-watch/src/recovery.rs"
  - "crates/varta-watch/src/config.rs"
  - "crates/varta-watch/src/lib.rs"
  - "crates/varta-watch/tests/recovery_e2e.rs"
  - "crates/varta-watch/tests/cli_smoke.rs"
  - "docs/roadmap/recovery-async-spawn/**"
parallel_safe: false
produces:
  - "docs/architecture/recovery-async-spawn.md"
  - "docs/acceptance/varta-v0-1-0.md"
  - "crates/varta-watch/src/recovery.rs"
  - "crates/varta-watch/src/config.rs"
  - "crates/varta-watch/tests/recovery_e2e.rs"
  - "crates/varta-watch/tests/cli_smoke.rs"
  - "docs/roadmap/recovery-async-spawn/session-01-handoff.md"
model: "opus"
---

# Session 01 — Charter, API contract, failing tests

```md
Mission: design the non-blocking recovery API and write the failing tests that
will drive sessions 02 and 03 (TDD red phase). Compilation must succeed; the
new acceptance tests must compile and run but FAIL.

Repository anchors (read before changing):
- crates/varta-watch/src/recovery.rs (existing blocking impl, line 71)
- crates/varta-watch/src/observer.rs (poll-loop cadence, READ_TIMEOUT)
- crates/varta-watch/src/main.rs (recovery call site)
- crates/varta-watch/src/config.rs (CLI flag surface, HELP text)
- crates/varta-watch/tests/recovery_e2e.rs (existing acceptance tests)
- crates/varta-watch/tests/cli_smoke.rs (existing CLI surface tests)
- docs/acceptance/varta-v0-1-0.md (contract — test names are load-bearing)

Tasks:
1. Write docs/architecture/recovery-async-spawn.md describing:
   - the new `RecoveryOutcome` variants: keep `Spawned { child_pid: u32 }`
     (no longer carries ExitStatus), `Debounced`, `SpawnFailed(io::Error)`;
     add `Reaped { child_pid: u32, status: ExitStatus }`,
     `Killed { child_pid: u32 }`, `ReapFailed(io::Error)`,
   - new `Recovery::with_timeout(template, debounce, timeout: Option<Duration>)`,
   - new `Recovery::try_reap(&mut self) -> Vec<RecoveryOutcome>` invoked
     once per observer tick,
   - new `Config::recovery_timeout: Option<Duration>` from `--recovery-timeout-ms`,
   - default behaviour when timeout is `None` (children are reaped but never
     killed).
2. Add the API STUBS in src/recovery.rs (new variants and methods that compile
   but `unimplemented!()` or return empty `Vec`). Keep `Recovery::new` working
   but route it to `with_timeout(.., None)`. Do NOT remove the blocking
   `.status()` call yet — sessions 02/03 own that.
3. Add `recovery_timeout: Option<Duration>` to `Config` with a stub default of
   `None`. Do NOT add the `--recovery-timeout-ms` parsing yet — Session 03
   owns config.rs parsing.
4. Append failing tests to crates/varta-watch/tests/recovery_e2e.rs:
   - `recovery_spawn_returns_within_50ms_for_slow_template`
   - `recovery_try_reap_yields_reaped_for_completed_child`
   - `recovery_try_reap_kills_after_timeout`
   - `recovery_concurrent_pids_run_in_parallel`
5. Append failing tests to crates/varta-watch/tests/cli_smoke.rs:
   - `cli_help_lists_recovery_timeout_ms_flag`
   - `cli_parses_recovery_timeout_ms`
6. Update docs/acceptance/varta-v0-1-0.md: add the six test names above to
   the contract under a new "Recovery — non-blocking" subsection.
7. Run `cargo build --workspace`, `cargo fmt --all -- --check`,
   `cargo clippy --workspace -- -D warnings`. Confirm `cargo test -p
   varta-watch` shows the six new tests FAILING (red phase).

Deliverables:
- All files listed in `produces:` above.
- docs/roadmap/recovery-async-spawn/session-01-handoff.md listing the chosen
  API, exact failing test names, and the file regions Sessions 02 and 03 may
  modify (recovery.rs vs config.rs+main.rs).

Quality gates:
- cargo fmt --all -- --check
- cargo clippy --workspace -- -D warnings
- cargo build --workspace
- cargo test -p varta-watch (red: new tests fail; preexisting pass)

Exit criteria: workspace compiles; new acceptance tests are present and
failing; architecture and contract docs published; handoff lists clean
file ownership for the next wave.
```
