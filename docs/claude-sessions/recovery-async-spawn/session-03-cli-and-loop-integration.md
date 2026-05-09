---
session: 03
title: "CLI flag + observer poll-loop integration"
depends_on: [1]
touches:
  - "crates/varta-watch/src/config.rs"
  - "crates/varta-watch/src/main.rs"
  - "docs/roadmap/recovery-async-spawn/session-03-handoff.md"
parallel_safe: true
produces:
  - "crates/varta-watch/src/config.rs"
  - "crates/varta-watch/src/main.rs"
  - "docs/roadmap/recovery-async-spawn/session-03-handoff.md"
model: "opus"
---

# Session 03 — CLI flag + observer poll-loop integration

```md
Continue from Session 01 artifacts in
docs/roadmap/recovery-async-spawn/session-01-handoff.md and
docs/architecture/recovery-async-spawn.md.

Mission: parse `--recovery-timeout-ms`, plumb it into `Recovery::with_timeout`,
and call `recovery.try_reap()` once per observer tick so reaped/killed
children produce diagnostic output and the loop never blocks.

Repository anchors:
- crates/varta-watch/src/config.rs (CLI parser + HELP text)
- crates/varta-watch/src/main.rs (the poll loop)
- crates/varta-watch/src/recovery.rs (read-only — Session 02 owns it)
- crates/varta-watch/tests/cli_smoke.rs (read-only — contract from 01)

Constraints:
- Touch only config.rs and main.rs. Do not modify recovery.rs, lib.rs, or
  any test file. Do not introduce dependencies.
- The poll loop stays single-threaded. Adding a worker thread or a runtime
  fails review.

Tasks (TDD green phase):
1. In config.rs:
   - Add `recovery_timeout: Option<Duration>` to `Config`.
   - Parse `--recovery-timeout-ms <MS>` as `u64` → `Duration::from_millis`.
   - Update `Config::HELP` to list the flag in OPTIONAL with prose roughly:
     "Send SIGKILL to a recovery child still running after this many
     milliseconds." Keep alphabetical/logical ordering with the existing
     `--recovery-debounce-ms`.
   - Extend `help_text_lists_every_known_flag` only by adding the new flag
     to its array (the test file is owned by the cli_smoke contract; this
     test is the in-module unit test inside config.rs).
   - Extend the `parses_full_flag_surface` unit test to include
     `--recovery-timeout-ms 250` and assert the value.
2. In main.rs:
   - Construct `Recovery` via `Recovery::with_timeout(template, debounce,
     cfg.recovery_timeout)`.
   - On every loop iteration (after the existing observer.poll handling and
     before the `prom_export.serve_pending` call), invoke
     `recovery.as_mut().map(|r| r.try_reap())` and log non-success outcomes
     via `eprintln!` exactly as the existing `Spawned` branch does.
       - `Reaped { child_pid, status }` with `!status.success()` →
         `varta-watch: recovery child {child_pid} exited {status}`.
       - `Killed { child_pid }` →
         `varta-watch: recovery child {child_pid} killed after timeout`.
       - `ReapFailed(e)` → `varta-watch: recovery reap failed: {e}`.
   - Update the existing `RecoveryOutcome::Spawned` match to use
     `Spawned { child_pid }` (no longer carries ExitStatus). Spawning is now
     an information-only event — log nothing, or eprintln a single line at
     debug verbosity.
3. Run `cargo test -p varta-watch --test cli_smoke` until both new tests
   from Session 01 pass.

Deliverables:
- crates/varta-watch/src/config.rs (with the new flag)
- crates/varta-watch/src/main.rs (with try_reap drain in the loop)
- docs/roadmap/recovery-async-spawn/session-03-handoff.md describing the
  exact eprintln formats (load-bearing for the metrics session) and the
  loop ordering.

Quality gates:
- cargo fmt --all -- --check
- cargo clippy --workspace -- -D warnings
- cargo build --workspace
- cargo test -p varta-watch --lib
- cargo test -p varta-watch --test cli_smoke

Exit criteria: both Session-01 cli_smoke tests pass; HELP lists every flag;
the binary runs `--help` and `--recovery-timeout-ms 250` without error.
```
