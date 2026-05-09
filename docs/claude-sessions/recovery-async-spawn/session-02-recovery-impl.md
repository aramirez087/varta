---
session: 02
title: "Recovery non-blocking spawn + try_reap + kill-after-timeout"
depends_on: [1]
touches:
  - "crates/varta-watch/src/recovery.rs"
  - "docs/roadmap/recovery-async-spawn/session-02-handoff.md"
parallel_safe: true
produces:
  - "crates/varta-watch/src/recovery.rs"
  - "docs/roadmap/recovery-async-spawn/session-02-handoff.md"
model: "opus"
---

# Session 02 — Recovery non-blocking spawn + try_reap + kill-after-timeout

```md
Continue from Session 01 artifacts in
docs/roadmap/recovery-async-spawn/session-01-handoff.md and
docs/architecture/recovery-async-spawn.md.

Mission: turn the failing recovery_e2e acceptance tests green by implementing
non-blocking spawn, asynchronous reaping, and kill-after-timeout enforcement
inside crates/varta-watch/src/recovery.rs.

Repository anchors:
- crates/varta-watch/src/recovery.rs (your only production target)
- crates/varta-watch/tests/recovery_e2e.rs (read-only — tests defined in 01)
- docs/architecture/recovery-async-spawn.md (the contract)

Constraints (do NOT violate):
- Touch only crates/varta-watch/src/recovery.rs. Do not edit config.rs,
  main.rs, lib.rs, or the recovery_e2e.rs / cli_smoke.rs test files —
  Session 03 owns CLI/main wiring and the tests are the contract.
- No registry dependencies. Use only std (`std::process::{Command, Child,
  ExitStatus}`, `std::time::{Duration, Instant}`, `std::collections::Vec`,
  `std::io`).
- No new threads, no background tasks, no async runtimes.

Tasks (TDD green phase):
1. Replace the blocking `.status()` call with `.spawn()`. On success, push a
   new `Outstanding { child_pid: u32, child: Child, started: Instant }` into
   `self.outstanding: Vec<Outstanding>` and return
   `RecoveryOutcome::Spawned { child_pid }`. On spawn failure return
   `SpawnFailed(io::Error)` and do not push.
2. Implement `try_reap(&mut self) -> Vec<RecoveryOutcome>`:
   - Iterate `self.outstanding` in place. For each entry call
     `child.try_wait()`.
     - `Ok(Some(status))` → drain entry, push `Reaped { child_pid, status }`.
     - `Ok(None)` and `started.elapsed() >= timeout` (when `Some`) → call
       `child.kill()`, then `child.wait()` to reap the corpse, drain entry,
       push `Killed { child_pid }`. If `kill` returns `InvalidInput` (already
       exited), retry `try_wait` once and treat success as `Reaped`.
     - `Ok(None)` otherwise → leave in place.
     - `Err(e)` → drain entry, push `ReapFailed(e)`.
   - Use `Vec::retain_mut` or a swap-remove pattern; the order of returned
     outcomes is unspecified.
3. Implement `Recovery::with_timeout(template, debounce, timeout)` and
   redirect `Recovery::new` to call it with `timeout = None`.
4. Update unit tests inside `mod tests` in src/recovery.rs to cover:
   - spawn returns immediately even for `sleep 1` templates,
   - try_reap on a freshly-spawned `true` returns `Reaped` after a brief
     `try_wait` wait loop,
   - try_reap kills after timeout for a `sleep 5` template with 100ms
     timeout,
   - dropping `Recovery` does not leak zombies (call try_reap or rely on
     `Drop` if you implement one — document the choice).
5. Run the recovery acceptance suite repeatedly under `cargo test -p
   varta-watch --test recovery_e2e -- --test-threads=1 --nocapture` until
   all four Session-01 acceptance tests pass.

Deliverables:
- crates/varta-watch/src/recovery.rs (rewritten)
- docs/roadmap/recovery-async-spawn/session-02-handoff.md describing the
  data model, kill semantics, the chosen `Drop` policy, and any caveats
  Session 03 must observe when calling `try_reap` from the loop.

Quality gates:
- cargo fmt --all -- --check
- cargo clippy --workspace -- -D warnings
- cargo build --workspace
- cargo test -p varta-watch --lib
- cargo test -p varta-watch --test recovery_e2e

Exit criteria: every recovery_e2e test added in Session 01 passes; the
existing `recovery_cmd_fires_once_per_stall_within_debounce` and
`recovery_cmd_template_substitutes_pid` tests still pass; clippy clean; no
new dependencies.
```
