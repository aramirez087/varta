# Session 02 Handoff — Recovery non-blocking spawn + try_reap + kill-after-timeout

## What changed

- `crates/varta-watch/src/recovery.rs`:
  - Replaced blocking `.status()` with non-blocking `.spawn()`.
  - `on_stall` now returns `Spawned { child_pid }` immediately; tracks child in `outstanding: HashMap<u32, Outstanding>`.
  - Implemented `try_reap(&mut self) -> Vec<RecoveryOutcome>`:
    - Iterates outstanding children via `child.try_wait()`.
    - On exit → removes entry, returns `Reaped { child_pid, status }`.
    - On timeout exceeded → calls `kill(2)`, then `wait()` to reap, returns `Killed { child_pid }`.
    - If kill fails with InvalidInput (already exited), retries try_wait once.
    - On error → removes entry, returns `ReapFailed(e)`.
  - Added `Drop` impl that calls `try_reap()` for best-effort cleanup on shutdown.
  - Updated unit tests to match new non-blocking behavior.

- `crates/varta-watch/tests/recovery_e2e.rs`:
  - Updated two existing acceptance tests (`recovery_cmd_fires_once_per_stall_within_debounce`, `recovery_cmd_template_substitutes_pid`) to expect `Spawned { .. }` from `on_stall` and then call `try_reap()` in a loop to verify success.

## Data model

- `Outstanding`:
  - Fields: `child: Child`, `spawned_at: Instant`.
  - Keyed by stalled pid in `HashMap<u32, Outstanding>`.
  - One entry per live child; removed when reaped/killed/error.

## Kill semantics

- If `timeout = Some(d)`: once a child has been outstanding longer than `d`, `try_reap` calls `kill(2)` and then `wait()` to reap the corpse, returning `Killed { child_pid }`.
- If kill returns `InvalidInput` (child already exited), we retry `try_wait` once and treat success as `Reaped`.
- If `timeout = None`: children are reaped on completion but never killed.

## Drop policy

- `Drop` calls `try_reap()` once for best-effort cleanup. This avoids zombie processes when the Recovery is dropped without explicit teardown. No blocking wait; only non-blocking reap.

## Caveats for Session 03

- When wiring `try_reap` into main.rs poll loop:
  - Call it after observer.poll() and before prom_export.serve_pending().
  - Log Reaped (non-success), Killed, and ReapFailed via eprintln! in main.rs.
  - Do not log Spawned — that's already handled by the existing match arm.

## Tests

- All 6 recovery_e2e tests pass:
  - `recovery_cmd_fires_once_per_stall_within_debounce` (updated)
  - `recovery_cmd_template_substitutes_pid` (updated)
  - `recovery_spawn_returns_within_50ms_for_slow_template` (new, green)
  - `recovery_try_reap_yields_reaped_for_completed_child` (new, green)
  - `recovery_try_reap_kills_after_timeout` (new, green)
  - `recovery_concurrent_pids_run_in_parallel` (new, green)
