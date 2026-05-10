# Recovery — Non-Blocking Spawn / Async Reap

> Status: charter (Session 01 of the `recovery-async-spawn` epic).
> Implementation lands in Sessions 02 (impl) and 03 (CLI + loop wiring).

## 1. Problem

`varta-watch` runs a single thread driving `Observer::poll` on a 100 ms
read-timeout cadence. When a stalled pid crosses its silence threshold,
the observer surfaces `Event::Stall` and the binary calls
`Recovery::on_stall(pid)`.

Today, `Recovery::on_stall` (`crates/varta-watch/src/recovery.rs:71`)
shells out via `Command::new("/bin/sh").arg("-c").arg(&rendered).status()`.
`status()` blocks the calling thread until the child exits, which means
the entire poll loop — beat decoding, exporter pumping, Prometheus
serving, stall surfacing for *other* pids — freezes for the duration
of the recovery template. A misbehaving template (`sleep 30`, a slow
restart script) effectively takes the observer offline.

This is blocker **B1** for v0.1.0.

## 2. Goal

Replace the blocking shell-out with a non-blocking spawn followed by an
asynchronous reap on subsequent observer ticks, and add an optional
kill-after deadline so a runaway template cannot consume an unbounded
recovery slot. All within the project's hard constraints:

- Zero registry dependencies in `varta-watch` (path-only deps).
- No new threads. No `tokio`, no executors.
- No `unsafe`. The crate already declares
  `#![deny(unsafe_op_in_unsafe_fn, rust_2018_idioms)]`.
- Library code does not print; diagnostics live in
  `crates/varta-watch/src/main.rs` only.

## 3. API surface (Session 01 lock-in)

The public surface in `varta_watch::recovery` becomes:

```rust
use std::process::ExitStatus;
use std::time::Duration;

#[derive(Debug)]
pub enum RecoveryOutcome {
    /// A child process was forked and is now outstanding. The observer
    /// has NOT waited on it. Reap on a later tick via `try_reap`.
    Spawned { child_pid: u32 },

    /// The previous invocation for this pid is still inside the per-pid
    /// debounce window; nothing was spawned.
    Debounced,

    /// `Command::spawn` failed before the shell could run (e.g. fork
    /// failure, `/bin/sh` missing). Surfaced verbatim.
    SpawnFailed(std::io::Error),

    /// A previously-`Spawned` child has exited and was reaped on this
    /// tick. The observer never blocks waiting for this transition.
    Reaped { child_pid: u32, status: ExitStatus },

    /// A previously-`Spawned` child exceeded `recovery_timeout` and was
    /// killed via `kill(2)` on this tick.
    Killed { child_pid: u32 },

    /// `try_wait` or `kill` failed for an outstanding child. The pid is
    /// still tracked; the observer will retry on the next tick.
    ReapFailed(std::io::Error),
}

pub struct Recovery { /* private */ }

impl Recovery {
    /// Backwards-compatible constructor. Equivalent to
    /// `with_timeout(template, debounce, None)`.
    pub fn new(template: String, debounce: Duration) -> Self;

    /// Construct a runner with an optional per-child deadline.
    ///
    /// `timeout = None` ⇒ children are reaped but never killed
    /// (preserves v0.1.0 semantics for users who tolerate long-running
    /// recovery templates).
    pub fn with_timeout(
        template: String,
        debounce: Duration,
        timeout: Option<Duration>,
    ) -> Self;

    /// Render `{pid}` and spawn `/bin/sh -c <rendered>` non-blockingly.
    /// Returns `Spawned`, `Debounced`, or `SpawnFailed` — never blocks.
    pub fn on_stall(&mut self, pid: u32) -> RecoveryOutcome;

    /// Drain completed (or deadline-exceeded) children for one observer
    /// tick. Returns one outcome per state transition observed:
    /// `Reaped`, `Killed`, or `ReapFailed`. Never blocks; returns an
    /// empty vector when no children have transitioned since the last
    /// tick.
    pub fn try_reap(&mut self) -> Vec<RecoveryOutcome>;
}
```

`Config` gains:

```rust
pub struct Config {
    /* existing fields */
    pub recovery_timeout: Option<Duration>,
}
```

The `--recovery-timeout-ms <MS>` flag is **not** parsed in Session 01 —
that is Session 03's deliverable. Session 01 only widens the type.

## 4. Lifecycle of one recovery

```
                    debounce-suppressed
                ┌──────────────► Debounced
                │
  Event::Stall ─┤                                  spawn ok
                │                              ┌────────────► Outstanding
                └─► Recovery::on_stall(pid) ───┤
                                               │ spawn err
                                               └────────────► SpawnFailed
                                                              (terminal)

  on every Observer tick:
      Recovery::try_reap()
         │
         ├─► child exited ─────► Reaped { child_pid, status }   (terminal)
         │
         ├─► deadline exceeded ─► kill(2) ─► Killed { child_pid } (terminal)
         │
         └─► try_wait/kill errno ─► ReapFailed(io::Error)        (retry)
```

`Outstanding` lives in a `HashMap<u32, _>` keyed by stalled pid (cold
path; allocation acceptable per the operator rules). One outstanding
child per stalled pid; if the pid stalls again while a child is still
outstanding, the per-pid debounce window suppresses a duplicate spawn.

## 5. Tick budget

The observer's `READ_TIMEOUT` is 100 ms. `try_reap` is invoked once
per `Observer::poll` iteration (Session 02 owns the wiring). Worst-case
latencies:

| Event | Latency upper bound |
|---|---|
| Successful child → `Reaped` surfaces | one tick (≤ 100 ms) after exit |
| Deadline exceeded → `Killed` surfaces | one tick (≤ 100 ms) after deadline |
| `kill(2)` → `Reaped` of killed child  | one further tick (≤ 100 ms) |

These are *additive* with the observer's normal stall-detection
latency; they do not affect beat decoding or exporter throughput on
the critical path.

## 6. Default behaviour when `--recovery-timeout-ms` is omitted

`Config::recovery_timeout = None` is the default. In that mode,
`Recovery::with_timeout` stores no deadline; outstanding children are
reaped on completion but are **never killed**. This preserves v0.1.0
semantics for operators whose recovery templates are intentionally
long-running (e.g. service restarts that block on health checks).

Operators who want the kill-after behaviour set
`--recovery-timeout-ms <MS>` explicitly. Sub-100 ms values still work
but the kill is surfaced no faster than one tick after the deadline.

## 7. Concurrency model

- Children are pid-indexed in `HashMap<u32, Outstanding>`. The
  observer's `Tracker` is bounded to 64 distinct pids, so the map
  caps at 64 outstanding children in steady state.
- Debounce is per-pid and unchanged. A repeat stall for the same pid
  inside the debounce window returns `Debounced` regardless of whether
  a child is still outstanding.
- No locks; the `Recovery` struct is owned exclusively by the binary's
  poll loop and is `!Send` by virtue of holding `std::process::Child`
  values, which is fine since the observer is single-threaded.

## 8. Out of scope for this epic

- `varta-vlp` (frame ABI is frozen).
- `varta-client` (no agent-side change).
- Observer poll cadence (still 100 ms read timeout).
- Exporter line schema.
- Panic-handler feature.

## 9. Cross-references

- Session 02 (`docs/claude-sessions/recovery-async-spawn/session-02-recovery-impl.md`)
  owns the green-phase implementation in `crates/varta-watch/src/recovery.rs`
  and the `try_reap` wiring in `crates/varta-watch/src/main.rs` /
  `observer.rs`.
- Session 03 (`docs/claude-sessions/recovery-async-spawn/session-03-cli-and-loop-integration.md`)
  owns the `--recovery-timeout-ms` parser, the HELP-text update, and
  threading `cfg.recovery_timeout` into `Recovery::with_timeout` at
  the binary call site.
- Acceptance contract: `docs/acceptance/varta-v0-1-0.md`, subsection
  *Recovery — non-blocking*.

## 10. Failing tests gating Sessions 02 and 03

Session 01 lands these as **red-phase** acceptance tests:

| Test | File | Owned by |
|---|---|---|
| `recovery_spawn_returns_within_50ms_for_slow_template` | `crates/varta-watch/tests/recovery_e2e.rs` | Session 02 |
| `recovery_try_reap_yields_reaped_for_completed_child`  | `crates/varta-watch/tests/recovery_e2e.rs` | Session 02 |
| `recovery_try_reap_kills_after_timeout`                | `crates/varta-watch/tests/recovery_e2e.rs` | Session 02 |
| `recovery_concurrent_pids_run_in_parallel`             | `crates/varta-watch/tests/recovery_e2e.rs` | Session 02 |
| `cli_help_lists_recovery_timeout_ms_flag`              | `crates/varta-watch/tests/cli_smoke.rs`    | Session 03 |
| `cli_parses_recovery_timeout_ms`                       | `crates/varta-watch/tests/cli_smoke.rs`    | Session 03 |
