# Recovery — Non-Blocking Spawn / Async Reap

This page documents how `varta-watch` keeps the observer loop responsive
while still firing recovery commands on stalled agents.

Implementation lives in
[`crates/varta-watch/src/recovery/`](https://github.com/aramirez087/Varta/tree/main/crates/varta-watch/src/recovery)
and is wired into the poll loop from
[`crates/varta-watch/src/main.rs`](https://github.com/aramirez087/Varta/blob/main/crates/varta-watch/src/main.rs).

## Why this exists

`varta-watch` runs a single thread driving `Observer::poll` on a 100 ms
read-timeout cadence. When a pid crosses its silence threshold the
observer surfaces `Event::Stall` and the binary calls
`Recovery::on_stall(pid)`.

A naive implementation would block the calling thread on the recovery
child until it exits. That would freeze the entire poll loop — beat
decoding, exporter pumping, Prometheus serving, and stall detection for
every *other* pid — for the duration of one recovery command. A slow
recovery template would take the observer offline.

Instead, `Recovery::on_stall` performs a non-blocking spawn and returns
immediately. Outstanding children are reaped (or killed past their
deadline) on subsequent observer ticks.

## Constraints

These follow from the workspace-wide hard rules (see
[CLAUDE.md](https://github.com/aramirez087/Varta/blob/main/CLAUDE.md)):

- Zero registry dependencies in `varta-watch` (path-only).
- No new threads. No `tokio`, no executors.
- No `unsafe`.
- Library code does not print; diagnostics live in `main.rs` only.

## Public API

```rust
use std::process::ExitStatus;
use std::time::Duration;

#[derive(Debug)]
pub enum RecoveryOutcome {
    /// A child process was forked and is now outstanding. The observer
    /// has NOT waited on it. Reap on a later tick via `try_reap`.
    Spawned { child_pid: u32 },

    /// Previous invocation for this pid is still inside the per-pid
    /// debounce window; nothing was spawned.
    Debounced,

    /// `Command::spawn` failed (e.g. fork failure, program not found).
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

impl Recovery {
    pub fn with_exec_and_timeout(
        program: String,
        args: Vec<String>,
        debounce: Duration,
        timeout: Option<Duration>,
    ) -> Self;

    /// Spawn the configured program with the stalled pid appended as
    /// the final argument. Returns immediately; never blocks.
    pub fn on_stall(&mut self, pid: u32) -> RecoveryOutcome;

    /// Drain completed (or deadline-exceeded) children for one tick.
    /// Returns one outcome per state transition; empty when no children
    /// have transitioned since the last call.
    pub fn try_reap(&mut self) -> Vec<RecoveryOutcome>;
}
```

## Lifecycle of one recovery

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

## Outstanding-child storage

`Outstanding` records live in
[`OutstandingTable`](https://github.com/aramirez087/Varta/blob/main/crates/varta-watch/src/outstanding_table.rs),
a `BoundedIndex`-backed slab keyed by stalled pid. The table is sized to
`tracker::MAX_CAPACITY = 4096` at construction
(`recovery/mod.rs:436`), so the recovery system can never hold more
outstanding children than the tracker can hold pids — both bounded
collections share the same ceiling. Operators raise the cap with
`--tracker-capacity`; see
[Deployment Ceiling & Sharding](deployment-ceiling-and-sharding.md).

When the table is full a fresh `on_stall` returns the bounded equivalent
of `Debounced` and increments
`varta_recovery_refused_total{reason="outstanding_capacity"}`
(`recovery/mod.rs:786`). See
[Bounded Collections](bounded-collections.md) for the table's allocation
proof and the static-allocation rationale.

One outstanding child per stalled pid; if the pid stalls again while a
child is still outstanding, the per-pid debounce window suppresses a
duplicate spawn regardless of the table state.

## Tick budget

Observer `READ_TIMEOUT` is 100 ms. `try_reap` is invoked once per
`Observer::poll` iteration. Worst-case latencies:

| Event | Latency upper bound |
|---|---|
| Successful child → `Reaped` surfaces | one tick (≤ 100 ms) after exit |
| Deadline exceeded → `Killed` surfaces | one tick (≤ 100 ms) after deadline |
| `kill(2)` → `Reaped` of killed child  | one further tick (≤ 100 ms) |

These are *additive* with the observer's normal stall-detection latency;
they do not affect beat decoding or exporter throughput on the critical
path.

## Default behaviour when `--recovery-timeout-ms` is omitted

`Config::recovery_timeout = None` is the default. In that mode
outstanding children are reaped on completion but **never killed**.
This preserves long-running-recovery semantics (e.g. a restart that
blocks on health checks).

Operators who want the kill-after behaviour set
`--recovery-timeout-ms <MS>` explicitly. Sub-100 ms values still work
but the kill is surfaced no faster than one tick after the deadline.

## Concurrency model

- The `Recovery` struct is owned exclusively by the binary's poll loop.
  It is `!Send` by virtue of holding `std::process::Child` values, which
  is fine since the observer is single-threaded.
- No locks anywhere on the recovery path.
- Debounce is per-pid; a repeat stall inside the debounce window
  returns `Debounced` regardless of whether a child is still outstanding.

## Recovery child environment policy

Recovery subprocesses run with an **isolated environment by default**:
the inherited observer environment is wiped, and the child only sees
`PATH=/usr/bin:/bin` plus any explicit `--recovery-env KEY=VALUE`
entries.

Rationale: observers typically run with secrets in their process
environment — `AWS_*`, `GOOGLE_APPLICATION_CREDENTIALS`, OAuth bearer
tokens, database URLs, Vault tokens. Inheriting that environment into
a recovery child means any recovery template (or any binary on the
recovery allowlist) becomes a credential-exfiltration vector. The blast
radius is catastrophic and silent. The observer default-clears.

Configuration matrix:

| Flags | Child env |
|---|---|
| *(none)* | `PATH=/usr/bin:/bin` only |
| `--recovery-env KEY=VAL` (one or more) | `PATH=/usr/bin:/bin` + explicit allowlist |
| `--recovery-inherit-env` | Full observer env inherited |
| `--recovery-inherit-env --recovery-env KEY=VAL` | Inherited env + explicit overrides |

Operators whose recovery templates relied on inherited variables
(e.g. `$HOME` for log paths) have two options:

1. Preferred — allowlist explicitly: `--recovery-env HOME=/var/log/varta`.
2. Escape hatch — full inheritance: pass `--recovery-inherit-env`. The
   observer emits a one-shot stderr warning at startup naming the risk
   so the choice is visible in SIEM/syslog audit trails.

Enforcement is centralised in `Recovery::apply_env`
([`recovery/mod.rs`](https://github.com/aramirez087/Varta/blob/main/crates/varta-watch/src/recovery/mod.rs));
all exec-mode children flow through it.

## Out of scope

- `varta-vlp` — frame ABI is frozen.
- `varta-client` — no agent-side change.
- Observer poll cadence — still 100 ms read timeout.
- Exporter line schema.
- Panic-handler feature.

## See also

- [Stall Detection & Liveness](observer-liveness.md) — how the observer
  surfaces `Event::Stall` in the first place.
- [Bounded Collections](bounded-collections.md) — the static-allocation
  proof for `OutstandingTable` and `Tracker`.
- [Deployment Ceiling & Sharding](deployment-ceiling-and-sharding.md) —
  what 4096 means in practice and how to scale past it.
- [Audit Logging](audit-log.md) — every recovery decision (Spawned /
  Debounced / Refused / Reaped / Killed) emits a TSV record.
