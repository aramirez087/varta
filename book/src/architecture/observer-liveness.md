# Observer Liveness — "Who Watches the Watcher?"

`varta-watch` is the single observer for all agents on a host.  If it crashes
or its poll loop hangs, no agent gets a `Stall` event and no recovery fires —
the entire monitoring layer fails silently.  For life-support deployments this
is the most critical functional gap.

This document describes four independent, layered defenses.  Deploy as many as
your environment supports; each catches failure modes the others cannot.

---

## Threat model

| Failure mode | L1 | L2 | L3 | L4 |
|---|:---:|:---:|:---:|:---:|
| Poll loop hangs (stuck in I/O or computation) | ✓ | ✓* | ✗ | ✓ |
| Process crash (SIGSEGV, stack overflow, OOM) | ✗ | ✓ | ✓† | ✓ |
| Watchdog thread dies silently (panic, signal) | ✗ | ✓‡ | ✓† | ✓ |
| Kernel hang / host deadlock | ✗ | ✗ | ✓ | ✗ |
| Misconfiguration (wrong socket path, wrong user) | ✗ | ✗ | ✗ | ✓ |

*systemd detects a hang only if `WATCHDOG=1` stops arriving; the self-watchdog
ensures that also stops when the loop wedges.  
†hardware watchdog fires when the kick loop stops; process crash achieves this.  
‡since H5 the watchdog thread is the *sole* source of `WATCHDOG=1`; if it
dies, the emission stream stops and systemd's `WatchdogSec=` fires.

---

## L1 — In-process self-watchdog (`--self-watchdog-secs`)

A background thread checks that the main poll loop has ticked at least once
within the configured deadline.  If not, it calls `process::abort()`.

```sh
varta-watch --self-watchdog-secs 4 ...
```

- The background thread is the **only non-main thread** in the binary.  The
  beat path and observer loop remain single-threaded.
- `process::abort()` produces SIGABRT, which appears in `journalctl`, enables
  core dumps, and triggers `Restart=on-abort` in systemd units.
- The deadline should be set to roughly 2× the expected worst-case poll
  latency (typically `--threshold-ms` + reaping time).
- **Per-stage wedge detection (H6):** in addition to the full-iteration check,
  the watchdog reads two atomics written by the main thread —
  `CURRENT_STAGE` (which of the six loop phases is running) and
  `LAST_STAGE_ENTRY_NS` (monotonic ns at which that phase started).  Each
  stage has an independent hard abort threshold in `STAGE_ABORT_NS` (≥ 5×
  the stage's soft budget):

  | Stage | Hard abort threshold |
  |---|---|
  | `drain_pending` | 2 s |
  | `poll` | 2 s |
  | `maintenance` | 500 ms |
  | `recovery_reap` | 1 s |
  | `serve_pending` | 2 s |
  | `housekeeping` | 1 s |

  A stage wedge (e.g. an `fdatasync` blocking indefinitely, or a single
  `waitpid` hanging) trips the per-stage threshold long before the
  full-iteration watchdog fires.  The watchdog logs which stage wedged and
  aborts.  Between iterations `CURRENT_STAGE` is set to `u8::MAX` (idle
  sentinel) so the per-stage check is suppressed during throttle sleeps.
- **H5 (post-2026-05-13):** the watchdog thread is ALSO the sole emitter of
  systemd `WATCHDOG=1`.  Emission used to live on the main loop, which left
  a silent-failure window: if the watchdog thread died while the main loop
  remained healthy, `WATCHDOG=1` kept arriving from the main thread and
  systemd had no way to notice the in-process abort path was already gone.
  Now `WATCHDOG=1` emission is moved to the watchdog thread (via a
  `dup(2)`-ed copy of the notify socket carved off `SdNotify` with
  `take_watchdog_notifier`).  If the thread dies, the emission stream stops
  and `WatchdogSec=` fires.  This is the only design where systemd can
  detect a dead watchdog while the main loop is still alive.
- **Auto-enable:** when `$WATCHDOG_USEC` is set by the service manager and
  `--self-watchdog-secs` is *not* passed, the watchdog thread is spawned
  unconditionally with a 4 s deadline.  Operators with tighter
  `WatchdogSec=` values can override via the CLI.  This collapses the L1+L2
  layers structurally: enabling `WatchdogSec=` in the unit automatically
  buys both the in-process abort path and the WATCHDOG=1 emission stream.

---

## L2 — systemd `sd_notify` watchdog integration

`varta-watch` speaks the `sd_notify(3)` protocol natively.  Set
`Type=notify` in the service unit and configure `WatchdogSec=`:

```ini
[Service]
Type=notify
NotifyAccess=main
WatchdogSec=5s
Restart=on-watchdog
RestartSec=1s
TimeoutStartSec=10s
ExecStart=/usr/bin/varta-watch \
    --socket /run/varta/agents.sock \
    --threshold-ms 5000 \
    --self-watchdog-secs 4 \
    --hw-watchdog /dev/watchdog \
    --heartbeat-file /run/varta/heartbeat
```

`varta-watch` sends:

- `READY=1` after observer bind succeeds and all listeners are attached
- `WATCHDOG=1` every `WATCHDOG_USEC / 2` microseconds while the poll loop runs
- `STOPPING=1` when the SHUTDOWN latch flips

If `WATCHDOG=1` stops arriving, systemd kills and restarts the process.  This
catches both crashes (no more sends) and hangs (LAST_TICK_NS stops advancing,
the self-watchdog aborts, systemd restarts).

`$NOTIFY_SOCKET` and `$WATCHDOG_USEC` are passed automatically by systemd;
no extra flags are needed.

---

## L3 — Hardware watchdog (`--hw-watchdog`)

On hosts with a kernel hardware watchdog (e.g. `/dev/watchdog`), `varta-watch`
can kick it once per poll iteration.  If the kick stops, the kernel reboots the
host — even if the OS itself is wedged.

```sh
varta-watch --hw-watchdog /dev/watchdog ...
```

**Magic close:** on a clean shutdown (SIGTERM/SIGINT followed by graceful exit)
`varta-watch` writes the magic byte `'V'` to disarm the watchdog before
exiting.  A crash or hang leaves the watchdog armed; the kernel reboots after
its timeout.

The `/dev/watchdog` device is typically root-owned (mode 0600).  Run
`varta-watch` as root or grant the `CAP_SYS_ADMIN` capability, or use a
watchdog daemon (e.g. `watchdog(8)`) for the actual device management.

---

## L4 — Paired observers (operational)

A second monitoring process scrapes the first observer's liveness signals and
restarts it if they stall.  This requires no code changes — use the existing
`--heartbeat-file` and `/metrics` primitives.

### Heartbeat-file poller

```bash
#!/bin/sh
HEARTBEAT=/run/varta/heartbeat
while :; do
    prev=$(awk '{print $1}' "$HEARTBEAT" 2>/dev/null || echo 0)
    sleep 5
    cur=$(awk '{print $1}' "$HEARTBEAT" 2>/dev/null || echo 0)
    if [ "$cur" -le "$prev" ]; then
        logger -t varta-watchdog "heartbeat stalled (loop_count=$prev); restarting"
        systemctl restart varta-watch
    fi
done
```

The first field in the heartbeat file is a monotonically increasing loop
counter.  If it stops advancing, the observer is wedged or dead.

### Prometheus uptime scraper

`/metrics` exposes `varta_watch_uptime_seconds`.  A second Prometheus instance
(or Alertmanager rule) can alert when the gauge stops increasing. The
canonical `VartaWatchStalled` rule ships in
[`observability/alerts/varta.rules.yml`](https://github.com/aramirez087/Varta/blob/main/observability/alerts/varta.rules.yml);
see [Monitoring & Alerting](../operations/monitoring.md#vartawatchstalled)
for the operator-facing rationale.

---

## Threading note

`--self-watchdog-secs` spawns one background thread.  This is the **only
non-main thread** in the `varta-watch` binary, and that property is a
**load-bearing architectural invariant**, not an accident.  All agent beat
processing, stall detection, recovery spawning, and Prometheus serving happen
on the main thread.  The watchdog thread reads two atomics (`SHUTDOWN`
and `LAST_TICK_NS`), calls `process::abort()` on wedge, and writes
`WATCHDOG=1` to its own `dup(2)`-ed `UnixDatagram` fd; it never touches
shared mutable state.  The dup-ed fd is independent kernel state — both
threads own their own descriptor and there is no synchronisation between
them on the notify path.

The single-threaded design is what lets the project preserve its zero-alloc,
ABI-stable beat contract: a beat is decoded into a stack-allocated
`[u8; 32]` and dispatched through the per-pid tracker without locking,
because nothing else holds a reference.  Moving any phase of the loop to a
second thread would require a lock-free SPSC ring between threads at the
ingress and break that contract.  Stall-detection latency under scrape load
is instead bounded by an explicit per-iteration latency budget — see below.

### Why `/metrics` is on the poll thread

> *"Doesn't scrape latency variance steal time from beat ingestion?"*

It can, by up to ~200 ms per iteration — the structural cap of
`PromExporter::serve_pending` (100 ms serve deadline + 100 ms drain
deadline, see `exporter.rs`). The obvious mitigation is to spawn a second
thread that owns `serve_pending` and reads tracker state through a shared
snapshot. We deliberately do *not* do this. Three reasons:

1. **The beat path would acquire a lock on every tick.** Whether via
   `Arc<Mutex<PromExporter>>` or an SPSC snapshot ring, every record-side
   counter increment (`pe.record_beat(...)`, `pe.record_stall(...)`,
   `pe.record_loop_tick(...)` etc.) becomes either a mutex acquisition or
   a single-producer write into a wait-free queue. Neither is
   zero-overhead on the hot path, and both introduce per-architecture
   memory-ordering questions that the current `&mut self` model
   eliminates by construction.
2. **The zero-allocation invariant becomes harder to enforce.** The beat
   path is currently zero-alloc post-`connect`, enforced by the
   `varta-tests` guard allocator. A snapshot ring requires either a
   pre-sized arena (more state on the hot path) or per-snapshot
   allocation (kills the invariant). Both are worse than what we have.
3. **The variance is already bounded and now observable.** Scrape work
   per iteration is capped at ~200 ms by `PROM_READ_DEADLINE = 10 ms`,
   `PROM_MAX_CONNECTIONS_PER_SERVE = 8`, `PROM_MAX_DRAIN_PER_SERVE = 50`,
   the 100 ms serve deadline, and the per-IP token bucket. Operators see
   the variance through `varta_observer_serve_pending_seconds` (new — see
   "Observing scrape-induced latency" below); beat-path latency is
   `iteration_seconds - serve_pending_seconds` in PromQL.

Scrape-storm alarms and beat-path alarms therefore route off different
metrics, and the load-bearing single-thread invariant is preserved.

---

## Latency budget — worst-case poll iteration time

A bounded iteration time guarantees a bounded stall-detection latency.  The
table below names the phases of the poll loop in `main.rs` and the
upper-bound source for each:

| Phase                                  | Worst case        | Source / constant                                                                                                 | Observable as                                              |
|---|---|---|---|
| 1. Drain queued stall events           | O(queue)·~1 µs    | `Observer::poll_pending` — one stack pop per call                                                                 | `varta_observer_stage_seconds{stage="drain_pending"}`      |
| 2. `Observer::poll()` (one recv each)  | ≤ `read_timeout`·*N* | UDS `recv(2)` blocks up to `--read-timeout-ms` (default 100 ms) per listener; UDP listeners are non-blocking   | `varta_observer_stage_seconds{stage="poll"}`               |
| 3. Maintenance: counter drains + audit ring flush | ≤10 ms | Constant counter work + `flush_pending(10 ms budget)` draining the 256-line audit ring to BufWriter+fdatasync | `varta_observer_stage_seconds{stage="maintenance"}`        |
| 4. `Recovery::try_reap`                | ~64 µs            | ≤64 `waitpid(2, WNOHANG)` syscalls; rotating cursor (bounded outstanding-pids fan)                                | `varta_observer_stage_seconds{stage="recovery_reap"}`      |
| 5. `PromExporter::serve_pending`       | ≤200 ms           | 100 ms serve deadline + 100 ms drain deadline (see `exporter.rs`)                                                 | `varta_observer_stage_seconds{stage="serve_pending"}` + independent `varta_observer_serve_pending_seconds` histo |
| 6. Heartbeat-file write + watchdog kicks | <6 ms           | `write_heartbeat_atomic` (rename) + one `sendmsg(2)` + one `write(2)`                                            | `varta_observer_stage_seconds{stage="housekeeping"}`       |
| **Iteration total (worst case)**       | **~310 ms**       | UDS read_timeout (100 ms) + serve_pending (≤200 ms) + maintenance ≤10 ms + small fixed work                       | `varta_observer_iteration_seconds`                         |

Two observations the table makes explicit:

- The UDS read-timeout is the **idle floor**: with no incoming beats and no
  scrape pressure, every iteration costs about `read_timeout`.  This is
  intentional — it yields CPU between recvs without busy-spinning.  Lower
  the floor by lowering `--read-timeout-ms`, at the cost of a tighter idle
  poll loop.
- The worst-case **active** iteration is bounded by `read_timeout +
  serve_pending`, since `recv(2)` returns early as soon as a frame arrives
  and `serve_pending` is the only other phase that can spend more than a
  few milliseconds.

The default soft budget is **250 ms** (`--iteration-budget-ms`).  Iterations
exceeding it increment `varta_observer_iteration_budget_exceeded_total` and
are visible in the `varta_observer_iteration_seconds` histogram.  The budget
is advisory: hard wedges (seconds, never returning) remain the responsibility
of `--self-watchdog-secs`.

The idle sleep at the end of an iteration with no pending I/O (10 ms) is
**excluded** from the histogram.  Idle time is a throttling primitive, not
work latency; including it would mask the bad iterations.

### Tuning relationship

For a given `--threshold-ms T`, stall-detection latency is bounded by
`T + per_iteration_worst_case`.  With defaults
(`--threshold-ms 5000`, `--read-timeout-ms 100`, default serve_pending bounds)
the worst case is ~310 ms, so a stalled agent surfaces no later than
~5.31 s after its last beat.

The soft `--iteration-budget-ms` (default 250 ms) sits between the typical
case (~100 ms idle floor) and the worst case (~310 ms under scrape storm)
so the budget-exceeded counter fires only during real scrape pressure, not
on every active iteration.  Operators with higher `--read-timeout-ms` or
multiple listeners should raise the budget proportionally
(`budget ≥ read_timeout × N_listeners + 150 ms`).

`--self-watchdog-secs` should be set such that
`self_watchdog_secs × 1000 ≥ 4 × iteration_budget_ms` so transient overruns
during scrape bursts do not trigger false-positive aborts.  The default
guidance (`--self-watchdog-secs 4` with `--iteration-budget-ms 250`) gives a
16× margin (4000 ms ÷ 250 ms), well above the worst-case ratio.

### Observing scrape-induced latency

Three metrics together let an operator separate scrape pressure from
beat-path slowness:

- **`varta_observer_iteration_seconds`** — wall time for the entire poll
  iteration (drain → poll → maintenance → recovery reap → serve_pending →
  heartbeat write → watchdog kicks). Bucketed by
  `[0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, +Inf]`. Includes
  serve_pending — unchanged contract.
- **`varta_observer_serve_pending_seconds`** — wall time for the
  `serve_pending` phase alone. Same bucket boundaries as
  `iteration_seconds` so the two are coherent. Configurable soft budget
  via `--scrape-budget-ms` (default 250 ms); overruns increment
  `varta_observer_scrape_budget_exceeded_total`.
- **`varta_observer_iteration_budget_exceeded_total`** — iterations
  exceeding `--iteration-budget-ms` (default 250 ms). Includes
  serve_pending time.

Beat-path latency is then a PromQL expression — the difference between
iteration time and serve-pending time:

```promql
# P99 beat-path latency = P99(iteration_seconds) − P99(serve_pending_seconds).
# Note: subtracting quantiles is approximate (P99 of diff ≠ diff of P99s),
# but in practice serve_pending and the rest of the iteration are weakly
# correlated, so the approximation is monotonic with the true beat-path
# latency.  Use sum_by-(le) rate() if you want exact derived histograms
# (compute beat_path_seconds in a recording rule from the two histos).
histogram_quantile(0.99,
  sum by (le) (rate(varta_observer_iteration_seconds_bucket[5m])))
- histogram_quantile(0.99,
    sum by (le) (rate(varta_observer_serve_pending_seconds_bucket[5m])))
```

Alarms that should fire on **beat-path** slowness route off
`iteration_seconds - serve_pending_seconds` or off
`iteration_budget_exceeded_total` minus `scrape_budget_exceeded_total`
when scrape overruns dominate the budget overruns.

Alarms that should fire on **scrape-storm** pressure route off
`scrape_budget_exceeded_total` and `serve_pending_seconds` quantiles
directly.

### Per-stage histograms (`varta_observer_stage_seconds`)

Each of the six loop phases emits an independent histogram with the same
bucket boundaries as `varta_observer_iteration_seconds`:

| Label value | Phase |
|---|---|
| `drain_pending` | Stall-event queue drain |
| `poll` | Non-blocking I/O receive + frame decode + auth |
| `maintenance` | Counter drains + audit-ring flush |
| `recovery_reap` | Bounded `waitpid(2, WNOHANG)` + kill |
| `serve_pending` | Prometheus `/metrics` accept + response loop |
| `housekeeping` | Heartbeat write + watchdog kick |

Every stage emits every bucket from the first scrape (stable label set) so
`absent()` alert rules stay valid before the first observation.

Use `rate(varta_observer_stage_seconds_sum[5m]) / rate(varta_observer_stage_seconds_count[5m])`
per stage to isolate which phase is contributing to latency.

### Audit-ring back-pressure metrics

The recovery audit log uses an in-memory ring (cap 256) to decouple
`fdatasync` from the hot path.  `record_spawn` / `record_complete` enqueue
formatted lines; the maintenance phase drains them within a 10 ms budget.

| Metric | Meaning |
|---|---|
| `varta_recovery_audit_dropped_total` | Lines dropped because the ring was full when they arrived |
| `varta_recovery_audit_flush_budget_exceeded_total` | Ticks where `flush_pending` exhausted its budget before emptying the ring |
| `varta_recovery_reap_truncated_total` | Ticks where `try_reap` hit `REAP_MAX_PER_TICK=64` before checking all outstanding children |

Non-zero `audit_dropped_total` means audit records are being permanently
lost — either the disk is too slow, the budget is too tight, or the event
rate is unsustainably high.  Non-zero `audit_flush_budget_exceeded_total`
is a precursor: lines are accumulating faster than they drain, but no data
is lost yet.

The canonical alert rules covering all three observer-liveness symptoms
(`VartaAuditRecordDropped`, `VartaAuditFlushBudgetPressure`,
`VartaRecoveryReapTruncated`) plus the iteration-budget /
beat-path-latency family (`VartaIterationBudgetOverruns`,
`VartaIterationP99High`, `VartaScrapeStormPressure`,
`VartaBeatPathP99High`) live in
[`observability/alerts/varta.rules.yml`](https://github.com/aramirez087/Varta/blob/main/observability/alerts/varta.rules.yml).
The beat-path-latency derivation uses the
`varta:beat_path_seconds:p99_5m` recording rule (defined in
[`observability/recording-rules/varta.rules.yml`](https://github.com/aramirez087/Varta/blob/main/observability/recording-rules/varta.rules.yml))
so dashboards and alerts read identical numbers.

### Recommended Prometheus alerts

See [Monitoring & Alerting](../operations/monitoring.md#alert-catalogue)
for the catalogue with per-alert runbooks and severity routing.

---

## Tracker bounded-work guarantee

Each beat frame triggers at most one call to `find_evictable_slot` when the
tracker is at capacity.  That call scans at most `eviction_scan_window` slots
(default 256, configurable via `--eviction-scan-window`).

**Per-frame slot reads ≤ eviction_scan_window.**

A full table sweep — confirming every slot is ineligible — takes at most:

```
ceil(tracker_capacity / eviction_scan_window)
```

consecutive `record()` calls (the rotating cursor resumes where it stopped).

With defaults (capacity = 256, window = 256) this is 1 call.  With
`--tracker-capacity 4096 --eviction-scan-window 16` the sweep takes 256 calls —
each individual call still reads ≤ 16 slots, so the per-frame beat-path cost
stays bounded.

The `varta_tracker_eviction_scan_window_max` gauge (set once at startup) exposes
the configured window so dashboards can derive the worst-case sweep depth.
Operators alert on `varta_tracker_eviction_scan_truncated_total` to detect when
the cap engages under a unique-pid flood.

Combine this bound with the iteration-budget WCET derivation above:

```
iteration_max ≤ read_timeout × N_listeners + eviction_scan_window × slot_read_ns
```

---

## Tick-latency budget and hardware-watchdog margin

### Bench-derived p99 cap

Under the **canonical stress profile** — 4096-slot tracker, `balanced`
eviction policy, 30 agents × 100 Hz (≈ 3 000 beats/s) over UDS — the
`varta_observer_iteration_seconds` p99 is ≤ **5 ms**.

Run the bench to reproduce the measurement on your hardware:

```bash
cargo build --workspace --release --features prometheus-exporter
cargo run -p varta-bench --release -- tick-distribution
```

The bench asserts `p99 ≤ 5 ms` and exits non-zero if the cap is breached,
printing the full bucket distribution and observed percentiles for triage.
It also reports `varta_tracker_eviction_scan_truncated_total` and
`varta_observer_iteration_budget_exceeded_total` so you can confirm the
eviction-scan cap engages under the test load without blowing the latency
budget.

### Soft iteration budget

`--iteration-budget-ms` (default **250 ms**) is the soft per-iteration
ceiling.  Overruns increment `varta_observer_iteration_budget_exceeded_total`
but do not abort the loop.  The default 250 ms gives **50× headroom** over the
5 ms p99 cap; overruns therefore indicate genuine scrape-storm pressure, not
normal active-load variance.  See the "Latency budget" section for the full
derivation.

### Hardware-watchdog timeout floor

Operators deploying `--hw-watchdog /dev/watchdog` **must** configure the
kernel watchdog device with a timeout of **≥ 30 s**.  The derivation:

| Margin factor             | Value       | Note                                            |
|---|---|---|
| p99 iteration time        | ≤ 5 ms      | Bench-certified under canonical load            |
| Iteration budget (soft)   | 250 ms      | Default; raise for higher `--read-timeout-ms`   |
| Self-watchdog deadline    | 4 s         | Default auto-set from `$WATCHDOG_USEC`          |
| Recommended device timeout| **≥ 30 s**  | ≥ 6000× p99 cap, ≥ 7× self-watchdog deadline   |

The observer kicks the hardware watchdog at the end of every poll iteration
(after heartbeat-file write and `sd_notify`).  A single missed kick cannot
trip the device; a **sustained stall of ≥ device-timeout** will.  The 30 s
floor provides ample budget for:

- Audit-log filesystem stalls (`varta_log_suppressed_total{kind="audit_io"}`
  will show rate limiting if these recur)
- Prometheus scrape contention (`serve_pending_seconds` quantiles)
- The H5 self-watchdog's 4 s deadline with ≥ 7× margin

### Round-robin fairness bound

`Observer::poll()` rotates the `next_listener_start` cursor on every
non-`WouldBlock` receive.  Per-listener worst-case admission delay is therefore
bounded by **N_listeners × per-listener-recv-cost**.  Under the canonical bench
profile (single UDS listener) this is simply the UDS recv latency; with
N additional UDP listeners add N × ~10 µs per iteration.

### Eviction scan under stress

The bench will record non-zero `varta_tracker_eviction_scan_truncated_total`
when the tracker fills and the 256-slot eviction window exhausts without
finding a stalled slot.  This is expected and by design — the cap proves the
per-frame cost stays bounded even under a unique-pid flood.  The p99 assertion
holds even when the truncation counter is non-zero.

---

## Debounce table semantics under load

The `Recovery` runner keeps a per-pid ledger of the most recent recovery
fire (`LastFiredTable`).  Each subsequent stall for the same pid is
gated on `now - last_fired[pid] >= debounce`; closer-than-debounce
stalls return `RecoveryOutcome::Debounced` and never spawn a child.

### Capacity and eviction policy

The ledger is a fixed-size, array-backed table with capacity
`MAX_LAST_FIRED_CAPACITY = 4096`.  Capacity is sized to make the M8
adversarial-burst pattern costly: 4096 distinct pids would have to
stall faster than `debounce` cadence before the eviction policy is
engaged.  Per-slot cost is `Option<LastFiredSlot>` ≈ 24 bytes →
~96 KiB total — within budget for the observer.

When the table is full and a stall arrives for a new pid, the policy
is **fail-closed**:

1. The oldest slot is identified by a single bounded linear scan.
2. If that slot's age is at least `debounce`, it is evicted and the
   new pid takes its place.  Per-pid debounce semantics are preserved
   because the evicted pid's window has already elapsed.  The
   eviction is counted in
   `varta_recovery_last_fired_evictions_total` (operators tune
   capacity on this signal).
3. If the oldest slot's age is below `debounce`, the recovery is
   **refused**.  The runner returns
   `RecoveryOutcome::RefusedDebounceCapacity { pid }`, emits a
   `RefusedRecord { reason: "debounce_capacity" }` to the audit log,
   and bumps both
   `varta_recovery_outcomes_total{outcome="refused_debounce_capacity"}`
   and
   `varta_recovery_refused_total{reason="debounce_capacity"}`.

Eviction is debounce-respecting churn; refusal is suppression.
Operators tune capacity on the first signal and alert on the second.

### Clock-regression defense

All age comparisons use `Instant::saturating_duration_since`, which
returns `Duration::ZERO` on regression.  ZERO-duration entries are
treated as "not eligible for eviction" — preventing a backwards
clock blip from auto-evicting the whole table.

### Recommended alerts

```promql
# Alert immediately on any debounce-capacity refusal — this is either
# legitimate scale-out past 4096 concurrent stalls or the M8
# adversarial stall-burst pattern.  Either case warrants paging.
rate(varta_recovery_refused_total{reason="debounce_capacity"}[5m]) > 0
```

```promql
# Warn on sustained eviction churn — debounce semantics are still
# intact, but capacity is becoming a bottleneck under steady-state
# load.  Tune MAX_LAST_FIRED_CAPACITY or audit which pids are
# stalling.
rate(varta_recovery_last_fired_evictions_total[5m]) > 0.1
```

```promql
# Page on any non-zero invariant-violation count — the defensive
# fall-throughs in LastFiredTable should never fire in correct
# operation.  Non-zero values indicate a code bug, not load.
varta_recovery_invariant_violations_total > 0
```

For the deployment-side answer to *exceeding* the 4096-agent cap —
running multiple `varta-watch` instances and fanning agents across
them — see
[Deployment Ceiling & Sharding](deployment-ceiling-and-sharding.md).

### Bounded-WCET guarantee

Every `LastFiredTable` operation is a linear scan over a fixed-size
backing store.  The unit test `last_fired_table_prune_bounded_wcet`
asserts the prune sweep completes in under 5 ms in debug builds at
full capacity (a future refactor that reintroduces O(n²) behaviour
disguised as "cleanup" is caught by this test).

The pre-M8 `HashMap`-based implementation was the source of the
debounce-bypass bug closed by this section: reactive pruning at the
top of `on_stall` (`prune_threshold = debounce * 10`) left the map
full of fresh entries under adversarial load, and the `at_capacity`
branch skipped the debounce check entirely.  The new table never
skips the check; capacity pressure surfaces as a refusal or an
audited eviction.

---

## Audit-log durability vs availability

The recovery audit log (`crate::audit::RecoveryAuditLog`) is the last
synchronous-disk path on the poll thread.  Three operator-controlled
budgets keep a wedged filesystem (NFS stall, full disk, slow SSD
garbage-collection) from blocking the poll loop:

| Flag                                | Default | Meaning                                                                                                            |
| ----------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------ |
| `--audit-fsync-budget-ms`           | `50`    | Soft per-call budget for one `fdatasync(2)`.  Overruns defer further fsyncs in the *current* drain to next tick.   |
| `--audit-sync-interval-ms`          | `0`     | Time-based fdatasync cadence (in addition to `--recovery-audit-sync-every`).  `0` disables the time-based rule.    |
| `--audit-rotation-budget-ms`        | `50`    | Per-tick budget for the rotation state machine.  Overruns preserve progress and resume on the next maintenance tick. |

The drain is *deferral-aware*: when one fsync exceeds
`--audit-fsync-budget-ms`, the remaining records in the same drain
are written to the BufWriter only — the fsync is reattempted on the
next tick.  This bounds the worst-case poll stall on a slow disk to
one fsync per tick, while still progressing the audit chain on disk
(records sit in the BufWriter, durable through process restart via
the `Drop` impl's best-effort `flush + sync_data`).

Rotation is a state machine (`drive_audit_rotation`): one sub-step
per call (one `rename`, then the fresh fd open, then the v2 header
write, then the chain-stitching boot record + fsync).  Each call
honours `--audit-rotation-budget-ms`; if exceeded, state is
preserved on `self` and the next tick resumes from the same
sub-step.  Recursion through `direct_write_line → maybe_rotate →
emit_boot → direct_write_line` is structurally impossible because
the hot path never drives rotation directly — it only sets a
`needs_rotation` flag for the main loop to consume.

The default configuration preserves IEC 62304 Class C durability
byte-for-byte: `--recovery-audit-sync-every=1` +
`--audit-sync-interval-ms=0` means every record fsyncs before the
drain returns, and `--audit-fsync-budget-ms=50` only ever takes
effect when a single fsync exceeds 50 ms — i.e. when the disk is
*already* stalling the poll loop.  Operators who can accept relaxed
durability (e.g. cloud SRE deployments, not safety-critical) set
`--recovery-audit-sync-every=64 --audit-sync-interval-ms=100` to
amortise fsync cost over many records while still pinning a
worst-case sync interval.

### Audit-log observability

Four signals back the operator's mental model:

- `varta_audit_fsync_seconds` (histogram, shares
  `ITERATION_BUCKET_BOUNDS_S` with `iteration_seconds`) — per-call
  wall time of each `fdatasync(2)` on the audit fd.
- `varta_audit_fsync_budget_exceeded_total` (counter) — fsync calls
  whose wall time exceeded `--audit-fsync-budget-ms`.
- `varta_audit_rotation_budget_exceeded_total` (counter) — rotation
  drive calls that ran out of budget and deferred to the next tick.
- `varta_audit_ring_watermark_total{level="warn"|"critical"}`
  (counter) — rising-edge transitions of the in-memory ring fill
  across 75% and 95% of `AUDIT_RING_CAP` (= 256).  Counter increments
  once per *excursion* above each threshold; falling-edge re-arms
  the rising-edge trigger.  Both label values are emitted from the
  first scrape (stable-label-set discipline).

### Recommended alerts

```promql
# fsync wall-time is climbing past the budget — disk is degraded but
# the poll loop is still bounded.  Investigate before audit records
# start dropping.
rate(varta_audit_fsync_budget_exceeded_total[5m]) > 0.1
```

```promql
# Critical watermark crossed — drain has fallen far enough behind
# that records will start dropping if the trend continues.  Pages
# operator before audit_dropped_total increments.
rate(varta_audit_ring_watermark_total{level="critical"}[5m]) > 0
```

```promql
# p99 fsync wall-time exceeds 100 ms — disk is becoming a poll-loop
# bottleneck even under the deferral.
histogram_quantile(0.99, rate(varta_audit_fsync_seconds_bucket[5m])) > 0.1
```

The structural answer to "what happens when the disk is permanently
slow" is *visible degradation*: every tick defers, both fsync and
rotation budget-exceeded counters climb, ring watermarks fire, and
operators see the regression *before* records start dropping or the
self-watchdog aborts.  The poll loop itself stays within budget.

---

## Cross-references

- [Safety profiles](safety-profiles.md) — compile-time vs. runtime feature
  gating for production-safe builds
- [VLP transports](vlp-transports.md) — transport-level trust classification
- [Peer authentication](peer-authentication.md) — kernel-level PID attestation
- [Verification](verification.md) — symbolic verification of `Frame::decode`
  (M7) and the LastFiredTable invariants on the verification roadmap
