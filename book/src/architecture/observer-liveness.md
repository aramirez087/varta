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
(or Alertmanager rule) can alert when the gauge stops increasing:

```promql
# Alert when varta-watch uptime has not increased for 30 seconds.
alert: VartaWatchStalled
expr: rate(varta_watch_uptime_seconds[30s]) == 0
for: 30s
labels:
  severity: critical
```

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
| 1. Drain queued stall events           | O(queue)·~1 µs    | `Observer::poll_pending` — one stack pop per call                                                                 | (subsumed in `iteration_seconds`)                          |
| 2. `Observer::poll()` (one recv each)  | ≤ `read_timeout`·*N* | UDS `recv(2)` blocks up to `--read-timeout-ms` (default 100 ms) per listener; UDP listeners are non-blocking   | (subsumed in `iteration_seconds`)                          |
| 3. Maintenance counter drains          | <1 ms             | Constant work over `observer.drain_*` counters                                                                    | (subsumed in `iteration_seconds`)                          |
| 3. `Recovery::try_reap`                | ~64 µs            | ≤64 `waitpid(2, WNOHANG)` syscalls (bounded outstanding-pids fan)                                                 | (subsumed in `iteration_seconds`)                          |
| 3. `PromExporter::serve_pending`       | ≤200 ms           | 100 ms serve deadline + 100 ms drain deadline (see `exporter.rs`)                                                 | `varta_observer_serve_pending_seconds` (independent histo) |
| 4. Heartbeat-file atomic write         | <5 ms             | Same-dir write + rename (`write_heartbeat_atomic`)                                                                | (subsumed in `iteration_seconds`)                          |
| 4. `sd_notify` + HW watchdog kicks     | <1 ms             | One `sendmsg(2)` + one `write(2)`                                                                                 | (subsumed in `iteration_seconds`)                          |
| **Iteration total (worst case)**       | **~310 ms**       | UDS read_timeout (100 ms) + serve_pending (≤200 ms) + small fixed work — assuming a single UDS listener           | `varta_observer_iteration_seconds`                         |

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

### Recommended Prometheus alerts

```promql
# Warn — more than 10% of recent iterations exceeded the soft budget.
alert: VartaIterationBudgetOverruns
expr: rate(varta_observer_iteration_budget_exceeded_total[5m])
    / rate(varta_observer_iteration_seconds_count[5m]) > 0.10
for: 5m
labels: { severity: warning }

# Crit — 99th-percentile iteration time has exceeded 500 ms (twice the budget).
alert: VartaIterationP99High
expr: histogram_quantile(0.99,
        sum by (le) (rate(varta_observer_iteration_seconds_bucket[5m]))) > 0.5
for: 5m
labels: { severity: critical }

# Warn — sustained scrape pressure (≥10% of serve_pending calls over budget).
# Fires on scrape-storm symptoms specifically, NOT on beat-path slowness.
alert: VartaScrapeStormPressure
expr: rate(varta_observer_scrape_budget_exceeded_total[5m])
    / rate(varta_observer_serve_pending_seconds_count[5m]) > 0.10
for: 5m
labels: { severity: warning }

# Crit — beat-path P99 latency exceeds 200 ms.  Derived: subtract scrape
# time from iteration time so this alarm is immune to scrape storms.
# (See "Observing scrape-induced latency" for the approximation caveat —
# put this in a recording rule for production use.)
alert: VartaBeatPathP99High
expr: |
  (histogram_quantile(0.99,
     sum by (le) (rate(varta_observer_iteration_seconds_bucket[5m])))
   - histogram_quantile(0.99,
     sum by (le) (rate(varta_observer_serve_pending_seconds_bucket[5m])))) > 0.2
for: 5m
labels: { severity: critical }
```

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

## Cross-references

- [Safety profiles](safety-profiles.md) — compile-time vs. runtime feature
  gating for production-safe builds
- [VLP transports](vlp-transports.md) — transport-level trust classification
- [Peer authentication](peer-authentication.md) — kernel-level PID attestation
- [Verification](verification.md) — symbolic verification of `Frame::decode`
  (M7) and the LastFiredTable invariants on the verification roadmap
