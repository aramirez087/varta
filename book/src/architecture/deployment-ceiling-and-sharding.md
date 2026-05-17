# Deployment ceiling and sharding

A single `varta-watch` instance is supported up to **4096 concurrently
tracked agents**. This chapter is the operator-facing answer to two
questions: *how do I detect that I'm approaching that cap?* and *what
do I do when I need to exceed it?*

The 4096 figure is the size of the observer's fixed-capacity tables,
not a saturation point of the poll loop. The two concerns are distinct:

- **The poll loop is single-threaded by load-bearing design.** See
  [Stall Detection & Liveness](observer-liveness.md) for the rationale
  (zero-alloc on the beat path, `&mut self` correctness model). The
  H5 / Issue #9 architectural decisions explicitly rejected splitting
  the beat path across threads. The horizontal answer is *another
  observer process*, not another thread.
- **The capacity tables are sized at 4096** for adversarial-burst
  resistance (the M8 debounce-bypass class). See
  [Bounded Collections](bounded-collections.md) for why every observer
  table is a fixed-size array indexed by a bounded probe, and the
  "Debounce table semantics under load" section of
  [Stall Detection & Liveness](observer-liveness.md#debounce-table-semantics-under-load)
  for the specific fail-closed behaviour at the ledger cap.

## The deployment ceiling per observer instance

Three independent tables enforce the 4096-agent ceiling:

| Table                 | Constant                                                    | Defined in                              |
| --------------------- | ----------------------------------------------------------- | --------------------------------------- |
| Tracker (per-pid)     | `MAX_CAPACITY = 4096`                                       | `crates/varta-watch/src/tracker.rs`     |
| Debounce ledger       | `MAX_LAST_FIRED_CAPACITY = 4096`                            | `crates/varta-watch/src/recovery/mod.rs` |
| Outstanding children  | Sized at construction from tracker capacity (≤ 4096)        | `crates/varta-watch/src/outstanding_table.rs` |

Above 4096 agents on a single observer, the behaviour is **graceful
degradation, not failure**:

- The tracker recycles slots, preferring dead agents (see the
  `--tracker-eviction-policy` flag and `varta_tracker_evicted_total`).
- The debounce ledger evicts the oldest debounce-expired entry, or
  refuses recovery when the oldest entry is still within debounce
  (per the fail-closed policy in `observer-liveness.md`).
- The outstanding-children table refuses additional recovery spawns
  when full.

Every refusal path increments a stable-label Prometheus counter, so
ceiling approach is detectable before it becomes user-visible.

## Bench-certified envelope

The benchmark `bench_observer_tick_p99_under_five_ms`
(`crates/varta-bench/src/main.rs`) certifies the observer at the
canonical stress profile:

- `--tracker-capacity 4096` (full ceiling)
- 30 concurrent agents beating at 100 Hz ≈ 3000 beats/s
- `TICK_P99_MS_THRESHOLD = 5.0` (poll-tick p99 ≤ 5 ms)

A realistic deployment of 4096 agents at typical 1 Hz beat cadence
produces 4096 beats/s — within ~37% of the stress profile. The poll
loop is not the bottleneck at the documented cap; the cap is
structural (adversarial-burst resistance), not throughput-driven.

## Detecting ceiling approach via existing metrics

All five capacity-pressure signals are already exported. No new metrics
are required to monitor cap proximity:

| Pressure source            | Watch metric                                              | Meaning when non-zero                                  |
| -------------------------- | --------------------------------------------------------- | ------------------------------------------------------ |
| Tracker fullness           | `varta_tracker_capacity_exceeded_total`                    | New agent dropped; tracker full                         |
| Tracker eviction churn     | `varta_tracker_eviction_scan_truncated_total`              | Eviction window exhausted without finding a victim      |
| Debounce table at capacity | `varta_recovery_last_fired_evictions_total`                | Old debounce ledger entries reclaimed                   |
| Recovery refused on cap    | `varta_recovery_refused_total{reason="debounce_capacity"}` | Stall couldn't fire because ledger full                |
| Outstanding-children full  | `varta_recovery_outstanding_probe_exhausted_total`         | OutstandingTable PID-index probe exhausted              |

Two further signals describe the configured envelope rather than
pressure:

- `varta_tracker_capacity` (gauge) — the configured ceiling.
- `varta_tracker_evicted_total` (counter) — healthy eviction of dead
  agents. Steady-state non-zero here is benign; co-monitor with
  `varta_tracker_eviction_scan_truncated_total` (which signals the
  unhealthy case).

## Recommended alerts

Three capacity-tier alerts cover the deployment-ceiling failure modes:

- `VartaTrackerEvictionTruncated` (**warning**) — eviction window
  exhausting; structural cap approaching.
- `VartaTrackerCapacityExceeded` (**critical**) — new agents being
  dropped at the cap.
- `VartaOutstandingProbeExhausted` (**critical**) — outstanding-children
  index probe exhausting under load.

All three ship in
[`observability/alerts/varta.rules.yml`](https://github.com/aramirez087/Varta/blob/main/observability/alerts/varta.rules.yml);
see [Monitoring & Alerting](../operations/monitoring.md#critical-page-on-call)
for per-alert runbooks and the related liveness-tier rules
(`VartaIterationBudgetOverruns`, `VartaBeatPathP99High`) that
operators monitoring deployment scale should configure alongside.

## Horizontal sharding pattern

When deployment needs more than 4096 agents on a single host, or wants
high availability across hosts, run multiple independent `varta-watch`
instances. The observer has no shared state between instances, so this
works without coordination, discovery, or any new code surface.

The pattern is:

1. **Run N `varta-watch` instances**, each bound to a distinct socket
   path and a distinct `/metrics` port. For example, with N = 2:

   ```bash
   varta-watch --socket /run/varta/0.sock --prom-addr 127.0.0.1:9100 \
       --prom-token-file /etc/varta/token --audit-log /var/log/varta/0.tsv
   varta-watch --socket /run/varta/1.sock --prom-addr 127.0.0.1:9101 \
       --prom-token-file /etc/varta/token --audit-log /var/log/varta/1.tsv
   ```

   Each instance carries its own 4096-slot ceiling and its own recovery
   audit log. Audit log paths (`--audit-log`) **must** be distinct per
   instance — the file is mode-`0600` and not designed for cross-process
   sharing.

2. **Deployment-side agent fanout.** Each agent computes a shard index
   and connects to the matching socket:

   ```rust
   let shard = (process::id() as usize) % N;
   let path = format!("/run/varta/{shard}.sock");
   let varta = Varta::connect(path)?;
   ```

   The agent-side API takes the socket path as an argument at
   `Varta::connect()` time (`crates/varta-client/src/client.rs`).
   Varta itself ships no discovery, routing, or sharding helper —
   deployment owns shard selection.

3. **Stable PID-based hashing is recommended.** `varta-watch`
   correlates beats by source PID; hashing on the agent's own PID
   guarantees that an agent reaches the same observer for the entire
   lifetime of its process. Hashing on volatile identity (e.g. a
   request ID) would scatter an agent's beats across observers and
   break stall detection.

4. **Per-shard Prometheus scraping.** Each instance exposes its own
   `/metrics`. Use one Prometheus scrape target per shard. Aggregation
   across shards (e.g. `sum by (instance)`) is a query-time concern,
   not a Varta concern.

## Why we don't fan-out inside one observer

The single-thread invariant for the beat path is a load-bearing project
decision documented in `observer-liveness.md` and in the H5 / Issue #9
architectural plans. Splitting beat ingestion across worker threads:

- breaks the zero-alloc guarantee on the beat path (shared state
  forces atomic or locked access where today there is plain `&mut self`),
- does not improve stall-detection latency (stalls surface on the same
  thread that drains them),
- and removes the structural property that today guarantees no
  cross-pid correctness races inside the per-pid tracker.

If a deployment needs more than 4096 agents on a single host, the
answer is *another `varta-watch` process*, not *another `varta-watch`
thread*. This chapter documents that path; it is supported, recipe-driven,
and adds no new code surface.

## Worked example — 8192-agent deployment

Two observer instances under a systemd template unit
`varta-watch@.service` with `%i ∈ {0, 1}`, each owning a 4096-slot
tracker. Agents shard by `pid % 2`:

```text
agent (pid 12345)  →  pid % 2 = 1  →  /run/varta/1.sock
agent (pid 54321)  →  pid % 2 = 1  →  /run/varta/1.sock
agent (pid 99998)  →  pid % 2 = 0  →  /run/varta/0.sock
```

Per-instance capacity: 4096 agents. Total deployment capacity: 8192
agents. Each instance independently meters its cap via the metric set
above; an operator alerted by `VartaTrackerEvictionTruncated` on either
instance knows precisely which half of the deployment is approaching
the ceiling.

The project does not ship a systemd unit today, so the exact unit file
is a deployment detail rather than a Varta artefact.
