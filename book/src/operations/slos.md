# SLOs & Tuning

Service-level objectives for `varta-watch`. These are starting points;
tune to your latency budget and audit-durability needs.

## Recommended SLOs

### SLO-1 — Beat-path latency

> 99% of poll-loop iterations complete within 100 ms,
> measured over a 30-day rolling window.

- **SLI:** `varta:iteration_seconds:p99_5m` (recording rule)
- **Error budget:** 1% of 30 days = ~7.2 h above 100 ms.
- **Polices it:** `VartaIterationBudgetOverruns` (warn at 10% of
  iterations >budget), `VartaIterationP99High` (page at p99 >500 ms).
- **Why 100 ms:** the documented worst-case iteration is ~310 ms
  (see [Observer Liveness](../architecture/observer-liveness.md)
  latency-budget table). 100 ms is well within that bound and leaves
  headroom for occasional fsync stalls.

### SLO-2 — Recovery responsiveness

> 99% of recoveries fire within `(stall_threshold + debounce_window + 100 ms)`
> of stall detection, measured over a 7-day rolling window.

- **SLI:** `varta_recovery_outcomes_total{outcome="spawned"}` rate
  vs. `varta_stalls_total` rate, joined on `pid`.
- **Error budget:** 1% of 7 days = ~1.7 h of mis-budgeted recoveries.
- **Polices it:** `VartaRecoveryReapTruncated` (queue backlog),
  `VartaBeatPathP99High` (stall detection itself is slow).
- **Why this matters:** the whole product is the chain
  "agent stops → stall detected → recovery fires". If recovery
  responsiveness regresses but the individual stages look fine,
  the queue-shape (debounce + outstanding tables) is the culprit.

### SLO-3 — Audit durability

> Zero `varta_recovery_audit_dropped_total` increments over any
> 7-day rolling window.

- **SLI:** `increase(varta_recovery_audit_dropped_total[7d])`
- **Error budget:** zero. This is a hard SLO for IEC 62304 Class C
  deployments; for other deployments, treat as warning.
- **Polices it:** `VartaAuditRecordDropped` (page on any non-zero),
  `VartaAuditRingWatermarkCritical` (warn at 95% fill).
- **Why this matters:** the audit log is the regulatory record. Any
  drop is a hole in the recovery decision trail.

### SLO-4 — Scrape availability

> 99.9% of Prometheus scrapes complete within `scrape_timeout`
> (default 10s), measured over a 7-day rolling window.

- **SLI:** scraper-side `up{job="varta-watch"} == 1` over total scrapes.
- **Error budget:** 0.1% of 7 days = ~10 minutes.
- **Polices it:** `VartaScrapeStormPressure` (warn at >10% serve
  overruns).

## Tuning matrix

When an SLO is at risk, the dial that affects it most:

| Symptom                                                       | First dial to turn                                                  | See also                                                                  |
|---------------------------------------------------------------|---------------------------------------------------------------------|---------------------------------------------------------------------------|
| `VartaIterationP99High` from `serve_pending` stage             | `--scrape-budget-ms`, scraper interval, scraper IP whitelist        | [Observer Liveness](../architecture/observer-liveness.md#why-metrics-is-on-the-poll-thread) |
| `VartaIterationP99High` from `maintenance` stage               | `--audit-fsync-budget-ms`, audit ring size                          | [Audit Logging](../architecture/audit-log.md)                             |
| `VartaTrackerEvictionTruncated` followed by `*CapacityExceeded`| `--tracker-capacity`, `--eviction-scan-window`, or shard            | [Deployment Ceiling](../architecture/deployment-ceiling-and-sharding.md)  |
| `VartaRateLimitingActive{reason="per_pid"}`                    | `--max-beat-rate`                                                   |                                                                           |
| `VartaRateLimitingActive{reason="global"}`                     | `--global-beat-rate`, `--global-beat-burst`                         |                                                                           |
| `VartaAuditFlushBudgetPressure`                                | `--audit-fsync-budget-ms`, disk latency investigation               | [Audit Logging](../architecture/audit-log.md)                             |
| `VartaScrapeStormPressure`                                     | `--prom-rate-limit-per-sec`, scraper count                          | [Peer Authentication](../architecture/peer-authentication.md)             |

## Sizing examples

### 50-agent single host

- `--tracker-capacity 64` (default 256 is fine but tighter is cheaper).
- `--max-beat-rate 100` (default).
- `--scrape-budget-ms 250` (default).
- Single Prometheus scraping at 15s.

Iteration p99 ≤ 50 ms typical, p99.9 ≤ 200 ms under audit-flush bursts.

### 1000-agent shard

- `--tracker-capacity 2048`.
- `--eviction-scan-window 512`.
- `--max-beat-rate 200` if your agents beat aggressively.
- `--audit-fsync-budget-ms 100` (twice the default to absorb disk hiccups).
- Two-host HA scrape: stagger the two Prometheus scrapers by 7.5s so the
  per-IP rate-limit table doesn't see them as a coordinated burst; raise
  `--prom-rate-limit-burst` to 20 as defence in depth.

### 4096-agent ceiling

This is the documented maximum per observer
([deployment ceiling](../architecture/deployment-ceiling-and-sharding.md)).
Beyond this, **shard**. Two 2048-agent observers on the same host with
separate UDS paths is cheaper than one tuned-up 4096-agent observer,
because every linear scan (`eviction_scan_window`) and every probe
budget (`PidIndex`) is duplicated rather than expanded.

## Trend signals

Three info-tier alerts are not alerts in the operational sense — they
are SLO erosion signals you should be watching in a dashboard, not
paging on:

- `VartaAuthFailureBurst` — bearer-token scanning is happening. Rotate.
- `VartaNamespaceConflict` — agent placement is leaking into wrong
  PID namespaces; review the deployer.
- `VartaFrameDecodeAnomaly{kind="bad_version"}` — client/observer
  version skew on the wire format. Coordinate the upgrade.

The dashboard's "Security & integrity" row surfaces all three.
