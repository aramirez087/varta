# Monitoring & Alerting

`varta-watch` ships with a turn-key Prometheus + Grafana + Alertmanager
bundle. The artefacts live under [`observability/`](https://github.com/aramirez087/Varta/tree/main/observability)
in the repo; this chapter is the operator-facing prose tying them
together.

If you just want files-on-disk, the bundle README is at
[`observability/README.md`](https://github.com/aramirez087/Varta/blob/main/observability/README.md).
Come back here for the **why** behind each alert and dashboard panel.

## 10-minute setup

1. Run `varta-watch` with the `prometheus-exporter` feature enabled and
   a bearer token. The token file is mandatory whenever `--prom-addr`
   is set:

   ```bash
   openssl rand -hex 32 > /etc/varta/prom.token
   chmod 0400 /etc/varta/prom.token
   varta-watch \
     --socket /run/varta/varta.sock \
     --prom-addr 127.0.0.1:9100 \
     --prom-token-file /etc/varta/prom.token \
     --self-watchdog-secs 4
   ```

2. Copy the rule files into your Prometheus config directory and reload:

   ```bash
   cp observability/recording-rules/varta.rules.yml /etc/prometheus/rules.d/
   cp observability/alerts/varta.rules.yml          /etc/prometheus/rules.d/
   curl -X POST http://localhost:9090/-/reload
   ```

3. Paste `observability/examples/prometheus-scrape.yml`'s `scrape_configs:`
   block into your `prometheus.yml`, point `credentials_file` at the
   token from step 1, and reload again.

4. Import `observability/dashboards/varta-health.json` in Grafana,
   selecting the Prometheus datasource on the import dialog.

5. Wire `observability/examples/alertmanager.yml` into your Alertmanager.
   Replace the PagerDuty key and Slack webhook before reloading.

For Kubernetes / kube-prometheus operators, use the CRDs in
[`observability/examples/kubernetes/`](https://github.com/aramirez087/Varta/tree/main/observability/examples/kubernetes)
instead of editing `prometheus.yml` directly. See
[Deployment Patterns](deployment.md) for full systemd / Docker / K8s
recipes.

## Severity model

Every Varta alert carries a `severity` label. Three values, three
routes:

| Severity   | Operator action                          | Examples                                                                  |
|------------|------------------------------------------|---------------------------------------------------------------------------|
| `critical` | Page on-call                             | `VartaWatchStalled`, `VartaTrackerCapacityExceeded`, `VartaAuditRecordDropped` |
| `warning`  | Ticket / investigate within working day  | `VartaIterationBudgetOverruns`, `VartaAuditFlushBudgetPressure`           |
| `info`     | Record for trend analysis                | `VartaAuthFailureBurst`, `VartaNamespaceConflict`                         |

`info` alerts are not actionable per-event; they are the trend signal
that earlier action is needed (auth-failure clustering ⇒ rotate token,
namespace-conflict spikes ⇒ review `--allow-cross-namespace-agents`
policy).

## Metrics by subsystem

Every `varta-watch` metric is in one of nine subsystems. Stable label
sets are emitted from the first scrape (every label value present at
zero), so `by (label)` queries and `absent()` rules are safe day-one.

### Beat path (5 metrics)

| Metric                          | Type    | Labels   | Operational meaning                                              |
|---------------------------------|---------|----------|------------------------------------------------------------------|
| `varta_beats_total`             | counter | `pid`    | Accepted beats per agent. Drops to 0 ⇒ silent agent.             |
| `varta_stalls_total`            | counter | `pid`    | Observer-detected stalls per agent.                              |
| `varta_status`                  | gauge   | `pid`    | Last classification (0=Ok, 1=Degraded, 2=Critical, 3=Stall). Stall is **observer-synthesised** when the silence threshold is crossed — it is never on the wire (see [VLP — Base Frame](../spec/vlp.md) §3.7). |
| `varta_nonce_wrap_total`        | counter |          | Agent exhausted its u64 nonce — must be unreachable in practice. |
| `varta_rate_limited_total`      | counter | `reason` | Beats dropped by per-pid or global token bucket.                 |

### Decode / authentication (5 metrics)

| Metric                                  | Type    | Labels  | Meaning                                                                                       |
|-----------------------------------------|---------|---------|-----------------------------------------------------------------------------------------------|
| `varta_decode_errors_total`             | counter | `kind`  | Wire-format rejects; `kind ∈ {bad_magic, bad_version, bad_status, bad_pid, bad_timestamp, bad_nonce, stall_on_wire}`. |
| `varta_frame_auth_failures_total`       | counter |         | Kernel peer-cred check disagreed with frame's claimed PID — spoofing attempt.                  |
| `varta_io_errors_total`                 | counter |         | Socket receive errors.                                                                         |
| `varta_ctrl_truncated_total`            | counter |         | `MSG_CTRUNC` — kernel truncated the ancillary-data payload (credential metadata).             |
| `varta_truncated_datagrams_total`       | counter |         | Wrong-sized datagrams (not 32 bytes for UDS, not 60/64 for secure-UDP).                       |

### Tracker / capacity (8 metrics)

| Metric                                          | Type    | Meaning                                                                            |
|-------------------------------------------------|---------|------------------------------------------------------------------------------------|
| `varta_tracker_capacity`                        | gauge   | Configured `--tracker-capacity`.                                                   |
| `varta_tracker_capacity_exceeded_total`         | counter | Beats dropped at the cap ⇒ silent data loss; **page**.                             |
| `varta_tracker_evicted_total`                   | counter | Dead-agent slot reclamation. Steady non-zero is benign.                            |
| `varta_tracker_eviction_scan_truncated_total`   | counter | Eviction window exhausted ⇒ precursor to capacity-exceeded; **warn**.              |
| `varta_tracker_invariant_violations_total`      | counter | DO-178C defensive fall-through; must stay at 0 forever; **page**.                  |
| `varta_tracker_pid_index_probe_exhausted_total` | counter | Open-addressed hash table blew its probe budget; **page**.                         |
| `varta_tracker_namespace_conflict_total`        | counter | Cross-PID-namespace agent refused.                                                 |
| `varta_tracker_eviction_scan_window_max`        | gauge   | Configured `--eviction-scan-window`.                                               |

### Observer liveness (5 metrics)

| Metric                                            | Type      | Meaning                                                                  |
|---------------------------------------------------|-----------|--------------------------------------------------------------------------|
| `varta_observer_iteration_seconds`                | histogram | Poll-loop wall time per iteration. 9 buckets including `+Inf`.           |
| `varta_observer_iteration_budget_exceeded_total`  | counter   | Iterations exceeding `--iteration-budget-ms`.                            |
| `varta_observer_clock_regression_total`           | counter   | Backward monotonic clock jumps absorbed.                                  |
| `varta_observer_clock_jump_forward_total`         | counter   | Forward wall-clock jumps >5s (VM migration / NTP step).                  |
| `varta_observer_uds_rcvbuf_bytes`                 | gauge     | Effective `SO_RCVBUF` on the observer UDS socket.                        |

### Recovery (11 metrics)

| Metric                                             | Type    | Labels    | Meaning                                                                                                 |
|----------------------------------------------------|---------|-----------|---------------------------------------------------------------------------------------------------------|
| `varta_recovery_outcomes_total`                    | counter | `outcome` | Per-outcome counter. Labels: `spawned, debounced, reaped_zero, reaped_nonzero, killed, reap_failed, audit_failed, spawn_failed, timeout_fired, outstanding_dropped, signal_send_failed`. |
| `varta_recovery_refused_total`                     | counter | `reason`  | Recovery refused by policy. Labels: `unauthenticated_transport, cross_namespace_agent, debounce_capacity, outstanding_capacity, socket_mode_only`. |
| `varta_recovery_duration_ns_sum`                   | counter |           | Sum of child wall-clock durations (ns).                                                                  |
| `varta_recovery_duration_count_total`              | counter |           | Number of completions. `sum/count` ⇒ mean.                                                              |
| `varta_recovery_last_fired_evictions_total`        | counter |           | LastFiredTable entries evicted at capacity.                                                              |
| `varta_recovery_invariant_violations_total`        | counter |           | Recovery's DO-178C defensive fall-through; must stay at 0.                                              |
| `varta_recovery_outstanding_probe_exhausted_total` | counter |           | OutstandingTable hash probe-limit exceeded; **page**.                                                   |
| `varta_recovery_reap_truncated_total`              | counter |           | Reap attempts cut by per-tick budget (64 max).                                                          |
| `varta_recovery_audit_dropped_total`               | counter |           | Audit records dropped (ring full) — regulatory data-loss event; **page**.                               |
| `varta_recovery_audit_flush_budget_exceeded_total` | counter |           | Audit flush exceeded `--audit-fsync-budget-ms`.                                                         |
| `varta_origin_conflict_total`                      | counter |           | Beats refused because transport origin disagreed.                                                       |

### Audit log (6 metrics)

| Metric                                              | Type      | Labels  | Meaning                                                                              |
|-----------------------------------------------------|-----------|---------|--------------------------------------------------------------------------------------|
| `varta_audit_fsync_seconds`                         | histogram |         | `fdatasync(2)` wall time on the audit log.                                            |
| `varta_audit_fsync_budget_exceeded_total`           | counter   |         | Fsyncs exceeding `--audit-fsync-budget-ms`.                                          |
| `varta_audit_rotation_budget_exceeded_total`        | counter   |         | Rotation ops exceeding `--audit-rotation-budget-ms`.                                  |
| `varta_audit_ring_watermark_total`                  | counter   | `level` | Rising-edge counter; `level ∈ {warning_75pct, critical_95pct}`.                       |
| `varta_socket_bind_dir_fsync_failed_total`          | counter   |         | Parent-directory `fsync(2)` failure on observer UDS bind.                            |
| `varta_frame_rejected_pid_above_max_total`          | counter   |         | Frames with `pid > /proc/sys/kernel/pid_max` (impossible PID).                        |

### Scrape (8 metrics)

| Metric                                              | Type      | Labels   | Meaning                                                                          |
|-----------------------------------------------------|-----------|----------|----------------------------------------------------------------------------------|
| `varta_observer_serve_pending_seconds`              | histogram |          | `/metrics` response time per tick. Independent of iteration histogram.            |
| `varta_observer_scrape_budget_exceeded_total`       | counter   |          | Scrape work exceeding `--scrape-budget-ms`.                                       |
| `varta_observer_stage_seconds`                      | histogram | `stage`  | Per-stage latency breakdown. `stage ∈ {drain_pending, poll, maintenance, recovery_reap, serve_pending, housekeeping}`. |
| `varta_scrape_skipped_total`                        | counter   |          | `/metrics` served from cache (rate-limited).                                      |
| `varta_prom_auth_failures_total`                    | counter   |          | Bearer-token rejections.                                                          |
| `varta_prom_connections_dropped_total`              | counter   | `reason` | Connections closed before response. `reason ∈ {drain, rate_limit, ip_table_full}`. |
| `varta_prom_ip_state_probe_exhausted_total`         | counter   |          | Per-IP rate-limit table hash probe exhausted.                                     |
| `varta_scrape_budget_exhausted_total`               | counter   |          | Budget exhaustion during a poll tick (advisory).                                  |

### Secure-UDP (4 metrics)

| Metric                                  | Type    | Labels | Meaning                                                                              |
|-----------------------------------------|---------|--------|--------------------------------------------------------------------------------------|
| `varta_frame_decrypt_failures_total`    | counter |        | AEAD decrypt/tag failure.                                                            |
| `varta_sender_state_full_total`         | counter |        | Authenticated secure-UDP frames refused because the sender-state table was full.      |
| `varta_secure_aead_attempts_total`      | counter |        | Total AEAD trials. Constant `keys.len() + master_key_configured` per accepted beat (closes the key-rotation timing channel). |
| `varta_log_suppressed_total`            | counter | `kind` | Per-kind rate-limited diagnostic log suppressions.                                   |

### Observer metadata (5 metrics)

| Metric                                       | Type    | Labels | Meaning                                                |
|----------------------------------------------|---------|--------|--------------------------------------------------------|
| `varta_watch_uptime_seconds`                 | gauge   |        | Observer process uptime. Frozen ⇒ wedge; **page**.    |
| `varta_watch_last_poll_loop_timestamp_seconds` | gauge |        | Unix timestamp of most recent poll tick.               |
| `varta_watch_pids_tracked`                   | gauge   |        | Current agent PIDs in tracker.                         |
| `varta_pid_max_current`                      | gauge   |        | Cached `/proc/sys/kernel/pid_max` (refreshed every 60s). |
| `varta_signal_handler_install_total`         | counter | `mode` | Signal-handler installs by `mode ∈ {direct, libc}`.    |

## Alert catalogue

The complete rule file is `observability/alerts/varta.rules.yml`. Below
is one line per alert linking the alert name (and its anchor) to the
metric and the operator action. Section anchors are stable: every alert
in the YAML references `#<lowercased alertname>` in its
`annotations.runbook_url`.

### Critical (page on-call)

#### `VartaWatchStalled`
- **Metric:** `varta_watch_uptime_seconds`
- **Trigger:** uptime gauge not advancing for 1 minute.
- **Why critical:** stall detection and recovery are not happening on
  this host; agents that go silent will not get killed-and-respawned.
- **Action:** check the host (is the process alive? `kill -0 $(pidof varta-watch)`);
  inspect kernel ring buffer for OOM kills; inspect the systemd journal
  for `process::abort()` from the self-watchdog thread; restart the unit
  if needed. The journal will name the stage that wedged.

#### `VartaTrackerCapacityExceeded`
- **Metric:** `varta_tracker_capacity_exceeded_total`
- **Trigger:** any non-zero increment over 5m.
- **Why critical:** new agents are not being added to the tracker —
  their beats are decoded and counted, but never reach the stall detector.
- **Action:** shard the deployment (see
  [Deployment Ceiling & Sharding](../architecture/deployment-ceiling-and-sharding.md))
  or raise `--tracker-capacity`. Check `varta_tracker_evicted_total`
  rate first — if eviction is healthy and you're still hitting the cap,
  sharding is mandatory.

#### `VartaOutstandingProbeExhausted`
- **Metric:** `varta_recovery_outstanding_probe_exhausted_total`
- **Trigger:** any non-zero increment over 5m.
- **Why critical:** the bounded `OutstandingTable` hit its probe budget;
  new recoveries cannot be tracked.
- **Action:** as above — shard or raise capacity.

#### `VartaPidIndexProbeExhausted`
- **Metric:** `varta_tracker_pid_index_probe_exhausted_total`
- **Trigger:** any non-zero increment over 5m.
- **Why critical:** the open-addressed PID hash blew its 64-probe budget.
- **Action:** as above. This usually fires *before*
  `VartaTrackerCapacityExceeded` on Linux hosts with high `pid_max`.

#### `VartaAuditRecordDropped`
- **Metric:** `varta_recovery_audit_dropped_total`
- **Trigger:** any non-zero increase over 5m.
- **Why critical:** for IEC 62304 Class C, every recovery decision must
  be auditable. A drop means at least one decision is unrecorded.
- **Action:** check disk latency, audit ring watermark history
  (`varta_audit_ring_watermark_total`), and the audit-flush budget;
  raise `--audit-fsync-budget-ms` if the disk is slow but still healthy.

#### `VartaInvariantViolation`
- **Metrics:** `varta_tracker_invariant_violations_total`,
  `varta_recovery_invariant_violations_total`
- **Trigger:** any non-zero rate over 5m on either metric.
- **Why critical:** this is the DO-178C "no unproven panics" counter —
  an unreachable defensive fall-through executed.
- **Action:** file a bug. Attach the metric values, the `varta-watch`
  version, and any nearby stage-budget alarms.

#### `VartaIterationP99High`
- **Metric:** `varta_observer_iteration_seconds` histogram
- **Trigger:** p99 over 5m exceeds 500 ms.
- **Why critical:** stall-detection latency is being burned.
- **Action:** inspect `varta_observer_stage_seconds` to find which
  phase contributes (likely `serve_pending` if it's a scrape storm, or
  `maintenance` if it's an audit-fsync stall).

#### `VartaBeatPathP99High`
- **Recording rule:** `varta:beat_path_seconds:p99_5m`
- **Trigger:** beat-path p99 (iteration − scrape) exceeds 200 ms.
- **Why critical:** the beat path itself is slow, independent of scrape
  pressure. Scrape-storm alarms route off
  `varta_observer_serve_pending_seconds`; this one is unaffected.
- **Action:** check audit fsync p99 first
  (`varta:audit_fsync_seconds:p99_5m`), then disk latency, then tracker
  eviction window.

### Warning (investigate within working day)

| Alert                              | Action                                                                                                  |
|------------------------------------|---------------------------------------------------------------------------------------------------------|
| `VartaIterationBudgetOverruns`     | >10% of iterations over budget. Inspect per-stage breakdown.                                            |
| `VartaScrapeStormPressure`         | >10% of `/metrics` serves over budget. Reduce scrape frequency or narrow scraper IP set.                |
| `VartaTrackerEvictionTruncated`    | Eviction window exhausting. Precursor to `VartaTrackerCapacityExceeded`. Plan shard.                    |
| `VartaAuditFlushBudgetPressure`    | `fdatasync(2)` over budget consistently. Check disk; raise `--audit-fsync-budget-ms` if disk is healthy.|
| `VartaRecoveryReapTruncated`       | >64 children completing per tick. Reap is keeping up; queue may grow.                                   |
| `VartaAuditRingWatermarkCritical`  | Ring crossed 95% fill at least once. Drops are imminent.                                                |
| `VartaRateLimitingActive`          | Rate-limit dropping beats. Either agent hot-loop or raise `--max-beat-rate` / `--global-beat-rate`.    |
| `VartaClockJump`                   | Forward wall-clock jump > 5s. VM migration / NTP step. Stall windows may be off.                        |

### Info (record for trend analysis)

| Alert                          | Meaning                                                                                  |
|--------------------------------|------------------------------------------------------------------------------------------|
| `VartaAuthFailureBurst`        | Bearer-token rejections. Misconfigured scraper or token-scanning probe.                  |
| `VartaNamespaceConflict`       | Cross-PID-namespace agent refused. By design (the namespace gate is working).            |
| `VartaFrameDecodeAnomaly`      | Frames arriving with `kind`-specific decode failures. Likely client/observer skew.       |
| `VartaAuditRingWatermarkWarn`  | Ring crossed 75% fill. Advance warning before `critical_95pct`.                          |
| `VartaFrameAuthFailure`        | Kernel peer-cred disagreed with frame's PID. Spoofing or forged frame.                   |
| `VartaRecoveryRefused`         | Stall fired but recovery refused (by transport origin, namespace, or capacity).          |

## Dashboard tour

The single dashboard `varta-health.json` has six rows. Each row maps
1:1 onto a subsystem; alerts you receive route back to the relevant row
via the `runbook_url` annotation.

| Row                  | Panels                                                                                  | Reads from                                                                                                |
|----------------------|-----------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| Overview             | uptime, agents tracked, beats/s, tracker utilisation                                    | `varta_watch_*`, `varta:tracker:utilization`                                                              |
| Beat path            | beats/s & stalls/s, beat-path latency (p50/p99), decode errors by kind                  | `varta_beats_total`, `varta_stalls_total`, `varta:beat_path_seconds:p99_5m`, `varta:decode_errors:rate_5m` |
| Observer iteration   | iteration p50/p99/p999, per-stage p99, iteration & scrape budget overruns               | `varta:iteration_seconds:*`, `varta:stage_seconds:p99_5m`, `varta_observer_*_budget_exceeded_total`       |
| Recovery             | outcomes stacked, duration mean, refusals stacked, audit fsync + ring + drops          | `varta:recovery_outcomes:rate_5m`, `varta:recovery_refused:rate_5m`, `varta:audit_fsync_seconds:p99_5m`   |
| Capacity & sharding  | tracker utilisation + evictions, probe exhaustion, rate-limit drops, namespace conflicts | `varta:tracker:utilization`, all probe-exhaustion counters, `varta:rate_limited:rate_5m`                  |
| Security & integrity | bearer-auth failures, frame-auth failures, decrypt failures, AEAD attempts ratio, status mix | `varta_prom_auth_failures_total`, `varta_frame_auth_failures_total`, `varta:secure_aead_attempts:ratio_5m` |

## See also

- [SLOs & Tuning](slos.md) — recommended SLO model and threshold tuning.
- [Deployment Patterns](deployment.md) — systemd / Docker / Kubernetes recipes.
- [Stall Detection & Liveness](../architecture/observer-liveness.md) —
  the rationale behind the iteration-budget mechanism.
- [Deployment Ceiling & Sharding](../architecture/deployment-ceiling-and-sharding.md) —
  what to do when the tracker capacity alarms fire.
- [Audit Logging](../architecture/audit-log.md) — the durability model
  behind `VartaAuditRecordDropped` and the ring watermark counters.
