# Varta vs HTTP `/health` checks

HTTP health endpoints are the default in Kubernetes and many service meshes.
They work well for **request/response services** behind a load balancer.
Varta targets **local agents and side processes** that should not pay for an
HTTP stack, TLS, JSON parsing, or a listening TCP port on every PID.

## Comparison

| Dimension | HTTP `/health` | Varta |
|-----------|----------------|-------|
| **Per-check cost** | Accept loop, parse, often JSON + mutex | One 32-byte datagram, stack encode, `send(2)` |
| **Failure mode** | Probe timeout blocks orchestrator path | Non-blocking socket → `BeatOutcome::Dropped` on the agent |
| **Port surface** | Listen on :8080 (or hostNetwork sidecar) | UDS path or UDP to observer — no per-agent listener |
| **Payload** | Unbounded body (risk) | 16-byte custom payload field in VLP v0.2 |
| **AuthN story** | mTLS / network policy | Kernel peer creds (Linux UDS), AEAD UDP optional |
| **Metrics** | Blackbox exporter or app-custom | First-class `varta-watch` Prometheus exporter |

## When HTTP health is the right tool

- The workload is already an HTTP server and `/health` is one route.
- Your orchestrator only speaks HTTP (some LB health checks).
- You need rich JSON diagnostics readable by curl.

## When Varta is the better fit

- **High-frequency liveness** (100ms–1s) on hot paths where p99 matters.
- **Embedded / `no_std` agents** using `varta-vlp` without an HTTP library.
- **Bare-metal fleets** monitored by Prometheus without kubelet probes.
- **Safety-critical** deployments where opening inbound TCP on every agent is
  unacceptable attack surface.

## Migration sketch

1. Stand up `varta-watch` with `--socket` (and optional secure UDP) —
   [Install](../operations/install.md).
2. Replace the periodic HTTP self-check loop with `beat(Status::Ok, payload)`.
3. Point Prometheus at `varta-watch` instead of per-agent blackbox jobs.
4. Map old probe failures to alert rules in
   [`observability/alerts/varta.rules.yml`](https://github.com/aramirez087/Varta/blob/main/observability/alerts/varta.rules.yml).

Keep HTTP `/health` for **external** traffic if customers still need it; use
Varta for **internal** liveness the platform owns.

## Next steps

- [Benchmark Results](../benchmarks/results.md)
- [Prometheus setup walkthrough](prometheus-setup.md)