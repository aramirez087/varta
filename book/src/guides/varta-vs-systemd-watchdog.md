# Varta vs systemd `WatchdogSec`

systemd's per-unit watchdog is excellent when **one service equals one unit**
and recovery is `systemctl restart <unit>`. Varta fits when **many processes**
on a host must report liveness to **one** operator-facing pipeline (Prometheus,
audit log, debounced recovery) without giving each agent an HTTP server or its
own systemd unit.

## Comparison

| Dimension | systemd `WatchdogSec` | Varta |
|-----------|----------------------|-------|
| **Scope** | One unit ↔ one watched process | One `varta-watch` ↔ thousands of agents (bounded table) |
| **Wire cost** | `sd_notify(WATCHDOG=1)` — cheap, local | 32-byte VLP frame over UDS/UDP — also cheap; no HTTP parse |
| **Observability** | `systemd` journals + unit state | Native Prometheus metrics, TSV export, structured audit log |
| **Recovery** | Unit `Restart=` policy | Per-PID debounced command templates (`--recovery-exec`) |
| **Cross-language** | C/libsystemd or notify socket protocol | Official clients + frozen JSON vectors (Rust, Python, Go, …) |
| **Safety-critical** | Depends on unit file + distro | Class-A profile: no HTTP server, no shell, compile-time config |

## When systemd alone is enough

- A single long-running daemon with a 1:1 unit file.
- Recovery policy is entirely `Restart=on-failure` inside systemd.
- You do not need per-beat custom payload (queue depth, degraded mode) in metrics.

## When to add Varta

- **Agent fleets** (tens–thousands of workers) where creating a unit per PID is
  operationally heavy.
- **Uniform metrics**: `varta_beats_total`, stall counters, recovery refusals with
  consistent labels across languages.
- **Kernel-attested beats** on Linux (peer credentials) with an explicit refusal
  to run recovery for unauthenticated origins — see
  [Peer Authentication](../architecture/peer-authentication.md).
- **Hospital / embedded profiles** that must not ship an HTTP `/metrics` server in
  the safety binary — use `prometheus-exporter` only on a non–Class-A build.

## Hybrid pattern (common in production)

Run `varta-watch` as a **single** `Type=notify` systemd service (see
[`observability/examples/varta-watch.service`](https://github.com/aramirez087/Varta/blob/main/observability/examples/varta-watch.service))
and keep application agents as lightweight processes that only call `beat()`.
Let systemd restart the **observer** if it stalls; let Varta restart **agents**
when their beats go silent.

## Next steps

- [Install (Quickstart)](../operations/install.md)
- [Prometheus setup walkthrough](prometheus-setup.md)