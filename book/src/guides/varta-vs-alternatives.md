# Varta vs the alternatives

If you run background workers, daemons, or edge agents, you already have *some*
liveness story — systemd `WatchdogSec`, a supervisord/monit config, Kubernetes
liveness probes, or an HTTP `/health` route a prober polls. Each is the right
tool when its assumptions hold: one process per unit, one orchestrator, one HTTP
server already in the binary. The question this page answers is narrower: when
you have *many* local processes and don't want to add a unit file, a pod, or an
inbound TCP port to each one, what does adding `varta-watch` actually buy you —
and where do the incumbents still win?

## At a glance

| Capability | systemd `WatchdogSec` | supervisord / monit | k8s liveness probes | HTTP `/health` polling | Varta |
|---|---|---|---|---|---|
| Watches many processes via one collector | No — one unit per process | Partial — one supervisor config, but per-process stanzas | No — one probe per container | No — one prober target per endpoint | Yes — one `varta-watch` ↔ thousands of agents (bounded table) |
| Per-process cost | One unit file + `sd_notify` | A config stanza + a managed child | A probe spec + kubelet exec/HTTP | A listening TCP port + handler per PID | One non-blocking UDS/UDP socket; 32-byte `send(2)`, zero-alloc after connect |
| Liveness signal | App pings the watchdog (push) | Process-alive + optional check command | kubelet polls the probe (pull) | Prober polls the endpoint (pull) | App pushes 32-byte beats; observer synthesises stall on silence |
| Auto-recovery | Yes — unit `Restart=` | Yes — restart managed child | Yes — kubelet restarts container | No — prober only signals; recovery is external | Yes — per-PID debounced command (`--recovery-exec`), refused for unauthenticated origins |
| Metrics | Journal + unit state; no native Prometheus | Status via socket/CLI; no native Prometheus | Pod conditions / events; metrics via separate stack | Whatever the endpoint exposes (often blackbox exporter) | Native Prometheus exporter, TSV export, structured audit log, uniform labels |
| Runs without systemd | No | Yes | Yes | Yes | Yes |
| Runs without k8s | Yes | Yes | No | Yes | Yes |
| Cross-language | C / libsystemd or notify-socket protocol | Process-level, language-agnostic | Language-agnostic (exec/HTTP) | Any language that serves HTTP | Frozen 32-byte wire format; clients in Rust, Python, Go, Node, .NET, JVM |
| Safety-critical profile | Depends on distro/unit; no built-in profile | No | No | No | Class-A build removes HTTP server, arg parser, and shell exec (IEC 62304 Class C grade) |

## Which one should you pick?

**Pick systemd `WatchdogSec`** if your processes are 1:1 with units, recovery is
just `Restart=on-failure`, and you don't need per-beat payload (queue depth,
degraded mode) or native Prometheus metrics. It's already on the host, costs
nothing extra, and is the simplest correct answer for a handful of long-running
daemons.

**Pick supervisord / monit** if you want a single process manager to start,
restart, and check a modest set of children on a non-systemd host, and
process-alive (plus an occasional check command) is a sufficient liveness
signal. You get supervision and recovery without per-beat instrumentation or a
metrics pipeline — and without each child needing to emit anything.

**Pick k8s liveness probes** if you're already on Kubernetes and your workloads
are containers the kubelet schedules. The probe + restart loop is built in, no
extra component to run, and it's the idiomatic choice — there's no reason to add
Varta for liveness of pods the orchestrator already restarts.

**Pick HTTP `/health` polling** if the workload is already an HTTP server,
`/health` is one more route, and your orchestrator or load balancer only speaks
HTTP. It's also the right call when you need rich JSON diagnostics a human can
`curl`. Note it signals liveness but doesn't recover anything — recovery stays
external.

**Pick Varta** when you have many local processes (tens to thousands) and adding
a unit file, pod, or inbound TCP port per PID is operationally heavy or simply
unavailable — embedded / `no_std` / non-systemd / inside a container with no
orchestrator. It fits high-frequency liveness (100 ms–1 s) where p99 matters,
polyglot fleets that need uniform metrics and labels, and safety-critical builds
that must not ship an HTTP server or a shell. It's niche and local-first by
design; for a single 1:1 daemon, systemd is the better tool.

## You don't have to choose just one

These aren't mutually exclusive, and the common production setup combines them:
run `varta-watch` *itself* as a single `Type=notify` systemd unit (or one k8s
sidecar), and let systemd/k8s watch the watcher while Varta watches the fleet.
systemd or the kubelet restarts the one observer if it stalls; Varta restarts the
many agents when their beats go silent. You get the incumbent's battle-tested
supervision for the single long-lived component, and Varta's
one-collector-many-agents model for everything that would otherwise need a unit,
pod, or HTTP port each. See
[Varta vs systemd `WatchdogSec`](varta-vs-systemd-watchdog.md) for the hybrid
systemd recipe and
[`observability/examples/varta-watch.service`](https://github.com/aramirez087/Varta/blob/main/observability/examples/varta-watch.service)
for the unit file.

## Next steps

- [Install (Quickstart)](../operations/install.md)
- [Varta vs systemd `WatchdogSec`](varta-vs-systemd-watchdog.md)
- [Varta vs HTTP `/health` checks](varta-vs-http-health.md)
- [Prometheus setup walkthrough](prometheus-setup.md)
