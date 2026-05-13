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
| Kernel hang / host deadlock | ✗ | ✗ | ✓ | ✗ |
| Misconfiguration (wrong socket path, wrong user) | ✗ | ✗ | ✗ | ✓ |

*systemd detects a hang only if `WATCHDOG=1` stops arriving; the self-watchdog
ensures that also stops when the loop wedges.  
†hardware watchdog fires when the kick loop stops; process crash achieves this.

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
non-main thread** in the `varta-watch` binary.  All agent beat processing,
stall detection, recovery spawning, and Prometheus serving happen on the main
thread.  The watchdog thread only reads two atomics (`SHUTDOWN` and
`LAST_TICK_NS`) and calls `process::abort()`; it never touches shared mutable
state.

---

## Cross-references

- [Safety profiles](safety-profiles.md) — compile-time vs. runtime feature
  gating for production-safe builds
- [VLP transports](vlp-transports.md) — transport-level trust classification
- [Peer authentication](peer-authentication.md) — kernel-level PID attestation
