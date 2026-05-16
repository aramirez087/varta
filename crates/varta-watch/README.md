# varta-watch

[![crates.io](https://img.shields.io/crates/v/varta-watch)](https://crates.io/crates/varta-watch)

← [Workspace root](../../README.md)

Observer binary — decode VLP frames from agent sockets, surface stalls, and
export metrics. A single-threaded poll loop; no background threads and no
signal handler dependency.

## Invocation

```sh
varta-watch \
  --socket /tmp/varta.sock \
  --threshold-ms 2000 \
  --recovery-exec /usr/local/bin/restart-myapp \
  --recovery-debounce-ms 5000 \
  --recovery-timeout-ms 3000 \
  --export-file /var/log/varta/events.tsv \
  --prom-addr 127.0.0.1:9100
```

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--socket <PATH>` | path | **required** | Bind the observer's UDS at this path. |
| `--threshold-ms <MS>` | u64 ms | **required** | Per-pid silence window before a stall is surfaced. |
| `--recovery-exec <CMD>` | string | — | Command (with optional arguments) executed directly on each unique stall. The stalled pid is appended as the final argument. |
| `--recovery-debounce-ms <MS>` | u64 ms | `1000` | Per-pid debounce window for recovery invocations. |
| `--recovery-timeout-ms <MS>` | u64 ms | — | Kill-after deadline for recovery children; if a child runs longer than this it is killed via kill(2). Without this flag the child is allowed to run until completion. |
| `--socket-mode <OCTAL>` | octal | `0600` | File mode for the observer socket (default 0600 — owner-only r/w). |
| `--read-timeout-ms <MS>` | u64 ms | `100` | UDS read timeout per poll call. Bounded so a stalled peer cannot hold the observer loop indefinitely. |
| `--export-file <PATH>` | path | — | Append one tab-separated event line per observer event to this file. |
| `--prom-addr <IP:PORT>` | `SocketAddr` | — | Bind the Prometheus `/metrics` endpoint here. |
| `--shutdown-after-secs <SECS>` | u64 secs | — | Exit cleanly after the given uptime (used by integration tests). |
| `-h`, `--help` | flag | — | Print help to stdout and exit 0. |

## `/metrics` schema

`GET /metrics` returns Prometheus text exposition format (v0.0.4). All pids
that have produced at least one beat or stall event appear in every metric
family. Pids are sorted numerically ascending.

```
# HELP varta_beats_total Total accepted beats per agent pid.
# TYPE varta_beats_total counter
varta_beats_total{pid="1234"} 42

# HELP varta_stalls_total Total observer-detected stalls per agent pid.
# TYPE varta_stalls_total counter
varta_stalls_total{pid="1234"} 1

# HELP varta_status Last reported status code per agent pid (0=ok,1=degraded,2=critical,3=stall).
# TYPE varta_status gauge
varta_status{pid="1234"} 0
```

## File export schema

Each line is tab-separated with a fixed column count:

```
<observer_ns>\t<kind>\t<pid>\t<nonce>\t<status>\t<payload>\n
```

- `observer_ns` — elapsed nanoseconds since the `FileExporter` was created.
- `kind` ∈ `{beat, stall, decode, io}`.
- For `decode` and `io` events the `pid`, `nonce`, `status`, and `payload`
  columns are written as `-` so the line stays rectangular.
- `status` is the lowercase name: `ok`, `degraded`, `critical`, or `stall`.

Example:

```
1234567\tbeat\t5678\t1\tok\t0
2345678\tstall\t5678\t1\tstall\t-
3456789\tdecode\t-\t-\t-\tBadMagic
```

## Recovery exec mode

The `--recovery-exec` value is executed directly via `execve(2)` — no shell
is involved. The stalled pid is appended as the final argument. This means
the program receives the pid as a clean integer, with no shell-injection
surface.

```sh
# Restart a systemd unit (the observer appends the pid as $1):
--recovery-exec /usr/local/bin/restart-myapp

# Or pass a fixed prefix followed by the pid:
--recovery-exec-file /etc/varta/recovery-cmd.txt
```

Recovery invocations are debounced per pid. A second stall for the same pid
within the debounce window is silently skipped; distinct pids are independent.
The debounce window resets after each successful or failed spawn.

Each recovery child is spawned asynchronously (non-blocking). The observer
never blocks on a slow command. Completed children are reaped automatically
each poll tick. If `--recovery-timeout-ms` is set, any child that exceeds the
deadline is killed via kill(2) and then reaped.

## Graceful shutdown

`SIGINT` and `SIGTERM` set an atomic latch; the next poll iteration finishes
cleanly, `STOPPING=1` is sent to systemd (when `--sd-notify` is wired),
outstanding recovery children are killed and reaped within the
`--shutdown-grace-ms` window (default 5 s), the audit log drains and
`fdatasync(2)`s, and the observer's UDS socket file is unlinked on the way
out. systemd `TimeoutStopSec=` should be at least `shutdown_grace_ms +
audit_fsync_budget_ms + ~200 ms` (≈ 5.3 s with defaults). See
[`book/src/architecture/graceful-shutdown.md`](../../book/src/architecture/graceful-shutdown.md)
for the full sequence, signal disposition table, and the cost of `SIGKILL`.

## Constraints

- **Zero production registry dependencies.** Only `varta-vlp` (path dep) and
  `std` are used.
- **Single-threaded.** The poll loop runs entirely on the main thread; the
  Prometheus listener is non-blocking and drained each tick.
- **Non-blocking beat.** Agents are never blocked by the observer; the UDS
  is a datagram socket and sends complete or fail immediately.

## See also

- Protocol crate: [`crates/varta-vlp/README.md`](../varta-vlp/README.md)
- Architecture: [`book/src/architecture/vlp-frame.md`](../../book/src/architecture/vlp-frame.md)
