# Graceful Shutdown

`varta-watch` is a long-running observer; an orderly stop is the difference
between a clean systemd cycle and a directory full of stranded sockets,
zombie children, and a half-flushed audit log. This chapter describes what
happens between the moment a signal arrives and the moment the process
exits, and how to tune the cycle for your deployment.

## Signal disposition

Two signals trigger an orderly stop; everything else is left to default
disposition.

| signal  | action |
|---------|--------|
| `SIGINT`  | set `SHUTDOWN` latch (Release ordering) |
| `SIGTERM` | set `SHUTDOWN` latch (Release ordering) |
| `SIGHUP`  | **not trapped** — reload via `systemctl reload` (no in-process reload) or restart |
| `SIGPIPE` | not handled here; broken pipes surface as `io::Error::BrokenPipe` and are classified by `classify_send_error` |

The latch is a `static SHUTDOWN: AtomicI32` (32-bit lock-free atomic; the
crate's `compile_error!` cfg gate enforces `target_has_atomic = "32"`). The
handler installed for `SIGINT`/`SIGTERM` is the only async-signal-safe code
path Varta executes from a signal context: it stores `1` and returns.

Installation strategy is per-platform (see [Signal-Handler Installation]):

* **Linux** — direct `rt_sigaction(2)` syscall (libc bypassed) so Varta owns
  the kernel ABI byte-for-byte. `--signal-handler-mode=libc` opts into the
  libc wrapper for environments where the direct syscall is unavailable.
* **macOS / FreeBSD / DragonFly / NetBSD** — libc `sigaction(3)` wrapper.
* **Other Unix** — POSIX `signal(2)` fallback.

[Signal-Handler Installation]: ./signal-install.md

## The shutdown sequence

After the latch is set, shutdown unfolds across the next iteration of the
observer poll loop. Each step is deterministic and bounded.

1. **Latch observation.** The poll loop checks `SHUTDOWN.load(Acquire)` at
   two points per iteration (`crates/varta-watch/src/main.rs:784, 877`).
   The current iteration finishes — heartbeat write, iteration histogram,
   serve-pending drain — so partial-tick state is never lost.
2. **`STOPPING=1` to systemd.** If `--sd-notify` is wired (or
   `$NOTIFY_SOCKET` is in the environment), the main thread emits
   `STOPPING=1\n` to the service manager so `systemctl status` reflects the
   stop transitionally rather than as an unexpected exit
   (`crates/varta-watch/src/main.rs:1559`). The watchdog thread, which is
   the sole owner of `WATCHDOG=1` (see [Stall Detection & Liveness]),
   observes the same latch and stops emitting; `WatchdogSec=` therefore
   does not fire during teardown.
3. **Drop chain.** Returning from `main` runs the Drop impls in declaration
   order. The load-bearing ones:
   * **`Recovery`** — kill all outstanding children immediately, then
     `try_wait` in a 10 ms-poll loop with a single shared deadline of
     `--shutdown-grace-ms` (default 5 s, minimum 100 ms). Children still
     alive at the deadline are reparented to PID 1 and the process exits
     anyway.
   * **`RecoveryAuditLog`** — drain the in-memory ring via
     `flush_pending(Duration::MAX)`, then a final `fdatasync(2)` so every
     append is durable on disk before the process leaves the kernel.
   * **`PromExporter` / file exporters** — close TCP sockets, flush
     buffers, fsync TSV outputs.
   * **`UdsListener`** — verify the bound socket file's `dev`/`ino` still
     match the values recorded at bind time, then `unlink(2)` it. The
     dev/ino check is what prevents a restarted observer from clobbering a
     fresh socket bound by a different instance.

[Stall Detection & Liveness]: ./observer-liveness.md

## Tuning knobs

| flag | default | minimum | role |
|------|---------|---------|------|
| `--shutdown-grace-ms` | `5000` | `100` | bound on `Recovery::Drop`'s child-reap window |
| `--audit-fsync-budget-ms` | `50` | — | bound on per-fdatasync wall time during audit drain |

The systemd unit's `TimeoutStopSec=` should be **at least**
`shutdown_grace_ms + audit_fsync_budget_ms + ~200 ms slack`. With the
defaults that is ≈ 5.3 s; round up to 10 s to be comfortable. If the
service exceeds `TimeoutStopSec=` systemd promotes the stop to `SIGKILL`,
which loses the guarantees in the next section.

## What `SIGKILL` (or any uncatchable kill) costs

Varta deliberately makes its shutdown observable rather than instantaneous
because the alternative is silent loss. A `SIGKILL` (whether from systemd's
timeout, an OOM-kill, or `kill -9`) skips the entire sequence above:

* **Outstanding recovery children orphan.** They reparent to PID 1 (or the
  closest subreaper) and complete on their own schedule, but their exit
  outcomes never reach the audit log.
* **Audit log loses anything in the ring.** Up to `AUDIT_RING_CAP = 256`
  records that arrived after the last `flush_pending` are dropped; the
  final `fdatasync` is also skipped, so the last few flushed records may
  not survive a power loss.
* **UDS socket file is left on disk.** The next start's
  `probe-then-bind` flow detects the stale inode (`ECONNREFUSED` on probe,
  `is_socket()` + dev/ino check before unlink) and cleans it up safely; no
  manual intervention is required.
* **Self-watchdog never disarms.** If the hardware watchdog (`HwWatchdog`)
  is in use, the magic-close sequence is skipped — the kernel continues
  toward the configured timeout, which may reboot the host. This is the
  intended behaviour for safety-critical deployments: an observer that
  cannot stop cleanly is not allowed to leave the watchdog quiescent.

The summary is "use `SIGTERM`, not `SIGKILL`," and "tune `TimeoutStopSec=`
above the sum of the bounded budgets so systemd does not have to escalate."

## systemd unit example

```ini
[Service]
Type=notify
ExecStart=/usr/bin/varta-watch --uds-path /run/varta.sock \
                               --shutdown-grace-ms 5000 \
                               --audit-fsync-budget-ms 50 \
                               --recovery-audit-file /var/log/varta-audit.tsv
TimeoutStopSec=10
WatchdogSec=4
Restart=on-failure
```

`Type=notify` enables the `READY=1` / `STOPPING=1` / `WATCHDOG=1` channel.
`WatchdogSec=4` auto-enables the in-process self-watchdog (cerebrum:
"H5 auto-enable collapses L1+L2 layers"). `TimeoutStopSec=10` leaves
~5 s of headroom above `--shutdown-grace-ms` for the audit drain and
listener cleanup.

## Cross-references

* Recovery `Drop` impl: `crates/varta-watch/src/recovery/mod.rs:904-928`
* Signal handler installation: `crates/varta-watch/src/signal_install/`
* Observer self-liveness (the WATCHDOG=1 channel): [Stall Detection & Liveness]
* Configuration constants: `DEFAULT_SHUTDOWN_GRACE_MS`,
  `MIN_SHUTDOWN_GRACE_MS` in `crates/varta-watch/src/config/types.rs`
