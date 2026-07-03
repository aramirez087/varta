# varta-client

[![crates.io](https://img.shields.io/crates/v/varta-client)](https://crates.io/crates/varta-client)

**Site:** [varta.sh](https://varta.sh) · **Book:** [documentation](https://varta.sh/book/)

← [Workspace root](../../README.md)

Agent API — emit VLP frames over a Unix Domain Socket. One `connect` call
allocates a socket; every subsequent `beat` call is zero-allocation and
non-blocking.

## Quick start

```rust,no_run
use varta_client::{BeatOutcome, Status, Varta};

fn main() -> std::io::Result<()> {
    let mut agent = Varta::connect("/tmp/varta.sock")?;
    loop {
        match agent.beat(Status::Ok, 0) {
            BeatOutcome::Sent         => {}
            BeatOutcome::Dropped(_)   => { /* observer absent or queue full — safe to ignore */ }
            BeatOutcome::Failed(e)    => eprintln!("beat error: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
```

## API summary

### `Varta`

| Method | Signature | Description |
|--------|-----------|-------------|
| `connect` | `(path: impl AsRef<Path>) -> io::Result<Varta>` | Open a non-blocking `UnixDatagram` to the observer. The only allocation point. |
| `beat` | `(&mut self, status: Status, payload: u64) -> BeatOutcome` | Emit one 32-byte VLP frame. Never blocks; never allocates. |
| `reconnect` | `(&mut self) -> io::Result<()>` | Re-bind the socket to the observer path (e.g. after an observer restart). |
| `set_reconnect_after` | `(&mut self, n: u32)` | Enable auto-reconnect after `n` consecutive `Dropped` outcomes. |

### `BeatOutcome`

| Variant | Meaning |
|---------|---------|
| `Sent` | Kernel accepted the datagram. |
| `Dropped(DropReason)` | Datagram not delivered — treat as no-op. The `DropReason` identifies the underlying cause (see table below). |
| `Failed(BeatError)` | Unexpected I/O error; the inner error does not allocate. |

### `DropReason`

| Variant | Source errors | Interpretation |
|---------|--------------|----------------|
| `KernelQueueFull` | `WouldBlock`, `ENOBUFS` | Transient burst; observer is likely alive. Retry or rely on `set_reconnect_after`. |
| `NoObserver` | `NotFound`, `ConnectionRefused` | Observer not yet bound — expected during rolling restarts. |
| `PeerGone` | `ConnectionReset`, `NotConnected`, `BrokenPipe` | Channel was live and disappeared (crash or shutdown). Call `reconnect` to recover. |
| `StorageFull` | `StorageFull` | Host filesystem full; operator intervention required. |

### `Status`

| Variant | Wire value | Meaning |
|---------|-----------|---------|
| `Ok` | `0` | Healthy and making progress. |
| `Degraded` | `1` | Making progress with elevated trouble. |
| `Critical` | `2` | About to die; also emitted by the panic hook. |
| `Stall` | `3` | Synthesised by `varta-watch` on silence; agents do not send this. |

## Payload encoding

The 64-bit `payload` field is application-defined. A common convention is to
pack two `u32` values:

```rust,no_run
// high 32 bits = queue depth, low 32 bits = last error code
let payload = (queue_depth as u64) << 32 | (last_error_code as u64);
```

The observer carries the payload opaquely; decoding belongs to the agent and
any downstream tool that reads the exported metrics file.

## `panic-handler` feature flag

Enable the optional panic hook to emit a `Status::Critical` frame before
normal unwinding:

```toml
# Cargo.toml
[dependencies.varta-client]
path = "../varta-client"
features = ["panic-handler"]
```

```rust,no_run
// Call once at process start, before any other setup.
varta_client::install_panic_handler("/tmp/varta.sock");
```

The hook chains the previously installed hook (preserving the default panic
message and any user hooks). The sole heap allocation is the `Box` created by
`std::panic::set_hook` at install time; the hook closure itself is stack-only.

## Fork recovery & tracker semantics

`Varta` snapshots the calling process's PID at `connect()` time and compares
`std::process::id()` against the snapshot on every `beat()`. If they differ
— i.e. the process executing `beat()` is a forked child that inherited the
parent's `Varta` — the client transparently recovers:

1. `transport.reconnect()` runs (re-binds the underlying socket; on
   secure-UDP, refreshes the IV salt from OS entropy so AEAD nonce uniqueness
   is preserved across the fork boundary).
2. The per-connection counters (`nonce`, `start`, `last_timestamp`,
   `consecutive_dropped`) reset, because the child's frame stream is
   logically a new connection from the observer's perspective — every wire
   field is keyed by `frame.pid`, which is now the child's PID.
3. The `fork_recoveries` counter increments. Surface it as
   `varta_client_fork_recoveries_total` via `Varta::fork_recoveries()` if
   you publish client-side telemetry.

Once recovered, the child's first beat goes into a fresh tracker slot on
the observer (different PID → different slot), so the child's frames never
race the parent's frames at the protocol level.

### The parent-pid stall window

The auto-recovery handles the *child*. The *parent* is harder: if the
parent process forks and then exits (a classic daemonise pattern), its PID
disappears from the kernel but the observer's tracker slot for that PID
keeps aging. After `--threshold-ms` it stalls; if recovery is configured
for kernel-attested origins, the observer may fire a recovery command for
a PID that no longer exists.

The fix is on the agent side, not the observer side. Two patterns work:

* **Preferred — emit a terminal frame before the parent exits.** Send one
  last `Status::Critical` beat from the parent immediately before
  `exit(0)`. The observer records the critical frame and treats subsequent
  silence as expected. The panic hook does this for free with
  `nonce == NONCE_TERMINAL`; for clean exits, hand-roll the call:

  ```rust,ignore
  let _ = agent.beat(Status::Critical, 0);  // "I am leaving"
  std::process::exit(0);
  ```

* **Alternative — widen the threshold.** If the parent reliably exits
  within a few hundred milliseconds of fork, set `--threshold-ms` on the
  observer above that window so the parent's slot is collected (per
  `EVICTION_MULTIPLIER × threshold_ns`) before recovery would fire.

The child's slot is never affected by this concern: it has a different PID,
its own slot, and its own monotonically resetting nonce stream. There is no
within-PID nonce collision because the IV salt + counter rotate on
secure-UDP and the plaintext transports do not key on continuity.

## Constraints

- **Zero production dependencies.** `[dependencies]` is empty (plus the
  path dep on `varta-vlp`); no registry crate is pulled in.
- **Zero steady-state allocation.** After `Varta::connect`, `beat()` does not
  touch the heap. Verified by a guard-allocator test in `varta-tests`.
- **Non-blocking.** The socket is set to non-blocking mode at `connect()` time; `WouldBlock` is treated as `Dropped(DropReason::KernelQueueFull)` — the caller never stalls.

## See also

- Protocol crate: [`crates/varta-vlp/README.md`](../varta-vlp/README.md)
- Examples: [`crates/varta-client/examples/`](examples/)
- Architecture: [`book/src/architecture/vlp-frame.md`](../../book/src/architecture/vlp-frame.md)

## Other languages

Official clients in non-Rust languages live under
[`clients/`](../../clients/). Today: Python
([`clients/python/`](../../clients/python/), `pip install varta`), Go
([`clients/go/`](../../clients/go/),
`go get github.com/aramirez087/Varta/clients/go`), Node.js
([`clients/node/`](../../clients/node/),
`npm install @varta-health/client`), .NET
([`clients/dotnet/`](../../clients/dotnet/),
`dotnet add package Varta.Client`), and JVM
([`clients/java/`](../../clients/java/),
`implementation("health.varta:varta-client:0.2.0")`). Each port preserves
the same wire-level contract and is verified against the same
`tools/vlp-test-vectors.json` conformance suite as this crate.
