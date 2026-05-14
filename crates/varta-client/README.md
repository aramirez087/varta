# varta-client

[![crates.io](https://img.shields.io/crates/v/varta-client)](https://crates.io/crates/varta-client)

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
            BeatOutcome::Sent    => {}
            BeatOutcome::Dropped => { /* observer absent — safe to ignore */ }
            BeatOutcome::Failed(e) => eprintln!("beat error: {e}"),
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
| `Dropped` | Observer absent, queue full, or socket vanished — treat as no-op. |
| `Failed(io::Error)` | Unexpected I/O error; the inner error does not allocate. |

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

## Constraints

- **Zero production dependencies.** `[dependencies]` is empty (plus the
  path dep on `varta-vlp`); no registry crate is pulled in.
- **Zero steady-state allocation.** After `Varta::connect`, `beat()` does not
  touch the heap. Verified by a guard-allocator test in `varta-tests`.
- **Non-blocking.** The socket is set to non-blocking mode at `connect()` time; `WouldBlock` is treated as `Dropped` — the caller never stalls.

## See also

- Protocol crate: [`crates/varta-vlp/README.md`](../varta-vlp/README.md)
- Examples: [`crates/varta-client/examples/`](examples/)
- Architecture: [`book/src/architecture/vlp-frame.md`](../../book/src/architecture/vlp-frame.md)
