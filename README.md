# Varta

<p align="center">
  <img src="assets/varta-animation.svg" alt="Varta Animation" width="100%">
</p>

Zero-overhead health protocol for distributed local agents.

Varta lets any local process emit a 32-byte heartbeat over a Unix Domain
Socket. A companion observer (`varta-watch`) decodes the frames, detects
stalls, triggers recovery commands, and exports Prometheus metrics — all
without a single registry dependency on either side.

## Why Varta

- **Zero dependencies.** Production crates carry an empty `[dependencies]`
  section. No `tokio`, no `serde`, no `libc`. Drop in one path dep and get
  health signalling.
- **Zero steady-state allocation.** After `Varta::connect`, every `beat()`
  call operates on a stack buffer. Verified by a guard-allocator test in
  `varta-tests`.
- **Sub-microsecond beat path.** The steady-state `beat()` encodes a 32-byte
  frame and hands it to `send(2)`. See [benchmark results](docs/benchmarks/results.md)
  for measured numbers.
- **Non-blocking by design.** The agent socket is set to non-blocking at
  connect time. A missing or busy observer surfaces as `BeatOutcome::Dropped`
  — never a stall in your hot path.

## Install

Varta is not yet published to crates.io (post-v0.1.0). Use a path dependency:

```toml
[dependencies.varta-client]
path = "path/to/varta/crates/varta-client"
```

To enable the optional panic hook:

```toml
[dependencies.varta-client]
path = "path/to/varta/crates/varta-client"
features = ["panic-handler"]
```

## Quickstart

```rust,no_run
use varta_client::{BeatOutcome, Status, Varta};

fn main() -> std::io::Result<()> {
    // One allocation: opens the Unix Domain Socket.
    let mut agent = Varta::connect("/tmp/varta.sock")?;

    loop {
        // Zero allocation: encodes on the stack, hands to send(2).
        match agent.beat(Status::Ok, 0) {
            BeatOutcome::Sent    => {}
            BeatOutcome::Dropped => { /* observer absent — safe to continue */ }
            BeatOutcome::Failed(e) => eprintln!("beat: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
```

Start the observer in a separate terminal:

```sh
varta-watch \
  --socket /tmp/varta.sock \
  --threshold-ms 2000 \
  --prom-addr 127.0.0.1:9100
```

Then inspect the metrics:

```sh
curl -s http://127.0.0.1:9100/metrics
```

## Crates

| Crate | README | Description |
|-------|--------|-------------|
| `varta-vlp` | [README](crates/varta-vlp/README.md) | 32-byte wire protocol — `Frame`, `Status`, encode/decode. |
| `varta-client` | [README](crates/varta-client/README.md) | Agent API — `Varta::connect`, `beat`, optional panic hook. |
| `varta-watch` | [README](crates/varta-watch/README.md) | Observer binary — stall detection, file export, Prometheus. |

## Performance

Benchmark results are in [docs/benchmarks/results.md](docs/benchmarks/results.md).
The steady-state `beat()` path is designed to be invisible at runtime: one
stack encode, one `send(2)`, no allocations.

## Constraints

- **No registry dependencies** in any production crate.
- **No heap allocation** after `Varta::connect` in the steady-state beat path.
- **No blocking** — `WouldBlock` is treated as `Dropped`, never as an error
  that stalls the caller.
- **Edition 2021**, pinned toolchain via `rust-toolchain.toml`.
