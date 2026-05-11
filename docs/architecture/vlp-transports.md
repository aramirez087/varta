# VLP Transports

The Varta Lifeline Protocol (VLP) wire format is entirely transport-agnostic — a 32-byte,
8-byte-aligned `#[repr(C)]` frame. The transport layer is abstracted via traits that
allow swapping out the underlying socket type without modifying the protocol core.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  varta-vlp                                                       │
│   Frame (32 bytes) │ Status │ DecodeError                        │
│   Zero dependencies. Never changes.                              │
└────────────┬───────────────────────────────┬─────────────────────┘
             │                               │
    ┌────────▼─────────┐            ┌────────▼──────────┐
    │  varta-client     │            │  varta-watch       │
    │                   │            │                    │
    │  BeatTransport    │            │  BeatListener      │
    │   ├── UdsTransport│            │   ├── UdsListener  │
    │   └── UdpTransport│            │   └── UdpListener  │
    │       (udp feat.) │            │       (udp feat.)  │
    └───────────────────┘            └────────────────────┘
```

### Agent side (`varta-client`)

```rust
pub trait BeatTransport: Send + 'static {
    fn send(&mut self, buf: &[u8; 32]) -> io::Result<usize>;
    fn reconnect(&mut self) -> io::Result<()>;
}
```

`Varta<T: BeatTransport>` owns a transport and calls `send(2)` on every `beat()`.
The default transport is `UdsTransport` (Unix Domain Socket). When the `udp`
feature is enabled, `UdpTransport` is available via `Varta::connect_udp(addr)`.

### Observer side (`varta-watch`)

```rust
pub trait BeatListener: Send + 'static {
    fn recv(&mut self) -> RecvResult;
}
```

The `Observer` holds a `Vec<Box<dyn BeatListener>>` and polls all listeners
round-robin on each `poll()` call. When `--udp-port` is passed at the CLI,
a `UdpListener` is added alongside the UDS listener.

## Transport comparison

| | UDS (default) | UDP (feature = "udp") |
|---|---|---|
| **Addressing** | Filesystem path | `IP:PORT` |
| **PID verification** | Linux: kernel-attested via `SO_PASSCRED` / `SCM_CREDENTIALS` | None — `peer_pid` is always 0 |
| **Trust model** | Filesystem permissions (`--socket-mode`) | Network segmentation (firewall, VPC) |
| **Socket cleanup** | `UdsListener::drop` unlinks the socket file | None (kernel reclaims port) |
| **Use case** | Local IPC, process monitoring | IoT/edge devices, microservices, containers |

## CLI additions

```bash
# Listen on UDS only (default)
varta-watch --socket /tmp/varta.sock --threshold-ms 500

# Listen on UDS + UDP (requires --features udp at build time)
varta-watch --socket /tmp/varta.sock --threshold-ms 500 \
            --udp-port 9000 --udp-bind-addr 0.0.0.0

# UDP-only (no UDS)
varta-watch --socket /tmp/varta.sock --threshold-ms 500 \
            --udp-port 9000
```

## Feature flags

| Crate | Flag | Effect |
|---|---|---|
| `varta-client` | `udp` | Enables `UdpTransport`, `Varta::connect_udp()`, `install_panic_handler_udp()` |
| `varta-watch` | `udp` | Enables `UdpListener`, `--udp-port` / `--udp-bind-addr` CLI flags |
| `varta-tests` | `udp` | Enables UDP integration tests |
| `varta-bench` | `udp` | Enables `udp-latency` benchmark subcommand |

## Security

- **UDS**: On Linux, the kernel attests the sender's PID via `SCM_CREDENTIALS`.
  The observer rejects frames where `frame.pid != peer_pid`. On macOS, this
  mechanism is unavailable for unconnected `SOCK_DGRAM`; the trust boundary is
  restricted by `--socket-mode 0600` (owner-only access).

- **UDP**: No kernel credential mechanism exists. `peer_pid` is always 0,
  which causes the observer to skip PID verification (same path as macOS UDS).
  Trust must be established at the network layer — firewall rules, VPC
  boundaries, or a shared secret embedded in the frame payload.

## Future transports

Additional transports can be implemented by implementing `BeatTransport` (agent
side) and `BeatListener` (observer side) without touching the protocol core:

- **Shared memory** (`memfd`, `shm`) — Wasm plugins writing directly to a
  shared ring buffer
- **Unix pipes** (`pipe`, `fifo`) — stdin/stdout health frames for supervised
  processes
- **WebSocket** — for browser-based health dashboards
