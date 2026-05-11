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
     │   ├── UdpTransport│            │   ├── UdpListener  │
     │   └── SecureUdpTransport (secure-udp feat.)│   └── SecureUdpListener (secure-udp feat.)│
     │       (udp feat.) │            │       (udp feat.) │
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
When the `secure-udp` feature is enabled, `SecureUdpTransport` is available
via `Varta::connect_secure_udp(addr, key)` — every beat is encrypted with
ChaCha20-Poly1305 AEAD (RFC 8439).

### Observer side (`varta-watch`)

```rust
pub trait BeatListener: Send + 'static {
    fn recv(&mut self) -> RecvResult;
    fn drain_decrypt_failures(&mut self) -> u64 { 0 }  // default = 0
    fn drain_truncated(&mut self) -> u64 { 0 }         // default = 0
}
```

The `Observer` holds a `Vec<Box<dyn BeatListener>>` and polls all listeners
round-robin on each `poll()` call. When `--udp-port` is passed at the CLI,
a `UdpListener` is added alongside the UDS listener.

## Transport comparison

| | UDS (default) | UDP (feature = "udp") | Secure UDP (feature = "secure-udp") |
|---|---|---|---|
| **Addressing** | Filesystem path | `IP:PORT` | `IP:PORT` |
| **Encryption** | None (kernel isolation) | None | ChaCha20-Poly1305 AEAD |
| **Authentication** | Kernel PID via `SO_PASSCRED` (Linux) | None | Poly1305 tag verification |
| **Replay protection** | None (local IPC) | None | Per-sender IV counter monotonicity |
| **Trust model** | Filesystem permissions | Network segmentation | 256-bit pre-shared key |
| **Frame size** | 32 bytes | 32 bytes | 60 bytes (AEAD overhead) |
| **Socket cleanup** | `UdsListener::drop` unlinks socket | Kernel reclaims port | Kernel reclaims port |
| **Use case** | Local IPC, process monitoring | IoT/edge, microservices | Anything crossing untrusted networks |

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

# UDP with ChaCha20-Poly1305 encryption
# Generate a 256-bit key (64 hex chars)
openssl rand -hex 32 > /tmp/varta.key

varta-watch --socket /tmp/varta.sock --threshold-ms 500 \
            --udp-port 9000 --key-file /tmp/varta.key

# Rotation: accept old key while transitioning to new key
openssl rand -hex 32 > /tmp/varta-new.key
varta-watch --socket /tmp/varta.sock --threshold-ms 500 \
            --udp-port 9000 --key-file /tmp/varta.key \
            --accepted-key-file /tmp/varta-new.key

# Key from environment variable (default: VARTA_KEY)
export VARTA_KEY=$(openssl rand -hex 32)
varta-watch --socket /tmp/varta.sock --threshold-ms 500 --udp-port 9000
```

## Feature flags

| Crate | Flag | Effect |
|---|---|---|
| `varta-vlp` | `crypto` | Enables ChaCha20-Poly1305 AEAD (`seal`, `open`, `Key`) |
| `varta-client` | `udp` | Enables `UdpTransport`, `Varta::connect_udp()`, `install_panic_handler_udp()` |
| `varta-client` | `secure-udp` | Enables `SecureUdpTransport`, `Varta::connect_secure_udp()`; implies `udp` |
| `varta-watch` | `udp` | Enables `UdpListener`, `--udp-port` / `--udp-bind-addr` CLI flags |
| `varta-watch` | `secure-udp` | Enables `SecureUdpListener`, `--key-file` / `--accepted-key-file` / `--key-env`; implies `udp` |
| `varta-tests` | `udp` | Enables UDP integration tests |
| `varta-bench` | `udp` | Enables `udp-latency` benchmark subcommand |

## Security

- **UDS**: On Linux, the kernel attests the sender's PID via `SCM_CREDENTIALS`.
  The observer rejects frames where `frame.pid != peer_pid`. On macOS, this
  mechanism is unavailable for unconnected `SOCK_DGRAM`; the trust boundary is
  restricted by `--socket-mode 0600` (owner-only access).

- **UDP (plaintext)**: No kernel credential mechanism exists. `peer_pid` is
  always 0, which causes the observer to skip PID verification. Trust must be
  established at the network layer — firewall rules, VPC boundaries.

- **UDP (secure)**: Every frame is encrypted with ChaCha20-Poly1305 (RFC 8439)
  using a 256-bit pre-shared key. The 60-byte wire format adds a 4-byte random
  IV prefix, an 8-byte monotonic counter, and a 16-byte Poly1305 tag. Replay
  attacks are blocked by enforcing monotonic IV counters per sender. Key
  rotation is supported via `--accepted-key-file` (no downtime required).

## Future transports

Additional transports can be implemented by implementing `BeatTransport` (agent
side) and `BeatListener` (observer side) without touching the protocol core:

- **Shared memory** (`memfd`, `shm`) — Wasm plugins writing directly to a
  shared ring buffer
- **Unix pipes** (`pipe`, `fifo`) — stdin/stdout health frames for supervised
  processes
- **WebSocket** — for browser-based health dashboards
