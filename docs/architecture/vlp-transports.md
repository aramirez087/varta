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
|---|---|---|---|---|
| **Addressing** | Filesystem path | `IP:PORT` | `IP:PORT` |
| **Encryption** | None (kernel isolation) | None | ChaCha20-Poly1305 AEAD |
| **Authentication** | Kernel PID + UID via `SO_PASSCRED` (Linux) / `LOCAL_PEERTOKEN` (macOS) | None | Poly1305 tag + PID in IV prefix (master-key mode) — wire-content only, not the sending process |
| **Replay protection** | None (local IPC) | None | Per-sender IV counter monotonicity |
| **Trust model** | Filesystem permissions + kernel credential attestation | Network segmentation | 256-bit pre-shared or per-agent derived key |
| **Origin classification** | `KernelAttested` | `NetworkUnverified` | `NetworkUnverified` (cryptographic binding ≠ kernel attestation) |
| **Recovery-eligible by default?** | **Yes** | **No** (see [peer-authentication.md → Recovery eligibility]) | **No** (same gate; even master-key derivation cannot replace kernel attestation) |
| **Frame size** | 32 bytes | 32 bytes | 60 bytes (AEAD overhead) |
| **Socket cleanup** | `UdsListener::drop` unlinks socket | Kernel reclaims port | Kernel reclaims port |
| **Use case** | Local IPC, process monitoring | IoT/edge, microservices | Anything crossing untrusted networks |

> **Recovery-on-UDP is structurally rejected by default.** Combining any
> recovery flag (`--recovery-cmd` / `--recovery-exec` / `*-file`) with
> `--udp-port` is a startup hard-error unless the operator passes
> `--i-accept-recovery-on-unauthenticated-transport`.  Even with the flag,
> the runtime origin gate still refuses to fire recovery for UDP-origin
> stalls — flipping `Recovery::with_allow_unauthenticated_source(true)` is
> a separate, conscious choice.  See
> `docs/architecture/peer-authentication.md` for the full threat model.

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

# Per-agent key derivation from master key
# The observer derives agent-specific keys from the PID embedded in
# each frame's iv_random prefix. Compromise of one agent's key does
# not reveal other agents' keys or the master key.
openssl rand -hex 32 > /tmp/varta-master.key
varta-watch --socket /tmp/varta.sock --threshold-ms 500 \
            --udp-port 9000 --master-key-file /tmp/varta-master.key
```

## Feature flags

| Crate | Flag | Effect |
|---|---|---|
| `varta-vlp` | `crypto` | Enables ChaCha20-Poly1305 AEAD (`seal`, `open`, `Key`) |
| `varta-client` | `udp` | Enables `UdpTransport`, `Varta::connect_udp()`, `install_panic_handler_udp()` |
| `varta-client` | `secure-udp` | Enables `SecureUdpTransport`, `Varta::connect_secure_udp()`; implies `udp` |
| `varta-watch` | `udp` | Enables `UdpListener`, `--udp-port` / `--udp-bind-addr` CLI flags |
| `varta-watch` | `secure-udp` | Enables `SecureUdpListener`, `--key-file` / `--accepted-key-file` / `--master-key-file`; implies `udp-core` |
| `varta-tests` | `udp` | Enables UDP integration tests |
| `varta-bench` | `udp` | Enables `udp-latency` benchmark subcommand |

## Security

- **UDS**: On Linux, the kernel attests the sender's PID and UID via
  `SCM_CREDENTIALS`. The observer rejects frames where `frame.pid != peer_pid`
  or `peer_uid != observer_uid`. On macOS, `getsockopt(LOCAL_PEERTOKEN)` is
  attempted for the same verification, falling back to `--socket-mode 0600`.
  On other platforms, the only defence is `--socket-mode`.

- **UDP (plaintext)**: No kernel credential mechanism exists. `peer_pid` is
  always 0, which causes the observer to skip PID verification. Trust must be
  established at the network layer — firewall rules, VPC boundaries.

- **UDP (secure)**: Every frame is encrypted with ChaCha20-Poly1305 (RFC 8439)
  using a 256-bit key. Primitives are provided by the `chacha20poly1305` crate
  (RustCrypto, NCC Group audit 2020) — no hand-rolled crypto. Key derivation
  uses HKDF-SHA256 (RFC 5869) via the `hkdf` + `sha2` crates. Two key modes:
  - **Shared key**: A single pre-shared key for all agents (`--key-file`).
  - **Master key**: Per-agent keys derived from the agent's PID via HKDF-SHA256
    (`--master-key-file`). The PID is embedded in the `iv_random` prefix so
    the observer can derive the correct agent key before decryption. Compromise
    of one agent's key does not reveal other agents' keys or the master key.
    **Note:** the HKDF-based KDF is incompatible with the ChaCha20-PRF KDF used
    in earlier releases — agents must re-key when upgrading from a pre-RustCrypto
    build if master-key mode was in use.
  - Replay attacks are blocked by enforcing monotonic IV counters per sender.
    Key rotation is supported via `--accepted-key-file` (no downtime required).
  - **Panic-hook entropy**: `install_panic_handler_secure_udp` reads entropy at
    install time and **fails closed** if all sources (`getrandom`, `getentropy`,
    `/dev/urandom`) are unavailable. In chrooted environments without `/dev`,
    use `install_panic_handler_secure_udp_accept_degraded_entropy` to opt into a
    non-cryptographic fallback — see `docs/architecture/peer-authentication.md`
    for the full nonce-reuse risk analysis.

- **Recovery commands**: Two execution modes:
  - `--recovery-cmd`: Shell mode — templates executed via `/bin/sh -c` with
    the PID as `$1` (positional argument, never string-interpolated).
  - `--recovery-exec`: Exec mode — commands executed directly via `execvp(2)`
    with `{pid}` replaced in arguments. No shell is involved.
  - `--recovery-cmd-file` / `--recovery-exec-file`: Read templates from files
    with mandatory ownership/permission checks (UID match, mode ≤ 0600).

## Cross-references

- [Observer liveness](observer-liveness.md) — the watcher's own liveness story: in-process self-watchdog, systemd `sd_notify`, hardware watchdog, and paired-observer pattern
- [Safety profiles](safety-profiles.md) — compile-time vs. runtime feature gating for production-safe builds
- [Peer authentication](peer-authentication.md) — kernel-level PID attestation and transport trust classification

---

## Future transports

Additional transports can be implemented by implementing `BeatTransport` (agent
side) and `BeatListener` (observer side) without touching the protocol core:

- **Shared memory** (`memfd`, `shm`) — Wasm plugins writing directly to a
  shared ring buffer
- **Unix pipes** (`pipe`, `fifo`) — stdin/stdout health frames for supervised
  processes
- **WebSocket** — for browser-based health dashboards
