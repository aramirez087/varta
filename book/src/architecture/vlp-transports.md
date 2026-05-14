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
> `book/src/architecture/peer-authentication.md` for the full threat model.

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
| `varta-vlp` | `crypto` | Enables ChaCha20-Poly1305 AEAD (`seal`, `open`, `Key`). No_std-compatible — all four RustCrypto deps are `default-features = false`. |
| `varta-vlp` | `std` | Opt-in std-dependent conveniences (`Key::from_file`, `std::path::Path`-typed helpers). **Off by default** so the crate is `#![no_std]` + alloc-free out of the box — ready for FreeRTOS/Zephyr targets. |
| `varta-client` | `udp` | Enables `UdpTransport`, `Varta::connect_udp()`, `install_panic_handler_udp()` |
| `varta-client` | `secure-udp` | Enables `SecureUdpTransport`, `Varta::connect_secure_udp()`; implies `udp`, `varta-vlp/crypto`, and `varta-vlp/std` (the `secure_udp` example calls `Key::from_file`). |
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
    non-cryptographic fallback — see `book/src/architecture/peer-authentication.md`
    for the full nonce-reuse risk analysis.

- **Recovery commands**: Two execution modes:
  - `--recovery-cmd`: Shell mode — templates executed via `/bin/sh -c` with
    the PID as `$1` (positional argument, never string-interpolated).
  - `--recovery-exec`: Exec mode — commands executed directly via `execvp(2)`
    with `{pid}` replaced in arguments. No shell is involved.
  - `--recovery-cmd-file` / `--recovery-exec-file`: Read templates from files
    with mandatory ownership/permission checks (UID match, mode ≤ 0600).

## Container / PID-namespace semantics

`Frame.pid` carries the agent's PID **in the agent's PID namespace**. The
observer's kernel-attested peer PID (`SO_PASSCRED` / `LOCAL_PEERTOKEN` /
`SCM_CREDS`) is in the **observer's** namespace. When the two namespaces
differ:

- The pid in the frame cannot be used to identify a process the observer can
  `kill(2)` or `systemctl restart` — the same numeric PID refers to a different
  process in each namespace.
- The existing `frame.pid == peer_pid` check at observer ingress catches most
  cases (different namespaces usually produce different numeric pids), but
  same-pid collisions across containers (every container's first process is
  PID 1) are invisible to that gate.

`varta-watch` therefore (Linux only):

1. Reads `/proc/self/ns/pid` once at startup and caches the inode as the
   observer's namespace identity.
2. For every kernel-attested beat (UDS), reads `/proc/<peer_pid>/ns/pid` and
   compares the inode to the observer's. Mismatch ⇒ drop the beat
   (`varta_frame_namespace_mismatch_total++`) and emit
   `Event::NamespaceConflict`.
3. Per-pid tracker slots pin the namespace inode at first beat; a later beat
   with a different `Some(_)` inode is rejected as `Update::NamespaceConflict`
   (`varta_tracker_namespace_conflict_total++`).
4. Recovery commands refuse to spawn for cross-namespace stalls and log an
   audit record with `reason=cross_namespace_agent`
   (`varta_recovery_refused_total{reason="cross_namespace_agent"}++`).

### Escape hatch — `--allow-cross-namespace-agents`

When agents are intentionally run with `--pid=host` (containers sharing the
host PID namespace), the observer's namespace and the agents' namespace agree
at the kernel level — the gate above is a no-op.

For deployments where the agent runs in a private namespace **and** the
operator has out-of-band PID translation (e.g. CNI metadata that lets a
recovery script translate container pids to host pids), pass
`--allow-cross-namespace-agents`. The audit log and metrics still fire, but
beats are admitted and recovery is permitted.

### `--strict-namespace-check`

Treat namespace mismatch as a fatal startup error: on the first
`Event::NamespaceConflict`, the daemon logs a `FATAL` line and exits with a
non-zero status. Used in environments where the operator wants the daemon to
fail loudly rather than silently log audit refusals.

### Non-Linux platforms

PID namespaces are a Linux kernel concept. On macOS and the BSDs,
`observer_pid_namespace_inode()` returns `None` and all comparisons
short-circuit to "match". The CLI flags are accepted for portability but
have no runtime effect.

### UDP transports

UDP listeners (plain or secure) have no kernel peer-cred mechanism.
`peer_pid` is 0; `peer_pid_ns_inode` is `None`. Recovery is already refused
for `NetworkUnverified` origins by the existing transport gate — namespace
mismatch adds nothing for UDP. See
[`peer-authentication.md`](peer-authentication.md) for the full trust model.

## Secure UDP — replay-shadow threat boundary (H4)

`SecureUdpListener` keeps per-sender replay state in a bounded `HashMap`
indexed by `SocketAddr`:

- Capacity: `MAX_SENDER_STATES = 1024` simultaneously-tracked senders.
- After capacity is reached, `force_evict_oldest_sender` stashes the
  evicted sender's `(addr, SenderState)` in a **single-slot**
  `last_evicted: Option<(SocketAddr, SenderState)>` shadow so a replay
  attempt from the just-evicted sender is still rejected.

The shadow is one entry deep.  An attacker who can spoof UDP source
addresses can cycle ≥1025 distinct sources to overwrite the shadow with
their own chaff, then replay a captured frame from the target sender as
if it were a "new" sender — the listener has no surviving record of
the target's last counter and accepts the replay.

### Why the shadow isn't deeper

A 1-deep shadow is acceptable for the loopback configuration: only
processes on the same host can craft loopback source addresses
(`127.0.0.0/8` requires `CAP_NET_RAW` to set as a UDP source, and even
then the kernel refuses spoofed loopback from external interfaces).  On
any reachable network — VLAN, VPC, the public internet — the source
address is freely forgeable, and a deeper shadow merely raises the
attacker's required address budget rather than closing the gap.
Bounding the shadow to a single slot keeps the eviction story
constant-time and aligns the threat boundary with a clean operational
constraint (network reach), rather than a fuzzy quantitative argument
about how many spoofed sources are "enough".

### Mitigation

`varta-watch` defaults `--udp-bind-addr` to `127.0.0.1` when secure-UDP
keys are configured.  Operators who genuinely need the listener to
accept non-loopback peers must pass `--i-accept-secure-udp-non-loopback`
explicitly — a CLI flag whose name signals the residual risk.  When the
flag is set, a high-visibility startup warning is emitted to stderr and
the operator is expected to constrain network reach (firewall, private
VLAN, mTLS-fronted tunnel) so that no untrusted host can reach the bound
port.

The recovery gate on `NetworkUnverified` origins (see
[`peer-authentication.md`](peer-authentication.md)) remains independent
of this flag — opting in to non-loopback secure-UDP does NOT enable
recovery commands from UDP-origin beats.  Those still require the
separate
`--secure-udp-i-accept-recovery-on-unauthenticated-transport`
acknowledgement.

## Fork-safety on secure-UDP

After `fork(2)`, a child process inherits its parent's
`SecureUdpTransport` state — the 16-byte `iv_session_salt`, the
`iv_prefix_index`, and the `iv_counter`. Three nominally-independent
fields whose product defines the AEAD nonce. If the child ever calls
`Varta::beat()` without intervention, it derives the same 12-byte
ChaCha20-Poly1305 nonce its parent has already emitted under the same
key — a *catastrophic* confidentiality and integrity failure (Poly1305
key recovery, plaintext XOR leak).

### How `Varta` enforces fork-safety structurally

`Varta::connect` snapshots `std::process::id()` into a private
`connect_pid` field. Every `Varta::beat` reads the current PID and
compares — on mismatch (i.e. the handle is now in a forked child), the
wrapper invokes `transport.reconnect()` **before** building the frame.
`SecureUdpTransport::reconnect()` re-reads OS entropy into a fresh
16-byte session salt, recomputes the IV prefix, and resets the prefix
index and counter to zero. The child's first emitted frame therefore
uses an IV prefix derived from independent entropy — nonce collision
across the fork boundary is impossible.

Auto-recovery is silent: the caller observes `BeatOutcome::Sent`. The
event is observable via `Varta::fork_recoveries() -> u64` (suggested
Prometheus name: `varta_client_fork_recoveries_total`). The local
session epoch resets too — `nonce → 0`, `start → Instant::now()`,
`last_timestamp → 0`, `consecutive_dropped → 0` — so the child's
wire stream looks like a fresh session to the observer.

### Observer view

The observer's per-sender state in `SecureUdpListener` is keyed by
`(SocketAddr, iv_prefix)` with a 1-deep replay history (see
[H4 replay shadow](#secure-udp--replay-shadow-threat-boundary-h4) above).
When the forked child sends frames from the same source port with a
new IV prefix, the observer transitions its current state into the
`prev_*` slots and accepts the new prefix as a fresh session — no
replay error, no protocol-level signal required. Fork-recovery is
*entirely transparent* to the wire format.

### Advanced callers

Callers using `SecureUdpTransport` directly (without the `Varta`
wrapper) do **not** get auto-detection. The `BeatTransport` trait is
intentionally low-level; the safety policy lives one layer up.
Direct-transport users must call `SecureUdpTransport::reconnect()`
themselves in the forked child before the first beat.

### Panic-hook parallel

`install_panic_handler_secure_udp` caches an 8-byte IV at install time
to avoid the (non-async-signal-safe) entropy read inside the panic
hook itself. The same fork hazard applies: a child that panics would
otherwise emit `(cached_iv, iv_counter=1)` — colliding with the
parent's identical pair if the parent panicked too. The installer
snapshots `install_pid` and, inside the hook, re-runs the entropy
chain (`getrandom`/`getentropy` → `/dev/urandom`) when the PID has
changed. The strict variant fails closed (skips the secure frame) when
no entropy source is reachable; the `accept-degraded-entropy` variant
falls back to `fallback_iv_random()` per the documented degraded-entropy
policy.

## Cross-references

- [Observer liveness](observer-liveness.md) — the watcher's own liveness story: in-process self-watchdog, systemd `sd_notify`, hardware watchdog, and paired-observer pattern
- [Safety profiles](safety-profiles.md) — compile-time vs. runtime feature gating for production-safe builds
- [Peer authentication](peer-authentication.md) — kernel-level PID attestation and transport trust classification
- [Namespaces](namespaces.md) — dedicated reference for cross-namespace deployments

---

## Future transports

Additional transports can be implemented by implementing `BeatTransport` (agent
side) and `BeatListener` (observer side) without touching the protocol core:

- **Shared memory** (`memfd`, `shm`) — Wasm plugins writing directly to a
  shared ring buffer
- **Unix pipes** (`pipe`, `fifo`) — stdin/stdout health frames for supervised
  processes
- **WebSocket** — for browser-based health dashboards
