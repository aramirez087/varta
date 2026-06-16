# Glossary

Terms that recur throughout the Varta documentation. Where a term has a
formal definition in the source, the canonical location is linked.

---

### AEAD
Authenticated Encryption with Associated Data. Varta's secure-UDP
transport uses **ChaCha20-Poly1305**, a stream cipher (ChaCha20) paired
with a polynomial MAC (Poly1305). Every secure-UDP frame is encrypted
and integrity-checked in one pass. See
[VLP — Secure Transport](../spec/vlp-secure.md).

### Agent
A process that emits Varta heartbeats. Agents link `varta-client` (or a
language port) and call `Varta::connect()` once at startup, then
`beat()` on whatever cadence they like.

### Audit log
The optional TSV file written by `varta-watch` when
`--recovery-audit-file <PATH>` is set. Records every recovery decision
— `Spawned`, `Debounced`, `Refused`, `Reaped`, `Killed` — with the
kernel-attested PID where available. Required for IEC 62304 / DO-178C
deployments. See [Audit Logging](../architecture/audit-log.md).

### Beat
One 32-byte VLP frame from agent to observer. The verb (`agent.beat()`)
and the noun (`varta_beats_total` counter) share the term.

### BeatOrigin
The observer's enum tag for *how the beat got here*. The recovery gate
uses this to decide whether to honour or refuse a stall.

| Variant | Meaning | Recovery eligibility |
|---|---|---|
| `KernelAttested` | UDS with peer-cred PID verified | ✅ |
| `OperatorAttestedTransport` | Secure-UDP with master-key (PID bound to key derivation) | ✅ |
| `SocketModeOnly` | UDS on a platform without per-datagram peer-creds (e.g. OpenBSD) | ❌ refused with `socket_mode_only` |
| `NetworkUnverified` | Plaintext UDP | ❌ refused with `unauthenticated_transport` |

New variants default to *refused*. See [Threat
Model](../architecture/threat-model.md) and CLAUDE.md hard-constraint #8.

### BeatOutcome
The return type of `Varta::beat()`. Three variants:

- `Sent` — the kernel accepted the datagram.
- `Dropped(DropReason)` — the kernel returned `WouldBlock` or similar
  *expected* failure. **Not** an error; the beat path is non-blocking
  by contract.
- `Failed(io::Error)` — an *unexpected* error (e.g. `EBADF` after a
  socket-mode change). Surfaces to the caller.

### Class-A / Class-C
Refers to safety-critical software classifications used by IEC 62304
(medical) and DO-178C (avionics). **Class-A profile** in Varta is the
structurally-excised binary built with the `compile-time-config`
feature instead of `prometheus-exporter`: no HTTP server, no `/bin/sh`,
no `--`-prefixed flag literals. CI's `safety-profiles` job enforces
this via a `strings` audit. See [Safety
Profiles](../architecture/safety-profiles.md).

### Debounce window
The per-pid interval (`--recovery-debounce-ms`) during which a repeat
stall on the same pid does **not** spawn another recovery child. Returns
the `Debounced` outcome instead.

### Frame
The 32-byte, fixed-layout, `#[repr(C, align(8))]` wire unit. Encoded
and decoded on the stack. See [VLP — Base Frame](../spec/vlp.md).

### Iteration
One full pass of the observer's poll loop: drain pending → poll
sockets → maintenance → recovery reap → serve pending → housekeeping.
The total wall time is `varta_observer_iteration_seconds`; per-stage
breakdown is `varta_observer_stage_seconds{stage=…}`. Worst-case bound:
~310 ms. See [Stall Detection &
Liveness](../architecture/observer-liveness.md).

### Kani
A bit-precise model checker for Rust by AWS. Varta uses Kani harnesses
under `crates/varta-vlp/` to exhaustively prove panic-freedom and
field-range correctness of `Frame::decode`. Runs as a nightly CI job.
See [Symbolic Verification](../architecture/verification.md).

### MAX_CAPACITY
The hard ceiling on simultaneously-tracked agent PIDs in
`varta-watch`: **4096**. Both the `Tracker` and `OutstandingTable`
share this bound. Operators tune the actual cap with
`--tracker-capacity`. To scale past 4096 on one host, run multiple
observer instances and shard the agent population client-side; see
[Deployment Ceiling &
Sharding](../architecture/deployment-ceiling-and-sharding.md).

### Observer
`varta-watch`. The single-threaded process that decodes beats, tracks
per-pid state, fires recovery, and exposes Prometheus metrics.

### `OutstandingTable`
The `BoundedIndex`-backed slab in `varta-watch` that holds outstanding
recovery children, keyed by stalled pid. Statically sized to
`MAX_CAPACITY`; zero heap allocation after construction. See
[Bounded Collections](../architecture/bounded-collections.md).

### Peer-cred / `SO_PASSCRED`
The Linux mechanism for the receiver of a UDS datagram to learn the
sender's UID + PID, attested by the kernel rather than claimed by the
sender. BSDs use `SCM_CREDS` / `SCM_CREDS2`; macOS pathname datagram sockets do not
provide equivalent per-datagram attestation for Varta's UDS transport.
Varta relies on peer credentials for `KernelAttested` BeatOrigin. See [Peer
Authentication](../architecture/peer-authentication.md).

### Recovery
The observer's response to a stall: spawn a configured command
(`--recovery-exec`) with the stalled pid as the final argument. Spawn
is non-blocking; the child is reaped on a later observer tick. See
[Recovery — Async Spawn](../architecture/recovery-async-spawn.md).

### Self-watchdog
The in-process watchdog thread (`--self-watchdog-secs`) that aborts
the observer (`SIGABRT`) if the main poll loop hasn't advanced within
the configured deadline. Distinct from the kernel hardware watchdog
(`--hw-watchdog`) and from systemd `WatchdogSec=`. All three can be
used together for layered defence.

### Shard
Running multiple `varta-watch` instances on one host, each bound to a
distinct socket path and `/metrics` port, with agents partitioning
themselves across the shards (typically by `pid % N`). The simplest
way to scale beyond `MAX_CAPACITY = 4096` on a single host.

### Stall
A pid that hasn't beat in `--threshold-ms`. The observer surfaces
`Event::Stall` and the recovery layer decides whether to fire.
Synthesised by the observer; never on the wire (`Status::Stall = 0x03`
is reserved for that purpose — frames carrying it are decoded as
`StallOnWire` errors).

### Status
The 1-byte field at offset 3 of every frame. Wire values: `0x00 Ok`,
`0x01 Degraded`, `0x02 Critical`. `0x03` is reserved for the
observer's stall synthesis and is rejected on the wire.

### Stage names
The six labels emitted under `varta_observer_stage_seconds{stage=…}`,
always in this canonical order: `drain_pending`, `poll`, `maintenance`,
`recovery_reap`, `serve_pending`, `housekeeping`.

### Tracker
The bounded open-addressed table in `varta-watch` that holds per-pid
state (last-seen-at, last-status, last-fired-recovery). Statically
sized to `MAX_CAPACITY = 4096`. Probe budget is bounded; see
[Bounded Collections](../architecture/bounded-collections.md).

### VLP
**V**arta **L**iveness **P**rotocol. The wire format. v0.2 is current
and frozen; future versions will be called out in the [Upgrade
Guide](../operations/upgrade.md). See [VLP — Base Frame](../spec/vlp.md).
