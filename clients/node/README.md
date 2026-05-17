# Varta — Node.js client

[![npm](https://img.shields.io/npm/v/@varta/client.svg)](https://www.npmjs.com/package/@varta/client)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Production Node.js client for the [Varta](https://github.com/aramirez087/Varta)
health protocol. Emits 32-byte VLP heartbeats to a `varta-watch` observer
over Unix domain sockets, plaintext UDP, or ChaCha20-Poly1305-encrypted
UDP. Written in TypeScript; ships compiled `.js` + `.d.ts`. The AEAD
primitives come from Node's built-in `node:crypto`; UDS support is
loaded from the optional `node-unix-socket` addon (prebuilds for
darwin-x64/arm64 and linux-x64/arm64 gnu+musl).

```bash
npm install @varta/client
```

## Quickstart

```ts
import { Varta, Status } from "@varta/client";

const agent = Varta.connectUds("/var/run/varta.sock");
setInterval(() => {
  const outcome = agent.beat(Status.Ok);
  if (outcome.kind === "dropped") {
    // Observer absent, kernel queue full, peer gone, or disk full.
    // Treat as a no-op; the next beat will retry.
  }
}, 500);
```

Loopback UDP for same-host deployments where UDS isn't available:

```ts
const agent = Varta.connectUdp("127.0.0.1", 5876);
```

## API parity with `varta-client` (Rust)

| Rust                                                | Node.js                                                                     |
| --------------------------------------------------- | --------------------------------------------------------------------------- |
| `Varta::connect(path)` (UDS)                        | `Varta.connectUds(path)` — requires the optional `node-unix-socket` addon   |
| `Varta::connect_udp(addr)`                          | `Varta.connectUdp(host, port)`                                              |
| `Varta::connect_secure_udp(addr, key)`              | `Varta.connectSecureUdp(host, port, key)`                                   |
| `Varta::connect_secure_udp_with_master(addr, mkey)` | `Varta.connectSecureUdpWithMaster(host, port, masterKey)`                   |
| `Varta::beat(status, payload) -> BeatOutcome`       | `Varta.beat(status, payload) -> BeatOutcome`                                |
| `BeatOutcome::{Sent, Dropped, Failed}`              | `BeatOutcome` (discriminated union: `{ kind: "sent" \| "dropped" \| "failed" }`) |
| `DropReason::{KernelQueueFull, NoObserver, PeerGone, StorageFull}` | `DropReason` enum — same four variants                       |
| `BeatError { errno, kind }`                         | `BeatError extends Error` with `errno` and `kind` fields                    |
| `classify_send_error`                               | `classifySendError(err)`                                                    |
| `Varta::reconnect`, `set_reconnect_after`           | `reconnect()`, `setReconnectAfter(n)`                                       |
| `Varta::clock_regressions()`, `fork_recoveries()`   | `clockRegressions()`, `forkRecoveries()` — return `bigint`                  |
| `install_panic_handler*`                            | `panic.installSignalHandlerUds` / `installSignalHandlerUdp` / `installSignalHandlerSecureUdp` |
| `panic::run` (defer/recover)                        | `panic.run(fn)`                                                             |

## Hard invariants

The Node.js client preserves the Rust client's wire-level contract:

1. **Non-blocking I/O.** Every socket is non-blocking. A
   kernel-queue-full send surfaces as
   `{ kind: "dropped", reason: DropReason.KernelQueueFull }`, never a
   block.
2. **Per-emission `process.pid`.** No PID caching — forked children
   report their own identity on the next beat. Fork auto-recovery
   refreshes the transport (and, for secure-UDP, re-reads OS entropy
   via `crypto.randomBytes`) before the frame leaves the child.
3. **Commit-on-success nonces.** Secure-UDP's per-emission IV counter
   advances only after `socket.send` resolves successfully. A
   dropped beat does NOT consume a nonce, eliminating cross-fork
   nonce reuse.
4. **Wire-format conformance.** The package ships a test that loads
   `tools/vlp-test-vectors.json` (the same fixture the Rust crate
   verifies against) and asserts byte-equality for every CRC, frame,
   and AEAD vector. Drift between languages is impossible without
   breaking both tests in the same PR.

## Unix Domain Sockets

UDS is the canonical same-host transport. The observer reads kernel
peer credentials over `SCM_CREDENTIALS` / `SCM_CREDS` / `LOCAL_PEERTOKEN`
and classifies the source as `BeatOrigin::KernelAttested` — recovery
commands gate on that classification, so UDS is the only Node
transport eligible for recovery.

UDS is loaded from `node-unix-socket`, an optional dependency.
Prebuilds are published for:

| Platform              | Prebuild |
| --------------------- | -------- |
| `darwin-arm64`        | ✅       |
| `darwin-x64`          | ✅       |
| `linux-x64-gnu`       | ✅       |
| `linux-x64-musl`      | ✅       |
| `linux-arm64-gnu`     | ✅       |
| `linux-arm64-musl`    | ✅       |
| `linux-arm-gnueabihf` | ✅       |
| Windows               | —        |

Installing on a platform without a prebuild (or with `npm install
--no-optional`) leaves UDS unavailable; UDP and secure-UDP still
work. `Varta.connectUds` throws `UdsUnavailableError` in that case.

## Peer-gone detection

The UDP and secure-UDP transports use connected-mode sockets. On
Linux, the kernel surfaces ICMP `port unreachable` on the next beat
as `{ kind: "dropped", reason: DropReason.NoObserver }` (1–2 beat
latency). On macOS and BSDs, ICMP propagation is best-effort — the
peer-absent condition may stay invisible at the agent layer and the
observer's stall-detection metric remains the canonical signal.

For UDS, the kernel returns `ECONNREFUSED` / `ENOENT` synchronously,
so peer-gone detection is reliable on every platform.

## Latency note

Node cannot match the ~1 µs-per-beat budget of the Rust client.
Measured cost on a modern x86_64 host is **~5–15 µs per `beat()`**
including frame allocation, send, and outcome dispatch. The Node
client is intended for tooling, batch jobs, Express/Fastify
sidecars, and process supervisors — not for tight inner loops
emitting kilo-beats per second.

## Secure UDP

```ts
import { Varta, Status } from "@varta/client";
import { readFileSync } from "node:fs";

const key = readFileSync("/etc/varta/secure.key");   // 32 raw bytes
const agent = Varta.connectSecureUdp("127.0.0.1", 5876, key);
agent.beat(Status.Ok);
```

ChaCha20-Poly1305 and HKDF-SHA256 are stdlib in Node ≥ 15.0; no
extra install is required.

## Panic hook

```ts
import { panic } from "@varta/client";

panic.installSignalHandlerUds("/var/run/varta.sock");
// any uncaught exception, unhandled rejection, or terminating
// signal (SIGTERM/SIGINT/SIGQUIT/SIGHUP) now emits a Critical beat
// with nonce=NONCE_TERMINAL before the process exits.
```

`installSignalHandlerUdp(host, port)` and
`installSignalHandlerSecureUdp(host, port, key)` provide equivalent
hooks for the UDP transports. All three pre-bind their socket at
install time so emission is async-signal-safe — no allocation or
DNS in the hot path.

For deferred panic emission inside an async pipeline:

```ts
await panic.run(async () => {
  await mainLoop();   // any throw inside emits Critical, then re-throws
});
```

## Stability

- **Wire format:** VLP v0.2, governed by `book/src/spec/vlp.md` in
  the workspace. Cross-language byte-equality is enforced by the
  conformance test suite.
- **Node API:** 0.x — refinements may land without deprecation
  cycles until 1.0.
- **Node version:** 18 LTS minimum. CI runs against Node 18, 20, 22.
