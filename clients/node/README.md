# Varta — Node.js client

[![npm](https://img.shields.io/npm/v/@varta/client.svg)](https://www.npmjs.com/package/@varta/client)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Production Node.js client for the [Varta](https://github.com/aramirez087/Varta)
health protocol. Emits 32-byte VLP heartbeats to a `varta-watch` observer
over plaintext UDP or ChaCha20-Poly1305-encrypted UDP. Written in
TypeScript; ships compiled `.js` + `.d.ts`. Zero npm runtime
dependencies — the AEAD primitives come from Node's built-in
`node:crypto`.

```bash
npm install @varta/client
```

## Quickstart

```ts
import { Varta, Status } from "@varta/client";

const agent = await Varta.connectUdp("127.0.0.1", 5876);
setInterval(() => {
  const outcome = agent.beat(Status.Ok);
  if (outcome.kind === "dropped") {
    // Observer absent, kernel queue full, peer gone, or disk full.
    // Treat as a no-op; the next beat will retry.
  }
}, 500);
```

## API parity with `varta-client` (Rust)

| Rust                                                | Node.js                                                                     |
| --------------------------------------------------- | --------------------------------------------------------------------------- |
| `Varta::connect(path)` (UDS)                        | _Not supported in 0.1.0_ — see "Non-goals" below                            |
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
| `install_panic_handler*`                            | `panic.installSignalHandlerUdp` / `installSignalHandlerSecureUdp`           |
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

## Non-goals (0.1.0)

- **Unix Domain Sockets.** Node's stdlib does not expose `AF_UNIX` /
  `SOCK_DGRAM`; only stream-mode `unix:` sockets are reachable from
  `node:net`. Shipping UDS support would require a native addon and
  break the zero-dep posture. For same-host deployments use
  `Varta.connectUdp("127.0.0.1", port)` — loopback is the same
  security domain. If you need authenticated same-host transport,
  use `Varta.connectSecureUdp` against `127.0.0.1` with a key
  configured on the observer.
- **`accept-degraded-entropy` secure-UDP variant.** Reserved for
  embedded targets that lack `/dev/urandom`; Node itself does not
  run on such targets.
- **Browser support.** This package targets Node.js ≥ 18 LTS only.
  It uses `node:dgram`, `node:crypto`, `node:os`, and `node:process`.

## Latency note

Node cannot match the ~1 µs-per-beat budget of the Rust client.
Measured cost on a modern x86_64 host is **~5–15 µs per `beat()`**
including frame allocation, UDP `send`, and outcome dispatch. The
Node client is intended for tooling, batch jobs, Express/Fastify
sidecars, and process supervisors — not for tight inner loops
emitting kilo-beats per second.

## Secure UDP

```ts
import { Varta, Status } from "@varta/client";
import { readFileSync } from "node:fs";

const key = readFileSync("/etc/varta/secure.key");   // 32 raw bytes
const agent = await Varta.connectSecureUdp("127.0.0.1", 5876, key);
agent.beat(Status.Ok);
```

ChaCha20-Poly1305 and HKDF-SHA256 are stdlib in Node ≥ 15.0; no
extra install is required.

## Panic hook

```ts
import { panic } from "@varta/client";

panic.installSignalHandlerUdp("127.0.0.1", 5876);
// any uncaught exception, unhandled rejection, or terminating
// signal (SIGTERM/SIGINT/SIGQUIT/SIGHUP) now emits a Critical beat
// with nonce=NONCE_TERMINAL before the process exits.
```

For deferred panic emission inside an async pipeline:

```ts
await panic.run(async () => {
  await mainLoop();   // any throw inside emits Critical, then re-throws
});
```

The handler pre-binds its socket at install time so emission is
async-signal-safe — no allocation or DNS in the hot path.

## Stability

- **Wire format:** VLP v0.2, governed by `book/src/spec/vlp.md` in
  the workspace. Cross-language byte-equality is enforced by the
  conformance test suite.
- **Node API:** 0.x — refinements may land without deprecation
  cycles until 1.0.
- **Node version:** 18 LTS minimum. CI runs against Node 18, 20, 22.
