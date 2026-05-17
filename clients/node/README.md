# Varta — Node.js client

[![npm](https://img.shields.io/npm/v/@varta/client.svg)](https://www.npmjs.com/package/@varta/client)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Production Node.js client for the [Varta](https://github.com/aramirez087/Varta) health protocol.

```bash
npm install @varta/client
```

Requires Node.js 18 LTS or newer. ESM-only. Ships compiled `.js` + `.d.ts`. AEAD primitives come from Node's built-in `node:crypto`; UDS support is loaded from the optional `node-unix-socket` addon.

## What is Varta?

Varta is a health protocol for processes running on the same host (or same network segment). Your process calls `agent.beat()` on a fixed schedule — typically every 500 ms. A companion observer (`varta-watch`) watches the socket, detects when beats stop arriving, and fires a configurable recovery command.

The wire is 32 bytes per beat. No HTTP, no JSON, no extra packages for the base transport.

## Quickstart

```ts
import { Varta, Status } from "@varta/client";

// Connect once at startup. path must match --socket on your observer.
const agent = Varta.connectUds("/var/run/varta.sock");

setInterval(() => {
  // beat() encodes and sends a 32-byte VLP frame.
  // It never blocks — if the kernel send queue is full it returns { kind: "dropped" }.
  const outcome = agent.beat(Status.Ok);

  if (outcome.kind === "dropped") {
    // Normal: observer restarted, queue momentarily full.
    // The observer's stall-detection fires if silence lasts too long.
    console.warn(`varta: dropped: ${outcome.reason}`);
  } else if (outcome.kind === "failed") {
    // Abnormal: OS resource exhaustion or socket in bad state.
    console.error(`varta: failed: ${outcome.error.kind}`);
  }
}, 500);
```

If UDS is not available on your platform, use loopback UDP:

```ts
const agent = Varta.connectUdp("127.0.0.1", 5876);
```

## How it works

`beat()` encodes a 32-byte frame (PID, timestamp, status, 32-bit payload, CRC) and sends it to `varta-watch`. The observer tracks the last-seen timestamp per PID. If a PID goes silent longer than `--threshold-ms`, the observer marks it stalled and fires any configured recovery command.

No polling. No persistent connection state beyond the socket file descriptor.

## Which transport?

| Transport | When to use |
| --------- | ----------- |
| **UDS** (`Varta.connectUds`) | Same-host deployment. The observer reads kernel peer credentials (`SCM_CREDENTIALS` on Linux, `LOCAL_PEERTOKEN` on macOS), granting `BeatOrigin::KernelAttested` status. **Only kernel-attested beats are eligible for observer-driven recovery commands.** Requires the optional `node-unix-socket` addon. |
| **UDP** (`Varta.connectUdp`) | Same-host or LAN when UDS is unavailable (or on Windows). Beats are `NetworkUnverified`; recovery is refused by the observer. |
| **Secure UDP** (`Varta.connectSecureUdp`) | Same use case as UDP, plus ChaCha20-Poly1305 AEAD encryption for beat confidentiality. Still refused for recovery. |

For same-host Node.js agents, UDS is the recommended transport. Fall back to UDP only when UDS is unavailable.

## Status values

`beat()` carries one of three status values. The observer surfaces all three through Prometheus.

| Status | When to send |
| ------ | ------------ |
| `Status.Ok` | Everything is working normally. Send this the vast majority of the time. |
| `Status.Degraded` | Running but unhealthy: high error rate, queue backlog, slow dependency. Not treated as a stall — recorded but does not trigger recovery. |
| `Status.Critical` | About to terminate due to an unrecoverable error. Typically sent by the panic handler, not your main beat loop. |

## Beat outcome

`beat()` returns a discriminated union. Check `outcome.kind`:

| `kind` | Meaning | Recommended action |
| ------ | ------- | ------------------ |
| `"sent"` | Frame handed to the kernel. | Nothing. |
| `"dropped"` | Frame not sent. `outcome.reason` is one of `KernelQueueFull`, `NoObserver`, `PeerGone`, or `StorageFull`. | Log at debug level or ignore. |
| `"failed"` | Unexpected error (encoding bug, OS resource exhaustion). | Log at warn. Consider calling `agent.reconnect()`. |

A `"dropped"` outcome is not a bug. Occasional drops are invisible to the observer — only sustained silence triggers a stall.

## Payload field

`beat(status, payload?)` accepts an optional 32-bit unsigned integer. The observer stores it verbatim and exposes it in the Prometheus `varta_agent_payload` gauge. Use it to pack any two metrics you want correlated with liveness:

```ts
function packPayload(queueDepth: number, lastErrorCode: number): number {
  // High 16 bits = queue depth. Low 16 bits = error code.
  return ((queueDepth & 0xffff) | ((lastErrorCode & 0xff) << 16)) >>> 0;
}

const payload = packPayload(currentQueueLen, lastErrCode);
const status  = lastErrCode !== 0 ? Status.Degraded : Status.Ok;
agent.beat(status, payload);
```

The encoding convention is yours to decide. The observer does not interpret the payload field.

## Unix Domain Sockets

UDS is the canonical same-host transport and the only Node transport eligible for observer-driven recovery.

UDS requires the optional `node-unix-socket` addon. Prebuilds are published for:

| Platform | Prebuild |
| -------- | -------- |
| `darwin-arm64` | ✅ |
| `darwin-x64` | ✅ |
| `linux-x64-gnu` | ✅ |
| `linux-x64-musl` | ✅ |
| `linux-arm64-gnu` | ✅ |
| `linux-arm64-musl` | ✅ |
| `linux-arm-gnueabihf` | ✅ |
| Windows | — |

Installing without the addon (or with `npm install --no-optional`) leaves UDS unavailable; UDP and secure-UDP still work. `Varta.connectUds` throws `UdsUnavailableError` in that case.

## Peer-gone detection

The UDP and secure-UDP transports use connected-mode sockets. On Linux, the kernel surfaces ICMP `port unreachable` on the next beat as `{ kind: "dropped", reason: DropReason.NoObserver }` (1–2 beat latency). On macOS and BSDs, ICMP propagation is best-effort — the peer-absent condition may stay invisible at the agent layer; the observer's stall-detection metric remains the canonical signal.

For UDS, the kernel returns `ECONNREFUSED`/`ENOENT` synchronously, so peer-gone detection is reliable on every platform.

## Panic hook

Register once at startup. Any uncaught exception, unhandled rejection, or terminating signal (`SIGTERM`/`SIGINT`/`SIGQUIT`/`SIGHUP`) emits a `Critical` beat with `nonce=NONCE_TERMINAL` before the process exits.

```ts
import { panic } from "@varta/client";

// For UDS deployments:
panic.installSignalHandlerUds("/var/run/varta.sock");

// For UDP deployments:
// panic.installSignalHandlerUdp("127.0.0.1", 5876);
```

All install functions pre-bind their socket at call time — no allocation or DNS resolution happens in the signal handler path.

For deferred emission inside an async pipeline:

```ts
await panic.run(async () => {
  await mainLoop();  // any throw inside emits Critical, then re-throws
});
```

## Secure UDP

```ts
import { readFileSync } from "node:fs";
import { Varta, Status } from "@varta/client";

// key must be exactly 32 raw bytes. Load from a Kubernetes secret, Vault, etc.
const key = readFileSync("/etc/varta/secure.key");
const agent = Varta.connectSecureUdp("127.0.0.1", 5876, key);
agent.beat(Status.Ok);
```

ChaCha20-Poly1305 and HKDF-SHA256 come from Node's built-in `node:crypto` (Node 15+) — no extra install required.

## API parity with `varta-client` (Rust)

| Rust                                                | Node.js                                                                     |
| --------------------------------------------------- | --------------------------------------------------------------------------- |
| `Varta::connect(path)` (UDS)                        | `Varta.connectUds(path)` — requires the optional `node-unix-socket` addon   |
| `Varta::connect_udp(addr)`                          | `Varta.connectUdp(host, port)`                                              |
| `Varta::connect_secure_udp(addr, key)`              | `Varta.connectSecureUdp(host, port, key)`                                   |
| `Varta::connect_secure_udp_with_master(addr, mkey)` | `Varta.connectSecureUdpWithMaster(host, port, masterKey)`                   |
| `Varta::beat(status, payload) -> BeatOutcome`       | `agent.beat(status, payload?) -> BeatOutcome`                               |
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

1. **Non-blocking I/O.** Every socket is non-blocking. A kernel-queue-full
   send surfaces as `{ kind: "dropped", reason: DropReason.KernelQueueFull }`,
   never a block.
2. **Per-emission `process.pid`.** No PID caching — forked children report
   their own identity on the next beat. Fork auto-recovery refreshes the
   transport (and, for secure-UDP, re-reads entropy via `crypto.randomBytes`)
   before the frame leaves the child.
3. **Synchronous nonce reservation.** Secure-UDP's per-emission IV counter
   advances at encode time, before the async `socket.send` call. This
   guarantees nonce uniqueness under concurrent beats: a send callback that
   reports an error burns one nonce slot (harmless — nonces are one-shot by
   design), but two concurrent calls can never share a nonce.
4. **Wire-format conformance.** The package ships a test that loads
   `tools/vlp-test-vectors.json` (the same fixture the Rust crate verifies
   against) and asserts byte-equality for every CRC, frame, and AEAD vector.
   Drift between languages is impossible without breaking both test suites in
   the same PR.

## Latency note

Node cannot match the ~1 µs-per-beat budget of the Rust client. Measured cost on a modern x86_64 host is **~5–15 µs per `beat()`** including frame allocation, send, and outcome dispatch. The Node client is intended for tooling, batch jobs, Express/Fastify sidecars, and process supervisors — not for tight inner loops emitting kilo-beats per second.

## Non-goals

- **Recovery commands for UDP beats.** Only UDS beats are kernel-attested; UDP and secure-UDP beats never trigger observer-driven recovery.
- **Sub-microsecond latency.** Use the Rust `varta-client` for that.
- **Native-addon-free UDS.** Node's standard `dgram` module does not support `AF_UNIX`/`SOCK_DGRAM`; the optional `node-unix-socket` addon bridges that gap. If the addon is unavailable, loopback UDP is the correct fallback.

## Stability

- **Wire format:** VLP v0.2, governed by `book/src/spec/vlp.md` in the workspace. Cross-language byte-equality is enforced by the conformance test suite.
- **Node API:** 0.x — refinements may land without deprecation cycles until 1.0.
- **Node version:** 18 LTS minimum. CI runs against Node 18, 20, 22.

## See also

- [Normative wire spec](../../book/src/spec/vlp.md)
- [Conformance vectors](../../tools/vlp-test-vectors.json)
- [Rust agent crate](../../crates/varta-client/)
- [Go client](../go/)
- [Python client](../python/)
- [Observer](../../crates/varta-watch/)
- [Changelog](CHANGELOG.md)
