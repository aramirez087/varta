# Node.js client

[![npm](https://img.shields.io/npm/v/@varta-health/client.svg)](https://www.npmjs.com/package/@varta-health/client)

The Node.js client (`npm install @varta-health/client`) is a first-class peer
of the Rust `varta-client` crate. It tracks the same wire-format
contract, passes the same `tools/vlp-test-vectors.json` conformance
suite, and interoperates with the same `varta-watch` observer binary.

## Install

```bash
npm install @varta-health/client
```

Requires Node.js 18 LTS or newer. ESM-only. Ships compiled JavaScript
plus TypeScript declarations. The only registry dependency is an
**optional** native addon (`node-unix-socket`) for the UDS transport;
UDP and secure-UDP work without it. ChaCha20-Poly1305 and
HKDF-SHA256 come from Node's built-in `node:crypto`.

## 20-line example

```ts
import { Varta, Status, DropReason } from "@varta-health/client";

const agent = Varta.connectUds("/var/run/varta.sock");
setInterval(() => {
  const outcome = agent.beat(Status.Ok);
  if (outcome.kind === "dropped") {
    // Four-way taxonomy mirrors the Rust client:
    const _: DropReason = outcome.reason;
  } else if (outcome.kind === "failed") {
    console.error("varta beat failed:", outcome.error);
  }
}, 500);
```

For secure-UDP, fork-safety, the panic-hook family, and the full parity
matrix see the package README in the repo:
[`clients/node/README.md`](https://github.com/aramirez087/Varta/blob/main/clients/node/README.md).

## Transports

| Transport | Status | Notes |
| --------- | ------ | ----- |
| Unix Domain Sockets | Supported (0.2.0+) | `Varta.connectUds(path)`. Requires the optional `node-unix-socket` addon (prebuilds for darwin x64/arm64 and linux x64/arm64 gnu+musl). Classified `BeatOrigin::KernelAttested` only on observer platforms with pathname-UDS peer credentials; macOS observers treat pathname UDS as socket-mode-only, so recovery is refused. |
| Plaintext UDP | Supported | `Varta.connectUdp(host, port)`. Connected-mode socket; on Linux ICMP `port unreachable` surfaces as `DropReason.NoObserver` on a subsequent beat. macOS ICMP propagation is best-effort. |
| Secure UDP (ChaCha20-Poly1305) | Supported | `Varta.connectSecureUdp(host, port, key)` |
| Master-key secure UDP | Supported | `Varta.connectSecureUdpWithMaster(host, port, masterKey)` |

## Stability

- **Wire format**: VLP v0.2, governed by [the spec](../spec/vlp.md).
- **Node API**: independent semver, tracked in
  [`clients/node/CHANGELOG.md`](https://github.com/aramirez087/Varta/blob/main/clients/node/CHANGELOG.md).

## Source

- [npm page](https://www.npmjs.com/package/@varta-health/client)
- [GitHub source](https://github.com/aramirez087/Varta/tree/main/clients/node)
- [Issue tracker](https://github.com/aramirez087/Varta/issues)
