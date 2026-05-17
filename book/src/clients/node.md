# Node.js client

[![npm](https://img.shields.io/npm/v/@varta/client.svg)](https://www.npmjs.com/package/@varta/client)

The Node.js client (`npm install @varta/client`) is a first-class peer
of the Rust `varta-client` crate. It tracks the same wire-format
contract, passes the same `tools/vlp-test-vectors.json` conformance
suite, and interoperates with the same `varta-watch` observer binary.

## Install

```bash
npm install @varta/client
```

Requires Node.js 18 LTS or newer. ESM-only. Ships compiled JavaScript
plus TypeScript declarations. **Zero npm runtime dependencies** —
ChaCha20-Poly1305 and HKDF-SHA256 come from Node's built-in
`node:crypto`.

## 20-line example

```ts
import { Varta, Status, DropReason } from "@varta/client";

const agent = Varta.connectUdp("127.0.0.1", 5876);
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
| Plaintext UDP | Supported | `Varta.connectUdp(host, port)` |
| Secure UDP (ChaCha20-Poly1305) | Supported | `Varta.connectSecureUdp(host, port, key)` |
| Master-key secure UDP | Supported | `Varta.connectSecureUdpWithMaster(host, port, masterKey)` |
| Unix Domain Sockets | **Not in 0.1.0** | Node stdlib does not expose `AF_UNIX`/`SOCK_DGRAM`. Adding it would require a native addon and break the zero-dep posture. Use loopback UDP for same-host deployments — the security domain is identical. |

## Stability

- **Wire format**: VLP v0.2, governed by [the spec](../spec/vlp.md).
- **Node API**: independent semver, tracked in
  [`clients/node/CHANGELOG.md`](https://github.com/aramirez087/Varta/blob/main/clients/node/CHANGELOG.md).

## Source

- [npm page](https://www.npmjs.com/package/@varta/client)
- [GitHub source](https://github.com/aramirez087/Varta/tree/main/clients/node)
- [Issue tracker](https://github.com/aramirez087/Varta/issues)
