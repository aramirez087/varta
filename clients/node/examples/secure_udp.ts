// Varta agent over ChaCha20-Poly1305 AEAD UDP.
//
// Mirror of `clients/python/examples/secure_udp.py` and
// `crates/varta-client/examples/secure_udp.rs`.
//
// Usage:
//   node --import tsx examples/secure_udp.ts <host> <port> <key-file>
//
// The key file must be a 32-byte raw key (NOT hex-encoded). Generate
// one with: `openssl rand -out /etc/varta/secure.key 32`.

import { readFileSync } from "node:fs";

import { Varta, Status } from "../src/index.js";

const [host, portStr, keyPath] = process.argv.slice(2);
if (!host || !portStr || !keyPath) {
  console.error("usage: secure_udp.ts <host> <port> <key-file>");
  process.exit(64);
}
const port = parseInt(portStr, 10);
const key = readFileSync(keyPath);
if (key.length !== 32) {
  console.error(`key must be exactly 32 bytes; got ${key.length}`);
  process.exit(64);
}

const agent = Varta.connectSecureUdp(host, port, key);
console.log(
  `[varta] secure beat loop (ChaCha20-Poly1305) to udp://${host}:${port}`,
);

const timer = setInterval(() => {
  const outcome = agent.beat(Status.Ok);
  if (outcome.kind === "dropped") {
    console.warn(`[varta] dropped: ${outcome.reason}`);
  } else if (outcome.kind === "failed") {
    console.error(`[varta] failed: ${outcome.error.kind}`);
  }
}, 500);

const shutdown = (): void => {
  clearInterval(timer);
  agent.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
