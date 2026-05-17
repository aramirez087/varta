// Minimal Varta beat loop — connect once, emit `Status.Ok` every 500ms.
//
// Mirror of `clients/python/examples/basic_uds.py` and
// `crates/varta-client/examples/basic.rs`. The Python version targets
// UDS; the Node client uses loopback UDP for same-host deployments
// (Node stdlib does not expose AF_UNIX/SOCK_DGRAM).
//
// Usage:
//   node --import tsx examples/basic_udp.ts [host=127.0.0.1] [port=5876]
//
// Or compiled:
//   node dist/examples/basic_udp.js [host=127.0.0.1] [port=5876]

import { Varta, Status } from "../src/index.js";

const host = process.argv[2] ?? "127.0.0.1";
const port = parseInt(process.argv[3] ?? "5876", 10);

const agent = Varta.connectUdp(host, port);
console.log(`[varta] beating Ok every 500ms to udp://${host}:${port}`);

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
