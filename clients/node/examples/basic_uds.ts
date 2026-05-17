// Minimal Varta beat loop — connect once over UDS, emit `Status.Ok`
// every 500ms.
//
// Mirror of `clients/python/examples/basic_uds.py` and
// `crates/varta-client/examples/basic.rs`. UDS is the preferred
// same-host transport: the observer reads kernel-attested peer
// credentials, classifying the source as `BeatOrigin::KernelAttested`
// and unlocking recovery-command eligibility.
//
// Requires the optional `node-unix-socket` addon to be installed
// (`npm install node-unix-socket`). On Windows or any platform
// without a prebuild, fall back to `basic_udp.ts`.
//
// Usage:
//   node --import tsx examples/basic_uds.ts [/path/to/varta.sock]

import { Varta, Status } from "../src/index.js";

const path = process.argv[2] ?? "/var/run/varta.sock";

const agent = Varta.connectUds(path);
console.log(`[varta] beating Ok every 500ms to uds://${path}`);

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
