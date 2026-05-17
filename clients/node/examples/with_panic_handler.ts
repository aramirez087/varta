// Demonstrates `panic.installSignalHandlerUdp` — emit a Critical+NONCE_TERMINAL
// beat on uncaught exceptions, unhandled rejections, or terminating signals.
//
// Mirror of `clients/python/examples/with_panic_handler.py`.
//
// Usage:
//   node --import tsx examples/with_panic_handler.ts [host=127.0.0.1] [port=5876]
//
// After 2 seconds the example intentionally throws to demonstrate the
// hook. You'll see the observer record a Critical beat with the
// terminal nonce, then the Node default crash printer runs and the
// process exits non-zero.

import { panic, Varta, Status } from "../src/index.js";

const host = process.argv[2] ?? "127.0.0.1";
const port = parseInt(process.argv[3] ?? "5876", 10);

panic.installSignalHandlerUdp(host, port);

const agent = Varta.connectUdp(host, port);
agent.beat(Status.Ok);

setTimeout(() => {
  throw new Error("intentional panic to demonstrate the hook");
}, 2000);
