// Beat loop that packs queue depth and last error code into the 32-bit
// payload field. Mirror of `clients/python/examples/with_payload.py`.
//
// Wire layout for the 32-bit payload here:
//   bits  0..15  = queue depth (u16)
//   bits 16..23  = last error code (u8)
//   bits 24..31  = reserved (0)
//
// The observer dashboard at `observability/dashboards/varta-health.json`
// surfaces the payload column verbatim, so any encoding is fine as long
// as your team agrees on it.
//
// Usage:
//   node --import tsx examples/with_payload.ts [host=127.0.0.1] [port=5876]

import { Varta, Status } from "../src/index.js";

const host = process.argv[2] ?? "127.0.0.1";
const port = parseInt(process.argv[3] ?? "5876", 10);

const agent = Varta.connectUdp(host, port);

function packPayload(queueDepth: number, lastErrorCode: number): number {
  return ((queueDepth & 0xffff) | ((lastErrorCode & 0xff) << 16)) >>> 0;
}

let depth = 0;
let lastError = 0;

const timer = setInterval(() => {
  // Pretend metrics. In production these come from your queue/observability layer.
  depth = (depth + 1) & 0xffff;
  lastError = depth % 4 === 0 ? 1 : 0;

  const status = lastError !== 0 ? Status.Degraded : Status.Ok;
  agent.beat(status, packPayload(depth, lastError));
}, 500);

const shutdown = (): void => {
  clearInterval(timer);
  agent.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
