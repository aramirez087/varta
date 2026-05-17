// Live interop: Node agent ↔ real `varta-watch` observer.
//
// Spawns the built observer binary, drives beats from the Node client
// over plaintext UDP (UDS is not supported on Node — see README), then
// scrapes `/metrics` and asserts the observer saw the traffic.
//
// Skipped unless the `VARTA_WATCH_BIN` env var points at a built
// binary (or `target/release/varta-watch` exists relative to the
// repo root).

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcessByStdio } from "node:child_process";
import { createSocket } from "node:dgram";
import { existsSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { join } from "node:path";
import type { Readable, Writable } from "node:stream";
import type { AddressInfo } from "node:net";

import { Varta } from "../src/client.js";
import { Status } from "../src/vlp.js";
import { locateWatchBinary, makeTempDir } from "./helpers.js";

// Must match `crates/varta-tests/tests/end_to_end.rs::PROM_TOKEN_HEX`
// and the Python interop test's `PROM_TOKEN_HEX`.
const PROM_TOKEN_HEX =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

async function pickEphemeralUdpPort(): Promise<number> {
  return await new Promise<number>((resolveFn, rejectFn) => {
    const s = createSocket("udp4");
    s.once("error", rejectFn);
    s.bind(0, "127.0.0.1", () => {
      const port = (s.address() as AddressInfo).port;
      s.close(() => resolveFn(port));
    });
  });
}

async function spawnObserver(binary: string): Promise<{
  promAddr: { host: string; port: number };
  agentPort: number;
  proc: ChildProcessByStdio<Writable, Readable, Readable>;
  cleanup: () => Promise<void>;
}> {
  const tmp = makeTempDir();
  const tokenPath = join(tmp.dir, "prom.token");
  writeFileSync(tokenPath, PROM_TOKEN_HEX, { mode: 0o600 });
  const udsPath = join(tmp.dir, "varta.sock");
  const agentPort = await pickEphemeralUdpPort();

  const proc = spawn(
    binary,
    [
      "--socket",
      udsPath,
      "--threshold-ms",
      "10000",
      "--udp-bind-addr",
      "127.0.0.1",
      "--udp-port",
      String(agentPort),
      "--i-accept-plaintext-udp",
      "--prom-addr",
      "127.0.0.1:0",
      "--prom-token-file",
      tokenPath,
      "--prom-rate-limit-burst",
      "0",
      "--shutdown-after-secs",
      "60",
    ],
    { stdio: ["pipe", "pipe", "pipe"] },
  );

  proc.stderr.resume();

  const promAddr = await new Promise<{ host: string; port: number }>(
    (resolveFn, rejectFn) => {
      let buffered = "";
      const onData = (chunk: Buffer): void => {
        buffered += chunk.toString("utf8");
        const idx = buffered.indexOf("\n");
        if (idx >= 0) {
          const line = buffered.slice(0, idx).trim();
          proc.stdout.removeListener("data", onData);
          // Format: `127.0.0.1:NNNN` or `[::1]:NNNN`
          const lastColon = line.lastIndexOf(":");
          if (lastColon < 0) {
            rejectFn(new Error(`unparseable prom address: ${line}`));
            return;
          }
          const hostPart = line.slice(0, lastColon).replace(/^\[|\]$/g, "");
          const portPart = parseInt(line.slice(lastColon + 1), 10);
          if (!Number.isFinite(portPart)) {
            rejectFn(new Error(`bad prom port: ${line}`));
            return;
          }
          resolveFn({ host: hostPart, port: portPart });
        }
      };
      proc.stdout.on("data", onData);
      proc.once("exit", (code) => {
        rejectFn(new Error(`observer exited before printing prom addr (code=${code})`));
      });
      setTimeout(() => rejectFn(new Error("observer stdout timeout")), 8000).unref();
    },
  );

  const cleanup = async (): Promise<void> => {
    try {
      proc.kill("SIGTERM");
    } catch {
      // Already dead.
    }
    await new Promise((r) => setTimeout(r, 200));
    try {
      proc.kill("SIGKILL");
    } catch {
      // Already dead.
    }
    tmp.cleanup();
  };

  return { promAddr, agentPort, proc, cleanup };
}

async function scrapeMetrics(addr: { host: string; port: number }): Promise<string> {
  return await new Promise<string>((resolveFn, rejectFn) => {
    const req = request(
      {
        host: addr.host,
        port: addr.port,
        path: "/metrics",
        method: "GET",
        headers: { Authorization: `Bearer ${PROM_TOKEN_HEX}` },
        timeout: 5000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          if (res.statusCode !== 200) {
            rejectFn(new Error(`/metrics HTTP ${res.statusCode}: ${body.slice(0, 200)}`));
          } else {
            resolveFn(body);
          }
        });
      },
    );
    req.on("error", rejectFn);
    req.end();
  });
}

test("Node agent beats reach varta-watch over UDP and appear in /metrics", async () => {
  const binary = locateWatchBinary();
  if (!binary || !existsSync(binary)) {
    console.log(
      `[skip] varta-watch binary not found at ${binary}; build with ` +
        "`cargo build --release -p varta-watch --features prometheus-exporter` " +
        "or set VARTA_WATCH_BIN",
    );
    return;
  }

  const observer = await spawnObserver(binary);
  try {
    const agent = Varta.connectUdp("127.0.0.1", observer.agentPort);
    let sent = 0;
    for (let i = 0; i < 50; i++) {
      const outcome = agent.beat(Status.Ok);
      if (outcome.kind === "sent") sent += 1;
      else if (outcome.kind === "dropped") {
        // Kernel-queue-full under burst is fine — slow down slightly.
        await new Promise((r) => setTimeout(r, 1));
      } else {
        assert.fail(`unexpected outcome: ${JSON.stringify(outcome)}`);
      }
    }
    agent.close();

    assert.ok(sent >= 10, `expected ≥10 successful beats, got ${sent}`);

    // Give the observer one poll-loop iteration to consume datagrams.
    await new Promise((r) => setTimeout(r, 500));

    const body = await scrapeMetrics(observer.promAddr);
    assert.ok(body.length > 0, "empty /metrics body");
    assert.ok(body.includes("varta_"), `no varta_ metrics in body: ${body.slice(0, 400)}`);

    // Look for any non-zero `varta_*` counter — confirms the observer
    // observed traffic on the UDP socket.
    let anyNonZero = false;
    for (const line of body.split("\n")) {
      if (line.startsWith("#") || !line.startsWith("varta_")) continue;
      const parts = line.split(" ");
      const value = parseFloat(parts[parts.length - 1] ?? "0");
      if (Number.isFinite(value) && value > 0) {
        anyNonZero = true;
        break;
      }
    }
    assert.ok(anyNonZero, "no varta_ metric reached a non-zero value");
  } finally {
    await observer.cleanup();
  }
});
