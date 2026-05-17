// Shared test helpers — port of `clients/python/tests/conftest.py`.

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createSocket, type Socket } from "node:dgram";
import type { AddressInfo } from "node:net";

let counter = 0;
function uniqueTag(): string {
  counter += 1;
  return `${process.pid}-${Date.now()}-${counter}`;
}

// Allocate a short, unique tempdir. macOS / BSD `sun_path` is 104
// chars — the Node default tmpdir is short enough but we keep the
// pattern from the Python conftest so future UDS work can drop in
// without re-deriving the constraint.
export function makeTempDir(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), `varta-${uniqueTag()}-`));
  return {
    dir,
    cleanup: () => {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // Best effort.
      }
    },
  };
}

// Bind an ephemeral loopback UDP listener that silently drops every
// datagram. Returns the bound socket and `127.0.0.1:<port>`.
export async function bindUdpListener(): Promise<{
  socket: Socket;
  host: string;
  port: number;
  close: () => Promise<void>;
}> {
  const socket = createSocket("udp4");
  await new Promise<void>((resolveBind, rejectBind) => {
    socket.once("error", rejectBind);
    socket.bind(0, "127.0.0.1", () => {
      socket.removeListener("error", rejectBind);
      resolveBind();
    });
  });
  const addr = socket.address() as AddressInfo;
  socket.unref();
  return {
    socket,
    host: "127.0.0.1",
    port: addr.port,
    close: () =>
      new Promise<void>((resolveClose) => {
        try {
          socket.close(() => resolveClose());
        } catch {
          resolveClose();
        }
      }),
  };
}

// Like `bindUdpListener` but records every received datagram so tests
// can decode/inspect what the agent actually wrote.
export async function bindUdpRecorder(): Promise<{
  host: string;
  port: number;
  received: Buffer[];
  wait: (n: number, timeoutMs?: number) => Promise<void>;
  close: () => Promise<void>;
}> {
  const socket = createSocket("udp4");
  const received: Buffer[] = [];
  socket.on("message", (msg) => {
    received.push(Buffer.from(msg));
  });
  await new Promise<void>((resolveBind, rejectBind) => {
    socket.once("error", rejectBind);
    socket.bind(0, "127.0.0.1", () => {
      socket.removeListener("error", rejectBind);
      resolveBind();
    });
  });
  const addr = socket.address() as AddressInfo;
  socket.unref();
  return {
    host: "127.0.0.1",
    port: addr.port,
    received,
    async wait(n, timeoutMs = 2000): Promise<void> {
      const start = Date.now();
      while (received.length < n) {
        if (Date.now() - start > timeoutMs) {
          throw new Error(
            `bindUdpRecorder: timed out waiting for ${n} datagrams; got ${received.length}`,
          );
        }
        await new Promise((r) => setTimeout(r, 5));
      }
    },
    close: () =>
      new Promise<void>((resolveClose) => {
        try {
          socket.close(() => resolveClose());
        } catch {
          resolveClose();
        }
      }),
  };
}

// Build a short UDS path inside a fresh tempdir. macOS / BSD enforce
// `sun_path` ≤ 104 chars; `mkdtemp` under the OS tmpdir keeps comfortably
// below that on every platform we test.
export function makeUdsPath(): { path: string; cleanup: () => void } {
  const t = makeTempDir();
  return { path: join(t.dir, "varta.sock"), cleanup: t.cleanup };
}

// Bind a `node-unix-socket` recorder on the returned path. Skips
// gracefully if the optional addon is not available.
export async function bindUdsRecorder(): Promise<{
  path: string;
  received: Buffer[];
  wait: (n: number, timeoutMs?: number) => Promise<void>;
  close: () => Promise<void>;
} | null> {
  let mod: typeof import("node-unix-socket");
  try {
    mod = (await import("node-unix-socket")) as typeof import("node-unix-socket");
  } catch {
    return null;
  }
  const { path: udsPath, cleanup } = makeUdsPath();
  const sock = new mod.DgramSocket();
  const received: Buffer[] = [];
  sock.on("data", (data) => {
    received.push(Buffer.from(data));
  });
  sock.bind(udsPath);
  return {
    path: udsPath,
    received,
    async wait(n, timeoutMs = 2000): Promise<void> {
      const start = Date.now();
      while (received.length < n) {
        if (Date.now() - start > timeoutMs) {
          throw new Error(
            `bindUdsRecorder: timed out waiting for ${n} datagrams; got ${received.length}`,
          );
        }
        await new Promise((r) => setTimeout(r, 5));
      }
    },
    async close(): Promise<void> {
      try {
        sock.close();
      } catch {
        // Already closed.
      }
      cleanup();
    },
  };
}

// Path to the repo root — three levels up from `clients/node/tests`.
export function repoRoot(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, "..", "..", "..");
}

export function vectorsPath(): string {
  return join(repoRoot(), "tools", "vlp-test-vectors.json");
}

// Locate the release `varta-watch` binary. Mirrors the Python and Go
// equivalents.
export function locateWatchBinary(): string | null {
  if (process.env.VARTA_WATCH_BIN) return process.env.VARTA_WATCH_BIN;
  const ext = process.platform === "win32" ? ".exe" : "";
  return join(repoRoot(), "target", "release", `varta-watch${ext}`);
}
