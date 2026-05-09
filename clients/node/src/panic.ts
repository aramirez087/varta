// Panic-style emitters — Node's analogue of Rust's `install_panic_handler`.
//
// Node has no `excepthook` in the Python sense, but it does have:
//   * `process.on('uncaughtException')` — synchronous throws.
//   * `process.on('unhandledRejection')` — async promise rejections.
//   * `process.on('SIGTERM' | 'SIGINT' | 'SIGQUIT' | 'SIGHUP')` —
//     terminating signals.
//
// Each installer wires all three into a single critical-beat emitter
// for the chosen transport. The socket and frame buffer are
// pre-allocated at install time so the hot path is alloc-free and
// async-signal-safe (cerebrum 2026-05-14).

import { randomBytes } from "node:crypto";
import { createSocket, type Socket } from "node:dgram";

import {
  UdsTransport,
  UdsUnavailableError,
} from "./transport.js";
import {
  encodeShared,
  KEY_BYTES,
  deriveIvPrefix,
  IV_RANDOM_BYTES,
  SESSION_SALT_BYTES,
} from "./vlp_secure.js";
import {
  encodeInto,
  FRAME_BYTES,
  NONCE_TERMINAL,
  Status,
} from "./vlp.js";

export class PanicInstallError extends Error {
  readonly kind: string;
  constructor(kind: string, message: string) {
    super(`${kind}: ${message}`);
    this.name = "PanicInstallError";
    this.kind = kind;
  }
}

const FATAL_SIGNALS: NodeJS.Signals[] = ["SIGTERM", "SIGINT", "SIGQUIT", "SIGHUP"];

function buildCriticalFrame(payload: number = 0): Buffer {
  const buf = Buffer.alloc(FRAME_BYTES);
  encodeInto(
    buf,
    Status.Critical,
    process.pid >>> 0,
    process.hrtime.bigint(),
    NONCE_TERMINAL,
    payload >>> 0,
  );
  return buf;
}

// Wire emit() into the three terminating event sources. Each callback
// is one-shot: after the first invocation we tear down the listeners
// so process exit isn't blocked by lingering handlers.
function arm(emit: () => void): void {
  let fired = false;
  const trigger = (): void => {
    if (fired) return;
    fired = true;
    try {
      emit();
    } catch {
      // Hook must never propagate.
    }
  };

  process.on("uncaughtException", (err) => {
    trigger();
    setImmediate(() => {
      throw err;
    });
  });

  process.on("unhandledRejection", (reason) => {
    trigger();
    setImmediate(() => {
      throw reason instanceof Error ? reason : new Error(String(reason));
    });
  });

  for (const sig of FATAL_SIGNALS) {
    process.on(sig, () => {
      trigger();
      process.removeAllListeners(sig);
      process.kill(process.pid, sig);
    });
  }
}

function createConnectedSocket(host: string, port: number): Socket {
  const family: "udp4" | "udp6" = host.includes(":") ? "udp6" : "udp4";
  const s = createSocket(family);
  s.on("error", () => {
    // Drop libuv async errors silently — emission is best-effort.
  });
  s.unref();
  s.connect(port, host);
  return s;
}

// Install a panic emitter that publishes a Critical+NONCE_TERMINAL
// frame over plaintext UDP on any terminating event.
export function installSignalHandlerUdp(host: string, port: number): void {
  let sock: Socket;
  try {
    sock = createConnectedSocket(host, port);
  } catch (err) {
    throw new PanicInstallError("SocketBind", (err as Error).message);
  }
  const frame = buildCriticalFrame();
  arm(() => {
    try {
      sock.send(frame);
    } catch {
      // Best effort.
    }
  });
}

// Install a panic emitter that publishes a Critical+NONCE_TERMINAL
// frame over UDS. Pre-binds a `UdsTransport` at install time so the
// hot path performs no module load. Throws
// `PanicInstallError(kind="UdsUnavailable")` if the optional
// `node-unix-socket` addon is missing.
export function installSignalHandlerUds(path: string): void {
  let transport: UdsTransport;
  try {
    transport = new UdsTransport(path);
  } catch (err) {
    if (err instanceof UdsUnavailableError) {
      throw new PanicInstallError("UdsUnavailable", err.message);
    }
    throw new PanicInstallError("SocketBind", (err as Error).message);
  }
  const frame = buildCriticalFrame();
  arm(() => {
    try {
      transport.send(frame);
    } catch {
      // Best effort.
    }
  });
}

// Install a panic emitter that publishes a Critical+NONCE_TERMINAL
// frame over ChaCha20-Poly1305 AEAD UDP. Fail-closed entropy posture:
// `crypto.randomBytes(16)` is invoked once at install time; if it
// throws, `PanicInstallError(kind="EntropyUnavailable")` propagates
// and no hook is registered.
export function installSignalHandlerSecureUdp(
  host: string,
  port: number,
  key: Buffer,
): void {
  if (key.length !== KEY_BYTES) {
    throw new RangeError(`key must be ${KEY_BYTES} bytes`);
  }

  let salt: Buffer;
  try {
    salt = randomBytes(SESSION_SALT_BYTES);
  } catch (err) {
    throw new PanicInstallError("EntropyUnavailable", (err as Error).message);
  }

  let sock: Socket;
  try {
    sock = createConnectedSocket(host, port);
  } catch (err) {
    throw new PanicInstallError("SocketBind", (err as Error).message);
  }

  const state = {
    salt,
    installPid: process.pid,
    counter: 0,
  };

  const keyCopy = Buffer.from(key);
  arm(() => {
    try {
      if (process.pid !== state.installPid) {
        try {
          state.salt = randomBytes(SESSION_SALT_BYTES);
        } catch {
          return;
        }
        state.installPid = process.pid;
        state.counter = 0;
      }
      const ivPrefix = deriveIvPrefix(state.salt, 0).subarray(0, IV_RANDOM_BYTES);
      const counter = state.counter;
      state.counter = (state.counter + 1) >>> 0;
      const plaintext = buildCriticalFrame();
      const wire = encodeShared(keyCopy, ivPrefix, counter, plaintext);
      sock.send(wire);
    } catch {
      // Hook must never propagate.
    }
  });
}

// Defer/recover-style wrapper. Any throw inside `fn` (sync or async)
// causes a critical beat to be emitted by whichever installer is
// already armed, then the original error is re-thrown so the caller's
// shutdown logic still runs.
export async function run(fn: () => void | Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    throw err;
  }
}
