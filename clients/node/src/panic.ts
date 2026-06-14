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
  derivePanicIvPrefix,
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

let activeTrigger: (() => void) | undefined;
let handlersInstalled = false;
const TIMESTAMP_INVALID = 0xffffffffffffffffn;
const TERMINAL_CLOCK_EPOCH_NS = process.hrtime.bigint();
let lastTerminalTimestamp = 0n;

function claimTerminalTimestamp(previous: bigint, raw: bigint): bigint | undefined {
  if (previous >= TIMESTAMP_INVALID - 1n) return undefined;
  const candidate = raw > previous ? raw : previous + 1n;
  return candidate < TIMESTAMP_INVALID ? candidate : undefined;
}

export function __claimTerminalTimestampForTest(
  previous: bigint,
  raw: bigint,
): bigint | undefined {
  return claimTerminalTimestamp(previous, raw);
}

function nextTerminalTimestamp(): bigint | undefined {
  const rawElapsed = process.hrtime.bigint() - TERMINAL_CLOCK_EPOCH_NS;
  const raw = rawElapsed > 0n ? rawElapsed : 1n;
  const candidate = claimTerminalTimestamp(lastTerminalTimestamp, raw);
  if (candidate !== undefined) lastTerminalTimestamp = candidate;
  return candidate;
}

interface CriticalFrameMeta {
  frame: Buffer;
  pid: number;
  timestamp: bigint;
}

// Build a Critical+NONCE_TERMINAL frame and return the pid and timestamp
// baked into it, so the secure emitter can feed the same values into the
// panic IV-prefix KDF — the AEAD nonce and the authenticated plaintext must
// agree on them.
function buildCriticalFrameWithMeta(
  payload: number = 0,
): CriticalFrameMeta | undefined {
  const timestamp = nextTerminalTimestamp();
  if (timestamp === undefined) return undefined;
  const pid = process.pid >>> 0;
  const buf = Buffer.alloc(FRAME_BYTES);
  encodeInto(buf, Status.Critical, pid, timestamp, NONCE_TERMINAL, payload >>> 0);
  return { frame: buf, pid, timestamp };
}

function buildCriticalFrame(payload: number = 0): Buffer | undefined {
  return buildCriticalFrameWithMeta(payload)?.frame;
}

function triggerActive(): void {
  activeTrigger?.();
}

// Publish the latest emitter and install one process-wide handler set.
// The active trigger is one-shot so panic.run() followed by the resulting
// uncaughtException cannot emit the same terminal event twice.
function installEmitter(emit: () => void): void {
  let fired = false;
  activeTrigger = (): void => {
    if (fired) return;
    fired = true;
    try {
      emit();
    } catch {
      // Hook must never propagate.
    }
  };

  if (handlersInstalled) return;
  handlersInstalled = true;

  const onUncaughtException = (err: unknown): void => {
    triggerActive();
    process.removeListener("uncaughtException", onUncaughtException);
    setImmediate(() => {
      throw err;
    });
  };

  const onUnhandledRejection = (reason: unknown): void => {
    triggerActive();
    process.removeListener("unhandledRejection", onUnhandledRejection);
    setImmediate(() => {
      throw reason instanceof Error ? reason : new Error(String(reason));
    });
  };

  process.on("uncaughtException", onUncaughtException);
  process.on("unhandledRejection", onUnhandledRejection);

  for (const sig of FATAL_SIGNALS) {
    process.on(sig, () => {
      triggerActive();
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
  installEmitter(() => {
    try {
      const frame = buildCriticalFrame();
      if (frame === undefined) return;
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
  installEmitter(() => {
    try {
      const frame = buildCriticalFrame();
      if (frame === undefined) return;
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
//
// Fork- and PID-recycle-safe by construction: every fire derives its IV
// prefix from the install-time salt plus the per-fire (pid, timestamp,
// counter) via `derivePanicIvPrefix`. The strictly-monotonic timestamp
// guarantees a unique nonce across `fork(2)` and PID recycling without any
// PID-equality probe or in-hook entropy read — a former
// `process.pid !== installPid` re-randomize path was unsound, since a
// descendant reassigned the installer's PID would reuse the inherited
// (prefix, counter=0) under the same key.
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
    counter: 0,
  };

  const keyCopy = Buffer.from(key);
  installEmitter(() => {
    try {
      const meta = buildCriticalFrameWithMeta();
      if (meta === undefined) return;
      const counter = state.counter;
      state.counter = (state.counter + 1) >>> 0;
      const ivPrefix = derivePanicIvPrefix(
        state.salt,
        meta.pid,
        meta.timestamp,
        counter,
      ).subarray(0, IV_RANDOM_BYTES);
      const wire = encodeShared(keyCopy, ivPrefix, counter, meta.frame);
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
    triggerActive();
    throw err;
  }
}
