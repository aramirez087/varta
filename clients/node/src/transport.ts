// Beat transport abstractions — UDS (AF_UNIX/SOCK_DGRAM), plaintext
// UDP, and ChaCha20-Poly1305-AEAD UDP.
//
// The UDS transport relies on the `node-unix-socket` napi-rs addon
// (listed under `optionalDependencies`). It ships prebuilds for
// darwin-x64/arm64 and linux-x64/arm64 (gnu + musl); installing on a
// platform without a published prebuild succeeds with the addon
// absent, and the UDS transport raises `UdsUnavailableError` at
// construction. UDP / secure-UDP work on every Node platform with
// only the stdlib.
//
// UDP and secure-UDP use connected-mode sockets (`dgram.Socket.connect`)
// so the kernel's ICMP `port unreachable` is queued onto the socket's
// `error` event and surfaces as `DropReason.NoObserver` on a subsequent
// beat. Pre-`connect` event sends are queued internally by libuv;
// errors from any source (send callback, recvmsg ICMP, async connect)
// drain into `pendingError` for the next caller.

import { randomBytes } from "node:crypto";
import { createSocket, type Socket } from "node:dgram";
import { createRequire } from "node:module";

import {
  encodeMaster,
  encodeShared,
  IV_RANDOM_BYTES,
  PLAINTEXT_BYTES,
  SESSION_SALT_BYTES,
  deriveIvPrefix,
} from "./vlp_secure.js";

export interface BeatTransport {
  // Synchronous send. Returns nothing on success; throws a
  // `NodeJS.ErrnoException`-shaped error on failure. libuv may report
  // kernel-level errors on a later send's callback or via a recvmsg
  // ICMP error event; transports drain those into `pendingError` so
  // callers see Rust-style synchronous semantics.
  send(buf: Buffer): void;
  // Rebuild the transport with the strong exception guarantee: if
  // replacement setup throws, the current socket and any secure-session
  // state remain usable and unchanged.
  reconnect(): void;
  close(): void;
}

function takePendingError(holder: { pendingError: NodeJS.ErrnoException | null }):
  | NodeJS.ErrnoException
  | null {
  const e = holder.pendingError;
  holder.pendingError = null;
  return e;
}

// ─── UDS (AF_UNIX/SOCK_DGRAM) ──────────────────────────────────

export class UdsUnavailableError extends Error {
  readonly cause: unknown;
  constructor(cause: unknown) {
    super(
      "UDS transport requires the optional `node-unix-socket` addon. " +
        "Install it with `npm install node-unix-socket`, or fall back to " +
        "`Varta.connectUdp(\"127.0.0.1\", port)` on platforms without a prebuild.",
    );
    this.name = "UdsUnavailableError";
    this.cause = cause;
  }
}

// `node-unix-socket`'s `DgramSocket` reports errors without populating
// `err.code` / `err.errno`. Translate the human-readable message back
// into the symbolic form that `classifySendError` expects.
function normalizeUdsError(err: unknown): NodeJS.ErrnoException {
  const e = (err instanceof Error ? err : new Error(String(err))) as NodeJS.ErrnoException;
  if (typeof e.code === "string" && e.code.length > 0) return e;
  const msg = (e.message ?? "").toLowerCase();
  if (msg.includes("no such file")) e.code = "ENOENT";
  else if (msg.includes("connection refused")) e.code = "ECONNREFUSED";
  else if (msg.includes("no buffer space")) e.code = "ENOBUFS";
  else if (msg.includes("resource temporarily unavailable")) e.code = "EAGAIN";
  else if (msg.includes("would block")) e.code = "EWOULDBLOCK";
  else if (msg.includes("no space left")) e.code = "ENOSPC";
  else if (msg.includes("broken pipe")) e.code = "EPIPE";
  else if (msg.includes("connection reset")) e.code = "ECONNRESET";
  else if (msg.includes("transport endpoint is not connected")) e.code = "ENOTCONN";
  return e;
}

interface DgramSocketLike {
  bind(socketPath: string): void;
  sendTo(
    buf: Buffer,
    offset: number,
    length: number,
    destPath: string,
    onWrite?: (err: undefined | Error) => void,
  ): void;
  close(): void;
  on(event: "error", listener: (err: Error) => void): unknown;
  on(event: "data", listener: (buf: Buffer, path: string) => void): unknown;
}

interface NodeUnixSocketModule {
  DgramSocket: new () => DgramSocketLike;
}

let cachedNodeUnixSocket: NodeUnixSocketModule | null | "missing" = null;

const requireFromHere = createRequire(import.meta.url);

function loadNodeUnixSocket(): NodeUnixSocketModule {
  if (cachedNodeUnixSocket === "missing") {
    throw new UdsUnavailableError(new Error("module not installed"));
  }
  if (cachedNodeUnixSocket !== null) return cachedNodeUnixSocket;
  try {
    // `createRequire` keeps this importable from an ESM build without a
    // top-level `await import` (which would force every consumer to
    // tolerate an async load even when they never touch UDS).
    const mod = requireFromHere("node-unix-socket") as NodeUnixSocketModule;
    cachedNodeUnixSocket = mod;
    return mod;
  } catch (err) {
    cachedNodeUnixSocket = "missing";
    throw new UdsUnavailableError(err);
  }
}

export class UdsTransport implements BeatTransport {
  private socket: DgramSocketLike;
  private readonly path: string;
  pendingError: NodeJS.ErrnoException | null = null;

  constructor(path: string) {
    this.path = path;
    this.socket = this.openSocket();
  }

  private openSocket(): DgramSocketLike {
    const { DgramSocket } = loadNodeUnixSocket();
    const s = new DgramSocket();
    // Upstream's `onError` self-closes the socket and re-emits as
    // `error`. Drain into pendingError so the next beat surfaces it,
    // and rely on `reconnect()` to rebuild. Most sendTo failures
    // arrive on the per-call callback (not this event), so this path
    // is rare.
    s.on("error", (err) => {
      if (this.socket === s) {
        this.pendingError = normalizeUdsError(err);
      }
    });
    return s;
  }

  send(buf: Buffer): void {
    const queued = takePendingError(this);
    if (queued !== null) throw queued;
    // Copy the caller's scratch buffer before handing off to libuv —
    // matching the UDP transports' guard. The agent reuses a single
    // 32-byte buffer across beats.
    const owned = Buffer.from(buf);
    const socket = this.socket;
    socket.sendTo(owned, 0, owned.length, this.path, (err) => {
      if (this.socket === socket && err !== null && err !== undefined) {
        this.pendingError = normalizeUdsError(err);
      }
    });
  }

  reconnect(): void {
    const replacement = this.openSocket();
    const old = this.socket;
    this.socket = replacement;
    this.pendingError = null;
    try {
      old.close();
    } catch {
      // Already closed — fine.
    }
  }

  close(): void {
    try {
      this.socket.close();
    } catch {
      // Already closed.
    }
  }
}

// ─── Plaintext UDP (connected-mode) ────────────────────────────

// Bound on how many beats may queue while `socket.connect` is in
// flight. IPv4 numeric connect completes in one libuv tick, so the
// queue is normally empty by the second beat; this cap exists only to
// guard against a `connect` that never fires (peer DNS issues etc.).
const PRE_CONNECT_QUEUE_LIMIT = 64;
const U32_MAX = 0xffffffff;

export class UdpTransport implements BeatTransport {
  private socket: Socket;
  private readonly host: string;
  private readonly port: number;
  private connected = false;
  private preConnectQueue: Buffer[] = [];
  pendingError: NodeJS.ErrnoException | null = null;

  constructor(host: string, port: number) {
    this.host = host;
    this.port = port;
    this.socket = this.openSocket();
  }

  private openSocket(): Socket {
    const family: "udp4" | "udp6" = this.host.includes(":") ? "udp6" : "udp4";
    const s = createSocket(family);
    // ICMP `port unreachable` for a connected dgram socket lands here
    // (libuv's recvmsg path), as do async-connect failures and any
    // out-of-band socket errors. Swallow into pendingError so the next
    // `send()` call surfaces it instead of crashing the process.
    s.on("error", (err) => {
      if (this.socket === s) {
        this.pendingError = err as NodeJS.ErrnoException;
      }
    });
    s.unref();
    // Connect for ICMP error propagation. Node's `dgram.Socket.send`
    // rejects the connected-mode (no-port/host) signature while the
    // socket is still CONNECTING; queue pre-connect-event beats and
    // flush them once the `connect` callback fires.
    try {
      s.connect(this.port, this.host, () => {
        if (this.socket !== s) return;
        this.connected = true;
        while (this.preConnectQueue.length > 0) {
          const owned = this.preConnectQueue.shift()!;
          s.send(owned, (err) => {
            if (this.socket === s && err !== null && err !== undefined) {
              this.pendingError = err as NodeJS.ErrnoException;
            }
          });
        }
      });
    } catch (err) {
      try {
        s.close();
      } catch {
        // Socket never became active.
      }
      throw err;
    }
    return s;
  }

  send(buf: Buffer): void {
    const queued = takePendingError(this);
    if (queued !== null) throw queued;
    // Buffer copy: libuv does NOT copy before handing to the kernel,
    // and the caller reuses a single 32-byte scratch buffer.
    const owned = Buffer.from(buf);
    if (!this.connected) {
      if (this.preConnectQueue.length >= PRE_CONNECT_QUEUE_LIMIT) {
        const e: NodeJS.ErrnoException = new Error(
          "UdpTransport: pre-connect queue full",
        );
        e.code = "ENOBUFS";
        throw e;
      }
      this.preConnectQueue.push(owned);
      return;
    }
    const socket = this.socket;
    socket.send(owned, (err) => {
      if (this.socket === socket && err !== null && err !== undefined) {
        this.pendingError = err as NodeJS.ErrnoException;
      }
    });
  }

  reconnect(): void {
    const replacement = this.openSocket();
    const old = this.socket;
    this.socket = replacement;
    this.connected = false;
    this.pendingError = null;
    // Keep any beats that were queued while the previous socket was still
    // connecting. They have not been sent yet, so discarding them would burn
    // committed client state without giving the replacement socket a chance
    // to deliver them.
    try {
      old.close();
    } catch {
      // Already closed — fine.
    }
  }

  close(): void {
    try {
      this.socket.close();
    } catch {
      // Already closed.
    }
  }
}

// ─── Secure UDP (ChaCha20-Poly1305 AEAD, connected-mode) ───────

export type SecureUdpKind = "shared" | "master";

interface SecureKeyShared {
  kind: "shared";
  key: Buffer;
}
interface SecureKeyMaster {
  kind: "master";
  masterKey: Buffer;
}
type SecureKey = SecureKeyShared | SecureKeyMaster;

interface NonceReservation {
  ivRandom: Buffer;
  counter: number;
  nextPrefixIndex: number;
  nextIvPrefix: Buffer;
  nextCounter: number;
}

export class SecureUdpTransport implements BeatTransport {
  private socket: Socket;
  private readonly host: string;
  private readonly port: number;
  private readonly secret: SecureKey;
  private sessionSalt: Buffer;
  private ivPrefix: Buffer;
  private prefixIndex: number;
  private counter: number;
  private connected = false;
  private preConnectQueue: Buffer[] = [];
  pendingError: NodeJS.ErrnoException | null = null;

  private constructor(host: string, port: number, secret: SecureKey) {
    this.host = host;
    this.port = port;
    this.secret = secret;
    this.sessionSalt = randomBytes(SESSION_SALT_BYTES);
    this.prefixIndex = 0;
    this.counter = 0;
    this.ivPrefix = deriveIvPrefix(this.sessionSalt, this.prefixIndex);
    this.socket = this.openSocket();
  }

  static shared(host: string, port: number, key: Buffer): SecureUdpTransport {
    if (key.length !== 32) {
      throw new RangeError("secure-UDP shared key must be 32 bytes");
    }
    return new SecureUdpTransport(host, port, { kind: "shared", key: Buffer.from(key) });
  }

  static master(host: string, port: number, masterKey: Buffer): SecureUdpTransport {
    if (masterKey.length !== 32) {
      throw new RangeError("secure-UDP master key must be 32 bytes");
    }
    return new SecureUdpTransport(host, port, {
      kind: "master",
      masterKey: Buffer.from(masterKey),
    });
  }

  private openSocket(): Socket {
    const family: "udp4" | "udp6" = this.host.includes(":") ? "udp6" : "udp4";
    const s = createSocket(family);
    s.on("error", (err) => {
      if (this.socket === s) {
        this.pendingError = err as NodeJS.ErrnoException;
      }
    });
    s.unref();
    try {
      s.connect(this.port, this.host, () => {
        if (this.socket !== s) return;
        this.connected = true;
        while (this.preConnectQueue.length > 0) {
          const wire = this.preConnectQueue.shift()!;
          s.send(wire, (err) => {
            if (this.socket === s && err !== null && err !== undefined) {
              this.pendingError = err as NodeJS.ErrnoException;
            }
          });
        }
      });
    } catch (err) {
      try {
        s.close();
      } catch {
        // Socket never became active.
      }
      throw err;
    }
    return s;
  }

  // Test hooks (matching Python `_set_*_for_test` and Go `*ForTest`).
  __setCounterForTest(v: number): void {
    this.counter = v >>> 0;
  }
  __setPrefixIndexForTest(v: number): void {
    this.prefixIndex = v >>> 0;
    this.ivPrefix = deriveIvPrefix(this.sessionSalt, this.prefixIndex);
  }
  __getCounterForTest(): number {
    return this.counter;
  }
  __getPrefixIndexForTest(): number {
    return this.prefixIndex;
  }
  __getIvPrefixForTest(): Buffer {
    return Buffer.from(this.ivPrefix);
  }

  private prepareNonce(): NonceReservation {
    if (this.counter === U32_MAX && this.prefixIndex === U32_MAX) {
      // The 64-bit per-session nonce space is exhausted. Match the Rust
      // reference: rotate the whole secure session before emitting another
      // frame, rather than wrapping back to prefix index 0 under the same salt.
      this.reconnect();
    }

    let nextPrefixIndex = this.prefixIndex;
    let nextIvPrefix = this.ivPrefix;
    let counter = this.counter;
    if (counter === U32_MAX) {
      nextPrefixIndex = (nextPrefixIndex + 1) >>> 0;
      nextIvPrefix = deriveIvPrefix(this.sessionSalt, nextPrefixIndex);
      counter = 0;
    }

    return {
      ivRandom: Buffer.from(nextIvPrefix.subarray(0, IV_RANDOM_BYTES)),
      counter,
      nextPrefixIndex,
      nextIvPrefix,
      nextCounter: (counter + 1) >>> 0,
    };
  }

  private commitNonce(reservation: NonceReservation): void {
    this.prefixIndex = reservation.nextPrefixIndex;
    this.ivPrefix = reservation.nextIvPrefix;
    this.counter = reservation.nextCounter;
  }

  send(buf: Buffer): void {
    const queued = takePendingError(this);
    if (queued !== null) throw queued;
    if (buf.length !== PLAINTEXT_BYTES) {
      throw new RangeError("plaintext must be a 32-byte VLP frame");
    }
    if (!this.connected && this.preConnectQueue.length >= PRE_CONNECT_QUEUE_LIMIT) {
      const e: NodeJS.ErrnoException = new Error(
        "SecureUdpTransport: pre-connect queue full",
      );
      e.code = "ENOBUFS";
      throw e;
    }

    // Compute IV state into locals and commit only after the frame is accepted
    // for delivery (or queued during connect). A later libuv callback error
    // still burns the nonce slot because the datagram may already have escaped.
    const nonce = this.prepareNonce();

    let wire: Buffer;
    if (this.secret.kind === "shared") {
      wire = encodeShared(this.secret.key, nonce.ivRandom, nonce.counter, buf);
    } else {
      wire = encodeMaster(
        this.secret.masterKey,
        process.pid >>> 0,
        nonce.ivRandom,
        nonce.counter,
        buf,
      );
    }

    if (!this.connected) {
      this.preConnectQueue.push(wire);
      this.commitNonce(nonce);
      return;
    }
    const socket = this.socket;
    socket.send(wire, (err) => {
      if (this.socket === socket && err !== null && err !== undefined) {
        this.pendingError = err as NodeJS.ErrnoException;
      }
    });
    this.commitNonce(nonce);
  }

  reconnect(): void {
    const newSalt = randomBytes(SESSION_SALT_BYTES);
    const newPrefixIndex = 0;
    const newIvPrefix = deriveIvPrefix(newSalt, newPrefixIndex);
    const newSocket = this.openSocket();
    const old = this.socket;
    this.socket = newSocket;
    this.connected = false;
    this.pendingError = null;
    // Preserve queued beats across reconnect for the same reason as the UDP
    // transport: a queued pre-connect datagram has not been accepted yet.
    this.sessionSalt = newSalt;
    this.prefixIndex = newPrefixIndex;
    this.counter = 0;
    this.ivPrefix = newIvPrefix;
    try {
      old.close();
    } catch {
      // Already closed.
    }
  }

  close(): void {
    try {
      this.socket.close();
    } catch {
      // Already closed.
    }
  }
}
