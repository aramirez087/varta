// Beat transport abstractions — UDP and ChaCha20-Poly1305-AEAD UDP.
//
// UDS (AF_UNIX/SOCK_DGRAM) is intentionally NOT implemented in this
// release. Node's stdlib `dgram` module accepts only `"udp4"` and
// `"udp6"` socket types; the `"unix_dgram"` type that exists in some
// platform sockets APIs is rejected with `ERR_SOCKET_BAD_TYPE`. Adding
// UDS would require a native addon (breaking the zero-dep posture) or
// pulling in `node:net.Socket(fd)` over a manually opened AF_UNIX FD
// (no portable JS path exists). For same-host deployments, use
// `Varta.connectUdp("127.0.0.1", port)` — loopback is the same
// security domain as UDS on a single host.

import { randomBytes } from "node:crypto";
import { createSocket, type Socket } from "node:dgram";

import {
  encodeMaster,
  encodeShared,
  IV_RANDOM_BYTES,
  SESSION_SALT_BYTES,
  deriveIvPrefix,
} from "./vlp_secure.js";

export interface BeatTransport {
  // Synchronous send. Returns nothing on success; throws a
  // `NodeJS.ErrnoException`-shaped error on failure. The Node libuv
  // model means most kernel-level errors actually arrive on the NEXT
  // call's path (via the cached `pendingError`); the implementations
  // below already paper over that asymmetry so callers see Rust-style
  // synchronous semantics.
  send(buf: Buffer): void;
  reconnect(): void;
  close(): void;
}

// Common helper: drain a libuv async error captured on a previous
// `socket.send` callback. Returns the error if one is queued and
// clears the slot, or `null` if the slot is empty.
function takePendingError(holder: { pendingError: NodeJS.ErrnoException | null }):
  | NodeJS.ErrnoException
  | null {
  const e = holder.pendingError;
  holder.pendingError = null;
  return e;
}

// ─── Plaintext UDP ──────────────────────────────────────────────

export class UdpTransport implements BeatTransport {
  private socket: Socket;
  private readonly host: string;
  private readonly port: number;
  pendingError: NodeJS.ErrnoException | null = null;

  constructor(host: string, port: number) {
    this.host = host;
    this.port = port;
    this.socket = this.openSocket();
  }

  private openSocket(): Socket {
    const family: "udp4" | "udp6" = this.host.includes(":") ? "udp6" : "udp4";
    const s = createSocket(family);
    // Swallow `error` events; they would otherwise crash the process.
    // The pending-error slot captures them for the next `send` call.
    s.on("error", (err) => {
      this.pendingError = err as NodeJS.ErrnoException;
    });
    s.unref();
    return s;
  }

  send(buf: Buffer): void {
    const queued = takePendingError(this);
    if (queued !== null) throw queued;
    // Use addressed sends instead of connected sends — `socket.connect`
    // is async and a `send()` issued before its `connect` event lands
    // fails with `ERR_SOCKET_DGRAM_NOT_CONNECTED`. The libuv callback
    // path still surfaces kernel-level send errors via `pendingError`.
    //
    // Copy the caller's scratch buffer before handing off to libuv:
    // `dgram.Socket.send` does NOT internally copy, and the agent
    // reuses a single 32-byte buffer across beats, so a non-copy
    // would let later beats overwrite earlier in-flight datagrams.
    const owned = Buffer.from(buf);
    this.socket.send(owned, this.port, this.host, (err) => {
      if (err !== null && err !== undefined) {
        this.pendingError = err as NodeJS.ErrnoException;
      }
    });
  }

  reconnect(): void {
    try {
      this.socket.close();
    } catch {
      // Already closed — fine.
    }
    this.pendingError = null;
    this.socket = this.openSocket();
  }

  close(): void {
    try {
      this.socket.close();
    } catch {
      // Already closed.
    }
  }
}

// ─── Secure UDP (ChaCha20-Poly1305 AEAD) ────────────────────────

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

export class SecureUdpTransport implements BeatTransport {
  private socket: Socket;
  private readonly host: string;
  private readonly port: number;
  private readonly secret: SecureKey;
  private sessionSalt: Buffer;
  private ivPrefix: Buffer;
  private prefixIndex: number;
  private counter: number;
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
      this.pendingError = err as NodeJS.ErrnoException;
    });
    s.unref();
    return s;
  }

  // Test hooks (matching Python `_set_*_for_test` and Go `*ForTest`).
  __setCounterForTest(v: number): void {
    this.counter = v >>> 0;
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

  send(buf: Buffer): void {
    const queued = takePendingError(this);
    if (queued !== null) throw queued;

    // The IV (8-byte prefix + 4-byte LE counter) is reserved
    // synchronously here. The Rust client uses commit-on-success
    // because its `send(2)` is synchronous and a `WouldBlock` lets it
    // safely re-use the nonce on retry. Node's `dgram.send` queues
    // datagrams via libuv async, so multiple concurrent calls would
    // all see the same proposed counter and encrypt distinct
    // plaintexts under the same nonce — that is the classic
    // ChaCha20-Poly1305 nonce-reuse footgun. We reserve and advance
    // synchronously here so every queued frame carries a unique IV;
    // a callback-reported `pendingError` simply burns one nonce
    // slot, which is harmless.
    const ivRandom = Buffer.alloc(IV_RANDOM_BYTES);
    this.ivPrefix.copy(ivRandom, 0, 0, IV_RANDOM_BYTES);
    const counter = this.counter;
    if (this.counter === 0xffffffff) {
      this.prefixIndex = (this.prefixIndex + 1) >>> 0;
      this.ivPrefix = deriveIvPrefix(this.sessionSalt, this.prefixIndex);
      this.counter = 0;
    } else {
      this.counter = (this.counter + 1) >>> 0;
    }

    let wire: Buffer;
    if (this.secret.kind === "shared") {
      wire = encodeShared(this.secret.key, ivRandom, counter, buf);
    } else {
      wire = encodeMaster(
        this.secret.masterKey,
        process.pid >>> 0,
        ivRandom,
        counter,
        buf,
      );
    }

    this.socket.send(wire, this.port, this.host, (err) => {
      if (err !== null && err !== undefined) {
        this.pendingError = err as NodeJS.ErrnoException;
      }
    });
  }

  reconnect(): void {
    try {
      this.socket.close();
    } catch {
      // Already closed.
    }
    this.pendingError = null;
    // Prepare a fresh session in locals; commit at the end without `?`.
    const newSalt = randomBytes(SESSION_SALT_BYTES);
    const newPrefixIndex = 0;
    const newIvPrefix = deriveIvPrefix(newSalt, newPrefixIndex);
    const newSocket = this.openSocket();
    this.sessionSalt = newSalt;
    this.prefixIndex = newPrefixIndex;
    this.counter = 0;
    this.ivPrefix = newIvPrefix;
    this.socket = newSocket;
  }

  close(): void {
    try {
      this.socket.close();
    } catch {
      // Already closed.
    }
  }
}
