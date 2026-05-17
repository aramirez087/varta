// VLP v0.2 wire encode / decode + CRC-32C.
//
// The normative wire specification lives at `book/src/spec/vlp.md`. This
// module is the canonical Node.js implementation that the production
// `Varta` client builds on top of. Cross-language byte equality is
// enforced by the conformance test suite at `tests/conformance.test.ts`,
// which drives `tools/vlp-test-vectors.json`.

export const MAGIC: Buffer = Buffer.from([0x56, 0x41]); // "VA"
export const VERSION: number = 0x02;
export const NONCE_TERMINAL: bigint = 0xffffffffffffffffn;
export const TIMESTAMP_INVALID: bigint = 0xffffffffffffffffn;
export const FRAME_BYTES: number = 32;

// Beat status — matches the 1-byte wire value at offset 3.
// `Stall` is observer-synthesized; agents MUST NOT emit it on the wire.
// `decode()` raises `DecodeError` with `kind="StallOnWire"` if it appears.
export enum Status {
  Ok = 0,
  Degraded = 1,
  Critical = 2,
  Stall = 3,
}

export type StatusLike = Status | number | string;

const STATUS_BY_NAME: Record<string, Status> = {
  ok: Status.Ok,
  degraded: Status.Degraded,
  critical: Status.Critical,
  stall: Status.Stall,
};

// Decode error kinds — these strings MUST match the entries in
// `tools/vlp-test-vectors.json` and the corresponding constants in
// the Rust, Python, and Go clients (cerebrum 2026-05-13).
export type DecodeErrorKind =
  | "BadMagic"
  | "BadVersion"
  | "BadCrc"
  | "BadStatus"
  | "StallOnWire"
  | "BadPid"
  | "BadTimestamp"
  | "BadNonce";

export class DecodeError extends Error {
  readonly kind: DecodeErrorKind;
  constructor(kind: DecodeErrorKind, detail = "") {
    super(detail ? `${kind}: ${detail}` : kind);
    this.name = "DecodeError";
    this.kind = kind;
  }
}

// CRC-32C (Castagnoli) — RFC 3720 appendix B. Reflected polynomial
// 0x82F63B78, init 0xFFFFFFFF, refin/refout, xorout 0xFFFFFFFF. Matches
// the canonical Rust implementation at `crates/varta-vlp/src/crc32c.rs`.

const POLY_REFLECTED = 0x82f63b78;

const CRC_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i >>> 0;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? (c >>> 1) ^ POLY_REFLECTED : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

export function crc32c(data: Buffer | Uint8Array): number {
  let crc = 0xffffffff >>> 0;
  for (let i = 0; i < data.length; i++) {
    const idx = ((crc ^ data[i]!) & 0xff) >>> 0;
    crc = ((CRC_TABLE[idx]! ^ (crc >>> 8)) >>> 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// Decoded view of a 32-byte VLP v0.2 frame. Mirrors the Python
// `Frame` dataclass and Go `Frame` struct field-for-field.
export interface Frame {
  status: Status;
  pid: number;
  timestamp: bigint;
  nonce: bigint;
  payload: number;
}

function coerceStatus(status: StatusLike): Status {
  if (typeof status === "string") {
    const s = STATUS_BY_NAME[status.toLowerCase()];
    if (s === undefined) {
      throw new RangeError(`unknown status name: ${status}`);
    }
    return s;
  }
  if (status === Status.Ok || status === Status.Degraded ||
      status === Status.Critical || status === Status.Stall) {
    return status as Status;
  }
  throw new RangeError(`invalid status: ${status}`);
}

// Encode a single VLP v0.2 frame into a fresh 32-byte Buffer.
//
// The hot path of the production client uses `encodeInto` against a
// pre-allocated scratch buffer to keep per-beat allocation minimal.
export function encode(
  status: StatusLike,
  pid: number,
  timestamp: bigint,
  nonce: bigint,
  payload: number,
): Buffer {
  const buf = Buffer.alloc(FRAME_BYTES);
  encodeInto(buf, status, pid, timestamp, nonce, payload);
  return buf;
}

// Encode a single VLP v0.2 frame into `buf` (must be ≥ 32 bytes).
export function encodeInto(
  buf: Buffer,
  status: StatusLike,
  pid: number,
  timestamp: bigint,
  nonce: bigint,
  payload: number,
): void {
  if (buf.length < FRAME_BYTES) {
    throw new RangeError(`buffer must be at least ${FRAME_BYTES} bytes`);
  }
  const s = coerceStatus(status);
  buf[0] = 0x56;
  buf[1] = 0x41;
  buf[2] = VERSION;
  buf[3] = s & 0xff;
  buf.writeUInt32LE(pid >>> 0, 4);
  buf.writeBigUInt64LE(timestamp, 8);
  buf.writeBigUInt64LE(nonce, 16);
  buf.writeUInt32LE(payload >>> 0, 24);
  const crc = crc32c(buf.subarray(0, 28));
  buf.writeUInt32LE(crc, 28);
}

// Decode a 32-byte VLP v0.2 frame.
//
// Throws `DecodeError` on the first failed validation step. See
// `book/src/spec/vlp.md` §5 for the normative decode order:
// magic → version → CRC → status (incl. Stall rejection) → pid →
// timestamp → nonce.
export function decode(buf: Buffer | Uint8Array): Frame {
  if (buf.length !== FRAME_BYTES) {
    throw new DecodeError("BadMagic", `length ${buf.length} != ${FRAME_BYTES}`);
  }
  if (buf[0] !== 0x56 || buf[1] !== 0x41) {
    throw new DecodeError(
      "BadMagic",
      Buffer.from(buf.slice(0, 2)).toString("hex"),
    );
  }
  if (buf[2] !== VERSION) {
    throw new DecodeError(
      "BadVersion",
      `0x${(buf[2]!).toString(16).padStart(2, "0")}`,
    );
  }

  const view = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  const storedCrc = view.readUInt32LE(28);
  const computedCrc = crc32c(view.subarray(0, 28));
  if (storedCrc !== computedCrc) {
    throw new DecodeError(
      "BadCrc",
      `expected ${computedCrc.toString(16).padStart(8, "0")}, got ${storedCrc
        .toString(16)
        .padStart(8, "0")}`,
    );
  }

  const statusByte = view[3]!;
  if (statusByte > 3) {
    throw new DecodeError(
      "BadStatus",
      `0x${statusByte.toString(16).padStart(2, "0")}`,
    );
  }
  if (statusByte === Status.Stall) {
    throw new DecodeError("StallOnWire");
  }

  const pid = view.readUInt32LE(4);
  const timestamp = view.readBigUInt64LE(8);
  const nonce = view.readBigUInt64LE(16);
  const payload = view.readUInt32LE(24);

  if (pid === 0 || pid === 1) {
    throw new DecodeError("BadPid", String(pid));
  }
  if (timestamp === TIMESTAMP_INVALID) {
    throw new DecodeError("BadTimestamp");
  }
  if (nonce === NONCE_TERMINAL && statusByte !== Status.Critical) {
    throw new DecodeError(
      "BadNonce",
      `nonce=NONCE_TERMINAL paired with status=0x${statusByte
        .toString(16)
        .padStart(2, "0")}`,
    );
  }

  return {
    status: statusByte as Status,
    pid,
    timestamp,
    nonce,
    payload,
  };
}

// Convenience wrapper for parity with the Go client's exported
// `DecodeFrame`. Returns the same shape as `decode()`.
export function decodeFrame(buf: Buffer | Uint8Array): Frame {
  return decode(buf);
}
