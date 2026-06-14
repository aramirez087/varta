// VLP v0.2 secure-transport wire encode / decode.
//
// Provides:
//   * HKDF-SHA256 key derivation (Node's built-in `crypto.hkdfSync`).
//   * ChaCha20-Poly1305 shared-key and master-key seal/open via the
//     built-in `crypto.createCipheriv` / `createDecipheriv` — no npm
//     dependency required (stable in Node ≥ 15.0).
//
// The normative spec lives at `book/src/spec/vlp-secure.md`. KDF info
// strings are versioned (`-v1`) and frozen; any future migration MUST
// bump the version suffix and the test vectors.

import {
  createCipheriv,
  createDecipheriv,
  hkdfSync,
  type CipherChaCha20Poly1305,
  type DecipherChaCha20Poly1305,
} from "node:crypto";

export const SECURE_SHARED_BYTES = 60;
export const SECURE_MASTER_BYTES = 64;
export const KEY_BYTES = 32;
export const IV_RANDOM_BYTES = 8;
export const IV_COUNTER_BYTES = 4;
export const TAG_BYTES = 16;
export const PLAINTEXT_BYTES = 32;
export const SESSION_SALT_BYTES = 16;

// HKDF-SHA256 (RFC 5869) — extract + expand.
//
// IMPORTANT: Node's `hkdfSync(digest, ikm, salt, info, length)` argument
// order matches the Python and Rust references when called with an
// EMPTY salt for `deriveIvPrefix` — see cerebrum note 2026-05-16. The
// IKM is `sessionSalt`, the salt is `Buffer.alloc(0)`.
export function hkdfSha256(
  ikm: Buffer,
  salt: Buffer,
  info: Buffer,
  length: number,
): Buffer {
  const out = hkdfSync("sha256", ikm, salt, info, length);
  return Buffer.from(out);
}

// Domain-specific key derivations — see `book/src/spec/vlp-secure.md` §6.

export function deriveAgentKey(masterKey: Buffer, agentId: number): Buffer {
  if (masterKey.length !== KEY_BYTES) {
    throw new RangeError(`masterKey must be ${KEY_BYTES} bytes`);
  }
  const info = Buffer.alloc("varta-agent-v1\x00".length + 4);
  info.write("varta-agent-v1\x00", 0, "binary");
  info.writeUInt32LE(agentId >>> 0, "varta-agent-v1\x00".length);
  return hkdfSha256(masterKey, Buffer.alloc(0), info, KEY_BYTES);
}

export function deriveIvPrefix(
  sessionSalt: Buffer,
  prefixIndex: number,
): Buffer {
  if (sessionSalt.length !== SESSION_SALT_BYTES) {
    throw new RangeError(`sessionSalt must be ${SESSION_SALT_BYTES} bytes`);
  }
  const info = Buffer.alloc("varta-iv-prefix-v1\x00".length + 4);
  info.write("varta-iv-prefix-v1\x00", 0, "binary");
  info.writeUInt32LE(prefixIndex >>> 0, "varta-iv-prefix-v1\x00".length);
  return hkdfSha256(sessionSalt, Buffer.alloc(0), info, IV_RANDOM_BYTES);
}

export function derivePanicIvPrefix(
  sessionSalt: Buffer,
  panicPid: number,
  timestamp: bigint,
  ivCounter: number,
): Buffer {
  if (sessionSalt.length !== SESSION_SALT_BYTES) {
    throw new RangeError(`sessionSalt must be ${SESSION_SALT_BYTES} bytes`);
  }
  // Mirrors crates/varta-vlp/src/crypto/kdf.rs::derive_panic_iv_prefix.
  // info = "varta-panic-iv-v1\0" || pid LE32 || timestamp LE64 || counter LE32
  const label = "varta-panic-iv-v1\x00";
  const info = Buffer.alloc(label.length + 4 + 8 + 4);
  info.write(label, 0, "binary");
  info.writeUInt32LE(panicPid >>> 0, label.length);
  info.writeBigUInt64LE(timestamp & 0xffffffffffffffffn, label.length + 4);
  info.writeUInt32LE(ivCounter >>> 0, label.length + 12);
  return hkdfSha256(sessionSalt, Buffer.alloc(0), info, IV_RANDOM_BYTES);
}

export function deriveEpochKey(agentKey: Buffer, epoch: bigint): Buffer {
  if (agentKey.length !== KEY_BYTES) {
    throw new RangeError(`agentKey must be ${KEY_BYTES} bytes`);
  }
  const info = Buffer.alloc("varta-epoch-v1\x00".length + 8);
  info.write("varta-epoch-v1\x00", 0, "binary");
  info.writeBigUInt64LE(epoch, "varta-epoch-v1\x00".length);
  return hkdfSha256(agentKey, Buffer.alloc(0), info, KEY_BYTES);
}

function buildNonce(ivRandom: Buffer, ivCounter: number): Buffer {
  const nonce = Buffer.alloc(12);
  ivRandom.copy(nonce, 0, 0, IV_RANDOM_BYTES);
  nonce.writeUInt32LE(ivCounter >>> 0, IV_RANDOM_BYTES);
  return nonce;
}

function aeadSeal(
  key: Buffer,
  nonce: Buffer,
  aad: Buffer | null,
  plaintext: Buffer,
): Buffer {
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, {
    authTagLength: TAG_BYTES,
  }) as CipherChaCha20Poly1305;
  if (aad !== null) {
    cipher.setAAD(aad, { plaintextLength: plaintext.length });
  }
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([ct, tag]);
}

function aeadOpen(
  key: Buffer,
  nonce: Buffer,
  aad: Buffer | null,
  ctAndTag: Buffer,
): Buffer {
  if (ctAndTag.length < TAG_BYTES) {
    throw new Error("ciphertext shorter than authentication tag");
  }
  const ct = ctAndTag.subarray(0, ctAndTag.length - TAG_BYTES);
  const tag = ctAndTag.subarray(ctAndTag.length - TAG_BYTES);
  const decipher = createDecipheriv("chacha20-poly1305", key, nonce, {
    authTagLength: TAG_BYTES,
  }) as DecipherChaCha20Poly1305;
  if (aad !== null) {
    decipher.setAAD(aad, { plaintextLength: ct.length });
  }
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// Produce a 60-byte shared-key secure frame.
// Wire layout: ivRandom[8] || ivCounter_LE[4] || ciphertext+tag[48]
export function encodeShared(
  key: Buffer,
  ivRandom: Buffer,
  ivCounter: number,
  plaintext: Buffer,
): Buffer {
  if (key.length !== KEY_BYTES) {
    throw new RangeError(`key must be ${KEY_BYTES} bytes`);
  }
  if (ivRandom.length !== IV_RANDOM_BYTES) {
    throw new RangeError(`ivRandom must be ${IV_RANDOM_BYTES} bytes`);
  }
  if (plaintext.length !== PLAINTEXT_BYTES) {
    throw new RangeError("plaintext must be a 32-byte VLP frame");
  }
  const nonce = buildNonce(ivRandom, ivCounter);
  const ctAndTag = aeadSeal(key, nonce, null, plaintext);
  const wire = Buffer.alloc(SECURE_SHARED_BYTES);
  ivRandom.copy(wire, 0);
  wire.writeUInt32LE(ivCounter >>> 0, IV_RANDOM_BYTES);
  ctAndTag.copy(wire, IV_RANDOM_BYTES + IV_COUNTER_BYTES);
  return wire;
}

export function decodeShared(key: Buffer, wire: Buffer): Buffer {
  if (wire.length !== SECURE_SHARED_BYTES) {
    throw new RangeError(`wire must be ${SECURE_SHARED_BYTES} bytes`);
  }
  const ivRandom = wire.subarray(0, IV_RANDOM_BYTES);
  const ivCounter = wire.readUInt32LE(IV_RANDOM_BYTES);
  const ctAndTag = wire.subarray(IV_RANDOM_BYTES + IV_COUNTER_BYTES);
  const nonce = buildNonce(ivRandom, ivCounter);
  return aeadOpen(key, nonce, null, ctAndTag);
}

// Produce a 64-byte master-key secure frame.
// Wire layout: agentPid_LE[4] (AAD) || ivRandom[8] || ivCounter_LE[4] || ciphertext+tag[48]
export function encodeMaster(
  masterKey: Buffer,
  agentPid: number,
  ivRandom: Buffer,
  ivCounter: number,
  plaintext: Buffer,
): Buffer {
  if (masterKey.length !== KEY_BYTES) {
    throw new RangeError(`masterKey must be ${KEY_BYTES} bytes`);
  }
  if (ivRandom.length !== IV_RANDOM_BYTES) {
    throw new RangeError(`ivRandom must be ${IV_RANDOM_BYTES} bytes`);
  }
  if (plaintext.length !== PLAINTEXT_BYTES) {
    throw new RangeError("plaintext must be a 32-byte VLP frame");
  }
  const agentKey = deriveAgentKey(masterKey, agentPid);
  const aad = Buffer.alloc(4);
  aad.writeUInt32LE(agentPid >>> 0, 0);
  const nonce = buildNonce(ivRandom, ivCounter);
  const ctAndTag = aeadSeal(agentKey, nonce, aad, plaintext);
  const wire = Buffer.alloc(SECURE_MASTER_BYTES);
  aad.copy(wire, 0);
  ivRandom.copy(wire, 4);
  wire.writeUInt32LE(ivCounter >>> 0, 4 + IV_RANDOM_BYTES);
  ctAndTag.copy(wire, 4 + IV_RANDOM_BYTES + IV_COUNTER_BYTES);
  return wire;
}

export function decodeMaster(masterKey: Buffer, wire: Buffer): Buffer {
  if (wire.length !== SECURE_MASTER_BYTES) {
    throw new RangeError(`wire must be ${SECURE_MASTER_BYTES} bytes`);
  }
  const aad = wire.subarray(0, 4);
  const agentPid = wire.readUInt32LE(0);
  const ivRandom = wire.subarray(4, 4 + IV_RANDOM_BYTES);
  const ivCounter = wire.readUInt32LE(4 + IV_RANDOM_BYTES);
  const ctAndTag = wire.subarray(4 + IV_RANDOM_BYTES + IV_COUNTER_BYTES);
  const agentKey = deriveAgentKey(masterKey, agentPid);
  const nonce = buildNonce(ivRandom, ivCounter);
  return aeadOpen(agentKey, nonce, aad, ctAndTag);
}
