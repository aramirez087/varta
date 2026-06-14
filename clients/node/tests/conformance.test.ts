// Conformance: every entry in `tools/vlp-test-vectors.json` must
// round-trip through the Node client. Cross-checked against the
// Rust loader test at `crates/varta-vlp/tests/conformance_vectors.rs`
// and the Python/Go test suites — wire-format drift is impossible
// without all four failing in the same PR.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  crc32c,
  decode,
  DecodeError,
  encode,
  type StatusLike,
} from "../src/vlp.js";
import {
  decodeMaster,
  decodeShared,
  deriveAgentKey,
  deriveEpochKey,
  deriveIvPrefix,
  derivePanicIvPrefix,
  encodeMaster,
  encodeShared,
} from "../src/vlp_secure.js";
import { vectorsPath } from "./helpers.js";

interface CrcVector {
  id: string;
  input_hex: string;
  expected_crc_hex: string;
}

interface FrameVector {
  id: string;
  expected_decode_error: string | null;
  wire_hex?: string;
  expected_wire_hex?: string;
  inputs?: {
    status: StatusLike;
    pid: number;
    timestamp: string;
    nonce: string;
    payload: number;
  };
}

interface SecureFrameVector {
  id: string;
  // shared / master seal
  key_hex?: string;
  master_key_hex?: string;
  agent_pid?: number;
  agent_id?: number;
  iv_random_hex?: string;
  iv_counter?: number;
  plaintext_hex?: string;
  expected_wire_hex?: string;
  // KDF
  session_salt_hex?: string;
  prefix_index?: number;
  expected_iv_prefix_hex?: string;
  agent_key_hex?: string;
  epoch?: string;
  expected_okm_hex?: string;
}

interface Vectors {
  crc32c_vectors: CrcVector[];
  frame_vectors: FrameVector[];
  secure_frame_vectors: SecureFrameVector[];
}

// JavaScript's `JSON.parse` coerces numeric literals through Number,
// losing precision above 2^53. Pre-quote the fields that may carry
// u64 values (`timestamp`, `nonce`, `epoch`) so they survive as
// strings — the test code then BigInt-parses them at point of use.
function loadVectors(): Vectors {
  const raw = readFileSync(vectorsPath(), "utf8");
  const quoted = raw.replace(
    /"(timestamp|nonce|epoch)":\s*(-?\d+)/g,
    '"$1": "$2"',
  );
  return JSON.parse(quoted) as Vectors;
}

const vectors: Vectors = loadVectors();

test("crc32c vectors round-trip", () => {
  assert.ok(vectors.crc32c_vectors.length > 0, "expected at least one CRC vector");
  for (const v of vectors.crc32c_vectors) {
    const data = Buffer.from(v.input_hex, "hex");
    const expected = parseInt(v.expected_crc_hex, 16);
    assert.equal(crc32c(data), expected, v.id);
  }
});

test("frame vectors encode/decode round-trip", () => {
  assert.ok(vectors.frame_vectors.length > 0, "expected at least one frame vector");
  for (const v of vectors.frame_vectors) {
    const wire = Buffer.from(v.expected_wire_hex ?? v.wire_hex ?? "", "hex");
    if (v.expected_decode_error) {
      try {
        decode(wire);
        assert.fail(`${v.id}: expected DecodeError ${v.expected_decode_error}`);
      } catch (err) {
        assert.ok(err instanceof DecodeError, `${v.id}: not a DecodeError`);
        assert.equal(
          (err as DecodeError).kind,
          v.expected_decode_error,
          `${v.id}: kind mismatch`,
        );
      }
    } else {
      assert.ok(v.inputs, `${v.id}: missing inputs`);
      const inp = v.inputs!;
      const encoded = encode(
        inp.status,
        inp.pid,
        BigInt(inp.timestamp),
        BigInt(inp.nonce),
        inp.payload,
      );
      assert.equal(encoded.toString("hex"), wire.toString("hex"), v.id);
      // Round-trip the decoded frame too — but only when decode is
      // legal. A handful of the encode-decode vectors are crafted to
      // be wire-valid only on the encode side (e.g. terminal nonce
      // paired with Critical); decoder accepts them.
      const frame = decode(wire);
      assert.equal(frame.pid, inp.pid, `${v.id}: pid`);
      assert.equal(frame.timestamp, BigInt(inp.timestamp), `${v.id}: ts`);
      assert.equal(frame.nonce, BigInt(inp.nonce), `${v.id}: nonce`);
      assert.equal(frame.payload, inp.payload, `${v.id}: payload`);
    }
  }
});

test("KDF derivations match vectors", () => {
  for (const v of vectors.secure_frame_vectors) {
    if (v.id === "kdf-agent-key") {
      const out = deriveAgentKey(
        Buffer.from(v.master_key_hex!, "hex"),
        v.agent_id!,
      );
      assert.equal(out.toString("hex"), v.expected_okm_hex, v.id);
    } else if (v.id === "kdf-iv-prefix") {
      const out = deriveIvPrefix(
        Buffer.from(v.session_salt_hex!, "hex"),
        v.prefix_index!,
      );
      assert.equal(out.toString("hex"), v.expected_iv_prefix_hex, v.id);
    } else if (v.id === "kdf-epoch-key") {
      const out = deriveEpochKey(
        Buffer.from(v.agent_key_hex!, "hex"),
        BigInt(v.epoch!),
      );
      assert.equal(out.toString("hex"), v.expected_okm_hex, v.id);
    } else {
      // secure-*-seal vectors handled in the AEAD test below
    }
  }
});

test("panic IV prefix: cross-impl KAT, per-input variance, recycle distinctness", () => {
  const saltA5 = Buffer.alloc(16, 0xa5);
  // Cross-impl known-answer (same KAT pinned in kdf.rs / Python / Go).
  const kat = derivePanicIvPrefix(saltA5, 42, 1000n, 7);
  assert.equal(kat.toString("hex"), "e2615ed3e4f44375");
  assert.deepEqual(kat, derivePanicIvPrefix(saltA5, 42, 1000n, 7)); // deterministic
  // Every input affects the prefix.
  assert.notDeepEqual(kat, derivePanicIvPrefix(saltA5, 43, 1000n, 7)); // pid
  assert.notDeepEqual(kat, derivePanicIvPrefix(saltA5, 42, 1001n, 7)); // timestamp
  assert.notDeepEqual(kat, derivePanicIvPrefix(saltA5, 42, 1000n, 8)); // counter
  // Domain separation from the regular session prefix.
  assert.notDeepEqual(kat, deriveIvPrefix(saltA5, 0));
  // Security regression: a PID-recycled descendant firing its first panic at
  // counter 0 must not reuse the installer's (pid, counter=0) prefix. The
  // strictly-monotonic timestamp is the only thing keeping them apart — the
  // structural replacement for the former (unsound) PID-equality check.
  const salt5a = Buffer.alloc(16, 0x5a);
  const installer = derivePanicIvPrefix(salt5a, 4242, 1000n, 0);
  const recycled = derivePanicIvPrefix(salt5a, 4242, 9_999_000n, 0);
  assert.notDeepEqual(installer, recycled);
});

test("AEAD seal/open vectors", () => {
  for (const v of vectors.secure_frame_vectors) {
    if (v.id === "secure-shared-key-seal") {
      const wire = encodeShared(
        Buffer.from(v.key_hex!, "hex"),
        Buffer.from(v.iv_random_hex!, "hex"),
        v.iv_counter!,
        Buffer.from(v.plaintext_hex!, "hex"),
      );
      assert.equal(wire.toString("hex"), v.expected_wire_hex, v.id);
      const pt = decodeShared(Buffer.from(v.key_hex!, "hex"), wire);
      assert.equal(pt.toString("hex"), v.plaintext_hex, v.id);
    } else if (v.id === "secure-master-key-seal") {
      const wire = encodeMaster(
        Buffer.from(v.master_key_hex!, "hex"),
        v.agent_pid!,
        Buffer.from(v.iv_random_hex!, "hex"),
        v.iv_counter!,
        Buffer.from(v.plaintext_hex!, "hex"),
      );
      assert.equal(wire.toString("hex"), v.expected_wire_hex, v.id);
      const pt = decodeMaster(Buffer.from(v.master_key_hex!, "hex"), wire);
      assert.equal(pt.toString("hex"), v.plaintext_hex, v.id);
    }
  }
});
