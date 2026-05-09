# Conformance & Test Vectors

This document describes the cross-language conformance contract for the
Varta Lifeline Protocol. An implementation in any language is **conformant**
if and only if it agrees with the published test-vector suite at
[`tools/vlp-test-vectors.json`](https://github.com/aramirez087/Varta/blob/main/tools/vlp-test-vectors.json).

The Rust reference implementation regenerates this file via:

```sh
cargo run -p varta-vlp --example gen_test_vectors --features "std crypto"
```

and asserts byte-equality on every entry via the integration test
`crates/varta-vlp/tests/conformance_vectors.rs`. The file is the **source of
truth**; if it drifts from the Rust implementation, the test fails before
CI passes.

---

## 1. JSON Schema

The top-level document is an object with these fields:

```json
{
  "spec_version": "0.2",
  "description": "...",
  "magic_hex": "5641",
  "version_byte": 2,
  "nonce_terminal_hex": "ffffffffffffffff",
  "crc32c_vectors": [ ... ],
  "frame_vectors":  [ ... ],
  "secure_frame_vectors": [ ... ]
}
```

### 1.1 `crc32c_vectors` (array)

Reference CRC-32C (Castagnoli) inputs and outputs. Each entry:

```json
{
  "id": "crc-rfc3720",
  "description": "RFC 3720 appendix B reference vector.",
  "input_hex": "313233343536373839",
  "expected_crc_hex": "e3069283"
}
```

* `input_hex` — the input byte string, lowercase hex.
* `expected_crc_hex` — the 4-byte CRC, lowercase hex, **big-endian** in the
  hex string (the leftmost hex pair is the most-significant CRC byte). On
  the wire, the CRC is little-endian; the JSON file presents the numeric
  value directly for readability.

### 1.2 `frame_vectors` (array)

Base-frame encode/decode goldens. Two `kind` values are defined.

**Kind `encode_decode_roundtrip`:**

```json
{
  "id": "frame-ok-minimal",
  "description": "Minimum legal frame.",
  "kind": "encode_decode_roundtrip",
  "expected_decode_error": null,
  "inputs": {
    "status": "ok",
    "pid": 2,
    "timestamp": 0,
    "nonce": 1,
    "payload": 0
  },
  "expected_wire_hex": "56410200020000000000000000000000010000000000000000000000e4116baa"
}
```

* `status` is one of `"ok"`, `"degraded"`, `"critical"`. (`"stall"` never
  appears as an input — `Status::Stall` is observer-synthesized only.)
* All numeric fields are unsigned decimal integers; widths match the
  base-frame spec (pid: u32, timestamp: u64, nonce: u64, payload: u32).
* `expected_wire_hex` is the canonical 32-byte wire frame, lowercase hex
  (64 characters).

A conformant implementation MUST:

1. Encode `inputs` and produce a byte sequence equal to `expected_wire_hex`.
2. Decode `expected_wire_hex` and recover fields equal to `inputs`.

**Kind `decode_error`:**

```json
{
  "id": "frame-error-bad-magic",
  "description": "First byte 0x00 instead of 'V'.",
  "kind": "decode_error",
  "expected_decode_error": "BadMagic",
  "wire_hex": "00410200020000006400000000000000010000000000000000000000421795be"
}
```

* `wire_hex` — 32 bytes lowercase hex.
* `expected_decode_error` — one of `BadMagic`, `BadVersion`, `BadCrc`,
  `BadStatus`, `StallOnWire`, `BadPid`, `BadTimestamp`, `BadNonce`.

A conformant implementation MUST decode `wire_hex` and surface the named
error variant.

### 1.3 `secure_frame_vectors` (array)

Secure-transport encode/decode + key-derivation goldens. Five `kind`
values are defined.

**Kind `shared_key_seal`:**

```json
{
  "id": "secure-shared-key-seal",
  "description": "Shared-key 60-byte secure frame.",
  "kind": "shared_key_seal",
  "key_hex": "0001020304…1f",
  "iv_random_hex": "1122334455667788",
  "iv_counter": 0,
  "plaintext_hex": "5641020002000000…1c",
  "expected_wire_hex": "11223344…975a"
}
```

A conformant implementation MUST:

1. Construct nonce = `iv_random || iv_counter_LE`.
2. AEAD-seal `plaintext_hex` under `key_hex` with empty AAD.
3. Concatenate `iv_random || iv_counter_LE || ciphertext || tag` and
   match `expected_wire_hex` exactly (60 bytes / 120 hex chars).

**Kind `master_key_seal`:**

```json
{
  "id": "secure-master-key-seal",
  "kind": "master_key_seal",
  "master_key_hex": "0001…1f",
  "agent_pid": 2,
  "derived_agent_key_hex": "db29…afd5",
  "iv_random_hex": "1122334455667788",
  "iv_counter": 0,
  "plaintext_hex": "...",
  "expected_wire_hex": "..."
}
```

Steps: derive `agent_key = HKDF-SHA256(master, info="varta-agent-v1\0" ||
agent_pid_LE)`; the derived key MUST match `derived_agent_key_hex`. Then
seal under `agent_key` with AAD = `agent_pid_LE` and assemble the 64-byte
wire frame.

**Kinds `kdf_agent_key`, `kdf_iv_prefix`, `kdf_epoch_key`:** HKDF goldens.
Each carries the input material, the assembled info string (as
`info_hex`), and the expected output. See
[VLP — Secure Transport §6](./vlp-secure.md#6-hkdf-key-derivation) for the
exact derivation procedure.

---

## 2. Running the Suite

### 2.1 Python (stdlib only)

```python
import json, sys
import vlp  # your implementation

vectors = json.load(open("tools/vlp-test-vectors.json"))

for v in vectors["crc32c_vectors"]:
    got = vlp.crc32c(bytes.fromhex(v["input_hex"]))
    want = int(v["expected_crc_hex"], 16)
    assert got == want, f"{v['id']}: {got:08x} != {want:08x}"

for v in vectors["frame_vectors"]:
    if v["kind"] == "encode_decode_roundtrip":
        i = v["inputs"]
        wire = vlp.encode(i["status"], i["pid"], i["timestamp"],
                          i["nonce"], i["payload"])
        assert wire.hex() == v["expected_wire_hex"], v["id"]
    elif v["kind"] == "decode_error":
        try:
            vlp.decode(bytes.fromhex(v["wire_hex"]))
            assert False, f"{v['id']}: expected error"
        except vlp.DecodeError as e:
            assert e.kind == v["expected_decode_error"], v["id"]
```

A full runner is at
[`tools/reference-implementations/python/verify_vectors.py`](https://github.com/aramirez087/Varta/blob/main/tools/reference-implementations/python/verify_vectors.py).

### 2.2 Go (stdlib only)

```go
import (
    "encoding/hex"
    "encoding/json"
    "os"
)

type Doc struct {
    Crc32cVectors []struct {
        ID, InputHex, ExpectedCRCHex string
    } `json:"crc32c_vectors"`
    // ...
}

doc := Doc{}
buf, _ := os.ReadFile("tools/vlp-test-vectors.json")
json.Unmarshal(buf, &doc)
for _, v := range doc.Crc32cVectors {
    input, _ := hex.DecodeString(v.InputHex)
    got := vlp.CRC32C(input)
    want, _ := strconv.ParseUint(v.ExpectedCRCHex, 16, 32)
    if uint64(got) != want { /* fail */ }
}
```

Full runner: [`tools/reference-implementations/go/verify_vectors.go`](https://github.com/aramirez087/Varta/blob/main/tools/reference-implementations/go/verify_vectors.go).

### 2.3 C99 (libsodium or hand-rolled)

The C reference at
[`tools/reference-implementations/c/`](https://github.com/aramirez087/Varta/tree/main/tools/reference-implementations/c)
uses a minimal hand-rolled JSON tokenizer and libsodium for AEAD. Run:

```sh
cd tools/reference-implementations/c
make verify
./verify_vectors ../../vlp-test-vectors.json
```

### 2.4 Shell quick-spot via `jq`

```sh
# Spot-check one CRC vector:
jq -r '.crc32c_vectors[] | select(.id=="crc-rfc3720") | .input_hex' \
   tools/vlp-test-vectors.json \
| xxd -r -p \
| your-crc-tool
```

---

## 3. Canonical Vectors (Inline)

For readers who want to confirm the spec without fetching the JSON, the
canonical vectors are reproduced here.

### 3.1 CRC-32C

| id | input (hex) | CRC-32C |
|---|---|---|
| `crc-empty` | (empty) | `00000000` |
| `crc-single-a` | `61` | `c1d04330` |
| `crc-rfc3720` | `313233343536373839` | `e3069283` |
| `crc-thirty-two-zeros` | 32 × `00` | `8a9136aa` |
| `crc-thirty-two-ffs` | 32 × `ff` | `62a8ab43` |

### 3.2 Base frames — encode/decode round-trips

| id | status | pid | ts | nonce | payload | wire (32 B hex) |
|---|---|---|---|---|---|---|
| `frame-ok-minimal` | ok | 2 | 0 | 1 | 0 | `56410200020000000000000000000000010000000000000000000000e4116baa` |
| `frame-degraded-typical` | degraded | 12345 | 1234567890 | 100 | 3735928559 | `5641020139300000d2029649000000006400000000000000efbeadde7bbc775f` |
| `frame-critical-operational` | critical | 99 | 10000 | 5 | 42 | `5641020263000000102700000000000005000000000000002a00000037ecf63f` |
| `frame-critical-terminal` | critical | 2 | 999 | 18446744073709551615 | 0 | `5641020202000000e703000000000000ffffffffffffffff00000000a299eeed` |
| `frame-ok-large-fields` | ok | 3735928559 | 81985529216486895 | 1 | 66 | `56410200efbeaddeefcdab896745230101000000000000004200000000b228b8` |
| `frame-ok-nonce-wrapped-to-zero` | ok | 2 | 1 | 0 | 0 | `56410200020000000100000000000000000000000000000000000000693259ac` |

### 3.3 Base frames — decode errors

| id | wire (32 B hex) | error |
|---|---|---|
| `frame-error-bad-magic` | `00410200…421795be` | `BadMagic` |
| `frame-error-bad-version` | `56410100…7a774318` | `BadVersion` |
| `frame-error-bad-crc` | `56410200…6bfbb06f` | `BadCrc` |
| `frame-error-bad-status` | `564102ff…9a03661d` | `BadStatus` |
| `frame-error-stall-on-wire` | `56410203…cca7ed1c` | `StallOnWire` |
| `frame-error-bad-pid-zero` | `56410200 00000000 …8608c31f` | `BadPid` |
| `frame-error-bad-pid-init` | `56410200 01000000 …08ca8ca5` | `BadPid` |
| `frame-error-bad-timestamp` | `56410200 02000000 ffffffffffffffff…30ddde54` | `BadTimestamp` |
| `frame-error-bad-nonce-…` | `56410200 02000000 64000000 00000000 ffffffffffffffff 00000000 8c2889f8` | `BadNonce` |

(Full wire bytes for the truncated rows live in the JSON file.)

### 3.4 Secure-frame goldens — summary

Full bytes live in
[`tools/vlp-test-vectors.json`](https://github.com/aramirez087/Varta/blob/main/tools/vlp-test-vectors.json);
the structural summary:

| id | kind | sizes |
|---|---|---|
| `secure-shared-key-seal` | shared-key seal | 60 B wire |
| `secure-master-key-seal` | master-key seal | 64 B wire (with 32 B derived agent key) |
| `kdf-agent-key` | HKDF (`varta-agent-v1`) | 32 B OKM |
| `kdf-iv-prefix` | HKDF (`varta-iv-prefix-v1`) | 8 B OKM |
| `kdf-epoch-key` | HKDF (`varta-epoch-v1`) | 32 B OKM |

The HKDF goldens published in
[VLP — Secure Transport §6.4](./vlp-secure.md#64-reference-vectors) are
sufficient to confirm an implementation's HKDF info-string assembly is
byte-correct.

---

## 4. What "Conformant" Means

An implementation is **conformant** if and only if:

1. It encodes every `frame_vectors[].inputs` to bytes equal to
   `expected_wire_hex`.
2. It decodes every `expected_wire_hex` back to fields equal to the
   corresponding `inputs`.
3. It rejects every `decode_error` entry with the named error variant.
4. For implementations that include secure transport: it reproduces every
   `secure_frame_vectors[]` byte-for-byte, including the HKDF derivations.

There is no partial conformance — `BadMagic` returned where `BadCrc` was
expected is a non-conforming bug, even if the frame is correctly
rejected.

---

## 5. Re-generating the file

The JSON file is checked into the repository so that:

* External implementers can clone the repo and run their conformance
  suite without any Rust toolchain.
* CI catches accidental wire-format drift via
  `cargo test -p varta-vlp --features "std crypto" --test conformance_vectors`.

The generator that emits the file is
[`crates/varta-vlp/examples/gen_test_vectors.rs`](https://github.com/aramirez087/Varta/blob/main/crates/varta-vlp/examples/gen_test_vectors.rs).
After any change to `Frame::encode`, the CRC table, the AEAD parameters,
or the HKDF info strings, regenerate the file:

```sh
cargo run -p varta-vlp --example gen_test_vectors --features "std crypto"
cargo test -p varta-vlp --features "std crypto" --test conformance_vectors
```

and commit the resulting JSON alongside the source change.

---

## See also

* [VLP — Base Frame](./vlp.md)
* [VLP — Secure Transport](./vlp-secure.md)
