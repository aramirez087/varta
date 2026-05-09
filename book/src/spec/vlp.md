# VLP v0.2 — Base Frame Specification

**Status:** Normative. **Wire version:** `0x02`. **Document audience:** anyone
building a Varta-compatible client, observer, packet decoder, or fuzz harness
in any language.

This document defines the on-wire layout of a Varta Lifeline Protocol (VLP)
heartbeat frame. The Rust reference implementation lives at
[`crates/varta-vlp`](https://github.com/aramirez087/Varta/tree/main/crates/varta-vlp),
but **no part of this specification depends on Rust**. A conforming
implementation in any language MUST produce and accept the byte sequences
described below.

A conformance test-vector suite is published at
[`tools/vlp-test-vectors.json`](https://github.com/aramirez087/Varta/blob/main/tools/vlp-test-vectors.json);
running an implementation against that file is the definition of conformance
(see [Conformance](./conformance.md)).

---

## 1. Conventions

The keywords **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY**
are interpreted as in RFC 2119 / RFC 8174.

* Integers are **unsigned**, **little-endian**, of the width specified in
  each field row.
* Byte offsets are zero-based and inclusive on the left.
* `||` denotes byte concatenation.
* `0x..` is hexadecimal; `0b..` is binary; ASCII byte literals appear in
  double quotes (`"VA"`).
* Capitalised type names (`Status`, `Frame`, `DecodeError`) refer to the
  conceptual entities defined in this document, not to types in any specific
  language.

### Terminology

| Term | Meaning |
|---|---|
| **Agent** | A process that emits VLP frames to declare its own liveness. |
| **Observer** | A process that receives VLP frames and tracks agent liveness. |
| **Beat** | A single 32-byte VLP frame transmitted from agent to observer. |
| **Nonce** | The monotonically-increasing 8-byte counter field at offset 16; see §3.5. |
| **Wire** | The byte sequence transmitted on the underlying transport (UDS, UDP, etc.). |

---

## 2. Frame Structure

A VLP frame is exactly **32 bytes**:

```text
offset │ size │ field      │ type   │ notes
───────┼──────┼────────────┼────────┼─────────────────────────────────────────
 0     │  2   │ magic      │ u8[2]  │ const [0x56, 0x41]  (ASCII "VA")
 2     │  1   │ version    │ u8     │ const 0x02  (this document)
 3     │  1   │ status     │ u8     │ Status enum, see §3.2
 4     │  4   │ pid        │ u32    │ LE — emitter's process id
 8     │  8   │ timestamp  │ u64    │ LE — emitter-local monotonic value
16     │  8   │ nonce      │ u64    │ LE — strictly increasing per session
24     │  4   │ payload    │ u32    │ LE — opaque application-defined context
28     │  4   │ crc32c     │ u32    │ LE — CRC-32C over bytes 0..28
───────┴──────┴────────────┴────────┴─────────────────────────────────────────
                                                              total 32 bytes
```

Senders MUST emit exactly 32 bytes per beat. Receivers MUST reject any
datagram whose length is not exactly 32 bytes (or, for secure transports,
the corresponding wrapped length defined in [VLP — Secure
Transport](./vlp-secure.md)).

---

## 3. Field Semantics

### 3.1 Magic (offset 0, 2 bytes)

The literal bytes `0x56 0x41` (ASCII `"VA"`). Senders MUST emit exactly
these two bytes. Receivers MUST reject any frame whose first two bytes
differ, with a `BadMagic` diagnostic.

### 3.2 Version (offset 2, 1 byte)

The literal byte `0x02`. Senders MUST emit `0x02`. Receivers MUST reject
any other version byte with a `BadVersion` diagnostic — including the
legacy `0x01` (VLP v0.1). Implementations MUST NOT attempt to
re-interpret a `0x01` frame; the v0.1 byte map is incompatible with
v0.2.

### 3.3 Status (offset 3, 1 byte)

A single byte enumerating the agent's last reported health:

| Value | Name | Meaning |
|---|---|---|
| `0x00` | `Ok` | The agent is healthy and making progress. |
| `0x01` | `Degraded` | The agent is making progress under elevated trouble (retrying, throttled). |
| `0x02` | `Critical` | The agent is about to terminate. Emitted by panic hooks immediately before unwinding. |
| `0x03` | `Stall` | **Observer-synthesized only — MUST NOT appear on the wire.** See §3.7. |

Receivers MUST reject any other value with a `BadStatus` diagnostic.

### 3.4 PID (offset 4, 4 bytes, u32 little-endian)

The operating-system process identifier of the emitting agent, in the
agent's own PID namespace. Senders MUST set this to the OS-reported PID
at frame-construction time, freshly per emit (caching across `fork(2)`
is a wire-protocol bug — see §3.7).

Receivers MUST reject pid values **0** (kernel/scheduler) and **1**
(init/systemd) with a `BadPid` diagnostic. No legitimate Varta agent
runs at either; the rejection closes a "spoof init has stalled"
recovery-trigger attack vector on unauthenticated transports.

### 3.5 Timestamp (offset 8, 8 bytes, u64 little-endian)

A monotonic timestamp chosen by the emitter, typically nanoseconds
since an agent-local epoch. Observers do not interpret it; they only
compare consecutive timestamps for the same `pid`.

Receivers MUST reject `timestamp == 0xFFFFFFFFFFFFFFFF` (the
saturation sentinel) with a `BadTimestamp` diagnostic. Reaching the
sentinel via real elapsed nanoseconds requires ~584 years, so the
value is reserved.

### 3.6 Nonce (offset 16, 8 bytes, u64 little-endian)

A strictly increasing 64-bit counter, starting at **1** on the first
beat after session establishment. On exhaustion at
`0xFFFFFFFFFFFFFFFE`, the counter wraps to `0` and continues. The
sentinel value `0xFFFFFFFFFFFFFFFF` (`NONCE_TERMINAL`) is reserved
for panic frames (see §3.7); regular beats MUST NOT use it.

### 3.7 Reserved Values

| Sentinel | Reserved by | Decoder behaviour |
|---|---|---|
| `status == 0x03` (`Stall`) on the wire | Observer-synthesis only | `StallOnWire` |
| `pid ∈ {0, 1}` | OS kernel and init | `BadPid` |
| `timestamp == 0xFFFFFFFFFFFFFFFF` | Saturation guard | `BadTimestamp` |
| `nonce == 0xFFFFFFFFFFFFFFFF` paired with status ≠ `Critical` | Panic-frame sentinel | `BadNonce` |

`nonce == 0xFFFFFFFFFFFFFFFF` paired with `status == Critical` is the
*unique on-wire marker* for a panic-terminated agent. Receivers MUST
accept this pairing; downstream consumers (alert rules, recovery
filters) MAY use it to distinguish panic-terminal from operational-critical
frames.

The converse — that `Critical` always implies the terminal nonce — is
**not** enforced. An agent emitting `Status::Critical` for operational
alerts (queue full, shedding load) MAY use any regular nonce value.

### 3.8 Payload (offset 24, 4 bytes, u32 little-endian)

Application-defined opaque context. The protocol carries it through
unchanged. Typical uses: queue depth, last error code, an index into
a shared ring buffer. Implementations MUST NOT interpret this field at
the protocol layer; downstream consumers define its meaning.

### 3.9 CRC-32C Trailer (offset 28, 4 bytes, u32 little-endian)

A CRC-32C (Castagnoli) checksum computed over bytes 0..28 of the
frame. Wire layout is little-endian. See §4 for the parameter list and
reference algorithm.

The CRC catches:

* Single-event-upset bit flips on non-ECC RAM (agent or observer host).
* NIC firmware corruption between RX queue and userspace.
* In-process memory corruption between encode and the transport write
  (or between transport read and decode).

For secure transports, the CRC is *defence-in-depth* against
in-process corruption on either side of the AEAD seal/open boundary;
AEAD tag failures surface as a transport-layer error
(`AuthError`/`AEAD failure`), never as `BadCrc`.

Receivers MUST verify the CRC **after** the magic and version checks
(so wrong-protocol bytes surface diagnostically as `BadMagic` /
`BadVersion`, not `BadCrc`) and **before** any field-range check (so
corruption cannot produce a "well-formed" frame with the wrong
meaning).

---

## 4. CRC-32C

VLP uses **CRC-32C (Castagnoli)** — the iSCSI/SCTP/ext4/Btrfs CRC, not the
IEEE 802.3 CRC-32. Parameters (Koopman notation `CRC-32C/iSCSI`):

| Parameter | Value |
|---|---|
| Width | 32 bits |
| Polynomial | `0x1EDC6F41` |
| Reflected polynomial | `0x82F63B78` |
| Initial value | `0xFFFFFFFF` |
| Reflect input | yes |
| Reflect output | yes |
| Output XOR | `0xFFFFFFFF` |

### 4.1 Reference vectors

| Input | CRC-32C |
|---|---|
| (empty) | `0x00000000` |
| `"a"` (single byte `0x61`) | `0xc1d04330` |
| `"123456789"` (RFC 3720 appendix B) | `0xe3069283` |
| 32 zero bytes | `0x8a9136aa` |
| 32 `0xFF` bytes | `0x62a8ab43` |

### 4.2 Byte-at-a-time algorithm

```text
compute(bytes):
    table[0..256] := build_table()
    crc := 0xFFFFFFFF
    for each byte b in bytes:
        idx := (crc XOR b) AND 0xFF
        crc := table[idx] XOR (crc >> 8)
    return crc XOR 0xFFFFFFFF

build_table():
    for i in 0..256:
        c := i
        repeat 8 times:
            if c AND 1 != 0:
                c := (c >> 1) XOR 0x82F63B78
            else:
                c := c >> 1
        table[i] := c
    return table
```

The Rust reference implementation lives at
[`crates/varta-vlp/src/crc32c.rs`](https://github.com/aramirez087/Varta/blob/main/crates/varta-vlp/src/crc32c.rs)
and is `const fn`-evaluable — the 256-entry table is built at compile time.

Hardware CRC-32C is available on x86_64 (SSE 4.2) and ARMv8.1+; conforming
implementations MAY use hardware acceleration as long as the output matches
the reference vectors above.

---

## 5. Decode Order

Receivers MUST validate fields in the following order, returning the first
encountered failure:

1. **Magic** → `BadMagic` if bytes 0..2 ≠ `0x56 0x41`.
2. **Version** → `BadVersion` if byte 2 ≠ `0x02`.
3. **CRC** → `BadCrc` if `compute(bytes[0..28]) ≠ read_u32_le(bytes[28..32])`.
4. **Status** → `BadStatus` if byte 3 ∉ `{0x00, 0x01, 0x02, 0x03}`.
5. **Stall-on-wire** → `StallOnWire` if status byte 3 = `0x03`.
6. **PID range** → `BadPid` if `pid ∈ {0, 1}`.
7. **Timestamp range** → `BadTimestamp` if `timestamp == 0xFFFFFFFFFFFFFFFF`.
8. **Nonce/status pairing** → `BadNonce` if `nonce == 0xFFFFFFFFFFFFFFFF`
   and `status ≠ Critical`.

The order is **normative**: operators rely on observing `BadMagic` versus
`BadCrc` to distinguish "wrong protocol on this port" from "real VLP but
corrupted in flight".

---

## 6. Encode Procedure

```text
encode(status, pid, timestamp, nonce, payload) -> [32]byte:
    out[0]      := 0x56            # 'V'
    out[1]      := 0x41            # 'A'
    out[2]      := 0x02            # version
    out[3]      := status_byte(status)
    out[4..8]   := u32_le(pid)
    out[8..16]  := u64_le(timestamp)
    out[16..24] := u64_le(nonce)
    out[24..28] := u32_le(payload)
    crc         := crc32c_compute(out[0..28])
    out[28..32] := u32_le(crc)
    return out
```

Senders MUST compute the CRC over the encoded bytes 0..28, after every
preceding field has been written. Mutating any byte between encode and
the transport write will cause the receiver to reject the frame as
`BadCrc`.

---

## 7. Decode Procedure

```text
decode(bytes: [32]byte) -> Frame | DecodeError:
    if bytes[0..2] != [0x56, 0x41]:
        return BadMagic
    if bytes[2] != 0x02:
        return BadVersion
    stored_crc   := u32_le(bytes[28..32])
    computed_crc := crc32c_compute(bytes[0..28])
    if stored_crc != computed_crc:
        return BadCrc(expected=computed_crc, actual=stored_crc)

    status_byte := bytes[3]
    if status_byte not in {0x00, 0x01, 0x02, 0x03}:
        return BadStatus(status_byte)
    if status_byte == 0x03:
        return StallOnWire

    pid       := u32_le(bytes[4..8])
    timestamp := u64_le(bytes[8..16])
    nonce     := u64_le(bytes[16..24])
    payload   := u32_le(bytes[24..28])

    if pid in {0, 1}:
        return BadPid(pid)
    if timestamp == 0xFFFFFFFFFFFFFFFF:
        return BadTimestamp(timestamp)
    if nonce == 0xFFFFFFFFFFFFFFFF and status_byte != 0x02:
        return BadNonce(nonce, status)

    return Frame{
        status, pid, timestamp, nonce, payload
    }
```

---

## 8. Worked Examples

### 8.1 Minimal `Ok` beat

`status = Ok`, `pid = 2`, `timestamp = 0`, `nonce = 1`, `payload = 0`:

```text
56 41 02 00 02 00 00 00 00 00 00 00 00 00 00 00
01 00 00 00 00 00 00 00 00 00 00 00 e4 11 6b aa
```

### 8.2 Panic-hook terminal frame

`status = Critical`, `pid = 2`, `timestamp = 999`, `nonce = 0xFFFF…FFFF`,
`payload = 0`:

```text
56 41 02 02 02 00 00 00 e7 03 00 00 00 00 00 00
ff ff ff ff ff ff ff ff 00 00 00 00 a2 99 ee ed
```

Additional encoded golden frames live in
[`tools/vlp-test-vectors.json`](https://github.com/aramirez087/Varta/blob/main/tools/vlp-test-vectors.json).

---

## 9. Reference Implementations

Non-normative encoders/decoders in Python, C99, and Go live under
[`tools/reference-implementations/`](https://github.com/aramirez087/Varta/tree/main/tools/reference-implementations).
Each ships a `verify_vectors` driver that loads the conformance JSON and
asserts every entry round-trips.

* **Python** — `tools/reference-implementations/python/vlp.py` (~80 lines,
  stdlib-only, Python 3.8+).
* **C99** — `tools/reference-implementations/c/vlp.c` (~120 lines,
  `<stdint.h>` + `<string.h>` only).
* **Go** — `tools/reference-implementations/go/vlp.go` (~80 lines,
  `encoding/binary` only).

These snippets are *examples*, not part of the normative spec. The
pseudocode in §6 and §7 is the authoritative reference.

---

## 10. Versioning Policy

The version byte `0x02` is the current wire format. Any change to field
order, width, or semantics requires bumping the version byte; receivers
emit `BadVersion` for unrecognised values. There is no silent backward
compatibility — a single decoder implementation can support multiple
versions only by branching on the byte at offset 2.

Future versions of this specification will increment `VERSION` and
publish a new document; the test-vector file at
`tools/vlp-test-vectors.json` carries a top-level `spec_version` field
matching the wire version.

---

## 11. Conformance

Run the test-vector suite against your implementation:

1. Load `tools/vlp-test-vectors.json`.
2. For each entry in `crc32c_vectors`, run your CRC over `input_hex` (after
   hex decoding) and compare against `expected_crc_hex`.
3. For each `encode_decode_roundtrip` entry in `frame_vectors`, encode the
   `inputs` block and compare byte-for-byte against `expected_wire_hex`.
   Then decode `expected_wire_hex` and compare the recovered fields against
   `inputs`.
4. For each `decode_error` entry in `frame_vectors`, decode `wire_hex` and
   confirm the decoder returns `expected_decode_error`.

See [Conformance & Test Vectors](./conformance.md) for the full JSON schema
and language-by-language driver recipes.

---

## See also

* [VLP — Secure Transport](./vlp-secure.md) — AEAD-wrapped frame for
  untrusted networks.
* [Conformance & Test Vectors](./conformance.md) — JSON schema for the
  test-vector file.
* [Rust implementation rationale](../architecture/vlp-frame.md) — design
  choices in the reference implementation (`#[repr(C, align(8))]`,
  zero-allocation policy, compile-time layout proofs). Not normative.
