# VLP Secure Transport Specification

**Status:** Normative. **Frame versions:** Shared-key 60-byte, Master-key
64-byte. **Document audience:** anyone implementing a Varta-compatible client
or observer that crosses an untrusted network.

This document defines the encrypted wrapping of a VLP base frame (see
[VLP — Base Frame](./vlp.md)) for transmission over a network where the
underlying transport offers no authentication or confidentiality (the
typical example is UDP).

The base 32-byte VLP frame remains the plaintext; the secure transport
wraps it in a ChaCha20-Poly1305 AEAD construction (RFC 8439). Two wrapped
forms are defined:

* **Shared-key** (60 bytes) — a single pre-shared symmetric key is used by
  every agent.
* **Master-key** (64 bytes) — every agent has a key derived from a single
  master via HKDF-SHA256; the agent's PID is bound into the AEAD AAD.

---

## 1. Conventions

The keywords **MUST**, **MUST NOT**, **SHOULD**, **MAY** follow RFC 2119 /
RFC 8174. The base-frame conventions in [VLP — Base Frame §1](./vlp.md#1-conventions)
apply unchanged.

In addition:

* `Plaintext` always refers to the canonical 32-byte VLP frame defined in
  [VLP — Base Frame §2](./vlp.md#2-frame-structure).
* `Ciphertext` is the AEAD-encrypted form of `Plaintext`, always 32 bytes.
* `Tag` is the 16-byte Poly1305 authentication tag.
* `Nonce` (in this document) refers to the 12-byte AEAD nonce, distinct
  from the 8-byte `nonce` *field* inside the plaintext base frame.

---

## 2. AEAD Primitive

All secure transports use **ChaCha20-Poly1305 AEAD** as defined in
[RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).

| Parameter | Value |
|---|---|
| Symmetric key | 32 bytes (256 bits) |
| AEAD nonce | 12 bytes (96 bits) |
| AAD | variable (see §3, §4) |
| Plaintext | 32 bytes (one VLP base frame) |
| Ciphertext | 32 bytes |
| Tag | 16 bytes (128 bits) |

Implementations SHOULD use an externally-audited AEAD library
(libsodium, BoringSSL, `golang.org/x/crypto/chacha20poly1305`, RustCrypto
`chacha20poly1305`). Hand-rolled implementations of ChaCha20 or Poly1305
are strongly discouraged for production use.

The AEAD `seal` and `open` operations:

```text
seal(key[32], nonce[12], aad[], plaintext[32]) -> (ciphertext[32], tag[16])
open(key[32], nonce[12], aad[], ciphertext[32], tag[16])
  -> Some(plaintext[32]) if tag verifies, else None
```

Senders MUST never reuse a `(key, nonce)` pair. Nonce-reuse under a fixed
key catastrophically breaks both confidentiality and integrity
(Poly1305 key recovery, plaintext-XOR leak). The nonce-construction rules
in §5 prevent reuse for conforming implementations.

---

## 3. Shared-Key Wire Format (60 bytes)

A single 32-byte symmetric key `K` is provisioned out-of-band to every
agent and observer. The wire frame is:

```text
offset │ size │ field        │ notes
───────┼──────┼──────────────┼────────────────────────────────────────────
 0     │  8   │ iv_random    │ per-session OS entropy or HKDF derivation
 8     │  4   │ iv_counter   │ u32 LE — strictly increasing per emit
12     │ 32   │ ciphertext   │ AEAD(K, nonce, "", plaintext)
44     │ 16   │ tag          │ Poly1305 tag
───────┴──────┴──────────────┴────────────────────────────────────────────
                                                              total 60 bytes
```

* **AEAD nonce** = `iv_random || iv_counter` (12 bytes total).
* **AAD** = empty byte string.
* **Plaintext** = the 32-byte VLP base frame.

### 3.1 Encoder

```text
encode_shared(key[32], iv_random[8], iv_counter: u32,
              plaintext[32]) -> [60]byte:
    nonce[0..8]  := iv_random
    nonce[8..12] := u32_le(iv_counter)
    (ct, tag) := seal(key, nonce, b"", plaintext)
    out[0..8]   := iv_random
    out[8..12]  := u32_le(iv_counter)
    out[12..44] := ct
    out[44..60] := tag
    return out
```

### 3.2 Decoder

```text
decode_shared(key[32], wire[60]) -> Plaintext | AuthError:
    iv_random  := wire[0..8]
    iv_counter := u32_le(wire[8..12])
    ct         := wire[12..44]
    tag        := wire[44..60]
    nonce[0..8]  := iv_random
    nonce[8..12] := u32_le(iv_counter)
    plaintext := open(key, nonce, b"", ct, tag)
    if plaintext is None:
        return AuthError
    return plaintext  # caller MUST then run base-frame decode (§7 of VLP)
```

Observers MUST run the base-frame decoder ([VLP — Base Frame §7](./vlp.md#7-decode-procedure))
on the recovered plaintext before trusting any field.

---

## 4. Master-Key Wire Format (64 bytes)

A single 32-byte master key `M` is provisioned out-of-band. Every agent
derives a per-agent key `K_agent = HKDF(M, agent_pid)` (see §6). The
agent's PID is bound into the AEAD AAD so an observer cannot accept a
frame whose plaintext PID disagrees with the wire prefix.

```text
offset │ size │ field        │ notes
───────┼──────┼──────────────┼────────────────────────────────────────────
 0     │  4   │ agent_pid    │ u32 LE — bound into AAD, NOT encrypted
 4     │  8   │ iv_random    │ per-session OS entropy or HKDF derivation
12     │  4   │ iv_counter   │ u32 LE — strictly increasing per emit
16     │ 32   │ ciphertext   │ AEAD(K_agent, nonce, agent_pid_bytes, pt)
48     │ 16   │ tag          │ Poly1305 tag
───────┴──────┴──────────────┴────────────────────────────────────────────
                                                              total 64 bytes
```

* **AEAD nonce** = `iv_random || iv_counter` (12 bytes).
* **AAD** = the 4-byte little-endian encoding of `agent_pid` (bytes 0..4
  of the wire frame, **verbatim**).
* **Plaintext** = the 32-byte VLP base frame.
* **K_agent** = `HKDF-SHA256(IKM=M, salt=empty, info="varta-agent-v1\0" || agent_pid_LE)`.

The plaintext frame still carries its own `pid` field at base-frame
offset 4..8. Observers MUST verify that `agent_pid` (wire offset 0..4)
equals the recovered plaintext `pid` and reject mismatches.

### 4.1 Encoder

```text
encode_master(master[32], agent_pid: u32, iv_random[8], iv_counter: u32,
              plaintext[32]) -> [64]byte:
    K_agent := derive_agent_key(master, agent_pid)
    aad := u32_le(agent_pid)
    nonce[0..8]  := iv_random
    nonce[8..12] := u32_le(iv_counter)
    (ct, tag) := seal(K_agent, nonce, aad, plaintext)
    out[0..4]   := aad
    out[4..12]  := iv_random
    out[12..16] := u32_le(iv_counter)
    out[16..48] := ct
    out[48..64] := tag
    return out
```

### 4.2 Decoder

```text
decode_master(master[32], wire[64]) -> Plaintext | AuthError:
    aad        := wire[0..4]               # agent_pid LE
    agent_pid  := u32_le(aad)
    iv_random  := wire[4..12]
    iv_counter := u32_le(wire[12..16])
    ct         := wire[16..48]
    tag        := wire[48..64]
    K_agent    := derive_agent_key(master, agent_pid)
    nonce[0..8]  := iv_random
    nonce[8..12] := u32_le(iv_counter)
    plaintext := open(K_agent, nonce, aad, ct, tag)
    if plaintext is None:
        return AuthError
    # Observer MUST also confirm plaintext.pid == agent_pid.
    return plaintext
```

---

## 5. Nonce Construction & Uniqueness

The AEAD nonce is the 12-byte concatenation `iv_random || iv_counter`.

* `iv_random` (8 bytes) MUST be drawn from cryptographic OS entropy at
  session start, **or** derived from a 16-byte session salt via the
  IV-prefix HKDF in §6.
* `iv_counter` (4 bytes, little-endian) MUST start at `0` for a new
  session and strictly increase by 1 per emit.
* The pair `(iv_random, iv_counter)` MUST NEVER be reused under the
  same key.

### 5.1 Counter exhaustion

A 32-bit `iv_counter` exhausts after 2^32 emits per session. Senders
MUST rotate `iv_random` (and reset `iv_counter` to `0`) before the
counter wraps. Implementations MAY rotate proactively at any threshold;
the canonical Rust transport rotates well under 2^32.

### 5.2 fork(2)

A child process inherits its parent's `iv_random` and `iv_counter`
after `fork(2)`. If the child emits without first refreshing the IV,
both processes will use the same `(iv_random, iv_counter)` under the
same key — catastrophic nonce reuse. Senders MUST detect fork (e.g. by
comparing the cached PID at session establishment against the current
PID at emit time) and either:

1. Re-read `iv_random` from OS entropy and reset `iv_counter = 0`, **or**
2. Refuse to emit until the application explicitly re-establishes the
   session.

The Rust reference implementation auto-detects fork and rotates IV
state transparently; see
[`book/src/architecture/vlp-transports.md` — "Fork-safety on secure-UDP"](../architecture/vlp-transports.md#fork-safety-on-secure-udp)
for the operational model.

---

## 6. HKDF Key Derivation

The master-key mode (and the IV-prefix rotation mode for both wire
formats) uses **HKDF-SHA256** as defined in
[RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869). Three info
strings are reserved, all suffixed with `-v1` for future versioning:

### 6.1 Per-agent key derivation

```text
derive_agent_key(master_key[32], agent_id: u32) -> [32]byte:
    info := b"varta-agent-v1\0" || u32_le(agent_id)
    # info length = 15 (the literal incl. NUL) + 4 = 19 bytes.
    return HKDF-SHA256(IKM=master_key, salt=empty, info=info, L=32)
```

* `IKM` = master key (32 B).
* `salt` = empty string (HKDF treats this as `0x00 * HashLen` per RFC 5869 §2.2).
* `info` = the byte string `"varta-agent-v1"` (14 ASCII bytes) followed by
  one NUL byte (`0x00`), followed by `agent_id` in 4-byte little-endian
  encoding. Total info length: 19 bytes.
* `L` = 32 output bytes.

### 6.2 Per-session IV prefix derivation

```text
derive_iv_prefix(session_salt[16], prefix_index: u32) -> [8]byte:
    info := b"varta-iv-prefix-v1\0" || u32_le(prefix_index)
    # info length = 19 + 4 = 23 bytes.
    return HKDF-SHA256(IKM=session_salt, salt=empty, info=info, L=8)
```

The session salt is the IKM; the HKDF-Extract `salt` argument is empty
(RFC 5869 §2.2 treats empty salt as `0x00 * HashLen`).

The Rust reference uses this to rotate `iv_random` over a session
without re-reading OS entropy on the hot path.

### 6.3 Per-epoch key derivation (reserved)

```text
derive_epoch_key(agent_key[32], epoch: u64) -> [32]byte:
    info := b"varta-epoch-v1\0" || u64_le(epoch)
    # info length = 15 + 8 = 23 bytes.
    return HKDF-SHA256(IKM=agent_key, salt=empty, info=info, L=32)
```

Epoch keys are **reserved for forward compatibility** — they are not
currently used on the wire. Conforming implementations MAY skip this
derivation.

### 6.4 Reference vectors

| Derivation | Inputs | Output |
|---|---|---|
| Agent key | master = `0001…1f`, agent_id = `42` | `61f5951b2bf1905d5053df0abb027002cba62da1f16d93c6552ff61cb65f2599` |
| IV prefix | salt = `0102…10`, prefix_index = `7` | `9fee777f36be69ce` |
| Epoch key | agent = `0001…1f`, epoch = `100` | `cb9fe8cb3db0d8d667b7dd9e72adce07c669d3b27bc68ea69e3cc3c129d601ab` |

Full `info` byte strings (so external implementers can confirm endianness
and the literal NUL):

| Derivation | info (hex) |
|---|---|
| Agent (agent_id=42) | `76617274612d6167656e742d7631002a000000` |
| IV prefix (prefix_index=7) | `76617274612d69762d7072656669782d76310007000000` |
| Epoch (epoch=100) | `76617274612d65706f63682d7631006400000000000000` |

---

## 7. Replay Protection

Observers MUST maintain per-sender state to reject replayed frames.

### 7.1 Shared-key mode

Per `(source_address, iv_random)` pair: track `last_seen_counter`.
Accept a new frame only if `iv_counter > last_seen_counter`; reject equal
or lesser counters.

### 7.2 Master-key mode

Per `(source_address, agent_pid, iv_random)` triple: same monotonicity
rule.

### 7.3 Bounded state

A real observer cannot retain unbounded per-sender state. The Rust
reference implementation bounds per-sender records to 1024 simultaneous
senders with a single-slot eviction shadow; see
[`book/src/architecture/vlp-transports.md` — "Secure UDP — replay-shadow
threat boundary (H4)"](../architecture/vlp-transports.md#secure-udp--replay-shadow-threat-boundary-h4)
for the precise eviction rule and the threat-model implication
(loopback-default binding when secure-UDP is configured).

---

## 8. Worked Example — Shared-Key Seal

* Key: `0001020304050607 0809 0a0b0c0d0e0f 1011 1213 1415 1617 1819 1a1b 1c1d 1e1f` (32 bytes)
* `iv_random`: `1122334455667788`
* `iv_counter`: `0`
* Plaintext (a base VLP frame, `Status::Ok` `pid=2` `ts=1000` `nonce=1`
  `payload=0`):
  `5641020002000000e80300000000000001000000000000000000000055d0861c`

Resulting 60-byte wire frame:

```text
1122334455667788 00000000
bcba1b202190b688a08e0a7ac909da44a2023cb7a421fd6428453fd12141c257
b6fd638c55fddf5c621020de1327975a
```

---

## 9. Worked Example — Master-Key Seal

* Master key: `0001020304…1f` (same as above, 32 bytes)
* `agent_pid`: `2` (`0x02000000` LE)
* Derived agent key: `db292f5843a0737aec785a9df270561b343d06e5fe8f89fce72f0869ba77afd5`
* `iv_random`: `1122334455667788`
* `iv_counter`: `0`
* Plaintext: same as §8.

Resulting 64-byte wire frame:

```text
02000000
1122334455667788 00000000
efe8fd8c226106641e01fc8fe649f79475e19b4f2093e063987f1c663a5d2f0b
73ba429fadc4c494e2723baff86af9cc
```

---

## 10. Stability

| Element | Stable? | Bump procedure |
|---|---|---|
| Shared-key wire layout (60 B) | Stable | Spec-version bump |
| Master-key wire layout (64 B) | Stable | Spec-version bump |
| HKDF info string `varta-agent-v1` | Versioned | Replace `-v1` suffix; all agents must re-key |
| HKDF info string `varta-iv-prefix-v1` | Versioned | Same |
| HKDF info string `varta-epoch-v1` | Versioned | Same |
| AEAD primitive (ChaCha20-Poly1305) | Stable | Spec-version bump |

Implementations MUST NOT silently accept an unknown info-string version;
any change to a derivation requires explicit re-keying across the
deployment.

---

## 11. Reference Implementation

The Rust reference lives in
[`crates/varta-vlp/src/crypto`](https://github.com/aramirez087/Varta/tree/main/crates/varta-vlp/src/crypto).
The `seal`/`open` operations delegate to the RustCrypto
`chacha20poly1305` crate (NCC Group audit 2020); the HKDF derivations use
the RustCrypto `hkdf` + `sha2` crates. No hand-rolled ChaCha20, Poly1305,
or KDF logic exists in the workspace.

Cross-language references (Python `cryptography`, C libsodium, Go
`golang.org/x/crypto/chacha20poly1305`) live in
[`tools/reference-implementations/`](https://github.com/aramirez087/Varta/tree/main/tools/reference-implementations).

---

## 12. Conformance

Run the test-vector suite against your implementation. The
`secure_frame_vectors` array in
[`tools/vlp-test-vectors.json`](https://github.com/aramirez087/Varta/blob/main/tools/vlp-test-vectors.json)
contains:

* `shared_key_seal` — encode a 60-byte wire frame; compare to `expected_wire_hex`.
* `master_key_seal` — derive the agent key, encode a 64-byte wire frame;
  compare both the derived key and the wire bytes to the goldens.
* `kdf_agent_key`, `kdf_iv_prefix`, `kdf_epoch_key` — drive each HKDF
  derivation and compare to the published OKM.

See [Conformance & Test Vectors](./conformance.md) for the JSON schema
and end-to-end recipe.

---

## See also

* [VLP — Base Frame](./vlp.md) — the 32-byte plaintext layout this
  document wraps.
* [Conformance & Test Vectors](./conformance.md) — JSON schema.
* [Rust transport rationale](../architecture/vlp-transports.md) — design
  trade-offs in the reference implementation (loopback default, replay
  shadow, fork-safety auto-recovery). Not normative.
