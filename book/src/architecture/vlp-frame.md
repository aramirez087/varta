# VLP Frame — Wire Layout (v0.2)

> **Audience: Rust contributors.** This page documents the *Rust
> implementation* of the Varta Lifeline Protocol — design rationale,
> type-system choices, performance characteristics. If you are building a
> client in another language, start at the
> [normative VLP specification](../spec/vlp.md) — it is language-neutral
> and carries a published conformance-vector suite.

The Varta Lifeline Protocol carries a single message type: a 32-byte
fixed-layout health frame. Every byte position is pinned at the protocol level
so encode/decode is a handful of `from_le_bytes` / `to_le_bytes` calls and a
single CRC-32C pass — nothing else.

## Byte map

```
offset │ size │ field      │ notes
───────┼──────┼────────────┼──────────────────────────────────────────────
 0     │  2   │ magic      │ const [0x56, 0x41]  (ASCII "VA")
 2     │  1   │ version    │ const 0x02         (v0.1 → BadVersion)
 3     │  1   │ status     │ Status::{Ok=0, Degraded=1, Critical=2, Stall=3}
 4     │  4   │ pid        │ u32 little-endian — emitter's process id
 8     │  8   │ timestamp  │ u64 little-endian — emitter-local monotonic
16     │  8   │ nonce      │ u64 little-endian — strictly increasing
24     │  4   │ payload    │ u32 little-endian — opaque app context (v0.2)
28     │  4   │ crc32c     │ u32 LE CRC-32C over bytes 0..28        (v0.2)
───────┴──────┴────────────┴──────────────────────────────────────────────
                                                              total 32 bytes
```

## Nonce semantics

The 8-byte `nonce` field at offset 16 carries two distinct kinds of value:

* **Regular beats** from `varta_client::Varta::beat` use a per-connection
  counter that starts at **1** on the first beat after `Varta::connect` and
  increments monotonically. On exhaustion the counter wraps at
  `NONCE_TERMINAL - 1 → 0` — so the regular-beat stream cycles through
  `1, 2, 3, …, u64::MAX - 1, 0, 1, 2, …` and **structurally never emits
  `NONCE_TERMINAL`** (== `u64::MAX`).
* **Panic frames** from `varta_client::panic::install*` hooks pin the nonce
  to `NONCE_TERMINAL` and the status to `Status::Critical`. This is the
  unique on-wire marker for a panic-terminated agent.

`Frame::decode` enforces the wire-side invariant
`nonce == NONCE_TERMINAL ⇒ status == Status::Critical`; any other status
paired with the sentinel is rejected as `DecodeError::BadNonce`. The
[Kani harness] in `crates/varta-vlp/src/proofs.rs` proves this for every
decodable byte pattern.

The converse — `Status::Critical ⇒ nonce == NONCE_TERMINAL` — is **not**
enforced. Agents legitimately emit `Status::Critical` at regular nonce
values for operational alerts (queue full, shedding load, etc.).
Downstream consumers (alert rules, log dashboards, recovery filters) that
need to distinguish "panic terminal" from "operational critical" must
inspect **both** `status` and `nonce`:

| `status` | `nonce` | meaning |
|----------|---------|---------|
| `Critical` | `NONCE_TERMINAL` | panic-hook terminal frame |
| `Critical` | any other value (including `0` after wrap) | operational critical alert |
| `Ok` / `Degraded` | any value `≠ NONCE_TERMINAL` | normal beat |
| any | `NONCE_TERMINAL` with status `≠ Critical` | rejected at decode (`BadNonce`) |

Wrap to `0` is rare in practice (an agent emitting one beat per millisecond
takes ~584 million years to consume `u64::MAX - 1`), but it is structurally
correct and observable: an agent that does wrap will continue emitting
without observer ambiguity, because nonce `0` paired with `Critical` is
classified as "operational critical," not "panic." The Kani harness covers
the wire boundary; the wrap arithmetic itself lives in `varta-client` and
is straight-line code in `Varta::beat`.

[Kani harness]: ./verification.md

## v0.2 wire integrity (CRC-32C)

Bytes 28..32 carry a CRC-32C (Castagnoli, polynomial `0x1EDC6F41`,
init `0xFFFFFFFF`, reflected, output-XOR `0xFFFFFFFF`) computed over
bytes 0..28. The CRC catches:

* Non-ECC RAM bit flips and cosmic-ray single-event upsets on the agent
  or the observer host.
* NIC firmware corruption between RX queue and userspace.
* In-process memory corruption between `Frame::encode` and the
  transport write (or between the transport read and `Frame::decode`),
  including the gap between `crypto::seal` / `crypto::open` and the
  frame-level codec on the secure-UDP transport. AEAD tag failures
  surface separately as `crypto::AuthError`; the CRC is the
  defence-in-depth catch for everything that AEAD does not (in-process
  corruption on either side of the seal/open boundary).

Decode order is fixed: `magic → version → CRC → status → pid → timestamp →
nonce`. CRC verification sits between version and field-range checks so
random bytes from a wrong-protocol sender still surface as `BadMagic` /
`BadVersion` (preserving the "this isn't even VLP" diagnostic) while a
single-bit-flipped status byte surfaces as `BadCrc`, never as a valid
frame with the wrong meaning.

Implementation: `crates/varta-vlp/src/crc32c.rs` carries a const-fn 256-entry
lookup table; per-frame cost is ~28 cycles (~9 ns on Apple Silicon). Hardware
CRC-32C is available on x86_64 (SSE 4.2) and ARMv8.1+ via `core::arch`
intrinsics; a future `target_feature` cfg can drop the cost to ~1 cycle
without changing the wire format.

The payload field shrank from `u64` (v0.1) to `u32` (v0.2) to make room
for the CRC trailer inside the 32-byte budget. Agents needing more than
4 bytes of context should externalize the data and reference it from the
payload (e.g. as a slot index into a shared ring buffer).

The two compile-time assertions in `crates/varta-vlp/src/lib.rs` lock this in:

```rust
const _: () = assert!(core::mem::size_of::<Frame>() == 32);
const _: () = assert!(core::mem::align_of::<Frame>() == 8);
```

A drift in field order, padding, or width breaks the build. The integration
test `frame_round_trip_matches_golden_bytes` cross-checks a hand-computed
golden byte array against `Frame::encode`, so the layout is also pinned at
runtime.

## Why `#[repr(C, align(8))]`

* `repr(C)` pins field order to declaration order. Without it the compiler is
  free to reorder fields, which would silently break a wire format consumed
  by any tool that decodes by offset (including `varta-watch` itself).
* `align(8)` makes the struct's start address 8-byte aligned, matching the
  natural alignment of the three `u64` fields. The first 8 bytes
  (`magic + version + status + pid`) total exactly 8 bytes, so once the struct
  is 8-aligned the `u64` fields land on 8-byte boundaries with **zero**
  padding. `size_of` therefore equals the sum of the field widths (32), and
  the const-assert proves it.
* No `unsafe` is required at the encode/decode boundary because we never
  transmute the struct to or from `[u8; 32]`. The body of `Frame::encode` and
  `Frame::decode` is a sequence of `to_le_bytes` / `from_le_bytes` calls
  against fixed-length array slices, all of which are checked at the type
  system level.

## Why little-endian on the wire

* Every tier-1 target Varta will plausibly run on (x86_64, aarch64) is
  little-endian natively, so `to_le_bytes` is a no-op copy on the hot path.
* Even on a hypothetical big-endian target the cost is one `bswap`-class
  instruction per integer field — a rounding error against UDS write/read.
* Pinning byte order in the spec means a frame captured on one host can be
  decoded byte-for-byte on another, which keeps the `varta-watch` recovery
  command testable in isolation.

## Why zero-dependency

* The protocol crate is the foundation everything else links against. Any
  registry crate it pulls in (`bytes`, `byteorder`, `zerocopy`, …) becomes a
  transitive obligation for every agent that wants to integrate Varta. Keeping
  `[dependencies]` empty preserves the "drop in one path dep, get health
  signaling" contract.
* The whole crate is a struct, an enum, and four free functions. There is
  nothing here that `core` does not already provide.
* Empty deps also keep the audit surface minimal: the only `unsafe` in the
  workspace will live in `varta-client` and `varta-watch` (where required for
  UDS plumbing), never in the protocol crate itself.

## Cross-references

* Acceptance contract: [`docs/acceptance/varta-v0-1-0.md`](../acceptance/varta-v0-1-0.md)
* Crate root: [`crates/varta-vlp/src/lib.rs`](../../crates/varta-vlp/src/lib.rs)
* Integration tests: [`crates/varta-vlp/tests/frame.rs`](../../crates/varta-vlp/tests/frame.rs)
