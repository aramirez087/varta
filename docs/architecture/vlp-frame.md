# VLP Frame — Wire Layout (v0.1.0)

The Varta Lifeline Protocol carries a single message type: a 32-byte
fixed-layout health frame. Every byte position is pinned at the protocol level
so encode/decode is a handful of `from_le_bytes` / `to_le_bytes` calls and
nothing else.

## Byte map

```
offset │ size │ field      │ notes
───────┼──────┼────────────┼──────────────────────────────────────────────
 0     │  2   │ magic      │ const [0x56, 0x41]  (ASCII "VA")
 2     │  1   │ version    │ const 0x01
 3     │  1   │ status     │ Status::{Ok=0, Degraded=1, Critical=2, Stall=3}
 4     │  4   │ pid        │ u32 little-endian — emitter's process id
 8     │  8   │ timestamp  │ u64 little-endian — emitter-local monotonic
16     │  8   │ nonce      │ u64 little-endian — strictly increasing
24     │  8   │ payload    │ u64 little-endian — opaque app context
───────┴──────┴────────────┴──────────────────────────────────────────────
                                                              total 32 bytes
```

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
