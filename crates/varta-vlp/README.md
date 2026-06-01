# varta-vlp

[![crates.io](https://img.shields.io/crates/v/varta-vlp)](https://crates.io/crates/varta-vlp)

← [Workspace root](../../README.md)

Wire protocol crate — defines the 32-byte Varta Lifeline Protocol (VLP) frame
that agents emit and observers decode. Zero registry dependencies on the
default build (optional `crypto` feature pulls four audited RustCrypto crates);
every encode/decode path operates on `[u8; 32]` stack buffers.

> **Building a client in another language?**
> The normative wire specification is at
> [`book/src/spec/vlp.md`](../../book/src/spec/vlp.md) (+
> [`vlp-secure.md`](../../book/src/spec/vlp-secure.md) for the AEAD-wrapped
> transport).
> A cross-language conformance vector suite ships at
> [`tools/vlp-test-vectors.json`](../../tools/vlp-test-vectors.json).
> Python, C99, and Go reference implementations live in
> [`tools/reference-implementations/`](../../tools/reference-implementations/).

## Byte map (v0.2)

```
offset │ size │ field      │ notes
───────┼──────┼────────────┼──────────────────────────────────────────────────
 0     │  2   │ magic      │ const [0x56, 0x41]  (ASCII "VA")
 2     │  1   │ version    │ const 0x02   (v0.1 → DecodeError::BadVersion)
 3     │  1   │ status     │ Status::{Ok=0, Degraded=1, Critical=2, Stall=3}
 4     │  4   │ pid        │ u32 little-endian — emitter's process id
 8     │  8   │ timestamp  │ u64 little-endian — emitter-local monotonic
16     │  8   │ nonce      │ u64 little-endian — strictly increasing per session
24     │  4   │ payload    │ u32 little-endian — opaque application context
28     │  4   │ crc32c     │ u32 LE CRC-32C over bytes 0..28
───────┴──────┴────────────┴──────────────────────────────────────────────────
                                                              total  32 bytes
```

The layout is locked by compile-time size/alignment assertions in `src/lib.rs`
and field-offset tests in the same module:

```rust
const _: () = assert!(core::mem::size_of::<Frame>() == 32);
const _: () = assert!(core::mem::align_of::<Frame>() == 8);
```

Plus a runtime golden-bytes regression in `tests/frame.rs`.

## Status variants

| Value | Variant    | Meaning |
|-------|------------|---------|
| `0`   | `Ok`       | Agent is healthy and making progress. |
| `1`   | `Degraded` | Agent is making progress under elevated trouble (retrying, throttled). |
| `2`   | `Critical` | Agent is about to die; emitted by the panic hook before unwinding. |
| `3`   | `Stall`    | **Observer-synthesized only** — `Frame::decode` rejects `Stall` on the wire (`DecodeError::StallOnWire`). |

## Usage

```rust
use varta_vlp::{Frame, Status};

// Encode — `Frame::encode` stamps the CRC trailer at bytes 28..32.
let frame = Frame::new(
    Status::Ok,
    std::process::id(),
    0,    // timestamp (emitter-local monotonic)
    1,    // nonce (starts at 1, strictly increasing per session)
    0,    // payload (opaque u32)
);
let mut buf = [0u8; 32];
frame.encode(&mut buf);

// Decode — validates magic, version, CRC, status, and field ranges.
let decoded = Frame::decode(&buf).unwrap();
assert_eq!(decoded.status, Status::Ok);
```

## Secure transport (60-byte / 64-byte frames)

The optional `crypto` feature enables ChaCha20-Poly1305 AEAD wrapping for
UDP and other untrusted transports:

```
shared-key wire (60 B): [iv_random:8] [iv_counter:4] [ciphertext:32] [tag:16]
master-key wire (64 B): [agent_pid:4] [iv_random:8] [iv_counter:4]
                        [ciphertext:32] [tag:16]
```

AEAD nonce = `iv_random || iv_counter` (12 B). Master-key mode binds
`agent_pid` as AAD so observers reject pid-spoofed frames.

Per-agent and per-epoch keys derive from a master key via HKDF-SHA256
with versioned info strings (`varta-agent-v1`, `varta-iv-prefix-v1`,
`varta-epoch-v1`). See
[`book/src/spec/vlp-secure.md`](../../book/src/spec/vlp-secure.md) for the
full normative spec.

## Version policy

The `VERSION` byte (`0x02` for v0.2 — current shipping format) is
incremented for any change that alters the byte map — field addition,
reorder, or width change. Observers that receive a frame with an unknown
version byte return `DecodeError::BadVersion` and drop the frame; they
never emit incorrect metrics for data they cannot interpret.

VLP v0.1 (payload `u64`, no CRC trailer, `version = 0x01`) is rejected at
decode. There is no backward compatibility — re-key all agents and
observers to v0.2.

## Constraints

- **Zero registry dependencies** on the default build. The optional `crypto`
  feature pulls four `optional = true` RustCrypto crates
  (`chacha20poly1305`, `hkdf`, `sha2`, `zeroize`), all `default-features =
  false`. The base build remains `#![no_std]` + alloc-free.
- **Zero heap allocation.** Every encode/decode path operates on `[u8; 32]`
  stack arrays. The workspace's `varta-tests` guard-allocator test enforces
  this end-to-end.
- **Layout-stable.** `#[repr(C, align(8))]` pins field order and alignment;
  the const assertions enforce size at compile time.

## Conformance & cross-language interop

Any implementation in any language is conformant if and only if it
agrees with every vector in
[`tools/vlp-test-vectors.json`](../../tools/vlp-test-vectors.json). The
Rust reference verifies its own output via:

```sh
cargo run -p varta-vlp --example gen_test_vectors --features "std crypto"
cargo test -p varta-vlp --features "std crypto" --test conformance_vectors
```

See [`book/src/spec/conformance.md`](../../book/src/spec/conformance.md)
for the cross-language recipe.

## See also

- Normative spec: [`book/src/spec/vlp.md`](../../book/src/spec/vlp.md),
  [`book/src/spec/vlp-secure.md`](../../book/src/spec/vlp-secure.md).
- Rust implementation rationale (`#[repr(C, align(8))]`, layout
  assertions, decode-order design choices):
  [`book/src/architecture/vlp-frame.md`](../../book/src/architecture/vlp-frame.md).
- Client crate: [`crates/varta-client/README.md`](../varta-client/README.md).
