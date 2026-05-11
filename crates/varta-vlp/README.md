# varta-vlp

[![crates.io](https://img.shields.io/crates/v/varta-vlp)](https://crates.io/crates/varta-vlp)

← [Workspace root](../../README.md)

Wire protocol crate — defines the 32-byte Varta Lifeline Protocol (VLP) frame
that agents emit and observers decode. Zero dependencies; operates entirely on
`[u8; 32]` stack buffers.

## Byte map

```
offset │ size │ field      │ notes
───────┼──────┼────────────┼──────────────────────────────────────────────────
 0     │  2   │ magic      │ const [0x56, 0x41]  (ASCII "VA")
 2     │  1   │ version    │ const 0x01
 3     │  1   │ status     │ Status::{Ok=0, Degraded=1, Critical=2, Stall=3}
 4     │  4   │ pid        │ u32 little-endian — emitter's process id
 8     │  8   │ timestamp  │ u64 little-endian — emitter-local monotonic ns
16     │  8   │ nonce      │ u64 little-endian — strictly increasing per pid
24     │  8   │ payload    │ u64 little-endian — opaque application context
───────┴──────┴────────────┴──────────────────────────────────────────────────
                                                              total  32 bytes
```

The layout is locked by two compile-time assertions:

```rust
const _: () = assert!(core::mem::size_of::<Frame>() == 32);
const _: () = assert!(core::mem::align_of::<Frame>() == 8);
```

## Status variants

| Value | Variant    | Meaning |
|-------|------------|---------|
| `0`   | `Ok`       | Agent is healthy and making progress. |
| `1`   | `Degraded` | Agent is making progress with elevated trouble (retrying, throttled). |
| `2`   | `Critical` | Agent is about to die; emitted by the panic hook before unwinding. |
| `3`   | `Stall`    | Agent appears stuck; emitted by `varta-watch` after silence threshold. |

## Usage

```rust
use varta_vlp::{Frame, Status, MAGIC, VERSION, DecodeError};

// Encode
let frame = Frame {
    magic: MAGIC,
    version: VERSION,
    status: Status::Ok,
    pid: std::process::id(),
    timestamp: 0,
    nonce: 1,
    payload: 0,
};
let mut buf = [0u8; 32];
frame.encode(&mut buf);

// Decode
let decoded = Frame::decode(&buf).unwrap();
assert_eq!(decoded.status, Status::Ok);
```

## Version policy

The `VERSION` byte (`0x01` for v0.1.0) is incremented for any change that
alters the byte map — field addition, reorder, or width change. Observers that
receive a frame with an unknown version byte return `DecodeError::BadVersion`
and drop the frame; they never emit incorrect metrics for data they cannot
interpret.

## Constraints

- **Zero dependencies.** `[dependencies]` is empty; only `core` and `std` are used.
- **Zero heap allocation.** Every encode/decode path operates on `[u8; 32]` stack arrays.
- **Layout-stable.** `#[repr(C, align(8))]` pins field order and alignment; the `const` assertions enforce size at compile time.

## See also

- Architecture doc: [`docs/architecture/vlp-frame.md`](../../docs/architecture/vlp-frame.md)
- Client crate: [`crates/varta-client/README.md`](../varta-client/README.md)
