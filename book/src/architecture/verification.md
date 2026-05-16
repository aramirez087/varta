# Symbolic Verification — `varta-vlp::Frame::decode`

## Rationale

`Frame::decode` (`crates/varta-vlp/src/lib.rs:211`) is the single
deserialisation entry point on the observer side of the wire.  Every
byte that crosses a Varta socket flows through it.  For an IEC 62304 /
DO-178C-grade deployment the cost of a panic, an unhandled byte
pattern, or a field-range gap inside this function is unbounded: the
observer poll loop is single-threaded and a panic terminates the
process.

Empirical coverage on the decode path is already strong:

* `cargo test -p varta-vlp` — 11 integration tests in
  `crates/varta-vlp/tests/frame.rs` covering golden-bytes CRC,
  decode-error precedence, every field-range guard, and single-bit-flip
  CRC detection.
* `cargo fuzz run frame_decode` — libfuzzer against arbitrary 32-byte
  slices, 30-second smoke per CI run, longer-form runs documented in
  `fuzz/README.md`.
* `cargo fuzz run frame_roundtrip` — encode→decode isomorphism over
  filtered-valid inputs.
* `cargo miri test -p varta-vlp --all-features` — pointer-provenance
  and undefined-behaviour interpretation of every test.

What none of those layers provide is a *universal* statement about the
function.  Fuzzing samples; Miri interprets execution traces; the unit
tests exercise hand-chosen byte sequences.  Symbolic verification with
[Kani] closes the gap by proving properties over *every* possible
32-byte input.

[Kani]: https://model-checking.github.io/kani/

## Tool choice — Kani

* **Mature.** Backed by the Model Checking working group; used by
  rust-stdlib's verification effort.
* **`no_std`-clean.** Harnesses compile under the same
  `#![cfg_attr(not(feature = "std"), no_std)]` posture as the rest of
  `varta-vlp`; no allocator, no `std::*` types in the proof bodies.
* **Zero-dep posture preserved.** The Kani crate is injected by
  `cargo kani` at proof time.  Nothing is added to
  `crates/varta-vlp/Cargo.toml`, so the zero-registry-dependency audit
  in `.github/workflows/ci.yml` continues to pass.
* **Stable toolchain.** Unlike `verus` or `prusti`, Kani runs on the
  pinned stable toolchain — matching `rust-toolchain.toml`.

Creusot and Verus were considered.  Both were rejected: Creusot adds a
Why3 toolchain dependency and an annotation burden disproportionate to
this proof surface; Verus requires the `verus!` macro that does not
coexist cleanly with the `#![no_std]` library surface.

## Split-harness design

A naive single proof of "decode is correct" multiplies three sources of
symbolic state:

1. The 32-byte input domain (`2^256` symbolic values).
2. The CRC-32C inner loop (28 iterations × 256-entry table lookup ×
   `u32` state).
3. The seven sequential decode gates (magic, version, CRC, status,
   stall, pid, timestamp, nonce).

CBMC handles each of these well in isolation; combined, the path count
saturates.  The harnesses are therefore *split* so the symbolic cost of
each proof stays bounded:

| Harness | What it proves | State scope |
|---|---|---|
| `crc_detects_bit_flip` | Flipping a single bit in `[0, 28*8)` changes the CRC output | CRC + single bit position |
| `decode_never_panics` | `Frame::decode(&[u8; 32])` returns without panicking on every input | Decode, no CRC assumption |
| `decode_classification` | When `Ok(frame)`, all five field-range post-conditions hold | Decode, CRC assumed valid |
| `encode_decode_roundtrips` | For constructable frames, `decode(encode(f)) == Ok(f)` | Encode + decode |
| `decode_error_precedence` | The first failing gate in the documented order is the one returned | Decode |

Decoupling CRC-correctness from decode-correctness means a bug in
either layer surfaces independently, with a focused
counter-example.

> **Why no `crc_compute_is_total` (determinism) harness?**  An earlier
> version of this suite included one; CBMC needed >19 minutes on it
> because two symbolic 28-iteration table-lookup expressions over the
> same input must be proved equivalent at the SMT level.  The property
> is already free in Rust: `crc32c::compute` is `pub const fn` with no
> global state, no allocation, no FFI.  The const-asserts in
> `crc32c.rs` exercise it concretely on the RFC 3720 reference vector,
> and panic-freedom is subsumed by `decode_never_panics` (which calls
> `compute` on the decode path).

## Local invocation

```bash
# One-time setup
cargo install --locked kani-verifier
cargo kani setup

# Run all proofs (uses the `default-unwind = 64` from Kani.toml)
cargo kani -p varta-vlp

# Run a single harness (useful when iterating)
cargo kani -p varta-vlp --harness decode_never_panics
```

The `default-unwind = 64` setting in `crates/varta-vlp/Kani.toml` covers
the 28-iteration CRC inner loop with margin.  Decode harnesses only
iterate over fixed-size 32-byte arrays and are unwind-insensitive.

## CI integration

The `kani-proofs` job in `.github/workflows/ci.yml` runs on every push
and on every PR that touches `crates/varta-vlp/**` or the workflow
itself.  It is a **required gate** — a failed proof blocks merge.  PRs
that do not touch the protocol crate skip the job and short-circuit to
"passing", keeping turnaround time bounded for unrelated changes.

Job timeout is 30 minutes per harness (matrix fan-out — each harness
runs in parallel in its own job).  Locally, every per-PR harness runs
in under two minutes on Apple Silicon.

### Long-form proofs (nightly)

`crc_detects_bit_flip` is excluded from the per-PR matrix.  Two
symbolic 28-iteration table-lookup expressions over inputs that differ
by one of 224 bit positions exceed CBMC's 30-min budget — locally
observed at >13 min CPU time without completion.  It runs in
`.github/workflows/kani-nightly.yml` with a 6 h budget on a daily
schedule and auto-opens a GitHub issue on failure.

CRC bit-flip detection is also guaranteed by the polynomial
construction of CRC-32C/Castagnoli (HD=8 for short messages); the
nightly harness is a structural sanity check on the table generator
and byte-at-a-time loop, not the source of the cryptographic
guarantee.  The const-asserts and RFC 3720 reference vectors in
`crc32c.rs` already catch any per-PR regression in the table or
algorithm.

## Roadmap

These harnesses are the first redemption of the
"Formal Verification: TLA+ or Kani proofs for core state machines"
roadmap item (see `ROADMAP.md`).  Future candidates:

* `tracker::PidIndex::insert` / `::get` — open-addressed probe-bound
  proofs that complement the existing `varta_tracker_pid_index_probe_exhausted_total`
  Prometheus signal.
* `recovery::LastFiredTable::try_insert` — eviction-policy proof
  showing the debounce invariant holds under capacity pressure
  (companion to the M8 fix landed in the same series).
* `Status::try_from_u8` total-coverage — minor; already total by
  construction, but a one-line harness is cheap.
