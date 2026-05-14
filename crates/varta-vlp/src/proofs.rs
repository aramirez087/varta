//! Kani symbolic-verification harnesses for [`crate::Frame`] and
//! [`crate::crc32c`].
//!
//! This module is gated `#[cfg(kani)]` so the harnesses are invisible to
//! every normal `cargo build` / `cargo test` invocation.  The Kani crate
//! is injected by `cargo kani` at proof time — there is no entry in
//! [`Cargo.toml`] for it, and the zero-registry-dependency invariant
//! documented in `CLAUDE.md` is preserved by construction.
//!
//! Run locally with `cargo kani -p varta-vlp`.  In CI, the
//! `kani-proofs` job in `.github/workflows/ci.yml` runs the same
//! command and is a required gate on every PR that touches
//! `crates/varta-vlp/**`.
//!
//! ### Split-harness design
//!
//! Combining the CRC-table loop (28 iterations × 256-entry lookup) with
//! the full decode path explodes CBMC's state space.  The proofs are
//! split so the symbolic cost stays bounded:
//!
//! * The two CRC harnesses ([`crc_compute_is_total`],
//!   [`crc_detects_bit_flip`]) prove pure properties of
//!   [`crate::crc32c::compute`] over arbitrary `[u8; 28]`.
//! * The decode harnesses ([`decode_never_panics`],
//!   [`decode_classification`]) assume the CRC verifies via
//!   [`kani::assume`], decoupling decode-correctness from
//!   CRC-correctness.
//! * [`encode_decode_roundtrips`] and [`decode_error_precedence`]
//!   exercise structural invariants over constructable frames.
//!
//! See `docs/architecture/verification.md` for the full strategy and a
//! mapping from each harness to the protocol invariant it proves.

#![allow(clippy::missing_safety_doc)]

// Harnesses are added incrementally — Step 2 (decode_*),
// Step 3 (crc_*), Step 4 (roundtrip_*, error_precedence).  This module
// starts empty so the scaffolding PR proves the CI plumbing works
// before any property is symbolically discharged.
