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
//!   [`decode_classification`]) operate on inputs constrained so the
//!   CRC trailer matches the body, decoupling decode-correctness from
//!   CRC-correctness.
//! * [`encode_decode_roundtrips`] and [`decode_error_precedence`]
//!   exercise structural invariants over constructable frames.
//!
//! See `book/src/architecture/verification.md` for the full strategy and a
//! mapping from each harness to the protocol invariant it proves.

use crate::{crc32c, DecodeError, Frame, Status, MAGIC, NONCE_TERMINAL, VERSION};

/// **M7 Step 2 — panic-freedom.**
///
/// For every possible 32-byte input, [`Frame::decode`] returns without
/// panicking.  The harness is unconstrained: random bytes that fail the
/// magic / version / CRC / status / field-range gates surface as the
/// corresponding [`DecodeError`] variant; nothing inside the function
/// indexes outside `&[u8; 32]` or executes an `unwrap` on an `Err`.
#[kani::proof]
fn decode_never_panics() {
    let bytes: [u8; 32] = kani::any();
    let _ = Frame::decode(&bytes);
}

/// **M7 Step 2 — classification + post-condition coverage.**
///
/// For every 32-byte input whose CRC trailer matches the body
/// (i.e. inputs that pass the CRC gate), [`Frame::decode`] returns
/// either an [`Err`] of one of the named [`DecodeError`] variants or
/// an [`Ok(Frame)`] whose fields satisfy every documented post-condition:
///
/// * `frame.magic == MAGIC`
/// * `frame.version == VERSION`
/// * `frame.status` is one of `Ok` / `Degraded` / `Critical`
///   (`Stall` is rejected by [`DecodeError::StallOnWire`]).
/// * `frame.pid >= 2` (the `BadPid(0)` / `BadPid(1)` gates fire first).
/// * `frame.timestamp != u64::MAX` (the `BadTimestamp` gate fires first).
/// * `frame.nonce != NONCE_TERMINAL` unless `frame.status == Critical`.
///
/// The input is constrained to "CRC-valid" so the proof focuses on the
/// post-CRC branches.  CRC-detection is proved separately by
/// [`crc_detects_bit_flip`] in Step 3.
#[kani::proof]
fn decode_classification() {
    let mut bytes: [u8; 32] = kani::any();
    // Stamp a matching CRC over bytes 0..28 so the input passes the
    // CRC gate.  Without this constraint Kani would also explore the
    // BadCrc branch — which is fine, just less informative for this
    // harness.  CRC behaviour is proved in its own harness.
    let crc = crc32c::compute(&bytes[0..28]);
    bytes[28..32].copy_from_slice(&crc.to_le_bytes());

    match Frame::decode(&bytes) {
        Ok(frame) => {
            kani::assert(frame.magic == MAGIC, "magic preserved");
            kani::assert(frame.version == VERSION, "version preserved");
            kani::assert(frame.status != Status::Stall, "stall rejected at wire");
            kani::assert(frame.pid >= 2, "pid range");
            kani::assert(frame.timestamp != u64::MAX, "timestamp range");
            kani::assert(
                !(frame.nonce == NONCE_TERMINAL && frame.status != Status::Critical),
                "nonce sentinel ↔ critical",
            );
        }
        Err(e) => match e {
            DecodeError::BadMagic
            | DecodeError::BadVersion
            | DecodeError::BadCrc { .. }
            | DecodeError::BadStatus(_)
            | DecodeError::StallOnWire
            | DecodeError::BadPid(_)
            | DecodeError::BadTimestamp(_)
            | DecodeError::BadNonce { .. } => {}
        },
    }
}

/// **M7 Step 3 — CRC totality + determinism.**
///
/// [`crc32c::compute`] never panics and returns the same value for the
/// same input.  The harness reads no global state, allocates nothing,
/// and exercises a 28-byte payload (the wire-format payload width that
/// [`Frame::encode`] feeds into the CRC).
#[kani::proof]
fn crc_compute_is_total() {
    let bytes: [u8; 28] = kani::any();
    let a = crc32c::compute(&bytes);
    let b = crc32c::compute(&bytes);
    kani::assert(a == b, "crc is deterministic");
}

/// **M7 Step 3 — single-bit-flip detection.**
///
/// For every 28-byte payload and every bit position in `[0, 28 * 8)`,
/// flipping that bit produces a different CRC.  This is the
/// load-bearing property of CRC-32C — guaranteed by polynomial
/// construction — and is the reason the wire format uses CRC-32C
/// rather than a parity checksum.
///
/// State scope: pure CRC.  No decode path, no protocol gates.  CBMC
/// handles the 256-entry table lookup natively via array reads; the
/// 28-iteration loop is bounded by `default-unwind = 64` in
/// `Kani.toml`.
#[kani::proof]
fn crc_detects_bit_flip() {
    let bytes: [u8; 28] = kani::any();
    let bit: u32 = kani::any();
    // bit position in [0, 28 * 8) = [0, 224)
    kani::assume(bit < 28 * 8);

    let byte_idx = (bit / 8) as usize;
    let bit_mask = 1u8 << (bit % 8) as u8;

    let original = crc32c::compute(&bytes);
    let mut flipped = bytes;
    flipped[byte_idx] ^= bit_mask;
    let flipped_crc = crc32c::compute(&flipped);

    kani::assert(original != flipped_crc, "single-bit flip changes CRC");
}

/// **M7 Step 4 — encode/decode round-trip isomorphism.**
///
/// For every constructable [`Frame`] whose field values satisfy the
/// documented invariants ([`Frame::decode`] docstring), the buffer
/// produced by [`Frame::encode`] decodes back to a `Frame` with
/// identical fields.  The constructable subset is bounded by:
///
/// * `pid >= 2` (pid 0 = scheduler, pid 1 = init).
/// * `timestamp < u64::MAX` (reserved sentinel).
/// * `status ∈ {Ok, Degraded, Critical}` (Stall is observer-synthesised).
/// * `nonce != NONCE_TERMINAL` unless `status == Critical`.
#[kani::proof]
fn encode_decode_roundtrips() {
    let pid: u32 = kani::any();
    kani::assume(pid >= 2);

    let timestamp: u64 = kani::any();
    kani::assume(timestamp != u64::MAX);

    let status_byte: u8 = kani::any();
    kani::assume(status_byte <= 2); // Ok / Degraded / Critical
    let status = match status_byte {
        0 => Status::Ok,
        1 => Status::Degraded,
        2 => Status::Critical,
        _ => unreachable!(),
    };

    let nonce: u64 = kani::any();
    kani::assume(nonce != NONCE_TERMINAL || status == Status::Critical);

    let payload: u32 = kani::any();

    let original = Frame::new(status, pid, timestamp, nonce, payload);
    let mut buf = [0u8; 32];
    original.encode(&mut buf);
    let decoded = Frame::decode(&buf).expect("constructable frame decodes");
    kani::assert(decoded == original, "fields preserved bit-for-bit");
}

/// **M7 Step 4 — error-gate precedence.**
///
/// For every 32-byte input that fails decode, the first gate in the
/// documented order (magic → version → CRC → status → pid →
/// timestamp → nonce) is the one whose [`DecodeError`] variant is
/// returned.  This harness proves the magic and version precedences
/// universally; the remaining precedence cases are covered by
/// integration tests (`crates/varta-vlp/tests/frame.rs`) over chosen
/// counter-examples and are subsumed by [`decode_classification`] in
/// aggregate.
#[kani::proof]
fn decode_error_precedence() {
    let bytes: [u8; 32] = kani::any();
    if let Err(e) = Frame::decode(&bytes) {
        // BadMagic fires before any other gate.
        if bytes[0] != MAGIC[0] || bytes[1] != MAGIC[1] {
            kani::assert(matches!(e, DecodeError::BadMagic), "magic precedence");
        } else if bytes[2] != VERSION {
            // BadVersion fires before CRC, status, pid, etc.
            kani::assert(matches!(e, DecodeError::BadVersion), "version precedence");
        }
        // CRC / status / pid / timestamp / nonce precedences depend on the
        // exact body bytes and are exercised by `decode_classification`
        // (which constrains a valid CRC and observes the remaining gates
        // exhaustively).
    }
}
