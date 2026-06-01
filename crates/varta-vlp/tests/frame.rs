//! Integration tests for the Varta Lifeline Protocol frame.
//!
//! These tests pin the on-wire layout, the validation rules, and the
//! status-byte mapping. They are authored before any production code in
//! `varta-vlp` exists; the RED capture in the Session 01 handoff is the
//! compile failure these references produce.

use varta_vlp::{crc32c, DecodeError, Frame, Status, NONCE_TERMINAL};

/// A canonical frame whose encoding is hand-computed in
/// `frame_round_trip_matches_golden_bytes`. Centralised so every round-trip
/// test starts from the same fixture.
fn fixture_frame() -> Frame {
    Frame::new(Status::Ok, 0xDEAD_BEEF, 0x0123_4567_89AB_CDEF, 1, 0x0042)
}

/// Golden encoding of `fixture_frame()` — little-endian, 32 bytes,
/// VLP v0.2 (version byte `0x02`, `u32` payload at bytes 24..28, CRC-32C
/// trailer at bytes 28..32 covering bytes 0..28).
///
/// CRC-32C value `0xB828B200` is hard-coded; the
/// `golden_bytes_crc_matches_compute` test guarantees it stays in sync
/// with [`crc32c::compute`].
const GOLDEN_BYTES: [u8; 32] = [
    // magic "VA"
    0x56, 0x41, // version (0x02) + status (Ok = 0x00)
    0x02, 0x00, // pid = 0xDEAD_BEEF (LE)
    0xEF, 0xBE, 0xAD, 0xDE, // timestamp = 0x0123_4567_89AB_CDEF (LE)
    0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01, // nonce = 1 (LE)
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // payload = 0x0000_0042 (LE, u32)
    0x42, 0x00, 0x00, 0x00, // CRC-32C of bytes 0..28 (LE) = 0xB828B200
    0x00, 0xB2, 0x28, 0xB8,
];

/// Mutate `buf[offset] = value` and re-stamp the CRC-32C trailer so the
/// resulting frame is *valid except for the targeted field*. Used by
/// decode-error tests that need to assert "we caught the wrong status /
/// pid / timestamp / nonce, not BadCrc".
fn patch_with_valid_crc(mut buf: [u8; 32], offset: usize, value: u8) -> [u8; 32] {
    buf[offset] = value;
    let crc = crc32c::compute(&buf[0..28]);
    buf[28..32].copy_from_slice(&crc.to_le_bytes());
    buf
}

/// Same as `patch_with_valid_crc` for a multi-byte little-endian write.
fn patch_range_with_valid_crc(
    mut buf: [u8; 32],
    range: core::ops::Range<usize>,
    src: &[u8],
) -> [u8; 32] {
    buf[range].copy_from_slice(src);
    let crc = crc32c::compute(&buf[0..28]);
    buf[28..32].copy_from_slice(&crc.to_le_bytes());
    buf
}

#[test]
fn frame_size_is_thirty_two_bytes_at_runtime() {
    assert_eq!(std::mem::size_of::<Frame>(), 32);
}

#[test]
fn frame_alignment_is_eight_at_runtime() {
    assert_eq!(std::mem::align_of::<Frame>(), 8);
}

#[test]
fn golden_bytes_crc_matches_compute() {
    // Defence-in-depth: if the hard-coded CRC in GOLDEN_BYTES ever drifts
    // from what `crc32c::compute` produces over the first 28 bytes, every
    // round-trip test silently regresses. This test pins the trailer to
    // the algorithm, independent of `Frame::encode`.
    let computed = crc32c::compute(&GOLDEN_BYTES[0..28]);
    let stored = u32::from_le_bytes([
        GOLDEN_BYTES[28],
        GOLDEN_BYTES[29],
        GOLDEN_BYTES[30],
        GOLDEN_BYTES[31],
    ]);
    assert_eq!(
        stored, computed,
        "GOLDEN_BYTES CRC trailer (stored {stored:#010x}) does not match crc32c::compute (computed {computed:#010x})"
    );
}

#[test]
fn frame_round_trip_matches_golden_bytes() {
    let frame = fixture_frame();
    let mut buf = [0u8; 32];
    frame.encode(&mut buf);
    assert_eq!(buf, GOLDEN_BYTES, "encoded bytes diverged from golden");

    let decoded = Frame::decode(&buf).expect("golden bytes must decode");
    assert_eq!(decoded, frame, "decoded frame diverged from source");
}

#[test]
fn decode_rejects_bad_magic() {
    let buf = [0xFFu8; 32];
    assert_eq!(Frame::decode(&buf), Err(DecodeError::BadMagic));
}

#[test]
fn decode_rejects_bad_version() {
    // VLP v0.1 frames (version byte 0x01) must now be rejected as
    // BadVersion, not silently accepted. Mutate the golden frame and
    // re-stamp the CRC so this test isolates the version check from the
    // CRC check (which sits after version).
    let buf = patch_with_valid_crc(GOLDEN_BYTES, 2, 0x01);
    assert_eq!(Frame::decode(&buf), Err(DecodeError::BadVersion));
}

#[test]
fn decode_rejects_bad_status() {
    let buf = patch_with_valid_crc(GOLDEN_BYTES, 3, 0x09);
    assert_eq!(Frame::decode(&buf), Err(DecodeError::BadStatus(0x09)));
}

#[test]
fn every_status_variant_round_trips() {
    // Agent-emitted statuses must round-trip through the wire decode
    // chokepoint cleanly. `Status::Stall` is excluded by design — see
    // `decode_rejects_stall_on_wire`. The byte mapping for `Stall` is still
    // covered here because `Status::try_from_u8` accepts it (in-memory
    // construction is intentionally permissive; observer code synthesises
    // `Stall` events via the tracker without round-tripping a `Frame`).
    for (byte, expected) in [
        (0u8, Status::Ok),
        (1u8, Status::Degraded),
        (2u8, Status::Critical),
    ] {
        assert_eq!(
            Status::try_from_u8(byte).expect("known byte must decode"),
            expected,
            "byte {byte:#x} did not map to {expected:?}"
        );

        let frame = Frame::new(expected, 7, 0, 1, 0);
        let mut buf = [0u8; 32];
        frame.encode(&mut buf);
        assert_eq!(buf[3], byte, "encoded status byte must round-trip");
        let decoded = Frame::decode(&buf).expect("variant frame must decode");
        assert_eq!(decoded.status, expected);
    }

    // `Status::Stall` parses from the byte but is rejected at wire decode.
    assert_eq!(
        Status::try_from_u8(3).expect("Stall byte must parse"),
        Status::Stall,
    );
}

#[test]
fn decode_rejects_stall_on_wire() {
    // Status::Stall is observer-synthesised when a pid goes silent; agents
    // emit only Ok/Degraded/Critical. A spoofed Stall frame would inject
    // false liveness telemetry from any pid, so decode rejects it at the
    // single chokepoint.
    let frame = Frame::new(Status::Stall, 12_345, 1_000, 7, 0);
    let mut buf = [0u8; 32];
    frame.encode(&mut buf);
    assert_eq!(Frame::decode(&buf), Err(DecodeError::StallOnWire));
}

#[test]
fn decode_stall_precedence_fires_before_bad_pid() {
    // The Stall-on-wire check sits between the status parse and the pid
    // range check, so a hostile frame combining `Status::Stall` with a
    // reserved pid must surface as `StallOnWire`, not `BadPid`. Locking
    // this in prevents accidental reordering during future refactors.
    let frame = Frame::new(Status::Stall, 1, 1_000, 7, 0);
    let mut buf = [0u8; 32];
    frame.encode(&mut buf);
    assert_eq!(Frame::decode(&buf), Err(DecodeError::StallOnWire));
}

#[test]
fn payload_preserved_at_u32_max() {
    // `timestamp == u64::MAX` is a reserved sentinel rejected at decode;
    // pick the largest non-sentinel value to keep this test pinned to the
    // "near-max round-trip" contract for the other fields. Payload narrowed
    // from u64 to u32 in VLP v0.2 (see crc32c trailer).
    let frame = Frame::new(
        Status::Critical,
        u32::MAX,
        u64::MAX - 1,
        NONCE_TERMINAL,
        u32::MAX,
    );
    let mut buf = [0u8; 32];
    frame.encode(&mut buf);
    let decoded = Frame::decode(&buf).expect("u32::MAX payload frame must decode");
    assert_eq!(decoded.timestamp, u64::MAX - 1);
    assert_eq!(decoded.nonce, NONCE_TERMINAL);
    assert_eq!(decoded.payload, u32::MAX);
    assert_eq!(decoded.pid, u32::MAX);
}

#[test]
fn decode_rejects_pid_zero() {
    let buf = patch_range_with_valid_crc(GOLDEN_BYTES, 4..8, &0u32.to_le_bytes());
    assert_eq!(Frame::decode(&buf), Err(DecodeError::BadPid(0)));
}

#[test]
fn decode_rejects_pid_one() {
    let buf = patch_range_with_valid_crc(GOLDEN_BYTES, 4..8, &1u32.to_le_bytes());
    assert_eq!(Frame::decode(&buf), Err(DecodeError::BadPid(1)));
}

#[test]
fn decode_rejects_timestamp_max() {
    let buf = patch_range_with_valid_crc(GOLDEN_BYTES, 8..16, &u64::MAX.to_le_bytes());
    assert_eq!(
        Frame::decode(&buf),
        Err(DecodeError::BadTimestamp(u64::MAX))
    );
}

#[test]
fn decode_rejects_terminal_nonce_with_non_critical_status() {
    // GOLDEN_BYTES carries Status::Ok at offset 3; jamming NONCE_TERMINAL
    // into the nonce slot must trip the protocol-invariant guard.
    let buf = patch_range_with_valid_crc(GOLDEN_BYTES, 16..24, &NONCE_TERMINAL.to_le_bytes());
    assert_eq!(
        Frame::decode(&buf),
        Err(DecodeError::BadNonce {
            nonce: NONCE_TERMINAL,
            status: Status::Ok,
        })
    );
}

#[test]
fn decode_accepts_terminal_nonce_with_critical_status() {
    // Guards the panic-hook contract: `panic.rs` always pairs
    // NONCE_TERMINAL with Status::Critical, and that combination MUST
    // continue to decode cleanly.
    let frame = Frame::new(Status::Critical, 42, 1_000, NONCE_TERMINAL, 0);
    let mut buf = [0u8; 32];
    frame.encode(&mut buf);
    let decoded = Frame::decode(&buf).expect("Critical + NONCE_TERMINAL must decode");
    assert_eq!(decoded.status, Status::Critical);
    assert_eq!(decoded.nonce, NONCE_TERMINAL);
}

#[test]
fn decode_rejects_single_bit_flip_in_payload_bytes() {
    // Every bit in bytes 0..28 of a valid frame must flip the CRC and
    // surface as BadCrc — proves the CRC is computed over the full
    // payload range, not just a prefix. Loops 28*8 = 224 sub-assertions.
    // The diagnostic checks magic-prefix bytes get caught as BadMagic
    // when the flip happens to leave magic invalid; for those we accept
    // either BadMagic or BadCrc as a guard-rail (BadMagic fires first by
    // decode order).
    let mut base = [0u8; 32];
    fixture_frame().encode(&mut base);

    for byte_idx in 0..28 {
        for bit in 0..8 {
            let mut buf = base;
            buf[byte_idx] ^= 1 << bit;
            let result = Frame::decode(&buf);
            match result {
                Err(DecodeError::BadCrc { .. }) => {}
                Err(DecodeError::BadMagic) if byte_idx < 2 => {}
                Err(DecodeError::BadVersion) if byte_idx == 2 => {}
                other => panic!(
                    "bit flip at byte {byte_idx} bit {bit} surfaced as {other:?}, \
                     expected BadCrc (or BadMagic/BadVersion for prefix bytes)"
                ),
            }
        }
    }
}

#[test]
fn decode_rejects_corrupted_crc_field() {
    // A flip in the CRC trailer itself (bytes 28..32) must surface as
    // BadCrc — the on-wire value differs from the recomputed one.
    let mut base = [0u8; 32];
    fixture_frame().encode(&mut base);

    for byte_idx in 28..32 {
        for bit in 0..8 {
            let mut buf = base;
            buf[byte_idx] ^= 1 << bit;
            match Frame::decode(&buf) {
                Err(DecodeError::BadCrc { .. }) => {}
                other => panic!(
                    "CRC byte flip at byte {byte_idx} bit {bit} surfaced as {other:?}, expected BadCrc"
                ),
            }
        }
    }
}

#[test]
fn decode_bad_crc_carries_expected_and_actual() {
    let mut buf = [0u8; 32];
    fixture_frame().encode(&mut buf);
    // Flip a non-prefix byte so the CRC mismatch is the only failure mode.
    buf[16] ^= 0xFF;
    match Frame::decode(&buf) {
        Err(DecodeError::BadCrc { expected, actual }) => {
            assert_ne!(expected, actual);
            // `expected` is the CRC the receiver recomputed from the corrupted
            // bytes; `actual` is what the (still-intact) trailer carried.
            let recomputed = crc32c::compute(&buf[0..28]);
            assert_eq!(expected, recomputed);
            let trailer = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
            assert_eq!(actual, trailer);
        }
        other => panic!("expected BadCrc, got {other:?}"),
    }
}

#[test]
fn decode_error_implements_display_and_error() {
    let bad_magic = format!("{}", DecodeError::BadMagic);
    let bad_version = format!("{}", DecodeError::BadVersion);
    let bad_crc = format!(
        "{}",
        DecodeError::BadCrc {
            expected: 0xDEAD_BEEF,
            actual: 0xCAFE_F00D,
        }
    );
    let bad_status = format!("{}", DecodeError::BadStatus(0x42));
    let stall_on_wire = format!("{}", DecodeError::StallOnWire);
    let bad_pid = format!("{}", DecodeError::BadPid(1));
    let bad_timestamp = format!("{}", DecodeError::BadTimestamp(u64::MAX));
    let bad_nonce = format!(
        "{}",
        DecodeError::BadNonce {
            nonce: NONCE_TERMINAL,
            status: Status::Ok
        }
    );
    assert!(!bad_magic.is_empty());
    assert!(!bad_version.is_empty());
    assert!(bad_crc.contains("deadbeef") || bad_crc.contains("DEADBEEF"));
    assert!(bad_crc.contains("cafef00d") || bad_crc.contains("CAFEF00D"));
    assert!(bad_status.contains("0x42") || bad_status.contains("66"));
    assert!(stall_on_wire.contains("Stall"));
    assert!(bad_pid.contains('1'));
    assert!(bad_timestamp.contains("ffff") || bad_timestamp.contains("FFFF"));
    assert!(bad_nonce.contains("Ok"));

    #[cfg(feature = "std")]
    {
        let _as_dyn: &dyn std::error::Error = &DecodeError::BadMagic;
        let _as_dyn_pid: &dyn std::error::Error = &DecodeError::BadPid(0);
        let _as_dyn_crc: &dyn std::error::Error = &DecodeError::BadCrc {
            expected: 0,
            actual: 0,
        };
    }
}
