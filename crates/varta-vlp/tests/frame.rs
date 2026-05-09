//! Integration tests for the Varta Lifeline Protocol frame.
//!
//! These tests pin the on-wire layout, the validation rules, and the
//! status-byte mapping. They are authored before any production code in
//! `varta-vlp` exists; the RED capture in the Session 01 handoff is the
//! compile failure these references produce.

use varta_vlp::{DecodeError, Frame, Status, MAGIC, VERSION};

/// A canonical frame whose encoding is hand-computed in
/// `frame_round_trip_matches_golden_bytes`. Centralised so every round-trip
/// test starts from the same fixture.
fn fixture_frame() -> Frame {
    Frame {
        magic: MAGIC,
        version: VERSION,
        status: Status::Ok as u8,
        pid: 0xDEAD_BEEF,
        timestamp: 0x0123_4567_89AB_CDEF,
        nonce: 1,
        payload: 0x0042,
    }
}

/// Golden encoding of `fixture_frame()` — little-endian, 32 bytes, no padding.
const GOLDEN_BYTES: [u8; 32] = [
    // magic "VA"
    0x56, 0x41, // version + status
    0x01, 0x00, // pid = 0xDEAD_BEEF (LE)
    0xEF, 0xBE, 0xAD, 0xDE, // timestamp = 0x0123_4567_89AB_CDEF (LE)
    0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01, // nonce = 1 (LE)
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // payload = 0x0042 (LE)
    0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn frame_size_is_thirty_two_bytes_at_runtime() {
    assert_eq!(std::mem::size_of::<Frame>(), 32);
}

#[test]
fn frame_alignment_is_eight_at_runtime() {
    assert_eq!(std::mem::align_of::<Frame>(), 8);
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
    let mut buf = GOLDEN_BYTES;
    buf[2] = 0x02;
    assert_eq!(Frame::decode(&buf), Err(DecodeError::BadVersion));
}

#[test]
fn decode_rejects_bad_status() {
    let mut buf = GOLDEN_BYTES;
    buf[3] = 0x09;
    assert_eq!(Frame::decode(&buf), Err(DecodeError::BadStatus(0x09)));
}

#[test]
fn every_status_variant_round_trips() {
    for (byte, expected) in [
        (0u8, Status::Ok),
        (1u8, Status::Degraded),
        (2u8, Status::Critical),
        (3u8, Status::Stall),
    ] {
        assert_eq!(
            Status::try_from_u8(byte).expect("known byte must decode"),
            expected,
            "byte {byte:#x} did not map to {expected:?}"
        );

        let frame = Frame {
            magic: MAGIC,
            version: VERSION,
            status: byte,
            pid: 7,
            timestamp: 0,
            nonce: 1,
            payload: 0,
        };
        let mut buf = [0u8; 32];
        frame.encode(&mut buf);
        let decoded = Frame::decode(&buf).expect("variant frame must decode");
        assert_eq!(decoded.status, byte);
    }
}

#[test]
fn payload_preserved_at_u64_max() {
    let frame = Frame {
        magic: MAGIC,
        version: VERSION,
        status: Status::Critical as u8,
        pid: u32::MAX,
        timestamp: u64::MAX,
        nonce: u64::MAX,
        payload: u64::MAX,
    };
    let mut buf = [0u8; 32];
    frame.encode(&mut buf);
    let decoded = Frame::decode(&buf).expect("u64::MAX frame must decode");
    assert_eq!(decoded.timestamp, u64::MAX);
    assert_eq!(decoded.nonce, u64::MAX);
    assert_eq!(decoded.payload, u64::MAX);
    assert_eq!(decoded.pid, u32::MAX);
}

#[test]
fn decode_error_implements_display_and_error() {
    let bad_magic = format!("{}", DecodeError::BadMagic);
    let bad_version = format!("{}", DecodeError::BadVersion);
    let bad_status = format!("{}", DecodeError::BadStatus(0x42));
    assert!(!bad_magic.is_empty());
    assert!(!bad_version.is_empty());
    assert!(bad_status.contains("0x42") || bad_status.contains("66"));

    let _as_dyn: &dyn core::error::Error = &DecodeError::BadMagic;
}
