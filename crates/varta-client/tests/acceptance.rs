//! Session 02 acceptance tests for `varta-client`.
//!
//! These exercise the public agent surface (`Varta`, `BeatOutcome`) against a
//! live `UnixDatagram` server bound to a per-test temp path. The contract is
//! authoritative — see `docs/acceptance/varta-v0-1-0.md` §S02.

use std::os::unix::net::UnixDatagram;

mod common;
use common::TempSocket;

use varta_client::{BeatOutcome, Frame, Status, Varta};

#[test]
fn connect_succeeds_when_observer_socket_exists() {
    let temp = TempSocket::new("connect");
    let _server = UnixDatagram::bind(&temp.path).expect("bind server");
    let _client = Varta::connect(&temp.path).expect("connect must succeed");
}

#[test]
fn beat_emits_canonical_32_byte_frame() {
    let temp = TempSocket::new("emit");
    let server = UnixDatagram::bind(&temp.path).expect("bind server");
    let mut client = Varta::connect(&temp.path).expect("connect");
    let outcome = client.beat(Status::Ok, 0xCAFE);
    assert!(
        matches!(outcome, BeatOutcome::Sent),
        "outcome was {outcome:?}"
    );

    let mut buf = [0u8; 32];
    let n = server.recv(&mut buf).expect("recv");
    assert_eq!(n, 32, "datagram must be exactly 32 bytes");

    let frame = Frame::decode(&buf).expect("decode");
    assert_eq!(frame.pid, std::process::id());
    assert_eq!(frame.status, Status::Ok);
    assert_eq!(frame.payload, 0xCAFE);
    assert_eq!(frame.nonce, 1);
}

#[test]
fn beat_increments_nonce_monotonically() {
    let temp = TempSocket::new("nonce");
    let server = UnixDatagram::bind(&temp.path).expect("bind server");
    let mut client = Varta::connect(&temp.path).expect("connect");

    for _ in 0..5 {
        let _ = client.beat(Status::Ok, 0);
    }

    let mut buf = [0u8; 32];
    let mut nonces = [0u64; 5];
    for slot in nonces.iter_mut() {
        server.recv(&mut buf).expect("recv");
        *slot = Frame::decode(&buf).expect("decode").nonce;
    }
    assert_eq!(nonces, [1, 2, 3, 4, 5]);
}

#[test]
fn beat_returns_dropped_when_observer_absent() {
    let temp = TempSocket::new("absent");
    let server = UnixDatagram::bind(&temp.path).expect("bind server");
    let mut client = Varta::connect(&temp.path).expect("connect");
    drop(server);

    let outcome = client.beat(Status::Ok, 0);
    assert!(
        matches!(outcome, BeatOutcome::Dropped),
        "expected Dropped, got {outcome:?}"
    );
}
