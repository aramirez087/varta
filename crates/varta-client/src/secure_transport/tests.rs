use super::*;
use std::net::{Ipv6Addr, SocketAddrV6};

#[test]
fn ipv6_connect_does_not_fail_with_einval() {
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9876, 0, 0));
    let key = Key::from_bytes([0x42; 32]);
    let result = SecureUdpTransport::connect(addr, key);
    assert!(result.is_ok(), "IPv6 connect failed: {:?}", result.err());
}

#[test]
fn fallback_iv_random_unique_across_calls() {
    use std::collections::HashSet;
    let outputs: HashSet<[u8; 8]> = (0..1000).map(|_| fallback_iv_random()).collect();
    assert_eq!(
        outputs.len(),
        1000,
        "collisions detected in fallback_iv_random"
    );
}

#[test]
fn os_random_yields_distinct_outputs() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    match (os_random(&mut a), os_random(&mut b)) {
        (Ok(()), Ok(())) => assert_ne!(a, b, "os_random returned identical outputs"),
        (Err(e), _) | (_, Err(e)) if e.kind() == io::ErrorKind::Unsupported => {}
        (Err(e), _) | (_, Err(e)) => panic!("os_random failed: {e}"),
    }
}

#[test]
fn os_random_zero_length_returns_without_spinning() {
    // A zero-length request must terminate immediately: the Linux loop guard
    // (`filled < buf.len()`) never enters, so the `n == 0` infinite-loop guard
    // is not even reached; getentropy(_, 0) likewise succeeds. The hazard the
    // guard exists for is a 0 return on a NON-empty request, which would spin
    // forever — this test pins the boundary that it stays a fast Ok.
    let mut empty: [u8; 0] = [];
    match os_random(&mut empty) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {}
        Err(e) => panic!("os_random(zero-length) failed: {e}"),
    }
}

#[test]
fn fallback_iv_session_salt_unique_across_calls() {
    use std::collections::HashSet;
    let outputs: HashSet<[u8; 16]> = (0..1000).map(|_| fallback_iv_session_salt()).collect();
    assert_eq!(
        outputs.len(),
        1000,
        "collisions detected in fallback_iv_session_salt"
    );
}

#[test]
fn read_iv_session_salt_succeeds() {
    assert!(
        read_iv_session_salt().is_ok(),
        "read_iv_session_salt failed on this platform"
    );
}

/// Once `connect()` has returned, any further call to the entropy
/// chain on the steady-state beat path is a regression. This test
/// guards by setting a poison flag that an entropy-mock in
/// `BeatTransport::send` would trip; since the new scheme does NOT
/// call any entropy helper on `send`, we simply verify that
/// `send_local_loopback_after_wrap` does not panic and rotates state
/// without calling `read_iv_session_salt`.  The latter is observable
/// indirectly: the prefix changes, prefix_index increments, and
/// `iv_counter` resets to 1.
#[test]
fn counter_wrap_rotates_prefix_without_entropy_read() {
    // Use a loopback UDP socket as a black-hole receiver. We don't
    // actually need anyone to receive; we just need send() to succeed.
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9876, 0, 0));
    let key = Key::from_bytes([0u8; 32]);
    let mut tx = SecureUdpTransport::connect(addr, key).expect("connect");

    let prefix_before = tx.iv_prefix_for_test();
    let salt_before = tx.iv_session_salt;
    tx.set_iv_counter_for_test(u32::MAX);

    // Send a stub buffer — the destination is a closed ephemeral
    // address so the send may fail at the network layer, but the
    // wrap-rotation logic runs before the syscall.
    let buf = [0u8; 32];
    let _ = <SecureUdpTransport as BeatTransport>::send(&mut tx, &buf);

    // Salt must NOT have changed — no entropy refresh.
    assert_eq!(
        tx.iv_session_salt, salt_before,
        "salt rotated unexpectedly on wrap"
    );
    // Prefix index advanced; prefix differs from the prior session-0.
    assert_eq!(
        tx.iv_prefix_index_for_test(),
        1,
        "prefix_index should advance to 1 on wrap"
    );
    assert_ne!(
        tx.iv_prefix_for_test(),
        prefix_before,
        "rotated prefix should differ from prior prefix"
    );
    assert_eq!(tx.iv_counter, 1, "counter should reset to 1 on wrap");
}

/// The wrap path must NOT call the OS entropy chain.  We assert this
/// structurally: after `connect()`, freezing the salt and forcing a
/// wrap must leave the salt unchanged.  Any future regression that
/// re-introduces an entropy call on `send()` will flip the salt and
/// fail this assertion.
///
/// Sends target a real UDP receiver so the commit-on-success path runs
/// deterministically — sending to a closed port can yield async ICMP
/// `ECONNREFUSED` on subsequent calls, which after the commit-on-success
/// fix would (correctly) hold prefix_index back and confuse this test.
#[test]
fn wrap_path_does_not_call_read_iv_session_salt() {
    let receiver = std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("bind receiver");
    let port = receiver.local_addr().expect("local_addr").port();
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
    let key = Key::from_bytes([0u8; 32]);
    let mut tx = SecureUdpTransport::connect(addr, key).expect("connect");

    let salt_snapshot = tx.iv_session_salt;
    // Run several wrap rotations back-to-back.
    for expected_index in 1..=4 {
        tx.set_iv_counter_for_test(u32::MAX);
        let buf = [0u8; 32];
        let r = <SecureUdpTransport as BeatTransport>::send(&mut tx, &buf);
        assert!(r.is_ok(), "send #{expected_index} failed: {r:?}");
        assert_eq!(
            tx.iv_session_salt, salt_snapshot,
            "salt mutated during wrap rotation (regression)"
        );
        assert_eq!(tx.iv_prefix_index_for_test(), expected_index);
    }
}

/// Both `iv_counter` AND `iv_prefix_index` exhausted — `send()` must
/// fall back to `reconnect()`, refresh the salt, and resume from
/// `iv_prefix_index = 0`, `iv_counter = 1`. This exercises the path
/// that previously recursed into `self.send(buf)`; it must now run
/// linearly without stack growth and still produce identical state.
///
/// Sends target a real UDP receiver so the commit-on-success path runs
/// deterministically — sending to a closed port can yield async ICMP
/// `ECONNREFUSED` on the post-reconnect send, which would hold
/// `iv_counter` at 0 and trip the assertion below.
#[test]
fn doubly_exhausted_nonce_falls_back_to_reconnect() {
    let receiver = std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("bind receiver");
    let port = receiver.local_addr().expect("local_addr").port();
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
    let key = Key::from_bytes([0u8; 32]);
    let mut tx = SecureUdpTransport::connect(addr, key).expect("connect");

    let salt_before = tx.iv_session_salt;
    let prefix_before = tx.iv_prefix_for_test();

    // Force both u32s to the brink of exhaustion.
    tx.set_iv_counter_for_test(u32::MAX);
    tx.set_iv_prefix_index_for_test(u32::MAX);

    let buf = [0u8; 32];
    let r = <SecureUdpTransport as BeatTransport>::send(&mut tx, &buf);
    assert!(r.is_ok(), "post-reconnect send failed: {r:?}");

    // Salt MUST have rotated — reconnect() is the only way out of
    // doubly-exhausted state.
    assert_ne!(
        tx.iv_session_salt, salt_before,
        "reconnect should refresh the session salt on double exhaustion"
    );
    // Both counters reset to a fresh session, then bumped by one beat.
    assert_eq!(tx.iv_prefix_index_for_test(), 0);
    assert_eq!(tx.iv_counter, 1);
    // Prefix-0 of the new salt is overwhelmingly likely to differ.
    assert_ne!(tx.iv_prefix_for_test(), prefix_before);
}

/// Successful `reconnect()` must atomically update all five state
/// fields: the connected socket (verified by the source port changing
/// after re-bind), the session salt, the derived prefix-0,
/// `iv_prefix_index = 0`, and `iv_counter = 0`.
///
/// Regression guard for the transactional contract: every fallible
/// step in `reconnect()` writes to a local, and the five `self.*`
/// writes happen in a tail block with no `?` operator.  An inverted
/// write order or a partial commit (e.g. `self.sock = sock` ahead of
/// a still-fallible step) would either trip this test or leave one of
/// the five assertions below false.
///
/// The port assertion is deterministic, not probabilistic: the old
/// `self.sock` is still held when `bind_ephemeral` runs for the new
/// socket, so the kernel cannot grant the same ephemeral port to both.
#[test]
fn reconnect_success_updates_all_iv_state_and_socket_port() {
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9876, 0, 0));
    let key = Key::from_bytes([0x42; 32]);
    let mut tx = SecureUdpTransport::connect(addr, key).expect("connect");

    // Drive non-default state so every reset is observable.
    tx.set_iv_counter_for_test(123);
    tx.set_iv_prefix_index_for_test(7);

    let port_before = tx.sock.local_addr().expect("local_addr").port();
    let salt_before = tx.iv_session_salt;
    let prefix_before = tx.iv_prefix_for_test();

    <SecureUdpTransport as BeatTransport>::reconnect(&mut tx)
        .expect("reconnect on loopback must succeed");

    assert_eq!(tx.iv_counter, 0, "iv_counter must reset to 0");
    assert_eq!(
        tx.iv_prefix_index_for_test(),
        0,
        "iv_prefix_index must reset to 0"
    );
    assert_ne!(
        tx.iv_session_salt, salt_before,
        "salt must be re-read from OS entropy (1-in-2^128 collision)"
    );
    assert_ne!(
        tx.iv_prefix_for_test(),
        prefix_before,
        "prefix must be re-derived from the new salt"
    );
    assert_ne!(
        tx.sock.local_addr().expect("local_addr").port(),
        port_before,
        "ephemeral source port must differ after re-bind"
    );
}

#[test]
fn direct_transport_refreshes_a_stale_fork_epoch_before_send() {
    let receiver = std::net::UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("bind receiver");
    let port = receiver.local_addr().expect("local_addr").port();
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
    let key = Key::from_bytes([0x42; 32]);
    let mut tx = SecureUdpTransport::connect(addr, key).expect("connect");

    let prefix_before = tx.iv_prefix;
    tx.connect_fork_epoch = tx.connect_fork_epoch.wrapping_add(1);

    let sent = <SecureUdpTransport as BeatTransport>::send(&mut tx, &[0u8; 32])
        .expect("send after fork-epoch mismatch");

    assert_eq!(sent, SECURE_FRAME_LEN);
    assert_eq!(tx.connect_fork_epoch, fork_epoch::current());
    assert_ne!(
        tx.iv_prefix, prefix_before,
        "stale inherited epoch must refresh the AEAD session before sealing"
    );
}

/// Commit-on-success contract: a failed `send(2)` (e.g. `WouldBlock` on
/// the beat path) must NOT advance `iv_counter`. The kernel never
/// accepted the datagram, so the speculative nonce is unobserved on
/// the wire and can be re-tried on the next call with no AEAD
/// nonce-reuse risk.
///
/// We force a deterministic failure by `mem::replace`-ing the connected
/// socket with an unconnected `UdpSocket::bind`. Calling `send(2)` on
/// an unconnected datagram socket yields `ENOTCONN` / `EDESTADDRREQ` —
/// platform-portable and immediate.
#[test]
fn iv_counter_commits_only_on_successful_send() {
    use std::mem;
    use std::net::{Ipv4Addr, UdpSocket};

    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9876, 0, 0));
    let key = Key::from_bytes([0u8; 32]);
    let mut tx = SecureUdpTransport::connect(addr, key).expect("connect");

    // Sanity baseline: a normal send on the connected socket commits
    // the counter advance.
    let baseline = tx.iv_counter;
    let buf = [0u8; 32];
    let ok = <SecureUdpTransport as BeatTransport>::send(&mut tx, &buf);
    assert!(
        ok.is_ok(),
        "baseline send on connected socket failed: {ok:?}"
    );
    assert_eq!(
        tx.iv_counter,
        baseline + 1,
        "successful send must advance iv_counter by exactly 1"
    );

    // Swap the connected socket for an unconnected one. send(2) on an
    // unconnected UDP socket fails with ENOTCONN / EDESTADDRREQ.
    let unconnected =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind unconnected UDP socket");
    unconnected
        .set_nonblocking(true)
        .expect("set_nonblocking on unconnected");
    let _replaced = mem::replace(&mut tx.sock, unconnected);

    let counter_before = tx.iv_counter;
    let prefix_before = tx.iv_prefix_for_test();
    let prefix_index_before = tx.iv_prefix_index_for_test();

    for attempt in 0..5 {
        let r = <SecureUdpTransport as BeatTransport>::send(&mut tx, &buf);
        assert!(
            r.is_err(),
            "send #{attempt} on unconnected socket unexpectedly succeeded: {r:?}"
        );
    }

    // Commit-on-success: none of the five failed sends may have moved
    // the committed AEAD state.
    assert_eq!(
        tx.iv_counter, counter_before,
        "iv_counter advanced despite send() failures \
         (commit-on-success contract violated)"
    );
    assert_eq!(
        tx.iv_prefix_for_test(),
        prefix_before,
        "iv_prefix mutated on failed send"
    );
    assert_eq!(
        tx.iv_prefix_index_for_test(),
        prefix_index_before,
        "iv_prefix_index mutated on failed send"
    );
}

/// Regression: a failed `send(2)` at the AEAD counter-wrap boundary
/// must NOT advance `iv_prefix_index` / `iv_prefix`. The previous
/// implementation mutated those fields eagerly inside `advance_nonce`,
/// so every retry under sustained kernel back-pressure (`ENOBUFS` /
/// `WouldBlock` at the wrap moment) burned a fresh prefix index and
/// ran HKDF on the beat path — violating both the commit-on-success
/// contract and the "no expensive ops on the beat path" invariant.
#[test]
fn wrap_failed_send_does_not_burn_prefix_index() {
    use std::mem;
    use std::net::{Ipv4Addr, UdpSocket};

    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9876, 0, 0));
    let key = Key::from_bytes([0u8; 32]);
    let mut tx = SecureUdpTransport::connect(addr, key).expect("connect");

    let prefix_before = tx.iv_prefix_for_test();
    let prefix_index_before = tx.iv_prefix_index_for_test();
    let salt_before = tx.iv_session_salt;

    // Stage the wrap: counter at u32::MAX so the next advance_nonce
    // takes the wrap branch.
    tx.set_iv_counter_for_test(u32::MAX);

    // Swap the connected socket for an unconnected one so every send
    // fails with ENOTCONN / EDESTADDRREQ.
    let unconnected =
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind unconnected UDP socket");
    unconnected
        .set_nonblocking(true)
        .expect("set_nonblocking on unconnected");
    let _replaced = mem::replace(&mut tx.sock, unconnected);

    let buf = [0u8; 32];
    for attempt in 0..5 {
        let r = <SecureUdpTransport as BeatTransport>::send(&mut tx, &buf);
        assert!(
            r.is_err(),
            "send #{attempt} on unconnected socket unexpectedly succeeded: {r:?}"
        );
    }

    assert_eq!(
        tx.iv_counter,
        u32::MAX,
        "iv_counter must stay at u32::MAX across failed wrap sends"
    );
    assert_eq!(
        tx.iv_prefix_index_for_test(),
        prefix_index_before,
        "iv_prefix_index must NOT advance on failed wrap send (commit-on-success)"
    );
    assert_eq!(
        tx.iv_prefix_for_test(),
        prefix_before,
        "iv_prefix must NOT rotate on failed wrap send (commit-on-success)"
    );
    assert_eq!(
        tx.iv_session_salt, salt_before,
        "iv_session_salt must not change on failed wrap send"
    );
}

/// `reconnect()` IS allowed to re-read entropy — it's the documented
/// manual escape hatch for fork-safety and salt refresh.
#[test]
fn manual_reconnect_does_re_read_entropy() {
    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9876, 0, 0));
    let key = Key::from_bytes([0u8; 32]);
    let mut tx = SecureUdpTransport::connect(addr, key).expect("connect");

    let salt_before = tx.iv_session_salt;
    let prefix_before = tx.iv_prefix_for_test();
    tx.iv_prefix_index = 42;
    tx.iv_counter = 12345;

    <SecureUdpTransport as BeatTransport>::reconnect(&mut tx).expect("reconnect");

    // Counter / index reset.
    assert_eq!(tx.iv_prefix_index_for_test(), 0);
    assert_eq!(tx.iv_counter, 0);
    // Salt should be fresh (cryptographically near-impossible to collide
    // with the previous read at 16 bytes).
    assert_ne!(
        tx.iv_session_salt, salt_before,
        "reconnect should refresh the session salt"
    );
    // Prefix-0 of the new salt is overwhelmingly likely to differ from
    // prefix-0 of the old salt.
    assert_ne!(tx.iv_prefix_for_test(), prefix_before);
}
