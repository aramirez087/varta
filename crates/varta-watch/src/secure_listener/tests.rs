use super::*;
use crate::{ClockSource, EvictionPolicy, Observer};
use std::net::SocketAddr;
use varta_vlp::{Frame, Status, NONCE_TERMINAL};

// --- Cross-prefix replay regression coverage -------------------------------
//
// These call `try_record_replay_state` directly (with explicit inner nonces)
// to exercise the per-sender nonce high-water mark added alongside the 1-deep
// IV-prefix history. The legacy tests below go through `record_for_test`, which
// auto-supplies a monotonic nonce and therefore never trips this guard.

#[test]
fn aged_out_prefix_replay_is_rejected() {
    let mut listener = new_listener();
    let identity = test_identity();
    let iv1 = test_iv();
    let iv2 = test_iv2();
    let iv3 = test_iv3();

    // Legitimate rotations carry strictly-increasing authenticated nonces.
    assert!(listener.try_record_replay_state(identity, iv1, 100, 10, 10));
    assert!(listener.try_record_replay_state(identity, iv2, 200, 20, 20));
    assert!(listener.try_record_replay_state(identity, iv3, 50, 30, 30));

    // iv1 has aged out of the 1-deep history (current = iv3, prev = iv2).
    // Replaying a captured iv1 frame with its original inner nonce must now be
    // rejected by the per-sender nonce high-water mark. Before the fix the
    // third arm accepted it unconditionally (see `double_rotation_shifts_prev`).
    assert!(!listener.try_record_replay_state(identity, iv1, 100, 10, 10));

    // The replay must not perturb committed state — iv3 stays current and the
    // high-water mark is unchanged.
    assert_eq!(listener.sender_iv_random(identity), Some(iv3));
    assert_eq!(listener.sender_last_counter(identity), Some(50));
    assert_eq!(listener.sender_max_regular_nonce(identity), Some(30));
}

#[test]
fn genuine_rotation_with_newer_nonce_still_accepted() {
    let mut listener = new_listener();
    let identity = test_identity();
    let iv1 = test_iv();
    let iv2 = test_iv2();
    let iv3 = test_iv3();

    assert!(listener.try_record_replay_state(identity, iv1, 100, 10, 10));
    assert!(listener.try_record_replay_state(identity, iv2, 200, 20, 20));

    // A real new prefix always carries a nonce newer than anything seen, even
    // when its per-prefix IV counter restarts low — it must still be accepted.
    assert!(listener.try_record_replay_state(identity, iv3, 1, 21, 21));

    assert_eq!(listener.sender_iv_random(identity), Some(iv3));
    assert_eq!(listener.sender_last_counter(identity), Some(1));
    assert_eq!(listener.sender_max_regular_nonce(identity), Some(21));
}

#[test]
fn recycled_pid_after_session_gap_is_admitted_and_resets_baseline() {
    let mut listener = new_listener();
    let identity = test_identity();
    let t0 = Instant::now();

    // A long-lived predecessor climbs to a high regular-nonce high-water mark.
    assert!(listener.try_record_replay_state_at(t0, identity, test_iv(), 100, 5_000, 5_000));
    assert_eq!(listener.sender_max_regular_nonce(identity), Some(5_000));

    // The OS recycles the PID to a brand-new process: a freshly-derived IV
    // prefix and a monotonic VLP nonce that restarts at 1. WITHIN the session
    // gap the high-water mark still rejects it (replay protection preserved)
    // and committed state is untouched.
    let within = t0 + SESSION_RESTART_GAP / 2;
    assert!(!listener.try_record_replay_state_at(within, identity, test_iv2(), 0, 1, 9_999));
    assert_eq!(
        listener.sender_max_regular_nonce(identity),
        Some(5_000),
        "a rejected frame must not perturb the high-water mark"
    );
    assert_eq!(listener.sender_iv_random(identity), Some(test_iv()));

    // Once the predecessor has been silent past SESSION_RESTART_GAP the
    // recycled process is admitted as a fresh session and the baseline resets,
    // bounding the lockout to the gap instead of EVICTION_TTL.
    let after = t0 + SESSION_RESTART_GAP + Duration::from_secs(1);
    assert!(listener.try_record_replay_state_at(after, identity, test_iv2(), 0, 1, 9_999));
    assert_eq!(
        listener.sender_max_regular_nonce(identity),
        Some(1),
        "session restart must reset the high-water mark to the new baseline"
    );
    assert_eq!(listener.sender_iv_random(identity), Some(test_iv2()));
    assert_eq!(
        listener.sender_prev_iv_random(identity),
        Some([0u8; 8]),
        "a session restart clears the 1-deep prefix history"
    );
}

#[test]
fn terminal_panic_nonce_does_not_poison_regular_rotation() {
    let mut listener = new_listener();
    let identity = test_identity();
    let regular_iv = test_iv();
    let panic_iv = test_iv2();
    let fresh_iv = test_iv3();

    assert!(listener.try_record_replay_state(identity, regular_iv, 100, 10, 1_000));
    assert!(listener.try_record_replay_state(identity, panic_iv, 1, NONCE_TERMINAL, 2_000));

    // The original regular transport can still have an in-flight frame from
    // the previous prefix after the panic-hook frame rotated the sender state.
    assert!(listener.try_record_replay_state(identity, regular_iv, 101, 11, 3_000));

    // Regression: storing NONCE_TERMINAL in the regular high-water mark made
    // every later fresh IV prefix look like an aged-out replay until the
    // sender state expired.
    assert!(listener.try_record_replay_state(identity, fresh_iv, 1, 12, 4_000));
    assert_eq!(listener.sender_iv_random(identity), Some(fresh_iv));
    assert_eq!(listener.sender_max_regular_nonce(identity), Some(12));
}

#[test]
fn aged_out_terminal_panic_replay_is_rejected_by_timestamp() {
    let mut listener = new_listener();
    let identity = test_identity();
    let regular_iv = test_iv();
    let panic_iv = test_iv2();
    let fresh_iv = test_iv3();
    let newer_panic_iv = test_iv4();

    assert!(listener.try_record_replay_state(identity, regular_iv, 100, 10, 1_000));
    assert!(listener.try_record_replay_state(identity, panic_iv, 1, NONCE_TERMINAL, 2_000));
    assert!(listener.try_record_replay_state(identity, fresh_iv, 1, 11, 3_000));
    assert!(listener.try_record_replay_state(identity, regular_iv, 101, 12, 4_000));

    // panic_iv has aged out of the 1-deep IV history (current = regular_iv,
    // previous = fresh_iv). Replaying the captured terminal frame must still
    // be rejected even though terminal frames do not advance max_regular_nonce.
    assert!(!listener.try_record_replay_state(identity, panic_iv, 1, NONCE_TERMINAL, 2_000));

    // A genuinely later terminal frame on a new prefix remains admissible.
    assert!(listener.try_record_replay_state(identity, newer_panic_iv, 1, NONCE_TERMINAL, 5_000));
}

fn test_key() -> Key {
    Key::from_bytes([0xabu8; 32])
}

fn test_iv() -> [u8; 8] {
    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
}

fn test_iv2() -> [u8; 8] {
    [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]
}

fn test_iv3() -> [u8; 8] {
    [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
}

fn test_iv4() -> [u8; 8] {
    [0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28]
}

fn new_listener() -> SecureUdpListener {
    SecureUdpListener::bind("127.0.0.1:0".parse().unwrap(), vec![test_key()])
        .expect("bind should succeed")
}

fn test_identity() -> ReplayIdentity {
    ReplayIdentity::from_pid(42)
}

fn set_last_seen(listener: &mut SecureUdpListener, identity: ReplayIdentity, last_seen: Instant) {
    let slot = listener
        .sender_index
        .get(identity)
        .expect("identity must be indexed");
    listener.sender_slab[slot]
        .as_mut()
        .expect("indexed slot must hold sender state")
        .last_seen = last_seen;
}

#[test]
fn bind_requires_at_least_one_key() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let result = SecureUdpListener::bind(addr, vec![]);
    assert!(result.is_err());
}

#[test]
fn new_sender_accepted_and_inserted() {
    let mut listener = new_listener();
    let identity = test_identity();
    let iv = test_iv();
    let counter = 1;

    assert!(listener.record_for_test(identity, iv, counter));
    assert_eq!(listener.sender_iv_random(identity), Some(iv));
    assert_eq!(listener.sender_last_counter(identity), Some(counter));
}

#[test]
fn increasing_counter_accepted() {
    let mut listener = new_listener();
    let identity = test_identity();
    let iv = test_iv();

    assert!(listener.record_for_test(identity, iv, 1));
    assert!(listener.record_for_test(identity, iv, 2));
    assert_eq!(listener.sender_last_counter(identity), Some(2));
}

#[test]
fn same_counter_rejected() {
    let mut listener = new_listener();
    let identity = test_identity();
    let iv = test_iv();

    assert!(listener.record_for_test(identity, iv, 5));
    assert!(!listener.record_for_test(identity, iv, 5));
}

#[test]
fn lower_counter_rejected() {
    let mut listener = new_listener();
    let identity = test_identity();
    let iv = test_iv();

    assert!(listener.record_for_test(identity, iv, 5));
    assert!(!listener.record_for_test(identity, iv, 3));
}

#[test]
fn new_iv_random_accepted_and_rotates() {
    let mut listener = new_listener();
    let identity = test_identity();
    let iv1 = test_iv();
    let iv2 = test_iv2();

    assert!(listener.record_for_test(identity, iv1, 100));
    // Rotation: iv1 → iv2
    assert!(listener.record_for_test(identity, iv2, 1));

    assert_eq!(listener.sender_iv_random(identity), Some(iv2));
    assert_eq!(listener.sender_last_counter(identity), Some(1));
    assert_eq!(listener.sender_prev_iv_random(identity), Some(iv1));
    assert_eq!(listener.sender_prev_last_counter(identity), Some(100));
}

#[test]
fn replay_after_rotation_rejected() {
    let mut listener = new_listener();
    let identity = test_identity();
    let iv1 = test_iv();
    let iv2 = test_iv2();

    // Sender uses iv1 up to counter 100, then rotates to iv2
    assert!(listener.record_for_test(identity, iv1, 100));
    assert!(listener.record_for_test(identity, iv2, 1));

    // Replay of a frame from the iv1 epoch at counter 50 → rejected
    assert!(!listener.record_for_test(identity, iv1, 50));
    // Replay of the last frame from iv1 epoch at counter 100 → rejected (not strictly greater)
    assert!(!listener.record_for_test(identity, iv1, 100));
}

#[test]
fn larger_counter_from_prev_iv_accepted() {
    let mut listener = new_listener();
    let identity = test_identity();
    let iv1 = test_iv();
    let iv2 = test_iv2();

    assert!(listener.record_for_test(identity, iv1, 100));
    assert!(listener.record_for_test(identity, iv2, 1));
    // An out-of-order delayed frame from iv1 with counter > prev_last_counter
    // is accepted (non-replay)
    assert!(listener.record_for_test(identity, iv1, 150));
    assert_eq!(listener.sender_iv_random(identity), Some(iv2));
    assert_eq!(listener.sender_prev_last_counter(identity), Some(150));
}

#[test]
fn double_rotation_shifts_prev() {
    let mut listener = new_listener();
    let identity = test_identity();
    let iv1 = test_iv();
    let iv2 = test_iv2();
    let iv3 = test_iv3();

    assert!(listener.record_for_test(identity, iv1, 100));
    assert!(listener.record_for_test(identity, iv2, 200));
    // Third rotation: iv2 → iv3; iv1 is lost from history
    assert!(listener.record_for_test(identity, iv3, 50));

    assert_eq!(listener.sender_iv_random(identity), Some(iv3));
    assert_eq!(listener.sender_last_counter(identity), Some(50));
    assert_eq!(listener.sender_prev_iv_random(identity), Some(iv2));
    assert_eq!(listener.sender_prev_last_counter(identity), Some(200));
}

#[test]
fn rotate_back_to_first_iv_accepted() {
    let mut listener = new_listener();
    let identity = test_identity();
    let iv1 = test_iv();
    let iv2 = test_iv2();

    assert!(listener.record_for_test(identity, iv1, 100));
    assert!(listener.record_for_test(identity, iv2, 50));
    // Frame from iv1 arrives with counter > prev_last_counter —
    // accepted as non-replay (delayed frame from previous epoch).
    // State is updated but iv2 remains current.
    assert!(listener.record_for_test(identity, iv1, 200));

    assert_eq!(listener.sender_iv_random(identity), Some(iv2));
    assert_eq!(listener.sender_last_counter(identity), Some(50));
    assert_eq!(listener.sender_prev_iv_random(identity), Some(iv1));
    assert_eq!(listener.sender_prev_last_counter(identity), Some(200));
}

#[test]
fn full_table_refuses_new_identity_without_eviction() {
    let mut listener = new_listener();
    let victim_identity = ReplayIdentity::from_pid(9000);
    let iv = test_iv();

    assert!(listener.record_for_test(victim_identity, iv, 10));
    for i in 1..MAX_SENDER_STATES {
        let identity = ReplayIdentity::from_pid(10_000 + i as u32);
        assert!(listener.record_for_test(identity, test_iv2(), 1));
    }
    assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);

    let new_identity = ReplayIdentity::from_pid(60_000);
    assert!(!listener.record_for_test(new_identity, test_iv3(), 1));
    assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);
    assert_eq!(listener.sender_last_counter(victim_identity), Some(10));
    assert!(!listener.record_for_test(victim_identity, iv, 5));
}

#[test]
fn stale_sender_eviction_uses_saturating_age() {
    let mut listener = new_listener();
    let fresh_identity = ReplayIdentity::from_pid(50_001);
    let stale_identity = ReplayIdentity::from_pid(50_002);

    assert!(listener.record_for_test(fresh_identity, test_iv(), 1));
    assert!(listener.record_for_test(stale_identity, test_iv2(), 1));

    let sweep_now = Instant::now() + EVICTION_TTL + Duration::from_secs(2);
    set_last_seen(
        &mut listener,
        fresh_identity,
        sweep_now + Duration::from_secs(1),
    );
    set_last_seen(
        &mut listener,
        stale_identity,
        sweep_now - EVICTION_TTL - Duration::from_secs(1),
    );

    listener.evict_stale_senders_at(sweep_now);

    assert!(
        listener.sender_state_for(fresh_identity).is_some(),
        "future last_seen must saturate to age 0 and remain tracked"
    );
    assert!(
        listener.sender_state_for(stale_identity).is_none(),
        "sender older than EVICTION_TTL must be evicted"
    );
}

// ----- H3: constant-trial-count AEAD poll -----

/// Build a 60-byte shared-key wire frame using the given key, iv_random,
/// iv_counter, and plaintext. Mirrors the layout enforced by
/// `SecureUdpListener::recv` so the listener's parser will accept it.
fn build_shared_frame(
    key: &Key,
    iv_random: [u8; 8],
    iv_counter: u32,
    plaintext: &[u8; 32],
) -> [u8; 60] {
    let mut nonce = [0u8; NONCE_BYTES];
    nonce[..8].copy_from_slice(&iv_random);
    nonce[8..12].copy_from_slice(&iv_counter.to_le_bytes());
    let (ciphertext, tag) = crypto::seal(key.as_bytes(), &nonce, b"", plaintext)
        .expect("seal infallible for fixed-size inputs");

    let mut wire = [0u8; 60];
    wire[0..8].copy_from_slice(&iv_random);
    wire[8..12].copy_from_slice(&iv_counter.to_le_bytes());
    wire[12..44].copy_from_slice(&ciphertext);
    wire[44..60].copy_from_slice(&tag);
    wire
}

/// Spin until the listener returns something other than `WouldBlock`.
/// UDP delivery on localhost is fast but not synchronous; busy-poll a
/// few times before giving up.
fn recv_one(listener: &mut SecureUdpListener) -> RecvResult {
    use std::time::Instant;
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match listener.recv() {
            RecvResult::WouldBlock => {
                if Instant::now() >= deadline {
                    return RecvResult::WouldBlock;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            other => return other,
        }
    }
}

fn bind_with_keys(keys: Vec<Key>) -> SecureUdpListener {
    SecureUdpListener::bind("127.0.0.1:0".parse().unwrap(), keys).expect("bind")
}

fn send_wire(target: SocketAddr, wire: &[u8]) {
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender bind");
    sender.send_to(wire, target).expect("send_to");
}

#[test]
fn overlong_shared_prefix_is_truncated_before_decrypt() {
    let key_bytes = [0x24u8; 32];
    let mut listener = bind_with_keys(vec![Key::from_bytes(key_bytes)]);
    let target = listener.test_local_addr();

    let mut plaintext = [0u8; 32];
    Frame::new(Status::Ok, 24_024, 1, 1, 0).encode(&mut plaintext);
    let shared = build_shared_frame(&Key::from_bytes(key_bytes), test_iv(), 1, &plaintext);
    let mut overlong = [0u8; SECURE_FRAME_RECV_CAP];
    overlong[..SECURE_FRAME_LEN].copy_from_slice(&shared);
    overlong[SECURE_FRAME_LEN..].fill(0xEE);

    send_wire(target, &overlong);

    assert!(
        matches!(recv_one(&mut listener), RecvResult::ShortRead),
        "overlong shared-key datagram must be rejected as wrong-size"
    );
    assert_eq!(listener.drain_truncated(), 1);
    assert_eq!(
        listener.drain_aead_attempts(),
        0,
        "wrong-size datagrams must be rejected before AEAD"
    );
    assert_eq!(listener.drain_decrypt_failures(), 0);
    assert_eq!(listener.sender_state_len(), 0);
}

#[test]
fn overlong_master_prefix_is_truncated_before_decrypt() {
    let master_bytes = [0x42u8; 32];
    let master = Key::from_bytes(master_bytes);
    let mut listener = SecureUdpListener::bind_with_master(
        "127.0.0.1:0".parse().unwrap(),
        vec![],
        Key::from_bytes(master_bytes),
    )
    .expect("bind");
    let target = listener.test_local_addr();

    let agent_pid = 42_042;
    let mut plaintext = [0u8; 32];
    Frame::new(Status::Ok, agent_pid, 1, 1, 0).encode(&mut plaintext);
    let master_wire = build_master_frame(&master, agent_pid, test_iv(), 1, &plaintext);
    let mut overlong = [0u8; SECURE_FRAME_RECV_CAP];
    overlong[..SECURE_FRAME_MASTER_LEN].copy_from_slice(&master_wire);
    overlong[SECURE_FRAME_MASTER_LEN] = 0xEE;

    send_wire(target, &overlong);

    assert!(
        matches!(recv_one(&mut listener), RecvResult::ShortRead),
        "overlong master-key datagram must be rejected as wrong-size"
    );
    assert_eq!(listener.drain_truncated(), 1);
    assert_eq!(
        listener.drain_aead_attempts(),
        0,
        "wrong-size datagrams must be rejected before AEAD"
    );
    assert_eq!(listener.drain_decrypt_failures(), 0);
    assert_eq!(listener.sender_state_len(), 0);
}

#[test]
fn full_table_existing_identity_is_accepted_without_eviction() {
    let key_bytes = [0x5Au8; 32];
    let mut listener = bind_with_keys(vec![Key::from_bytes(key_bytes)]);
    let target = listener.test_local_addr();

    for i in 0..MAX_SENDER_STATES {
        let identity = ReplayIdentity::from_pid(10_000 + i as u32);
        assert!(listener.record_for_test(identity, test_iv(), 1));
    }
    assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);

    let existing_pid = 10_000 + (MAX_SENDER_STATES as u32 - 1);
    let mut plaintext = [0u8; 32];
    Frame::new(Status::Ok, existing_pid, 777, 2, 0).encode(&mut plaintext);
    let wire = build_shared_frame(&Key::from_bytes(key_bytes), test_iv(), 2, &plaintext);

    send_wire(target, &wire);
    match recv_one(&mut listener) {
        RecvResult::Authenticated { data, .. } => {
            assert_eq!(data, plaintext, "known sender should still authenticate");
        }
        _ => panic!("expected existing sender to authenticate"),
    }

    assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);
    assert_eq!(listener.drain_sender_state_full(), 0);
    assert_eq!(
        listener.sender_last_counter(ReplayIdentity::from_pid(existing_pid)),
        Some(2)
    );
    assert!(
        listener
            .sender_state_for(ReplayIdentity::from_pid(10_000))
            .is_some(),
        "accepting a known sender at capacity must not evict unrelated replay state"
    );
}

#[test]
fn full_table_new_identity_is_refused_without_forgetting_replay_state() {
    let key_bytes = [0x6Bu8; 32];
    let mut listener = bind_with_keys(vec![Key::from_bytes(key_bytes)]);
    let target = listener.test_local_addr();
    let victim_identity = ReplayIdentity::from_pid(9000);

    assert!(listener.record_for_test(victim_identity, test_iv(), 10));
    for i in 1..MAX_SENDER_STATES {
        let identity = ReplayIdentity::from_pid(10_000 + i as u32);
        assert!(listener.record_for_test(identity, test_iv2(), 1));
    }
    assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);

    let new_pid = 60_000;
    let mut plaintext = [0u8; 32];
    Frame::new(Status::Ok, new_pid, 777, 1, 0).encode(&mut plaintext);
    let wire = build_shared_frame(&Key::from_bytes(key_bytes), test_iv3(), 1, &plaintext);

    send_wire(target, &wire);
    assert!(
        matches!(recv_one(&mut listener), RecvResult::WouldBlock),
        "new sender at capacity must be consumed and refused"
    );
    assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);
    assert_eq!(listener.drain_sender_state_full(), 1);
    assert_eq!(listener.drain_decrypt_failures(), 0);
    assert_eq!(listener.sender_last_counter(victim_identity), Some(10));
    assert!(!listener.record_for_test(victim_identity, test_iv(), 5));
}

/// A captured ciphertext replayed from a different UDP source port must still
/// be rejected. The replay key is the authenticated frame PID, not the
/// unauthenticated source address.
#[test]
fn replay_from_different_source_port_is_rejected() {
    let key_bytes = [0x5Au8; 32];
    let mut listener = bind_with_keys(vec![Key::from_bytes(key_bytes)]);
    let target = listener.test_local_addr();

    let mut plaintext = [0u8; 32];
    Frame::new(Status::Ok, 12_345, 777, 1, 0).encode(&mut plaintext);
    let wire = build_shared_frame(&Key::from_bytes(key_bytes), test_iv(), 9, &plaintext);

    send_wire(target, &wire);
    match recv_one(&mut listener) {
        RecvResult::Authenticated { data, .. } => {
            assert_eq!(data, plaintext, "first ciphertext should authenticate");
        }
        _ => panic!("expected first frame to authenticate"),
    }

    send_wire(target, &wire);
    assert!(
        matches!(recv_one(&mut listener), RecvResult::WouldBlock),
        "replayed ciphertext from a new source port must be consumed and rejected"
    );
    assert_eq!(
        listener.drain_replay_refused(),
        1,
        "transport replay rejection must increment replay_refused, not decrypt_failures"
    );
    assert_eq!(
        listener.drain_decrypt_failures(),
        0,
        "a replay refusal (AEAD tag valid) must not be counted as a decrypt failure"
    );
}

/// Authenticated UDP payloads that fail VLP decode must still surface to the
/// observer as decode errors, but they must not allocate replay-state slots.
/// Before the fix, a key holder could send CRC-valid `Status::Stall` frames
/// with many distinct pids and fill `MAX_SENDER_STATES` before the observer
/// rejected those frames at `Frame::decode`.
#[test]
fn authenticated_invalid_vlp_does_not_allocate_replay_state() {
    let key_bytes = [0x72u8; 32];
    let mut listener = bind_with_keys(vec![Key::from_bytes(key_bytes)]);
    let target = listener.test_local_addr();

    let pid = 44_444;
    let identity = ReplayIdentity::from_pid(pid);
    let mut plaintext = [0u8; 32];
    Frame::new(Status::Stall, pid, 777, 1, 0).encode(&mut plaintext);
    assert!(
        matches!(
            Frame::decode(&plaintext),
            Err(varta_vlp::DecodeError::StallOnWire)
        ),
        "fixture must be structurally authenticated but VLP-invalid"
    );
    let wire = build_shared_frame(&Key::from_bytes(key_bytes), test_iv(), 1, &plaintext);

    send_wire(target, &wire);
    match recv_one(&mut listener) {
        RecvResult::Authenticated { data, .. } => {
            assert_eq!(data, plaintext, "observer must still see the decode error");
        }
        _ => panic!("expected authenticated plaintext"),
    }

    assert_eq!(
        listener.sender_state_len(),
        0,
        "decode-invalid payload must not allocate sender replay state"
    );
    assert!(listener.sender_state_for(identity).is_none());
    assert_eq!(
        listener.drain_decrypt_failures(),
        0,
        "VLP decode failures remain observer decode errors, not AEAD failures"
    );
}

/// Frame encrypted by the *last* rotation key must still decrypt, AND
/// `drain_aead_attempts` must equal `keys.len()` — proving the poll did
/// not early-exit on success.
#[test]
fn aead_attempts_equals_keys_len_when_last_key_matches() {
    // `Key` is `!Clone` by design; construct two instances over the same
    // public test bytes rather than cloning the secret type.
    let key2_bytes = [0x33u8; 32];
    let mut listener = bind_with_keys(vec![
        Key::from_bytes([0x11u8; 32]),
        Key::from_bytes([0x22u8; 32]),
        Key::from_bytes(key2_bytes),
    ]);
    let target = listener.test_local_addr();

    let plaintext = [0x55u8; 32];
    let wire = build_shared_frame(&Key::from_bytes(key2_bytes), test_iv(), 1, &plaintext);
    send_wire(target, &wire);

    let result = recv_one(&mut listener);
    match result {
        RecvResult::Authenticated { data, .. } => {
            assert_eq!(data, plaintext, "decrypted plaintext must match");
        }
        _ => panic!("expected Authenticated, got non-Authenticated RecvResult"),
    }
    assert_eq!(
        listener.drain_aead_attempts(),
        3,
        "every loaded key must be trialled even when the last one matches"
    );
}

/// Frame encrypted by the *first* rotation key must produce the same
/// attempt count as a last-key match — no early-exit timing signal.
#[test]
fn aead_attempts_equals_keys_len_when_first_key_matches() {
    let key0_bytes = [0x44u8; 32];
    let mut listener = bind_with_keys(vec![
        Key::from_bytes(key0_bytes),
        Key::from_bytes([0x55u8; 32]),
        Key::from_bytes([0x66u8; 32]),
    ]);
    let target = listener.test_local_addr();

    let plaintext = [0xAAu8; 32];
    let wire = build_shared_frame(&Key::from_bytes(key0_bytes), test_iv(), 1, &plaintext);
    send_wire(target, &wire);

    let result = recv_one(&mut listener);
    match result {
        RecvResult::Authenticated { data, .. } => {
            assert_eq!(data, plaintext, "decrypted plaintext must match");
        }
        _ => panic!("expected Authenticated, got non-Authenticated RecvResult"),
    }
    assert_eq!(
        listener.drain_aead_attempts(),
        3,
        "every loaded key must be trialled even when the first one matches"
    );
}

/// Build a 64-byte master-key wire frame. Mirrors the layout parsed by
/// the `SECURE_FRAME_MASTER_LEN` arm in `SecureUdpListener::recv`.
fn build_master_frame(
    master: &Key,
    agent_pid: u32,
    iv_random: [u8; 8],
    iv_counter: u32,
    plaintext: &[u8; 32],
) -> [u8; 64] {
    use varta_vlp::crypto::kdf;
    let agent_key = kdf::derive_agent_key(master, agent_pid).expect("KDF infallible");
    let mut nonce = [0u8; NONCE_BYTES];
    nonce[..8].copy_from_slice(&iv_random);
    nonce[8..12].copy_from_slice(&iv_counter.to_le_bytes());
    let aad = agent_pid.to_le_bytes();
    let (ciphertext, tag) =
        crypto::seal(agent_key.as_bytes(), &nonce, &aad, plaintext).expect("seal infallible");
    let mut wire = [0u8; 64];
    wire[0..4].copy_from_slice(&aad);
    wire[4..12].copy_from_slice(&iv_random);
    wire[12..16].copy_from_slice(&iv_counter.to_le_bytes());
    wire[16..48].copy_from_slice(&ciphertext);
    wire[48..64].copy_from_slice(&tag);
    wire
}

/// Master-key frames must count the derived-key AEAD attempt in
/// `aead_attempts` — total must equal `shared_keys.len() + 1`.
/// Before the fix the master attempt was silently uncounted, making
/// the operator invariant "attempts == frames × (keys + 1)" false.
#[test]
fn aead_attempts_includes_master_key_attempt() {
    let master_bytes = [0xABu8; 32];
    let mut listener = SecureUdpListener::bind_with_master(
        "127.0.0.1:0".parse().unwrap(),
        vec![Key::from_bytes([0x11u8; 32]), Key::from_bytes([0x22u8; 32])],
        Key::from_bytes(master_bytes),
    )
    .expect("bind");
    let target = listener.test_local_addr();

    let agent_pid: u32 = 12345;
    // plaintext pid field (bytes 4..8) must match agent_pid so the inner-PID
    // defence in try_master_key_decrypt passes.
    let mut plaintext = [0u8; 32];
    plaintext[4..8].copy_from_slice(&agent_pid.to_le_bytes());

    let wire = build_master_frame(
        &Key::from_bytes(master_bytes),
        agent_pid,
        test_iv(),
        1,
        &plaintext,
    );
    send_wire(target, &wire);

    let _ = recv_one(&mut listener);
    assert_eq!(
        listener.drain_aead_attempts(),
        3, // 2 shared keys + 1 master-key derivation
        "master-key AEAD attempt must be counted: total == keys.len() + 1"
    );
}

/// Frame that decrypts under no key must still pay the full attempt
/// budget — failure path is constant-trial-count too.
#[test]
fn aead_attempts_equals_keys_len_on_decrypt_failure() {
    let key0 = Key::from_bytes([0x77u8; 32]);
    let key1 = Key::from_bytes([0x88u8; 32]);
    let key2 = Key::from_bytes([0x99u8; 32]);
    let mut listener = bind_with_keys(vec![key0, key1, key2]);
    let target = listener.test_local_addr();

    // Encrypt with an unrelated key the listener does not hold.
    let stranger = Key::from_bytes([0xFFu8; 32]);
    let plaintext = [0xBBu8; 32];
    let wire = build_shared_frame(&stranger, test_iv(), 1, &plaintext);
    send_wire(target, &wire);

    // recv() consumes one unauthenticated frame, increments
    // decrypt_failures, and returns WouldBlock.
    let _ = recv_one(&mut listener);
    assert_eq!(
        listener.drain_aead_attempts(),
        3,
        "decrypt-failure path must still pay the full attempt budget"
    );
}

#[test]
fn rejected_ciphertext_reports_consumed_io_to_observer() {
    let key_bytes = [0xA1u8; 32];
    let listener = bind_with_keys(vec![Key::from_bytes(key_bytes)]);
    let target = listener.test_local_addr();
    let mut observer = Observer::from_listener(
        listener,
        Duration::from_secs(60),
        64,
        EvictionPolicy::Strict,
        crate::tracker::DEFAULT_EVICTION_SCAN_WINDOW,
        None,
        0,
        0,
        ClockSource::Monotonic,
    )
    .expect("observer construction");

    let stranger = Key::from_bytes([0xB2u8; 32]);
    let wire = build_shared_frame(&stranger, test_iv(), 1, &[0xCCu8; 32]);
    send_wire(target, &wire);

    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        assert!(
            observer.poll().is_none(),
            "AEAD-invalid datagram must not produce an observer event"
        );
        if observer.drain_decrypt_failures() == 1 {
            assert!(
                observer.last_poll_consumed(),
                "a rejected secure datagram was dequeued, so the main loop \
                 must keep draining instead of taking the 10 ms idle sleep"
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "observer did not consume the queued invalid ciphertext"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn recv_returns_after_one_decrypt_failure_even_when_valid_frame_is_queued() {
    use std::time::Instant;

    let key_bytes = [0x31u8; 32];
    let mut listener = bind_with_keys(vec![Key::from_bytes(key_bytes)]);
    let target = listener.test_local_addr();

    let invalid_wire =
        build_shared_frame(&Key::from_bytes([0xFFu8; 32]), test_iv(), 1, &[0xBBu8; 32]);
    let mut valid_plaintext = [0u8; 32];
    Frame::new(Status::Ok, 22_222, 777, 1, 0).encode(&mut valid_plaintext);
    let valid_wire =
        build_shared_frame(&Key::from_bytes(key_bytes), test_iv(), 1, &valid_plaintext);

    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender bind");
    sender.send_to(&invalid_wire, target).expect("send invalid");
    sender.send_to(&valid_wire, target).expect("send valid");

    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match listener.recv() {
            RecvResult::WouldBlock => {
                if listener.drain_decrypt_failures() == 1 {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "listener did not consume the queued invalid frame"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            RecvResult::Authenticated { .. } => {
                panic!("recv must not drain past an invalid frame to a queued valid frame")
            }
            RecvResult::ShortRead => panic!("test sends only secure-frame-sized datagrams"),
            RecvResult::CtrlTruncated(e) | RecvResult::IoError(e) => {
                panic!("unexpected receive error: {e}")
            }
        }
    }

    match recv_one(&mut listener) {
        RecvResult::Authenticated { data, .. } => assert_eq!(data, valid_plaintext),
        _ => panic!("queued valid frame should authenticate on the next recv call"),
    }
}
