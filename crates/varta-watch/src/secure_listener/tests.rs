use super::*;
use std::net::SocketAddr;

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

fn new_listener() -> SecureUdpListener {
    SecureUdpListener::bind("127.0.0.1:0".parse().unwrap(), vec![test_key()])
        .expect("bind should succeed")
}

fn test_addr() -> SocketAddr {
    "127.0.0.1:9999".parse().unwrap()
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
    let addr = test_addr();
    let iv = test_iv();
    let counter = 1;

    assert!(listener.try_record_replay_state(addr, iv, counter));
    assert_eq!(listener.sender_iv_random(&addr), Some(iv));
    assert_eq!(listener.sender_last_counter(&addr), Some(counter));
}

#[test]
fn increasing_counter_accepted() {
    let mut listener = new_listener();
    let addr = test_addr();
    let iv = test_iv();

    assert!(listener.try_record_replay_state(addr, iv, 1));
    assert!(listener.try_record_replay_state(addr, iv, 2));
    assert_eq!(listener.sender_last_counter(&addr), Some(2));
}

#[test]
fn same_counter_rejected() {
    let mut listener = new_listener();
    let addr = test_addr();
    let iv = test_iv();

    assert!(listener.try_record_replay_state(addr, iv, 5));
    assert!(!listener.try_record_replay_state(addr, iv, 5));
}

#[test]
fn lower_counter_rejected() {
    let mut listener = new_listener();
    let addr = test_addr();
    let iv = test_iv();

    assert!(listener.try_record_replay_state(addr, iv, 5));
    assert!(!listener.try_record_replay_state(addr, iv, 3));
}

#[test]
fn new_iv_random_accepted_and_rotates() {
    let mut listener = new_listener();
    let addr = test_addr();
    let iv1 = test_iv();
    let iv2 = test_iv2();

    assert!(listener.try_record_replay_state(addr, iv1, 100));
    // Rotation: iv1 → iv2
    assert!(listener.try_record_replay_state(addr, iv2, 1));

    assert_eq!(listener.sender_iv_random(&addr), Some(iv2));
    assert_eq!(listener.sender_last_counter(&addr), Some(1));
    assert_eq!(listener.sender_prev_iv_random(&addr), Some(iv1));
    assert_eq!(listener.sender_prev_last_counter(&addr), Some(100));
}

#[test]
fn replay_after_rotation_rejected() {
    let mut listener = new_listener();
    let addr = test_addr();
    let iv1 = test_iv();
    let iv2 = test_iv2();

    // Sender uses iv1 up to counter 100, then rotates to iv2
    assert!(listener.try_record_replay_state(addr, iv1, 100));
    assert!(listener.try_record_replay_state(addr, iv2, 1));

    // Replay of a frame from the iv1 epoch at counter 50 → rejected
    assert!(!listener.try_record_replay_state(addr, iv1, 50));
    // Replay of the last frame from iv1 epoch at counter 100 → rejected (not strictly greater)
    assert!(!listener.try_record_replay_state(addr, iv1, 100));
}

#[test]
fn larger_counter_from_prev_iv_accepted() {
    let mut listener = new_listener();
    let addr = test_addr();
    let iv1 = test_iv();
    let iv2 = test_iv2();

    assert!(listener.try_record_replay_state(addr, iv1, 100));
    assert!(listener.try_record_replay_state(addr, iv2, 1));
    // An out-of-order delayed frame from iv1 with counter > prev_last_counter
    // is accepted (non-replay)
    assert!(listener.try_record_replay_state(addr, iv1, 150));
    assert_eq!(listener.sender_iv_random(&addr), Some(iv2));
    assert_eq!(listener.sender_prev_last_counter(&addr), Some(150));
}

#[test]
fn double_rotation_shifts_prev() {
    let mut listener = new_listener();
    let addr = test_addr();
    let iv1 = test_iv();
    let iv2 = test_iv2();
    let iv3 = test_iv3();

    assert!(listener.try_record_replay_state(addr, iv1, 100));
    assert!(listener.try_record_replay_state(addr, iv2, 200));
    // Third rotation: iv2 → iv3; iv1 is lost from history
    assert!(listener.try_record_replay_state(addr, iv3, 50));

    assert_eq!(listener.sender_iv_random(&addr), Some(iv3));
    assert_eq!(listener.sender_last_counter(&addr), Some(50));
    assert_eq!(listener.sender_prev_iv_random(&addr), Some(iv2));
    assert_eq!(listener.sender_prev_last_counter(&addr), Some(200));
}

#[test]
fn rotate_back_to_first_iv_accepted() {
    let mut listener = new_listener();
    let addr = test_addr();
    let iv1 = test_iv();
    let iv2 = test_iv2();

    assert!(listener.try_record_replay_state(addr, iv1, 100));
    assert!(listener.try_record_replay_state(addr, iv2, 50));
    // Frame from iv1 arrives with counter > prev_last_counter —
    // accepted as non-replay (delayed frame from previous epoch).
    // State is updated but iv2 remains current.
    assert!(listener.try_record_replay_state(addr, iv1, 200));

    assert_eq!(listener.sender_iv_random(&addr), Some(iv2));
    assert_eq!(listener.sender_last_counter(&addr), Some(50));
    assert_eq!(listener.sender_prev_iv_random(&addr), Some(iv1));
    assert_eq!(listener.sender_prev_last_counter(&addr), Some(200));
}

#[test]
fn capacity_exceeded_forces_evict_and_increments_counter() {
    let mut listener = new_listener();
    // Fill the map with unique addresses.
    for i in 0..MAX_SENDER_STATES {
        let addr = SocketAddr::from(([127, 0, 0, 1], (10_000 + i as u16)));
        assert!(listener.try_record_replay_state(addr, test_iv(), 1));
    }
    assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);

    // Eviction before force-evict is a no-op for fresh entries.
    listener.evict_stale_senders();
    assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);

    // Force-evict should remove one entry.
    listener.force_evict_oldest_sender();
    assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES - 1);
}

#[test]
fn evicted_sender_replay_rejected_repeatedly() {
    let mut listener = new_listener();
    let victim_addr = SocketAddr::from(([127, 0, 0, 1], 9000));
    let iv = test_iv();

    // Victim sends frames up to counter 10.
    assert!(listener.try_record_replay_state(victim_addr, iv, 10));

    // Fill remaining slots so table is at capacity.
    for i in 1..MAX_SENDER_STATES {
        let addr = SocketAddr::from(([127, 0, 0, 1], (10_000 + i as u16)));
        assert!(listener.try_record_replay_state(addr, test_iv2(), 1));
    }
    assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);

    // Force-evict the victim (oldest entry).
    listener.force_evict_oldest_sender();
    assert!(listener
        .last_evicted
        .as_ref()
        .is_some_and(|(a, _)| *a == victim_addr));

    // Attacker replays an old frame (counter 5) — must be rejected.
    assert!(!listener.try_record_replay_state(victim_addr, iv, 5));
    // Shadow must survive the rejection so the next replay is also caught.
    assert!(listener.last_evicted.is_some());

    // Second replay of the same frame — must still be rejected, not
    // treated as a new sender.
    assert!(!listener.try_record_replay_state(victim_addr, iv, 5));
    assert!(listener.last_evicted.is_some());

    // A genuinely new frame (counter 11) from the victim should pass.
    assert!(listener.try_record_replay_state(victim_addr, iv, 11));
    // Shadow consumed on success.
    assert!(listener.last_evicted.is_none());
}

#[test]
fn shadow_restored_when_allocate_fails() {
    let mut listener = new_listener();
    let victim_addr = SocketAddr::from(([127, 0, 0, 1], 9000));
    let iv = test_iv();

    // Victim sends frames up to counter 10.
    assert!(listener.try_record_replay_state(victim_addr, iv, 10));

    // Fill remaining slots so table is at capacity.
    for i in 1..MAX_SENDER_STATES {
        let addr = SocketAddr::from(([127, 0, 0, 1], (10_000 + i as u16)));
        assert!(listener.try_record_replay_state(addr, test_iv2(), 1));
    }

    // Force-evict the victim — it goes to the shadow.
    listener.force_evict_oldest_sender();
    assert!(listener
        .last_evicted
        .as_ref()
        .is_some_and(|(a, _)| *a == victim_addr));

    // Consume the freed slot with a brand-new sender so the slab is full
    // again. This makes the next allocate_sender_slot call fail.
    let filler = SocketAddr::from(([127, 0, 0, 1], 60_000));
    assert!(listener.try_record_replay_state(filler, test_iv2(), 1));
    assert_eq!(listener.sender_state_len(), MAX_SENDER_STATES);

    // A genuinely new frame from the victim (counter 11) enters the
    // shadow path, passes validation, but allocate_sender_slot fails
    // because the slab is full. The shadow must be RESTORED.
    assert!(!listener.try_record_replay_state(victim_addr, iv, 11));
    assert!(listener.last_evicted.is_some());

    // A replay of an old counter must still be rejected — the shadow
    // was restored with the advanced counter (11), so counter ≤ 11 fails.
    assert!(!listener.try_record_replay_state(victim_addr, iv, 11));
    assert!(!listener.try_record_replay_state(victim_addr, iv, 5));
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

    // recv() consumes datagrams in a loop; the unauthenticated frame
    // increments decrypt_failures and continues, returning WouldBlock.
    let _ = recv_one(&mut listener);
    assert_eq!(
        listener.drain_aead_attempts(),
        3,
        "decrypt-failure path must still pay the full attempt budget"
    );
}
