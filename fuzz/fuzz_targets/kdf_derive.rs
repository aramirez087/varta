#![no_main]

use libfuzzer_sys::fuzz_target;
use varta_vlp::crypto::kdf;
use varta_vlp::crypto::Key;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Use first 32 bytes as master key (pad/truncate).
    let mut master_bytes = [0u8; 32];
    let copy_len = std::cmp::min(data.len(), 32);
    master_bytes[..copy_len].copy_from_slice(&data[..copy_len]);
    let master = Key::from_bytes(master_bytes);

    // Different agent IDs must produce different keys.
    let k0 = kdf::derive_agent_key(&master, 0);
    let k1 = kdf::derive_agent_key(&master, 1);
    assert_ne!(
        k0.as_bytes(),
        k1.as_bytes(),
        "different agent IDs must produce different keys"
    );

    // Different epochs must produce different keys.
    let e0 = kdf::derive_epoch_key(&k0, 0);
    let e1 = kdf::derive_epoch_key(&k0, 1);
    assert_ne!(
        e0.as_bytes(),
        e1.as_bytes(),
        "different epochs must produce different keys"
    );

    // Agent key must differ from its epoch key.
    assert_ne!(
        k0.as_bytes(),
        e0.as_bytes(),
        "agent key must differ from its epoch key"
    );

    // Determinism: same inputs produce same outputs.
    let k0_again = kdf::derive_agent_key(&master, 0);
    assert_eq!(
        k0.as_bytes(),
        k0_again.as_bytes(),
        "derivation must be deterministic"
    );

    // Key hierarchy is one-way: agent 0's key != master key.
    assert_ne!(
        k0.as_bytes(),
        master.as_bytes(),
        "derived key must differ from master"
    );

    // Fuzz with arbitrary PIDs and epochs extracted from the input.
    if data.len() >= 44 {
        let agent_id = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        let epoch = u64::from_le_bytes([
            data[36], data[37], data[38], data[39],
            data[40], data[41], data[42], data[43],
        ]);
        let key = kdf::derive_agent_key(&master, agent_id);
        let ekey = kdf::derive_epoch_key(&key, epoch);

        // Determinism for fuzzed inputs.
        let key2 = kdf::derive_agent_key(&master, agent_id);
        assert_eq!(
            key.as_bytes(),
            key2.as_bytes(),
            "determinism for fuzzed agent_id"
        );
        let ekey2 = kdf::derive_epoch_key(&key, epoch);
        assert_eq!(
            ekey.as_bytes(),
            ekey2.as_bytes(),
            "determinism for fuzzed epoch"
        );
    }
});
