#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[..32]);

        let nonce = if data.len() >= 44 {
            let mut n = [0u8; 12];
            n.copy_from_slice(&data[32..44]);
            n
        } else {
            return;
        };

        let plaintext = if data.len() >= 76 {
            let mut p = [0u8; 32];
            p.copy_from_slice(&data[44..76]);
            p
        } else {
            return;
        };

        // Extract optional AAD from fuzz data (4 bytes after plaintext)
        let aad: &[u8] = if data.len() >= 80 { &data[76..80] } else { b"" };

        // Roundtrip: encrypt then decrypt with same key/nonce/aad
        let (ciphertext, tag) = varta_vlp::crypto::seal(&key, &nonce, aad, &plaintext);

        match varta_vlp::crypto::open(&key, &nonce, aad, &ciphertext, &tag) {
            Ok(decrypted) => {
                assert_eq!(decrypted, plaintext, "roundtrip mismatch");
            }
            Err(_) => {
                panic!("roundtrip decryption failed after successful encryption");
            }
        }

        // Tampered ciphertext must fail (false-positive probability ~ 2^-128)
        if ciphertext != [0u8; 32] {
            let mut tampered = ciphertext;
            tampered[0] ^= 0x01;
            let result = varta_vlp::crypto::open(&key, &nonce, aad, &tampered, &tag);
            assert!(result.is_err(), "tampered ciphertext must not pass AEAD");
        }

        // Wrong key must fail
        let mut wrong_key = key;
        wrong_key[0] ^= 0x01;
        let result = varta_vlp::crypto::open(&wrong_key, &nonce, aad, &ciphertext, &tag);
        assert!(result.is_err(), "wrong key must not pass AEAD");
    }
});
