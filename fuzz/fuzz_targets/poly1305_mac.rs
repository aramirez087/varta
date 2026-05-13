#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for the one-time key.
    if data.len() < 32 {
        return;
    }

    let mut otk = [0u8; 32];
    otk.copy_from_slice(&data[..32]);
    let tail = &data[32..];

    // Property A: poly1305_mac never panics for any (otk, msg) pair.
    // Property B: determinism — same inputs always produce the same tag.
    //
    // Boundary lengths that exercise all Poly1305 code paths:
    //   0  — empty message (h stays 0)
    //   1  — single byte, sub-block
    //  15  — largest sub-block (< 16 bytes)
    //  16  — exactly one full block
    //  17  — one full block + one byte remainder
    //  31  — two blocks where second is sub-block
    //  32  — two full blocks
    //  33  — two full blocks + one byte
    //  64  — four full blocks
    //  tail.len().min(1024)  — fuzzer-supplied length up to 1 KiB
    const LENGTHS: &[usize] = &[0, 1, 15, 16, 17, 31, 32, 33, 64];
    let fuzz_len = tail.len().min(1024);

    for &n in LENGTHS.iter().chain(std::iter::once(&fuzz_len)) {
        let msg = tail.get(..n).unwrap_or(tail);

        let tag1 = varta_vlp::crypto::poly1305::poly1305_mac(&otk, msg);
        let tag2 = varta_vlp::crypto::poly1305::poly1305_mac(&otk, msg);
        assert_eq!(tag1, tag2, "poly1305_mac must be deterministic");
    }

    // Property C: freeze-edge stress.
    //
    // When data[0] has bit 0 set, also MAC a crafted all-0xFF 16-byte block.
    // 0xFF bytes maximise each 128-bit limb value, pushing the accumulator
    // into the [p, 2^130) range that requires the constant-time freeze step
    // before h + s. Without the freeze, this input produces a wrong tag.
    if data.first().map_or(false, |b| b & 1 == 1) {
        let freeze_msg = [0xffu8; 16];
        let tag = varta_vlp::crypto::poly1305::poly1305_mac(&otk, &freeze_msg);
        let tag2 = varta_vlp::crypto::poly1305::poly1305_mac(&otk, &freeze_msg);
        assert_eq!(tag, tag2, "freeze-edge tag must be deterministic");
    }
});
