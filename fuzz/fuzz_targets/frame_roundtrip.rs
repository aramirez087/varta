#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 28 {
        return;
    }

    let mut magic = [0u8; 2];
    magic.copy_from_slice(&data[0..2]);

    let version = data[2];
    let status_byte = data[3];

    let pid = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let timestamp = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    let nonce = u64::from_le_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);

    // VLP v0.2: payload is u32 at bytes 24..28; bytes 28..32 carry CRC-32C
    // over bytes 0..28 (overwritten below regardless of fuzz input).
    let payload = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

    let status = match varta_vlp::Status::try_from_u8(status_byte) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Build the raw 32-byte frame via encode-equivalent byte writes
    // (same layout Frame::encode produces) so we can test decode round-tripping
    // without constructing a non_exhaustive Frame from outside the crate.
    let mut buf = [0u8; 32];
    buf[0..2].copy_from_slice(&magic);
    buf[2] = version;
    buf[3] = status_byte;
    buf[4..8].copy_from_slice(&pid.to_le_bytes());
    buf[8..16].copy_from_slice(&timestamp.to_le_bytes());
    buf[16..24].copy_from_slice(&nonce.to_le_bytes());
    buf[24..28].copy_from_slice(&payload.to_le_bytes());
    let crc = varta_vlp::crc32c::compute(&buf[0..28]);
    buf[28..32].copy_from_slice(&crc.to_le_bytes());

    match varta_vlp::Frame::decode(&buf) {
        Ok(decoded) => {
            assert_eq!(decoded.magic, magic, "magic mismatch");
            assert_eq!(decoded.version, version, "version mismatch");
            assert_eq!(decoded.status, status, "status mismatch");
            assert_eq!(decoded.pid, pid, "pid mismatch");
            assert_eq!(decoded.timestamp, timestamp, "timestamp mismatch");
            assert_eq!(decoded.nonce, nonce, "nonce mismatch");
            assert_eq!(decoded.payload, payload, "payload mismatch");
        }
        Err(_) => {
            // Decode rejected a frame whose magic/version/status we allowed
            // through — that's fine (e.g. bad magic bytes).  The fuzzer
            // is really checking that encode → decode never panics and
            // that when decode succeeds it round-trips exactly.
        }
    }
});
