#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let mut magic = [0u8; 2];
    magic.copy_from_slice(&data[0..2]);

    let version = data[2];
    let status_byte = data[3];

    let mut pid_bytes = [0u8; 4];
    pid_bytes.copy_from_slice(&data[4..8]);
    let pid = u32::from_le_bytes(pid_bytes);

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&data[8..16]);
    let timestamp = u64::from_le_bytes(ts_bytes);

    let mut nonce_bytes = [0u8; 8];
    nonce_bytes.copy_from_slice(&data[16..24]);
    let nonce = u64::from_le_bytes(nonce_bytes);

    let mut payload_bytes = [0u8; 8];
    payload_bytes.copy_from_slice(&data[24..32]);
    let payload = u64::from_le_bytes(payload_bytes);

    let status = match varta_vlp::Status::try_from_u8(status_byte) {
        Ok(s) => s,
        Err(_) => return,
    };

    let frame = varta_vlp::Frame {
        magic,
        version,
        status,
        pid,
        timestamp,
        nonce,
        payload,
    };

    let mut buf = [0u8; 32];
    frame.encode(&mut buf);

    match varta_vlp::Frame::decode(&buf) {
        Ok(decoded) => {
            assert_eq!(decoded.magic, frame.magic, "magic mismatch");
            assert_eq!(decoded.version, frame.version, "version mismatch");
            assert_eq!(decoded.status, frame.status, "status mismatch");
            assert_eq!(decoded.pid, frame.pid, "pid mismatch");
            assert_eq!(decoded.timestamp, frame.timestamp, "timestamp mismatch");
            assert_eq!(decoded.nonce, frame.nonce, "nonce mismatch");
            assert_eq!(decoded.payload, frame.payload, "payload mismatch");
        }
        Err(_) => {
            // Decode rejected a frame whose magic/version/status we allowed
            // through — that's fine (e.g. bad magic bytes).  The fuzzer
            // is really checking that encode → decode never panics and
            // that when decode succeeds it round-trips exactly.
        }
    }
});
