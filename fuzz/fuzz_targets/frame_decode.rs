#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Pass any input size — short slices are harmless (Frame::decode takes
    // &[u8; 32] so they can't reach it), and with 32+ bytes we exercise
    // all decode branches: magic check, version check, status discriminant
    // range, and the full 7-field decode path.
    if data.len() >= 32 {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&data[..32]);
        let _ = varta_vlp::Frame::decode(&buf);
    }
});
