#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() == 32 {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(data);
        let _ = varta_vlp::Frame::decode(&buf);
    }
});
