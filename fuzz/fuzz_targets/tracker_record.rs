#![no_main]

use libfuzzer_sys::fuzz_target;
use varta_watch::tracker::{Tracker, Update};

fuzz_target!(|data: &[u8]| {
    // Each record call consumes 37 bytes of input:
    //   pid(4) + nonce(8) + status_raw(1) + timestamp(8) + now_ns(8) + threshold_ns(8)
    const RECORD_BYTES: usize = 37;

    if data.is_empty() {
        return;
    }

    // Capacity between 1 and 65 — exercises full, near-full, and tiny trackers.
    let capacity = 1 + (data[0] as usize % 65);
    let mut tracker = Tracker::new(capacity);
    let mut offset: usize = 1;
    let mut wall: u64 = 0;

    while offset + RECORD_BYTES <= data.len() {
        let chunk = &data[offset..offset + RECORD_BYTES];
        offset += RECORD_BYTES;

        let pid = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let nonce = u64::from_le_bytes([
            chunk[4], chunk[5], chunk[6], chunk[7], chunk[8], chunk[9], chunk[10], chunk[11],
        ]);
        let status = match varta_vlp::Status::try_from_u8(chunk[12] & 0x03) {
            Ok(s) => s,
            Err(_) => varta_vlp::Status::Ok,
        };
        let timestamp = u64::from_le_bytes([
            chunk[13], chunk[14], chunk[15], chunk[16],
            chunk[17], chunk[18], chunk[19], chunk[20],
        ]);
        let now_ns = u64::from_le_bytes([
            chunk[21], chunk[22], chunk[23], chunk[24],
            chunk[25], chunk[26], chunk[27], chunk[28],
        ]);
        let threshold_ns = u64::from_le_bytes([
            chunk[29], chunk[30], chunk[31], chunk[32],
            chunk[33], chunk[34], chunk[35], chunk[36],
        ]);

        wall = wall.wrapping_add(1).max(now_ns);

        let frame = varta_vlp::Frame {
            magic: varta_vlp::MAGIC,
            version: varta_vlp::VERSION,
            status,
            pid,
            timestamp,
            nonce,
            payload: 0,
        };

        let _update = tracker.record(&frame, wall, threshold_ns);

        // Periodically drain stall iterators and counter reads so those
        // code paths see a mixture of populated / empty trackers.
        if offset % 7 < 3 {
            let _: Vec<_> = tracker.iter_stalled(wall, threshold_ns).collect();
            let _ = tracker.take_evictions();
            let _ = tracker.take_capacity_exceeded();
            let _ = tracker.len();
            let _ = tracker.is_empty();
        }
    }

    // Final invariants: counter reads must never panic on any tracker state.
    let _ = tracker.take_evictions();
    let _ = tracker.take_capacity_exceeded();
    let _ = tracker.len();
    let _ = tracker.is_empty();
    let _ = tracker.iter_stalled(wall, 1).collect::<Vec<_>>();
});
