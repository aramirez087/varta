//! Beat loop that packs queue depth and last error code into the 32-bit payload.
//!
//! Layout: high 16 bits = queue_depth (capped), low 16 bits = last_error_code.
//! The observer carries the payload opaquely; decoding is the agent's concern.
//!
//! VLP v0.2 shrunk `payload` from `u64` to `u32` to make room for the
//! CRC-32C wire-integrity trailer. Agents that need more than 4 bytes of
//! context should externalize the data and reference it from the payload
//! (e.g. as a slot index into a shared ring buffer).
//!
//! Run alongside varta-watch:
//!
//! ```sh
//! varta-watch --socket /tmp/varta.sock --threshold-ms 2000 &
//! cargo run --example with_payload
//! ```

use std::sync::atomic::{AtomicU16, Ordering};

static QUEUE_DEPTH: AtomicU16 = AtomicU16::new(0);
static LAST_ERROR: AtomicU16 = AtomicU16::new(0);

fn main() -> std::io::Result<()> {
    let mut agent = varta_client::Varta::connect("/tmp/varta.sock")?;
    loop {
        let depth = QUEUE_DEPTH.load(Ordering::Relaxed);
        let err = LAST_ERROR.load(Ordering::Relaxed);
        let payload = ((depth as u32) << 16) | (err as u32);
        match agent.beat(varta_client::Status::Ok, payload) {
            varta_client::BeatOutcome::Sent => {}
            varta_client::BeatOutcome::Dropped => {
                eprintln!("varta: beat dropped (observer down or queue full)");
            }
            varta_client::BeatOutcome::Failed(e) => {
                eprintln!("varta: beat failed: {e}");
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
