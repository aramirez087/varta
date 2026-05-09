//! Beat loop that packs queue depth and last error code into the 64-bit payload.
//!
//! Layout: high 32 bits = queue_depth, low 32 bits = last_error_code.
//! The observer carries the payload opaquely; decoding is the agent's concern.
//!
//! Run alongside varta-watch:
//!
//! ```sh
//! varta-watch --socket /tmp/varta.sock --threshold-ms 2000 &
//! cargo run --example with_payload
//! ```

use std::sync::atomic::{AtomicU32, Ordering};

static QUEUE_DEPTH: AtomicU32 = AtomicU32::new(0);
static LAST_ERROR: AtomicU32 = AtomicU32::new(0);

fn main() -> std::io::Result<()> {
    let mut agent = varta_client::Varta::connect("/tmp/varta.sock")?;
    loop {
        let depth = QUEUE_DEPTH.load(Ordering::Relaxed);
        let err = LAST_ERROR.load(Ordering::Relaxed);
        let payload = (depth as u64) << 32 | (err as u64);
        let _ = agent.beat(varta_client::Status::Ok, payload);
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
