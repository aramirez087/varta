//! Minimal Varta beat loop — connect once, emit `Status::Ok` every 500 ms.
//!
//! Run alongside varta-watch:
//!
//! ```sh
//! varta-watch --socket /tmp/varta.sock --threshold-ms 2000 &
//! cargo run --example basic
//! ```

fn main() -> std::io::Result<()> {
    let mut agent = varta_client::Varta::connect("/tmp/varta.sock")?;
    loop {
        let _ = agent.beat(varta_client::Status::Ok, 0);
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
