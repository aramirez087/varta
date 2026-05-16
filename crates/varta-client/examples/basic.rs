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
        match agent.beat(varta_client::Status::Ok, 0) {
            varta_client::BeatOutcome::Sent => {}
            varta_client::BeatOutcome::Dropped(_) => {
                eprintln!("varta: beat dropped (observer down or queue full)");
            }
            varta_client::BeatOutcome::Failed(e) => {
                eprintln!("varta: beat failed: {e}");
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
