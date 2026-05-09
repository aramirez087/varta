//! Demonstrates the opt-in panic handler.
//!
//! When the process panics, a `Status::Critical` VLP frame is emitted to the
//! observer before the normal panic message and stack unwind proceed.
//!
//! Build and run:
//!
//! ```sh
//! varta-watch --socket /tmp/varta.sock --threshold-ms 2000 &
//! cargo run --example with_panic_handler --features panic-handler
//! ```

fn main() -> std::io::Result<()> {
    // Register the hook before connecting so any early panic is still signalled.
    varta_client::install_panic_handler("/tmp/varta.sock");

    let mut agent = varta_client::Varta::connect("/tmp/varta.sock")?;
    for _ in 0..10 {
        let _ = agent.beat(varta_client::Status::Ok, 0);
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(())
}
