//! Example: Varta agent with secure UDP transport (ChaCha20-Poly1305 AEAD).
//!
//! Demonstrates connecting to a `varta-watch` observer over encrypted UDP.
//! The agent emits 10 heartbeats at 500ms intervals, toggling between
//! `Ok` and `Degraded` status.
//!
//! # Usage
//!
//! 1. Start the observer (in another terminal):
//!    ```sh
//!    cargo run -p varta-watch --features secure-udp -- \
//!        --socket /tmp/varta.sock \
//!        --threshold-ms 2000 \
//!        --udp-port 9000 \
//!        --key-file /tmp/varta.key
//!    ```
//!
//! 2. Generate a key (one-time):
//!    ```sh
//!    openssl rand -hex 32 > /tmp/varta.key
//!    ```
//!
//! 3. Run this example:
//!    ```sh
//!    cargo run -p varta-client --features secure-udp --example secure_udp
//!    ```

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use varta_client::{BeatOutcome, SecureUdpTransport, Status, Varta};

fn main() -> io::Result<()> {
    let key_val = std::env::var("VARTA_KEY").unwrap_or_else(|_| {
        eprintln!("VARTA_KEY not set — using zero key (INSECURE, for demo only)");
        // 64 zeros = insecure demo key
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    });

    let key = varta_vlp::crypto::Key::from_hex(&key_val)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid key: {e}")))?;

    let addr: SocketAddr = "127.0.0.1:9000".parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid address: {e}"))
    })?;

    let mut agent = Varta::<SecureUdpTransport>::connect_secure_udp(addr, key)?;

    println!("Connected to {addr} with secure UDP. Emitting 10 beats...");

    for i in 0..10 {
        let status = if i % 2 == 0 {
            Status::Ok
        } else {
            Status::Degraded
        };

        let outcome = agent.beat(status, i);
        match outcome {
            BeatOutcome::Sent => println!("beat {i}: sent (status={status:?})"),
            BeatOutcome::Dropped => println!("beat {i}: dropped"),
            BeatOutcome::Failed(e) => eprintln!("beat {i}: failed — {e}"),
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    println!("Done.");
    Ok(())
}
