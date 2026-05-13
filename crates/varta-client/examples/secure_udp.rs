//! Example: Varta agent with secure UDP transport (ChaCha20-Poly1305 AEAD).
//!
//! Demonstrates connecting to a `varta-watch` observer over encrypted UDP.
//! The agent reads its pre-shared key from a 0600-mode file (the same path
//! shape the observer uses); environment-variable keys are intentionally
//! not supported because they leak through `/proc/<pid>/environ` and
//! `docker inspect`.  See `docs/architecture/peer-authentication.md`.
//!
//! # Usage
//!
//! 1. Generate a key (one-time) and lock its permissions:
//!    ```sh
//!    openssl rand -hex 32 > /tmp/varta.key
//!    chmod 600 /tmp/varta.key
//!    ```
//!
//! 2. Start the observer (in another terminal):
//!    ```sh
//!    cargo run -p varta-watch --features secure-udp -- \
//!        --socket /tmp/varta.sock \
//!        --threshold-ms 2000 \
//!        --udp-port 9000 \
//!        --key-file /tmp/varta.key
//!    ```
//!
//! 3. Run this example, pointing at the same key file:
//!    ```sh
//!    cargo run -p varta-client --features secure-udp --example secure_udp -- /tmp/varta.key
//!    ```

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use varta_client::{BeatOutcome, SecureUdpTransport, Status, Varta};

fn main() -> io::Result<()> {
    let key_path: PathBuf = std::env::args().nth(1).map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: secure_udp <key-file>  (the file must contain 64 hex chars; chmod 600)",
        )
    })?;

    let key = varta_vlp::crypto::Key::from_file(&key_path)?;

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
