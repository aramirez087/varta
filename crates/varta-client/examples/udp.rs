use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use varta_client::{BeatOutcome, Status, Varta};

fn main() {
    let addr: SocketAddr = env::var("VARTA_UDP_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9000".to_string())
        .parse()
        .expect("invalid VARTA_UDP_ADDR");

    let mut agent = Varta::connect_udp(addr).expect("connect_udp");
    eprintln!("varta-client UDP example: sending to {addr}");

    for i in 1..=10 {
        let status = if i % 3 == 0 {
            Status::Degraded
        } else {
            Status::Ok
        };
        match agent.beat(status, i) {
            BeatOutcome::Sent => eprintln!("beat {i:>2}: Sent    (status={status:?})"),
            BeatOutcome::Dropped => eprintln!("beat {i:>2}: Dropped (status={status:?})"),
            BeatOutcome::Failed(e) => {
                eprintln!("beat {i:>2}: Failed  (status={status:?}, err={e})")
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
