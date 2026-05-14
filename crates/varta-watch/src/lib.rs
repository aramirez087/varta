#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]
// SAFETY: unsafe_code is legitimately required for FFI to kernel interfaces
// (recvmsg/cmsg parsing in peer_cred.rs, umask in listener.rs).  All unsafe
// sites are guarded by compile-time layout assertions and per-block SAFETY
// comments.  The workspace-level deny forces us to explicitly opt in here.
#![allow(unsafe_code)]

//! Varta observer library — receive loop over configurable transport listeners,
//! per-pid tracker, stall surface.
//!
//! This crate is the in-process kernel of `varta-watch`. The binary
//! drives [`Observer::poll`] in a single thread and routes
//! [`Event`] values to exporters and the recovery command. The protocol root
//! is [`varta_vlp`]; nothing else is on the dependency surface.

// Class-A safety-critical builds (`compile-time-config`) intentionally have
// no /metrics endpoint, no HTTP server, no bearer-token loader, and no argv
// parser.  Combining `compile-time-config` with `prometheus-exporter` would
// link the HTTP server back into the binary, defeating the structural
// guarantee that the Class-A profile rests on.  The combination is rejected
// at compile time so a misconfigured build line fails loudly rather than
// producing a binary that silently fails the strings audit at deploy time.
#[cfg(all(feature = "prometheus-exporter", feature = "compile-time-config"))]
compile_error!(
    "`prometheus-exporter` cannot be combined with `compile-time-config` \
     — Class-A safety-critical builds intentionally have no /metrics \
     surface.  See book/src/architecture/safety-profiles.md for the supported \
     feature matrix."
);

pub mod audit;
pub mod clock;
pub mod config;
pub mod exporter;
pub mod hw_watchdog;
pub mod listener;
pub mod log;
pub mod log_ratelimit;
pub mod notify;
pub mod observer;
pub mod peer_cred;
pub mod recovery;
pub mod tracker;

#[cfg(feature = "secure-udp")]
pub mod secure_listener;

pub use clock::{Clock, ClockError, ClockSource};
pub use config::{Config, ConfigError};
#[cfg(feature = "prometheus-exporter")]
pub use exporter::PromExporter;
pub use exporter::{Exporter, FileExporter};
pub use listener::{BeatListener, TransportTrust, UdsListener};
pub use observer::{Event, Observer};
pub use peer_cred::BeatOrigin;
pub use recovery::{Recovery, RecoveryOutcome};
pub use tracker::{EvictionPolicy, Slot, Tracker, Update};

#[cfg(feature = "unsafe-plaintext-udp")]
pub use listener::UdpListener;

#[cfg(feature = "secure-udp")]
pub use secure_listener::SecureUdpListener;
