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

pub mod config;
pub mod exporter;
pub mod listener;
pub mod log;
pub mod observer;
pub mod peer_cred;
pub mod recovery;
pub mod tracker;

#[cfg(feature = "secure-udp")]
pub mod secure_listener;

pub use config::{Config, ConfigError};
pub use exporter::{Exporter, FileExporter, PromExporter};
pub use listener::{BeatListener, UdsListener};
pub use observer::{Event, Observer};
pub use recovery::{Recovery, RecoveryOutcome};
pub use tracker::{EvictionPolicy, Slot, Tracker, Update};

#[cfg(feature = "udp")]
pub use listener::UdpListener;

#[cfg(feature = "secure-udp")]
pub use secure_listener::SecureUdpListener;
