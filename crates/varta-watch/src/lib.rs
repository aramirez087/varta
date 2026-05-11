#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]

//! Varta observer library — UDS receive loop, per-pid tracker, stall surface.
//!
//! This crate is the in-process kernel of `varta-watch`. The binary
//! (Session 05) drives [`Observer::poll`] in a single thread and routes
//! [`Event`] values to exporters and the recovery command. The protocol root
//! is [`varta_vlp`]; nothing else is on the dependency surface.

pub mod config;
pub mod exporter;
pub mod observer;
pub mod peer_cred;
pub mod recovery;
pub mod tracker;

pub use config::{Config, ConfigError};
pub use exporter::{Exporter, FileExporter, PromExporter};
pub use observer::{Event, Observer};
pub use recovery::{Recovery, RecoveryOutcome};
pub use tracker::{Slot, Tracker, Update};
