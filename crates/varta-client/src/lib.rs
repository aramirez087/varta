#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]

//! Varta agent API — `Varta::connect` opens a transport to the observer;
//! `Varta::beat` emits a fire-and-forget 32-byte VLP frame with zero
//! post-init heap traffic.
//!
//! # Transports
//!
//! The default transport is [`UdsTransport`] (Unix Domain Socket). Alternative
//! transports are available behind feature flags (e.g. `udp` for UDP).
//! The [`BeatTransport`] trait allows custom transport implementations.
//!
//! The crate re-exports [`Frame`], [`Status`], and [`DecodeError`] from
//! `varta-vlp` so downstream consumers depend on a single facade.

pub mod client;
pub mod transport;

#[cfg(feature = "panic-handler")]
pub mod panic;

pub use client::{classify_send_error, BeatOutcome, Varta};
pub use transport::{BeatTransport, UdsTransport};
pub use varta_vlp::{DecodeError, Frame, Status, NONCE_TERMINAL};

/// Install the panic hook — see [`panic::install`] for the full contract.
#[cfg(feature = "panic-handler")]
pub use panic::install as install_panic_handler;

/// Install the UDP panic hook — see [`panic::install_panic_handler_udp`] for
/// the full contract.
#[cfg(all(feature = "panic-handler", feature = "udp"))]
pub use panic::install_panic_handler_udp;
