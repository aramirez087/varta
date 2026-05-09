#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]

//! Varta agent API — `Varta::connect` opens a Unix Domain Socket to the
//! observer; `Varta::beat` emits a fire-and-forget 32-byte VLP frame with zero
//! post-init heap traffic.
//!
//! The crate re-exports [`Frame`], [`Status`], and [`DecodeError`] from
//! `varta-vlp` so downstream consumers depend on a single facade.

pub mod client;

pub use client::{BeatOutcome, Varta};
pub use varta_vlp::{DecodeError, Frame, Status};
