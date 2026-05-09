#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]

//! Varta agent API — Session 02 will land `Varta::connect` and `beat()` here.
//!
//! This crate currently exposes no public items. The path dependency on
//! `varta-vlp` and the public `Frame`/`Status` re-exports are introduced by
//! Session 02, which owns the agent surface.
