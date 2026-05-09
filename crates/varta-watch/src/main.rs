#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]

//! Varta observer binary — Session 05 will land the full daemon entry point.
//!
//! This binary is the only place in the workspace where `eprintln!` is
//! permitted (per the operator rules). Until Session 05, it prints a single
//! placeholder line to stderr and exits cleanly.

fn main() {
    eprintln!("varta-watch v0.1.0 — implemented in session 05");
}
