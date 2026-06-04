//! Hand-rolled GNU-style argv parser for the `varta-watch` binary.
//!
//! No `clap`, no `getopts`, no proc-macros — the parser is a single pass
//! over an iterator of [`String`] tokens. The [`Config::HELP`] constant is
//! the single source of truth for `--help` output and the
//! `cli_help_lists_every_documented_flag` acceptance test.

mod compile_time;
/// Single source of truth for every accepted CLI flag and compile-time-config
/// key.  See [`flag_catalogue::FLAGS`] for the full table.
pub mod flag_catalogue;
mod help;
mod loaders;
mod parse_helpers;
mod parser;
mod types;
mod validate;

#[cfg(all(test, not(feature = "compile-time-config")))]
mod tests;

pub use types::{
    Config, ConfigError, DEFAULT_PROM_RATE_LIMIT_BURST, DEFAULT_PROM_RATE_LIMIT_PER_SEC,
    DEFAULT_READ_TIMEOUT_MS, DEFAULT_RECOVERY_CAPTURE_BYTES, DEFAULT_RECOVERY_DEBOUNCE_MS,
    DEFAULT_SHUTDOWN_GRACE_MS, DEFAULT_SOCKET_MODE, MAX_ITERATION_BUDGET_MS, MAX_READ_TIMEOUT_MS,
    MAX_RECOVERY_CAPTURE_BYTES, MAX_SCRAPE_BUDGET_MS, MIN_ITERATION_BUDGET_MS,
    MIN_SCRAPE_BUDGET_MS, MIN_SHUTDOWN_GRACE_MS, MIN_THRESHOLD_MS, POLL_STAGE_ABORT_MS,
};
pub use validate::parse_exec_cmd;
