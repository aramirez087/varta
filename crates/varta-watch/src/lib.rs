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
pub mod pid_max;
pub mod signal_install;
// When `fuzzing` is on, bounded-collection modules are exposed as
// public so the `fuzz/` crate can drive them directly through
// `varta_watch::__fuzz_internals::*`. The names stay namespaced under
// `__fuzz_internals` so accidental external use is loud.
#[cfg(all(feature = "prometheus-exporter", not(feature = "fuzzing")))]
mod ip_state_table;
#[cfg(not(feature = "fuzzing"))]
mod outstanding_table;
#[cfg(not(feature = "fuzzing"))]
mod probe_table;
pub mod recovery;

#[cfg(feature = "fuzzing")]
#[path = "ip_state_table.rs"]
pub mod ip_state_table;
#[cfg(feature = "fuzzing")]
#[path = "outstanding_table.rs"]
pub mod outstanding_table;
#[cfg(feature = "fuzzing")]
#[path = "probe_table.rs"]
pub mod probe_table;

/// Test-only: stable namespace for the fuzz-only re-exports.
#[cfg(feature = "fuzzing")]
pub mod __fuzz_internals {
    pub use crate::ip_state_table;
    pub use crate::outstanding_table;
    pub use crate::probe_table;
}

/// Test-only: expose the Linux kernel-ABI signal structs and syscall wrapper
/// so integration tests can consume the *real* definitions instead of
/// maintaining parallel duplicates. Gated to `test-hooks` (which CI always
/// enables for the integration-test binary) or `test` cfg.
///
/// Mirrors the `__fuzz_internals` pattern used for bounded-collection modules.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub mod __test_signal_abi {
    #[cfg(target_os = "linux")]
    pub use crate::signal_install::linux::test_abi::*;
}
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
