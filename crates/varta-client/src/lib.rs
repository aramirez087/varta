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

// Class-A safety guard: refuse to compile a build that combines the
// degraded-entropy panic-hook fallback with the strict safety profile.
// The fallback path derives IVs through a SipHash mixer rather than an OS
// entropy source — acceptable for embedded targets that have explicitly
// opted in, never acceptable when `safety-profile-strict` is asserted.
// Mirrors the `prometheus-exporter` + `compile-time-config` exclusion in
// `crates/varta-watch/src/lib.rs`.
#[cfg(all(feature = "accept-degraded-entropy", feature = "safety-profile-strict"))]
compile_error!(
    "`accept-degraded-entropy` cannot be combined with `safety-profile-strict` \
     — Class-A safety-critical builds intentionally exclude the non-cryptographic \
     IV-derivation fallback (`fallback_iv_random`). Choose one: drop the \
     degraded-entropy variant, or drop the strict safety profile."
);

pub mod client;
pub mod transport;

mod fork_epoch;

#[cfg(feature = "secure-udp")]
pub mod secure_transport;

#[cfg(feature = "panic-handler")]
pub mod panic;

pub use client::{classify_send_error, BeatError, BeatOutcome, DropReason, Varta};
pub use transport::{BeatTransport, UdsTransport};

#[cfg(feature = "udp")]
pub use transport::UdpTransport;

#[cfg(feature = "secure-udp")]
pub use secure_transport::SecureUdpTransport;

pub use varta_vlp::{DecodeError, Frame, Status, NONCE_TERMINAL};

/// Install the panic hook — see [`panic::install`] for the full contract.
#[cfg(feature = "panic-handler")]
pub use panic::install as install_panic_handler;

/// Install the UDP panic hook — see [`panic::install_panic_handler_udp`] for
/// the full contract.
#[cfg(all(feature = "panic-handler", feature = "udp"))]
pub use panic::install_panic_handler_udp;

/// Error returned by [`install_panic_handler_secure_udp`].
#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
pub use panic::PanicInstallError;

/// Install the secure UDP panic hook (fail-closed) — see
/// [`panic::install_panic_handler_secure_udp`] for the full contract.
#[cfg(all(feature = "panic-handler", feature = "secure-udp"))]
pub use panic::install_panic_handler_secure_udp;

/// Install the secure UDP panic hook with non-cryptographic IV fallback — see
/// [`panic::install_panic_handler_secure_udp_accept_degraded_entropy`] for
/// the full contract including nonce-reuse risk.
///
/// Gated behind the explicit `accept-degraded-entropy` feature. Builds
/// that pin `safety-profile-strict` cannot enable this feature (see the
/// `compile_error!` at the top of this crate).
#[cfg(feature = "accept-degraded-entropy")]
pub use panic::install_panic_handler_secure_udp_accept_degraded_entropy;
