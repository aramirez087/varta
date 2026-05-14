//! Per-platform FFI surface for kernel credential extraction.
//!
//! Each `mod {linux,macos,bsd}` defines the platform's `Iovec`, `Msghdr`,
//! `Cmsghdr` / `AuditToken` / `Xucred` / `Cmsgcred`, the relevant constants
//! (`SOL_SOCKET`, `SO_PASSCRED` / `LOCAL_PEERTOKEN` / `LOCAL_CREDS`, ...),
//! the inline `extern "C"` declarations for `setsockopt` / `recvmsg` /
//! `getsockopt`, the `ANCILLARY_BUFFER_SIZE` constant, the
//! `peer_pid_after_recv` extractor, and the compile-time `offset_of!`
//! assertions that catch ABI drift on any kernel/libc combination.
//!
//! Only the active target's module is compiled; this `mod.rs` re-exports its
//! contents under the path `super::plat::*` (aliased in `peer_cred::mod.rs`)
//! so the receive path needs no further cfg gating.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(super) use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub(super) use macos::*;

// The BSD module is compiled on the actual BSD targets *and* on Linux. On
// Linux it provides pure-data types and the `unsafe impl CmsgPlatform for
// BsdCmsg` body so the cmsg miri tests can drive the BSD walker arm on a
// Linux CI host. The `extern "C"` FFI, `LOCAL_CREDS`, and `peer_pid_after_recv`
// stay gated to actual BSD targets via inner `#[cfg]` attributes.
#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
))]
pub(super) mod bsd;
#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
pub(super) use bsd::*;
