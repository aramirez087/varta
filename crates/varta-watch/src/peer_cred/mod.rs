//! Kernel-level peer credential verification for Unix domain datagrams.
//!
//! On Linux the observer calls `recvmsg(2)` with `SO_PASSCRED` enabled so
//! the kernel attaches `SCM_CREDENTIALS` (containing `struct ucred`) to each
//! datagram. Both PID and UID are verified against the VLP frame and the
//! observer's own identity.
//!
//! On macOS per-datagram peer credentials are obtained via `getsockopt(2)`
//! with `LOCAL_PEERTOKEN`, which returns an `audit_token_t` containing the
//! sender's PID, UID, GID, etc. Because the observer is single-threaded and
//! calls `getsockopt(LOCAL_PEERTOKEN)` immediately after `recvmsg(2)`, no
//! other datagram can arrive between the two syscalls.
//!
//! The module uses only inline `extern "C"` FFI — no `libc` crate — to
//! satisfy the workspace's zero-registry-dependency constraint.
//!
//! ## Module layout
//!
//! - [`types`] — public [`BeatOrigin`] / [`RecvResult`] enums and the cached
//!   observer-UID accessor.
//! - [`ns_inode`] — Linux `/proc/<pid>/ns/pid` namespace-inode reader (with
//!   non-Linux stub).
//! - the cmsg walker, the per-platform `plat` modules, and
//!   `enable_credential_passing` / `recv_authenticated` currently live in this
//!   file; later commits split them out.

mod ns_inode;
mod recv;
mod types;

pub(crate) use ns_inode::{observer_pid_namespace_inode, read_pid_namespace_inode};
pub(crate) use recv::{enable_credential_passing, recv_authenticated};
pub(crate) use types::observer_uid;
pub use types::{BeatOrigin, RecvResult};

mod cmsg;

mod platform;
use platform as plat;

