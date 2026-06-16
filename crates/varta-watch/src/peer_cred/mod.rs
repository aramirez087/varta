//! Kernel-level peer credential verification for Unix domain datagrams.
//!
//! On Linux the observer calls `recvmsg(2)` with `SO_PASSCRED` enabled so
//! the kernel attaches `SCM_CREDENTIALS` (containing `struct ucred`) to each
//! datagram. Both PID and UID are verified against the VLP frame and the
//! observer's own identity.
//!
//! On macOS, `LOCAL_PEERTOKEN` is available only for connected local sockets;
//! Varta's pathname datagram observer socket cannot obtain per-datagram peer
//! credentials and therefore falls back to `BeatOrigin::SocketModeOnly`.
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

mod macos_fallback;
mod ns_inode;
mod recv;
mod start_time;
mod types;

#[cfg(any(fuzzing, test))]
#[cfg(target_os = "linux")]
pub mod fuzz_entry;

pub(crate) use ns_inode::{observer_pid_namespace_inode, read_pid_namespace_inode};
pub(crate) use recv::{enable_credential_passing, recv_authenticated};
pub(crate) use start_time::read_pid_start_time;
pub(crate) use types::observer_uid;
pub use types::{BeatOrigin, PeerPidFd, RecvResult};

/// Read PID namespace and start-time metadata for a kernel-attested peer.
///
/// When Linux supplied a pidfd with the datagram, `/proc/<pid>` metadata is
/// trusted only if the pidfd proves the original sender is still live both
/// before and after the reads. If the sender has already exited, the numeric
/// PID may have been recycled, so returning `(None, None)` is safer than
/// pinning namespace/generation from the wrong process.
pub(crate) fn read_peer_identity(
    peer_pid: u32,
    peer_pidfd: Option<&PeerPidFd>,
) -> (Option<u64>, Option<u64>) {
    #[cfg(target_os = "linux")]
    if let Some(pidfd) = peer_pidfd {
        if pidfd.is_live() != Some(true) {
            return (None, None);
        }
        let ns = read_pid_namespace_inode(peer_pid);
        let generation = read_pid_start_time(peer_pid);
        if pidfd.is_live() == Some(true) {
            return (ns, generation);
        }
        return (None, None);
    }

    let _ = peer_pidfd;
    (
        read_pid_namespace_inode(peer_pid),
        read_pid_start_time(peer_pid),
    )
}

mod cmsg;

mod platform;
use platform as plat;

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[cfg(not(miri))]
    use super::{read_peer_identity, PeerPidFd};
    #[cfg(not(miri))]
    use std::os::unix::io::IntoRawFd;

    #[test]
    #[cfg(not(miri))]
    fn read_peer_identity_without_pidfd_preserves_proc_fallback() {
        let (_ns, generation) = read_peer_identity(std::process::id(), None);
        assert!(
            generation.is_some(),
            "self /proc stat should expose a start-time generation"
        );
    }

    #[test]
    #[cfg(not(miri))]
    fn read_peer_identity_with_non_live_pidfd_refuses_proc_metadata() {
        // A regular file polls readable immediately, which exercises the same
        // "not proven live" branch as an exited pidfd. PeerPidFd takes
        // ownership and closes the descriptor on drop.
        let fd = std::fs::File::open("/dev/null")
            .expect("open /dev/null")
            .into_raw_fd();
        let pidfd = unsafe { PeerPidFd::from_raw(fd) };

        assert_eq!(
            read_peer_identity(std::process::id(), Some(&pidfd)),
            (None, None),
            "unverified pidfd state must not allow /proc identity pinning"
        );
    }
}
