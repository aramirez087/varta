//! Linux FFI surface — `SO_PASSCRED` / `SCM_CREDENTIALS` / `struct ucred`.
//!
//! On Linux the observer enables `SO_PASSCRED` on its receive socket; the
//! kernel then attaches `SCM_CREDENTIALS` ancillary data containing a
//! `struct ucred` (pid, uid, gid) to every datagram. Extraction is done by
//! walking the ancillary buffer with the shared `super::super::cmsg_*`
//! helpers (still in `peer_cred/mod.rs` at this commit).

use core::ffi::c_void;
use core::mem;

use crate::peer_cred::types::PeerPidFd;

// --- structs --------------------------------------------------------------

#[repr(C)]
pub(crate) struct Iovec {
    pub iov_base: *mut c_void,
    pub iov_len: usize,
}

#[repr(C)]
pub(crate) struct Msghdr {
    pub msg_name: *mut c_void,
    pub msg_namelen: u32,
    pub _pad1: u32,
    pub msg_iov: *mut Iovec,
    pub msg_iovlen: usize,
    pub msg_control: *mut c_void,
    pub msg_controllen: usize,
    pub msg_flags: i32,
    pub _pad2: i32,
}

#[repr(C)]
pub(crate) struct Cmsghdr {
    pub cmsg_len: usize,
    pub cmsg_level: i32,
    pub cmsg_type: i32,
}

#[repr(C)]
pub(crate) struct Ucred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

// --- constants ------------------------------------------------------------

pub(crate) const SOL_SOCKET: i32 = 1;
pub(crate) const SO_PASSCRED: i32 = 16;
/// `SO_PASSPIDFD` asks Linux 6.5+ to attach an `SCM_PIDFD` cmsg per datagram.
pub(crate) const SO_PASSPIDFD: i32 = 76;
pub(crate) const SCM_CREDENTIALS: i32 = 2;
/// `SCM_PIDFD` ancillary type carrying one pidfd (`int`).
pub(crate) const SCM_PIDFD: i32 = 0x04;
/// Set by the kernel when ancillary data was truncated (buffer too small).
pub(crate) const MSG_CTRUNC: i32 = 0x20;
/// Close received file descriptors atomically during `recvmsg(2)`.
pub(crate) const MSG_CMSG_CLOEXEC: i32 = 0x4000_0000;

// --- FFI ------------------------------------------------------------------

extern "C" {
    pub(crate) fn setsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *const c_void,
        optlen: u32,
    ) -> i32;

    pub(crate) fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;
}

// --- ancillary buffer sizing ----------------------------------------------

// CMSG_SPACE for a single SCM_CREDENTIALS on 64-bit Linux:
//   cmsg_align(sizeof(Cmsghdr)) + cmsg_align(sizeof(Ucred))
//   = cmsg_align(16)          + cmsg_align(12)
//   = 16                      + 16
//   = 32 bytes
//
// On SELinux-enabled kernels (RHEL, CentOS, Fedora enforcing mode),
// the kernel additionally attaches SCM_SECURITY with the process's
// SELinux context string (~50-100 bytes).  64 bytes is insufficient
// for SCM_CREDENTIALS + SCM_SECURITY, causing MSG_CTRUNC on every
// datagram and silently dropping all frames.
//
// 256 bytes covers:
//   SCM_CREDENTIALS:           ~32 bytes (CMSG_SPACE)
//   SCM_SECURITY context:      up to ~128 bytes (CMSG_SPACE with label)
//   + generous headroom for future kernel ancillary-data extensions.
pub(crate) const ANCILLARY_BUFFER_SIZE: usize = 256;

// Compile-time guard: the ancillary buffer must fit at least one
// SCM_CREDENTIALS message (aligned cmsghdr + struct ucred).
const _: () = assert!(
    ANCILLARY_BUFFER_SIZE
        >= super::super::cmsg::cmsg_align(core::mem::size_of::<Cmsghdr>())
            + core::mem::size_of::<Ucred>()
);

/// Zero-sized marker type that selects the Linux cmsg-walking parameters.
pub(crate) struct LinuxCmsg;

// SAFETY: All required layouts are verified by size assertions and offset
// tests elsewhere in this file:
// - `Cmsghdr`: cmsg_len@0 (usize), cmsg_level@8 (i32), cmsg_type@12 (i32),
//   total size 16.
// - `Ucred`: pid@0 (i32), uid@4 (u32), gid@8 (u32), total size 12.
// - `Msghdr`: msg_control@32 (*c_void), msg_controllen@40 (usize), total
//   size 56.
// `SOL_SOCKET` and `SCM_CREDENTIALS` are the kernel-defined `(level, type)`
// pair for `SO_PASSCRED` credential ancillary data on Linux.
unsafe impl super::super::cmsg::CmsgPlatform for LinuxCmsg {
    type Hdr = Cmsghdr;
    type Cred = Ucred;
    type Msghdr = Msghdr;
    const TARGET_LEVEL: i32 = SOL_SOCKET;
    const TARGET_TYPE: i32 = SCM_CREDENTIALS;

    fn cmsg_len(hdr: &Cmsghdr) -> usize {
        hdr.cmsg_len
    }
    fn cmsg_level(hdr: &Cmsghdr) -> i32 {
        hdr.cmsg_level
    }
    fn cmsg_type(hdr: &Cmsghdr) -> i32 {
        hdr.cmsg_type
    }
    fn msg_control(mhdr: &Msghdr) -> *const u8 {
        mhdr.msg_control as *const u8
    }
    fn msg_controllen(mhdr: &Msghdr) -> usize {
        mhdr.msg_controllen
    }
    unsafe fn extract_pid_uid(data: *const u8, len: usize) -> Option<(u32, u32)> {
        // find_credential guarantees len >= size_of::<Ucred>().
        debug_assert!(len >= core::mem::size_of::<Ucred>());
        // SAFETY: guaranteed by find_credential's pre-check and the caller's
        // contract that `data` points to initialised kernel-supplied bytes.
        let cred = unsafe { &*(data as *const Ucred) };
        Some((cred.pid as u32, cred.uid))
    }
}

/// Extract peer PID, UID, and optional pidfd after a successful `recvmsg`.
pub(crate) fn peer_pid_after_recv(
    _fd: i32,
    mhdr: &Msghdr,
) -> Option<(u32, u32, Option<PeerPidFd>)> {
    let mut cred = None;
    let mut pidfd = None;
    scan_linux_cmsgs(mhdr, |hdr, data_ptr| {
        if hdr.cmsg_level != SOL_SOCKET {
            return;
        }
        let payload_len = hdr
            .cmsg_len
            .saturating_sub(<LinuxCmsg as super::super::cmsg::CmsgPlatform>::cmsg_hdr_size());
        match hdr.cmsg_type {
            SCM_CREDENTIALS if payload_len >= core::mem::size_of::<Ucred>() => {
                // SAFETY: payload length was checked above and the cmsg
                // walker proved the bytes are inside the kernel-supplied
                // ancillary buffer.
                let uc = unsafe { &*(data_ptr as *const Ucred) };
                cred = Some((uc.pid as u32, uc.uid));
            }
            SCM_PIDFD if payload_len >= core::mem::size_of::<i32>() => {
                // SAFETY: payload length was checked above. Use
                // `read_unaligned` because the cmsg payload ABI only
                // promises byte validity; alignment is cheap to avoid.
                let fd = unsafe { data_ptr.cast::<i32>().read_unaligned() };
                if fd >= 0 {
                    // SAFETY: the fd was installed into this process by
                    // recvmsg as an owned SCM_PIDFD descriptor.
                    pidfd = Some(unsafe { PeerPidFd::from_raw(fd) });
                }
            }
            _ => {}
        }
    });
    cred.map(|(pid, uid)| (pid, uid, pidfd))
}

/// Best-effort cleanup used when recvmsg reported truncated ancillary data
/// before normal credential extraction could take ownership of `SCM_PIDFD`.
pub(crate) fn close_pidfds_after_recv(mhdr: &Msghdr) {
    scan_linux_cmsgs(mhdr, |hdr, data_ptr| {
        if hdr.cmsg_level != SOL_SOCKET || hdr.cmsg_type != SCM_PIDFD {
            return;
        }
        let payload_len = hdr
            .cmsg_len
            .saturating_sub(<LinuxCmsg as super::super::cmsg::CmsgPlatform>::cmsg_hdr_size());
        if payload_len < core::mem::size_of::<i32>() {
            return;
        }
        // SAFETY: payload length was checked above.
        let fd = unsafe { data_ptr.cast::<i32>().read_unaligned() };
        if fd >= 0 {
            // SAFETY: take ownership long enough to close on drop.
            let _owned = unsafe { PeerPidFd::from_raw(fd) };
        }
    });
}

fn scan_linux_cmsgs(mhdr: &Msghdr, mut cb: impl FnMut(&Cmsghdr, *const u8)) {
    // SAFETY: `mhdr` was populated by recvmsg, so msg_control/msg_controllen
    // describe initialized ancillary bytes. The iterator bounds-checks every
    // header before yielding it.
    let iter = unsafe { super::super::cmsg::CmsgIter::<LinuxCmsg>::new(mhdr) };
    for (hdr, data_ptr) in iter {
        cb(hdr, data_ptr);
    }
}

/// Build a zero-initialised `Msghdr` for use as the `recvmsg(2)` argument.
/// Isolates the per-platform field-order differences so `recv.rs` stays
/// cfg-free.
pub(crate) fn msghdr_for_recv(
    iov: *mut Iovec,
    ctrl: *mut core::ffi::c_void,
    ctrl_len: usize,
) -> Msghdr {
    Msghdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        _pad1: 0,
        msg_iov: iov,
        msg_iovlen: 1,
        msg_control: ctrl,
        msg_controllen: ctrl_len,
        msg_flags: 0,
        _pad2: 0,
    }
}

/// Return `true` when the kernel set `MSG_CTRUNC` on the received datagram,
/// indicating the ancillary buffer was too small and credentials were dropped.
pub(crate) fn ctrl_truncated(mhdr: &Msghdr) -> bool {
    mhdr.msg_flags & MSG_CTRUNC != 0
}

// Compile-time invariant: glibc/Linux msghdr is 56 bytes on every 64-bit
// target Rust supports.  A Rust-side field reorder or padding mistake
// becomes a test failure instead of UB at recvmsg time.
const _: () = assert!(mem::size_of::<Msghdr>() == 56);

// Offset checks for every field the recvmsg path touches. Manual layouts are a
// tradeoff: we avoid the libc crate to satisfy the zero-dependency constraint,
// but field-order / padding mistakes would silently corrupt I/O. These guards
// catch divergence on any kernel/libc version during tests.
#[cfg(test)]
mod layout_tests {
    use super::{Cmsghdr, Iovec, Msghdr, Ucred};

    #[test]
    fn recvmsg_layout_offsets_match_linux_abi() {
        assert_field_offset!(Msghdr, msg_name, 0);
        assert_field_offset!(Msghdr, msg_namelen, 8);
        assert_field_offset!(Msghdr, msg_iov, 16);
        assert_field_offset!(Msghdr, msg_iovlen, 24);
        assert_field_offset!(Msghdr, msg_control, 32);
        assert_field_offset!(Msghdr, msg_controllen, 40);
        assert_field_offset!(Msghdr, msg_flags, 48);

        assert_field_offset!(Iovec, iov_base, 0);
        assert_field_offset!(Iovec, iov_len, 8);

        assert_field_offset!(Cmsghdr, cmsg_len, 0);
        assert_field_offset!(Cmsghdr, cmsg_level, 8);
        assert_field_offset!(Cmsghdr, cmsg_type, 12);

        assert_field_offset!(Ucred, pid, 0);
        assert_field_offset!(Ucred, uid, 4);
        assert_field_offset!(Ucred, gid, 8);
    }
}
