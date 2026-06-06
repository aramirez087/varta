//! FreeBSD / DragonFly / NetBSD FFI surface — `LOCAL_CREDS` / `SCM_CREDS` /
//! `struct cmsgcred`.
//!
//! On the BSD family the observer enables `LOCAL_CREDS` on its receive
//! socket; the kernel then attaches `SCM_CREDS` ancillary data containing a
//! `struct cmsgcred` (pid, uid, euid, gid, groups) to every datagram.
//! Extraction is done by walking the ancillary buffer with the shared
//! `super::super::cmsg_*` helpers.
//!
//! On Linux this module is compiled for one reason only: the cmsg miri
//! tests in `super::super::cmsg` drive the BSD walker arm against a
//! fabricated BSD-shaped buffer. The unused items on that target are
//! intentional, so we silence `dead_code` for non-BSD compilations.

#![cfg_attr(
    not(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd")),
    allow(dead_code)
)]

use core::ffi::c_void;
use core::mem;

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
    pub msg_iovlen: i32,
    pub _pad2: u32,
    pub msg_control: *mut c_void,
    pub msg_controllen: u32,
    pub msg_flags: i32,
}

#[repr(C)]
pub(crate) struct Cmsghdr {
    pub cmsg_len: u32,
    pub cmsg_level: i32,
    pub cmsg_type: i32,
}

/// `struct cmsgcred` — FreeBSD/NetBSD peer credentials ancillary message.
///
/// Attached by the kernel to every recvmsg(2) datagram when `LOCAL_CREDS`
/// is enabled on the socket. Contains the sending process's PID, real and
/// effective UID/GID, and group list.
///
/// Layout (64-bit, `<sys/socket.h>`):
///   offset  0: cmcred_pid      (pid_t  = i32,  4 bytes)
///   offset  4: cmcred_uid      (uid_t  = u32,  4 bytes)
///   offset  8: cmcred_euid     (uid_t  = u32,  4 bytes)
///   offset 12: cmcred_gid      (gid_t  = u32,  4 bytes)
///   offset 16: cmcred_ngroups  (short  = i16,  2 bytes)
///   offset 18: (padding, 2 bytes)
///   offset 20: cmcred_groups   (gid_t[CMGROUP_MAX], 16 × 4 = 64 bytes)
///   total: 84 bytes
#[repr(C)]
pub(crate) struct Cmsgcred {
    pub cmcred_pid: i32,
    pub cmcred_uid: u32,
    pub cmcred_euid: u32,
    pub cmcred_gid: u32,
    pub cmcred_ngroups: i16,
    /// Padding inserted by the compiler to maintain 4-byte alignment for
    /// `cmcred_groups`.  Not accessed directly — we just need the correct
    /// struct size and offset for `cmcred_groups`.
    _pad: i16,
    pub cmcred_groups: [u32; 16],
}

// --- constants ------------------------------------------------------------

/// `SOL_SOCKET` on FreeBSD / XNU derivatives = `0xffff` (`<sys/socket.h>`).
pub(crate) const SOL_SOCKET: i32 = 0xffff;
/// `LOCAL_CREDS` enables SCM_CREDS ancillary data on received datagrams.
/// Value: 0x0002 on FreeBSD/DragonFly (`<sys/un.h>`),
///        0x0001 on NetBSD.
#[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
pub(crate) const LOCAL_CREDS: i32 = 0x0002;
#[cfg(target_os = "netbsd")]
pub(crate) const LOCAL_CREDS: i32 = 0x0001;
/// `SCM_CREDS` — the CMSG type for cmsgcred ancillary data.
pub(crate) const SCM_CREDS: i32 = 0x03;

// --- FFI ------------------------------------------------------------------
//
// Gated to actual BSD targets so the symbols don't get accidentally invoked
// on a Linux host that compiles this module for its pure-data types
// (see `peer_cred/platform/mod.rs` — Linux includes `mod bsd;` so the
// `unsafe impl CmsgPlatform for BsdCmsg` body is available for miri tests).

#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
extern "C" {
    pub(crate) fn setsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *const c_void,
        optlen: u32,
    ) -> i32;

    pub(crate) fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;

    pub(crate) fn close(fd: i32) -> i32;
}

/// `SCM_RIGHTS` — the CMSG type for passed file descriptors (`<sys/socket.h>`;
/// `0x01` on the BSD family). Varta never sends fds, so any `SCM_RIGHTS` a peer
/// attaches is unsolicited and must be reclaimed — see [`reclaim_scm_rights`].
#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
pub(crate) const SCM_RIGHTS: i32 = 0x01;

/// Reclaim every peer-injected `SCM_RIGHTS` file descriptor the kernel
/// installed from this datagram's ancillary data.
///
/// `LOCAL_CREDS` makes the kernel prepend an `SCM_CREDS` cmsg, but a peer can
/// still append an `SCM_RIGHTS` cmsg in the same datagram; `recvmsg(2)`
/// installs those fds into the observer regardless. The 256-byte ancillary
/// buffer holds both, so [`peer_pid_after_recv`] would walk past the
/// credentials and leave the passed fds open — an fd-exhaustion DoS. This is
/// the single SCM_RIGHTS reclamation point on the BSD family, invoked once per
/// datagram by `recv_authenticated` ahead of every return path.
#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
pub(crate) fn reclaim_scm_rights(mhdr: &Msghdr) {
    super::super::cmsg::reclaim_scm_rights::<BsdCmsg>(mhdr, SCM_RIGHTS, |fd| {
        // SAFETY: recvmsg installed this descriptor into our fd table; close it
        // to reclaim. Close errors cannot be usefully recovered on the receive
        // path.
        let _ = unsafe { close(fd) };
    });
}

// --- ancillary buffer sizing ----------------------------------------------

// CMSG_SPACE(sizeof(struct cmsgcred)) on 64-bit BSD:
//   cmsg_align(sizeof(Cmsghdr)) + cmsg_align(sizeof(Cmsgcred))
//   = cmsg_align(12)           + cmsg_align(84)
//   = 16                       + 88
//   = 104 bytes
//
// 256 bytes provides generous headroom for kernel ancillary-data
// extensions (e.g. future security labels) — same sizing as Linux.
pub(crate) const ANCILLARY_BUFFER_SIZE: usize = 256;

const _: () = assert!(
    ANCILLARY_BUFFER_SIZE
        >= super::super::cmsg::cmsg_align(core::mem::size_of::<Cmsghdr>())
            + core::mem::size_of::<Cmsgcred>()
);

/// Zero-sized marker type that selects the BSD-family cmsg-walking parameters.
pub(crate) struct BsdCmsg;

// SAFETY: All required layouts are verified at compile time elsewhere in
// this file:
// - `Cmsghdr`: cmsg_len@0 (u32), cmsg_level@4 (i32), cmsg_type@8 (i32),
//   total size 12.
// - `Cmsgcred`: cmcred_pid@0 (i32), cmcred_uid@4 (u32), cmcred_euid@8 (u32),
//   cmcred_gid@12, cmcred_ngroups@16, cmcred_groups@20 — total size 84.
// - `Msghdr`: msg_control@32 (*c_void), msg_controllen@40 (u32), total
//   size 48.
// `SOL_SOCKET` and `SCM_CREDS` are the kernel-defined `(level, type)` pair
// for `LOCAL_CREDS` credential ancillary data on the BSD family.
unsafe impl super::super::cmsg::CmsgPlatform for BsdCmsg {
    type Hdr = Cmsghdr;
    type Cred = Cmsgcred;
    type Msghdr = Msghdr;
    const TARGET_LEVEL: i32 = SOL_SOCKET;
    const TARGET_TYPE: i32 = SCM_CREDS;

    fn cmsg_len(hdr: &Cmsghdr) -> usize {
        hdr.cmsg_len as usize
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
        mhdr.msg_controllen as usize
    }
    unsafe fn extract_pid_uid(data: *const u8, len: usize) -> Option<(u32, u32)> {
        // find_credential guarantees len >= size_of::<Cmsgcred>().
        debug_assert!(len >= core::mem::size_of::<Cmsgcred>());
        // SAFETY: guaranteed by find_credential's pre-check and the caller's
        // contract that `data` points to initialised kernel-supplied bytes.
        let cred = unsafe { &*(data as *const Cmsgcred) };
        Some((cred.cmcred_pid as u32, cred.cmcred_euid))
    }
}

/// Extract peer PID and effective UID after a successful `recvmsg` on BSD.
pub(crate) fn peer_pid_after_recv(_fd: i32, mhdr: &Msghdr) -> Option<(u32, u32, NonePidFd)> {
    super::super::cmsg::find_credential::<BsdCmsg>(mhdr).map(|(pid, uid)| (pid, uid, None))
}

type NonePidFd = Option<super::super::types::PeerPidFd>;

/// Build a zero-initialised `Msghdr` for use as the `recvmsg(2)` argument.
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
        _pad2: 0,
        msg_control: ctrl,
        msg_controllen: ctrl_len as u32,
        msg_flags: 0,
    }
}

/// BSD does not set `MSG_CTRUNC` for `SCM_CREDS` data — always `false`.
pub(crate) fn ctrl_truncated(_mhdr: &Msghdr) -> bool {
    false
}

// --- layout guards ----------------------------------------------------------

const _: () = assert!(mem::size_of::<Msghdr>() == 48);
const _: () = assert!(mem::size_of::<Cmsgcred>() == 84);
const _: () = assert!(mem::size_of::<Iovec>() == 16);

#[cfg(test)]
mod layout_tests {
    use super::{Cmsgcred, Cmsghdr, Iovec, Msghdr};

    #[test]
    fn recvmsg_layout_offsets_match_bsd_abi() {
        assert_field_offset!(Msghdr, msg_name, 0);
        assert_field_offset!(Msghdr, msg_namelen, 8);
        assert_field_offset!(Msghdr, msg_iov, 16);
        assert_field_offset!(Msghdr, msg_iovlen, 24);
        assert_field_offset!(Msghdr, msg_control, 32);
        assert_field_offset!(Msghdr, msg_controllen, 40);
        assert_field_offset!(Msghdr, msg_flags, 44);

        assert_field_offset!(Iovec, iov_base, 0);
        assert_field_offset!(Iovec, iov_len, 8);

        assert_field_offset!(Cmsghdr, cmsg_len, 0);
        assert_field_offset!(Cmsghdr, cmsg_level, 4);
        assert_field_offset!(Cmsghdr, cmsg_type, 8);

        assert_field_offset!(Cmsgcred, cmcred_pid, 0);
        assert_field_offset!(Cmsgcred, cmcred_uid, 4);
        assert_field_offset!(Cmsgcred, cmcred_euid, 8);
        assert_field_offset!(Cmsgcred, cmcred_gid, 12);
        assert_field_offset!(Cmsgcred, cmcred_ngroups, 16);
        assert_field_offset!(Cmsgcred, cmcred_groups, 20);
    }
}
