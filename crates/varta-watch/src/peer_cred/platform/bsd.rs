//! FreeBSD / DragonFly / NetBSD FFI surface — `LOCAL_CREDS` / `SCM_CREDS` /
//! `struct cmsgcred`.
//!
//! On the BSD family the observer enables `LOCAL_CREDS` on its receive
//! socket; the kernel then attaches `SCM_CREDS` ancillary data containing a
//! `struct cmsgcred` (pid, uid, euid, gid, groups) to every datagram.
//! Extraction is done by walking the ancillary buffer with the shared
//! `super::super::cmsg_*` helpers (still in `peer_cred/mod.rs` at this
//! commit).

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
    ANCILLARY_BUFFER_SIZE >= super::super::cmsg_hdr_size() + core::mem::size_of::<Cmsgcred>()
);

/// Extract peer PID and effective UID after a successful `recvmsg` on BSD.
///
/// Iterates ancillary data looking for an `SCM_CREDS` message containing
/// a `struct cmsgcred`.  Returns `(cmcred_pid, cmcred_euid)`.
pub(crate) fn peer_pid_after_recv(
    _fd: i32,
    mhdr: &Msghdr,
    anc_base: *const u8,
) -> Option<(u32, u32)> {
    debug_assert_eq!(
        mhdr.msg_control as *const u8, anc_base,
        "msg_control and ancillary buffer base must be the same address"
    );
    let hdr = unsafe { super::super::cmsg_firsthdr(mhdr) };
    unsafe { super::super::find_credential_pid(hdr, mhdr, anc_base) }
}

// --- compile-time layout guards -------------------------------------------

const _: () = assert!(mem::size_of::<Msghdr>() == 48);
const _: () = assert!(mem::size_of::<Cmsgcred>() == 84);
const _: () = assert!(mem::size_of::<Iovec>() == 16);

const _: () = assert!(mem::offset_of!(Msghdr, msg_name) == 0);
const _: () = assert!(mem::offset_of!(Msghdr, msg_namelen) == 8);
const _: () = assert!(mem::offset_of!(Msghdr, msg_iov) == 16);
const _: () = assert!(mem::offset_of!(Msghdr, msg_iovlen) == 24);
const _: () = assert!(mem::offset_of!(Msghdr, msg_control) == 32);
const _: () = assert!(mem::offset_of!(Msghdr, msg_controllen) == 40);
const _: () = assert!(mem::offset_of!(Msghdr, msg_flags) == 44);

const _: () = assert!(mem::offset_of!(Iovec, iov_base) == 0);
const _: () = assert!(mem::offset_of!(Iovec, iov_len) == 8);

const _: () = assert!(mem::offset_of!(Cmsghdr, cmsg_len) == 0);
const _: () = assert!(mem::offset_of!(Cmsghdr, cmsg_level) == 4);
const _: () = assert!(mem::offset_of!(Cmsghdr, cmsg_type) == 8);

const _: () = assert!(mem::offset_of!(Cmsgcred, cmcred_pid) == 0);
const _: () = assert!(mem::offset_of!(Cmsgcred, cmcred_uid) == 4);
const _: () = assert!(mem::offset_of!(Cmsgcred, cmcred_euid) == 8);
const _: () = assert!(mem::offset_of!(Cmsgcred, cmcred_gid) == 12);
const _: () = assert!(mem::offset_of!(Cmsgcred, cmcred_ngroups) == 16);
const _: () = assert!(mem::offset_of!(Cmsgcred, cmcred_groups) == 20);
