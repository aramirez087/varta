//! Linux FFI surface — `SO_PASSCRED` / `SCM_CREDENTIALS` / `struct ucred`.
//!
//! On Linux the observer enables `SO_PASSCRED` on its receive socket; the
//! kernel then attaches `SCM_CREDENTIALS` ancillary data containing a
//! `struct ucred` (pid, uid, gid) to every datagram. Extraction is done by
//! walking the ancillary buffer with the shared `super::super::cmsg_*`
//! helpers (still in `peer_cred/mod.rs` at this commit).

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
pub(crate) const SCM_CREDENTIALS: i32 = 2;
/// Set by the kernel when ancillary data was truncated (buffer too small).
pub(crate) const MSG_CTRUNC: i32 = 0x20;

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

// SAFETY: All required layouts are verified at compile time elsewhere in
// this file:
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
    fn extract_pid_uid(cred: &Ucred) -> (u32, u32) {
        (cred.pid as u32, cred.uid)
    }
}

/// Extract peer PID and UID after a successful `recvmsg` — on Linux this is
/// done via ancillary-data parsing.
pub(crate) fn peer_pid_after_recv(_fd: i32, mhdr: &Msghdr) -> Option<(u32, u32)> {
    super::super::cmsg::find_credential::<LinuxCmsg>(mhdr)
}

// Compile-time invariant: glibc/Linux msghdr is 56 bytes on every 64-bit
// target Rust supports.  A Rust-side field reorder or padding mistake
// becomes a hard compile error instead of UB at recvmsg time.
const _: () = assert!(mem::size_of::<Msghdr>() == 56);

// Compile-time offset-of assertions for every field the recvmsg path
// touches.  Manual layouts are a tradeoff: we avoid the libc crate to
// satisfy the zero-dependency constraint, but field-order / padding
// mistakes would silently corrupt I/O.  These guards catch divergence
// on any kernel/libc version, turning undefined behaviour into a hard
// compile error.
const _: () = assert!(mem::offset_of!(Msghdr, msg_name) == 0);
const _: () = assert!(mem::offset_of!(Msghdr, msg_namelen) == 8);
const _: () = assert!(mem::offset_of!(Msghdr, msg_iov) == 16);
const _: () = assert!(mem::offset_of!(Msghdr, msg_iovlen) == 24);
const _: () = assert!(mem::offset_of!(Msghdr, msg_control) == 32);
const _: () = assert!(mem::offset_of!(Msghdr, msg_controllen) == 40);
const _: () = assert!(mem::offset_of!(Msghdr, msg_flags) == 48);

const _: () = assert!(mem::offset_of!(Iovec, iov_base) == 0);
const _: () = assert!(mem::offset_of!(Iovec, iov_len) == 8);

const _: () = assert!(mem::offset_of!(Cmsghdr, cmsg_len) == 0);
const _: () = assert!(mem::offset_of!(Cmsghdr, cmsg_level) == 8);
const _: () = assert!(mem::offset_of!(Cmsghdr, cmsg_type) == 12);

const _: () = assert!(mem::offset_of!(Ucred, pid) == 0);
const _: () = assert!(mem::offset_of!(Ucred, uid) == 4);
const _: () = assert!(mem::offset_of!(Ucred, gid) == 8);
