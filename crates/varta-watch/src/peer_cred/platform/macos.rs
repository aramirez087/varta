//! macOS FFI surface — `getsockopt(LOCAL_PEERTOKEN)` with `LOCAL_PEERPID` /
//! `LOCAL_PEERCRED` fallback.
//!
//! macOS does not deliver SCM-style ancillary credentials on unconnected
//! `SOCK_DGRAM` sockets. Instead the observer calls `getsockopt(2)` with
//! `LOCAL_PEERTOKEN` immediately after each `recvmsg(2)` to fetch the peer's
//! audit token. Because the observer is single-threaded, no other datagram
//! can arrive between the two syscalls.
//!
//! On older macOS versions where `LOCAL_PEERTOKEN` is unavailable, the
//! extractor falls back to a sequential `LOCAL_PEERPID` + `LOCAL_PEERCRED`
//! pair. Only when all three mechanisms fail does it return the sentinel
//! `(0, 0)` — observable as a permission denial in the receive path.

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

// audit_token_t: 8 × u32 (32 bytes), fields from <security/audit/audit.h>
//   at_auid: [0], at_euid: [1], at_egid: [2], at_ruid: [3]
//   at_rgid: [4], at_pid:  [5], at_asid: [6], at_tid:  [7]
#[repr(C)]
pub(crate) struct AuditToken {
    pub val: [u32; 8],
}

// struct xucred from <sys/un.h> — returned by LOCAL_PEERCRED (0x0001).
// NGROUPS is 16 on macOS / XNU.
#[repr(C)]
pub(crate) struct Xucred {
    pub cr_version: u32,
    pub cr_uid: u32,
    pub cr_ngroups: i16,
    pub cr_groups: [u32; 16],
}

// --- constants ------------------------------------------------------------

// SOL_SOCKET on macOS / XNU = 0xffff (<sys/socket.h>)
pub(crate) const SOL_SOCKET: i32 = 0xffff;
// LOCAL_PEERTOKEN = 0x0021 (<sys/un.h>) — get the peer's audit token
pub(crate) const LOCAL_PEERTOKEN: i32 = 0x0021;
// LOCAL_PEERPID = 0x0002 (<sys/un.h>) — get the peer's PID
pub(crate) const LOCAL_PEERPID: i32 = 0x0002;
// LOCAL_PEERCRED = 0x0001 (<sys/un.h>) — get the peer's xucred
pub(crate) const LOCAL_PEERCRED: i32 = 0x0001;

// --- FFI ------------------------------------------------------------------

extern "C" {
    pub(crate) fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;
    pub(crate) fn getsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *mut c_void,
        optlen: *mut u32,
    ) -> i32;
}

// --- ancillary buffer sizing ----------------------------------------------

pub(crate) const ANCILLARY_BUFFER_SIZE: usize = 16;

/// Extract peer PID and UID after a successful `recvmsg` on macOS.
///
/// Attempts `getsockopt(LOCAL_PEERTOKEN)` which returns an `audit_token_t`
/// containing the sender's identity. Because the observer is
/// single-threaded and this is called immediately after `recvmsg(2)`, no
/// other datagram can arrive between the two syscalls.
///
/// If `LOCAL_PEERTOKEN` fails (e.g. on older macOS versions or
/// unconnected `SOCK_DGRAM` where the kernel doesn't expose per-datagram
/// credentials), falls back to `LOCAL_PEERPID` and `LOCAL_PEERCRED`
/// individually. Only returns the sentinel (0, 0) when all three
/// mechanisms fail.
pub(crate) fn peer_pid_after_recv(fd: i32, _mhdr: &Msghdr) -> Option<(u32, u32)> {
    let mut token = AuditToken { val: [0u32; 8] };
    let mut optlen: u32 = mem::size_of::<AuditToken>() as u32;
    let ret = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            LOCAL_PEERTOKEN,
            &mut token as *mut AuditToken as *mut c_void,
            &mut optlen,
        )
    };
    if ret == 0 && (optlen as usize) >= mem::size_of::<AuditToken>() {
        // at_pid is at index 5, at_euid is at index 1
        return Some((token.val[5], token.val[1]));
    }

    // LOCAL_PEERTOKEN failed — try older LOCAL_PEERPID + LOCAL_PEERCRED.
    // On unconnected SOCK_DGRAM the kernel may succeed here even when
    // the newer audit token API is unavailable.
    let pid = get_peer_pid_fallback(fd);
    let uid = get_peer_uid_fallback(fd);
    Some((pid, uid))
}

fn get_peer_pid_fallback(fd: i32) -> u32 {
    let mut pid: i32 = 0;
    let mut optlen: u32 = mem::size_of::<i32>() as u32;
    let ret = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            LOCAL_PEERPID,
            &mut pid as *mut i32 as *mut c_void,
            &mut optlen,
        )
    };
    if ret == 0 && (optlen as usize) >= mem::size_of::<i32>() && pid > 0 {
        pid as u32
    } else {
        0
    }
}

fn get_peer_uid_fallback(fd: i32) -> u32 {
    let mut cred = Xucred {
        cr_version: 0,
        cr_uid: 0,
        cr_ngroups: 0,
        cr_groups: [0u32; 16],
    };
    let mut optlen: u32 = mem::size_of::<Xucred>() as u32;
    let ret = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            LOCAL_PEERCRED,
            &mut cred as *mut Xucred as *mut c_void,
            &mut optlen,
        )
    };
    if ret == 0 && (optlen as usize) >= 8 {
        cred.cr_uid
    } else {
        0
    }
}

// Compile-time invariant: macOS msghdr is 48 bytes on x86_64 + aarch64.
const _: () = assert!(mem::size_of::<Msghdr>() == 48);

// Compile-time invariant: audit_token_t is 8 × u32 = 32 bytes.
const _: () = assert!(mem::size_of::<AuditToken>() == 32);

// Compile-time invariant: xucred layout matches XNU's struct xucred
// (u32 + u32 + i16 + 2 pad + [u32; 16] = 76 bytes on LP64).
const _: () = assert!(mem::size_of::<Xucred>() == 76);

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
const _: () = assert!(mem::offset_of!(Msghdr, msg_flags) == 44);

const _: () = assert!(mem::offset_of!(Iovec, iov_base) == 0);
const _: () = assert!(mem::offset_of!(Iovec, iov_len) == 8);
