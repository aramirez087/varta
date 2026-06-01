//! illumos / Solaris FFI surface — `SO_RECVUCRED` / `SCM_UCRED` / opaque
//! `ucred_t`.
//!
//! On illumos and Solaris, enabling `SO_RECVUCRED` on the receive socket
//! causes the kernel to attach a `SCM_UCRED` ancillary message to every
//! received datagram. The payload is an opaque `ucred_t` — its binary layout
//! is not a stable ABI contract, so field extraction MUST go through the
//! `ucred_getpid(3C)` / `ucred_geteuid(3C)` accessors rather than a direct
//! struct cast.
//!
//! This is a true per-datagram credential mechanism analogous to Linux's
//! `SO_PASSCRED` / `SCM_CREDENTIALS` and BSD's `LOCAL_CREDS` / `SCM_CREDS`.
//!
//! # Zone isolation
//!
//! `ucred_getzoneid(3C)` returns the Solaris zone-id of the sending process.
//! Cross-zone detection (analogous to the Linux PID-namespace gate) is a
//! planned follow-up: for this pass `peer_pid_ns_inode` is `None` on
//! illumos/Solaris, which disables the cross-container recovery refusal.
//! Until that is implemented, operators deploying across zone boundaries
//! should set `--allow-cross-namespace-agents` (which is a no-op here) and
//! be aware of the limitation.
//!
//! # Miri / Linux compilation
//!
//! This module is also compiled on Linux so the Miri walker tests in
//! `super::super::cmsg` can drive the illumos-shaped buffer layout end-to-end
//! on the Linux CI host (same pattern as `platform/bsd.rs`). The `extern "C"`
//! FFI declarations are gated to illumos/Solaris; Linux receives `unsafe fn`
//! shims instead that read PID at offset 0 (i32) and UID at offset 4 (u32) of
//! the test-fabricated buffer.

#![cfg_attr(
    not(any(target_os = "illumos", target_os = "solaris")),
    allow(dead_code)
)]

use core::ffi::c_void;
use core::mem;

// --- structs --------------------------------------------------------------
//
// The illumos LP64 `struct msghdr` has the same field offsets as the BSD
// family (verified by compile-time assertions below).

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

// --- constants ------------------------------------------------------------

/// `SOL_SOCKET` on illumos / Solaris (`<sys/socket.h>`).
pub(crate) const SOL_SOCKET: i32 = 0xffff;
/// `SO_RECVUCRED` — enables `SCM_UCRED` ancillary data on received datagrams
/// (`<sys/socket.h>`).
pub(crate) const SO_RECVUCRED: i32 = 0x0400;
/// `SCM_UCRED` — CMSG type for the `ucred_t` ancillary payload
/// (`<sys/socket.h>`).
pub(crate) const SCM_UCRED: i32 = 0x1012;

// --- FFI ------------------------------------------------------------------

// `setsockopt` and `recvmsg` are only needed on the actual illumos/Solaris
// targets; `recv.rs` gates its calls to those platforms.
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
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

// The `ucred_t` opaque accessors are provided as real `extern "C"` declarations
// on illumos/Solaris.  On all other hosts (Linux CI for Miri tests) they are
// replaced by inline Rust shims that read PID at offset 0 (i32) and UID at
// offset 4 (u32) of the test-fabricated buffer — matching the convention used
// by the Miri cmsg tests that construct the ancillary buffer themselves.
#[cfg(any(target_os = "illumos", target_os = "solaris"))]
extern "C" {
    /// Returns the sending process's PID, or `-1` on failure.
    pub(crate) fn ucred_getpid(uc: *const c_void) -> i32;

    /// Returns the sending process's effective UID, or `u32::MAX` on failure.
    pub(crate) fn ucred_geteuid(uc: *const c_void) -> u32;

    /// Returns the Solaris zone-id, or `-1` on failure.
    #[allow(dead_code)]
    pub(crate) fn ucred_getzoneid(uc: *const c_void) -> i32;
}

// Shims for non-illumos/Solaris hosts (Linux CI, Miri).
// Layout convention for the test buffer: offset 0 = pid (i32), offset 4 = uid (u32).
#[cfg(not(any(target_os = "illumos", target_os = "solaris")))]
pub(crate) unsafe fn ucred_getpid(uc: *const c_void) -> i32 {
    // SAFETY: callers guarantee `uc` points to ≥ 4 initialised bytes.
    unsafe { (uc as *const i32).read_unaligned() }
}
#[cfg(not(any(target_os = "illumos", target_os = "solaris")))]
pub(crate) unsafe fn ucred_geteuid(uc: *const c_void) -> u32 {
    // SAFETY: callers guarantee `uc` points to ≥ 8 initialised bytes.
    unsafe { (uc as *const u8).add(4).cast::<u32>().read_unaligned() }
}

// --- ancillary buffer sizing ----------------------------------------------
//
// `ucred_t` is opaque and its internal size is not a stable ABI contract.
// Under Trusted Solaris / labelled zones, the kernel includes audit and MAC
// label attributes that can push the payload to 512+ bytes. 1024 bytes
// provides headroom for all currently documented extensions. The
// `CtrlTruncated` metric surfaces under-sizing in production.
pub(crate) const ANCILLARY_BUFFER_SIZE: usize = 1024;

// --- CmsgPlatform implementation ------------------------------------------

/// Zero-sized marker type that selects the illumos/Solaris cmsg-walking
/// parameters.
pub(crate) struct IllumosCmsg;

// SAFETY:
// - `Cmsghdr`: cmsg_len@0 (u32), cmsg_level@4 (i32), cmsg_type@8 (i32),
//   total size 12. Verified by compile-time assertions below.
// - `Cred = ()`: illumos `ucred_t` is opaque; extraction goes through
//   `ucred_getpid(3C)` / `ucred_geteuid(3C)` rather than a direct cast.
//   `size_of::<()>() == 0` so the minimum-payload check in `find_credential`
//   evaluates to `cmsg_hdr_size + 0 = cmsg_hdr_size`, accepting any non-empty
//   payload. The ucred accessors handle malformed payloads by returning error
//   sentinels.
// - `Msghdr`: msg_control@32, msg_controllen@40. Verified below.
// - `SOL_SOCKET` and `SCM_UCRED` are the kernel-defined `(level, type)` pair
//   for `SO_RECVUCRED` credential ancillary data on illumos/Solaris.
unsafe impl super::super::cmsg::CmsgPlatform for IllumosCmsg {
    type Hdr = Cmsghdr;
    /// `ucred_t` is opaque — use the unit type and let `extract_pid_uid`
    /// delegate to the libc accessor functions rather than casting a pointer.
    type Cred = ();
    type Msghdr = Msghdr;
    const TARGET_LEVEL: i32 = SOL_SOCKET;
    const TARGET_TYPE: i32 = SCM_UCRED;

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

    unsafe fn extract_pid_uid(data: *const u8, _len: usize) -> Option<(u32, u32)> {
        // SAFETY: `data` points to the `ucred_t` payload inside the
        // kernel-supplied ancillary buffer. Both calls complete before this
        // function returns; the buffer outlives both calls (it is
        // stack-allocated in `recv_authenticated`). Neither accessor stores
        // the pointer past the call (per illumos `ucred(3C)` semantics).
        let pid = unsafe { ucred_getpid(data as *const c_void) };
        let uid = unsafe { ucred_geteuid(data as *const c_void) };
        if pid < 0 || uid == u32::MAX {
            None
        } else {
            Some((pid as u32, uid))
        }
    }
}

/// Extract peer PID and effective UID after a successful `recvmsg` on
/// illumos / Solaris via the `SCM_UCRED` ancillary-data walker.
pub(crate) fn peer_pid_after_recv(_fd: i32, mhdr: &Msghdr) -> Option<(u32, u32)> {
    super::super::cmsg::find_credential::<IllumosCmsg>(mhdr)
}

/// Build a zero-initialised `Msghdr` for use as the `recvmsg(2)` argument.
pub(crate) fn msghdr_for_recv(iov: *mut Iovec, ctrl: *mut c_void, ctrl_len: usize) -> Msghdr {
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

/// illumos / Solaris: `MSG_CTRUNC` is not set for credential ancillary data
/// truncation in the same way as Linux — rely on the `CtrlTruncated` metric
/// path only when `find_credential` returns `None` unexpectedly.
pub(crate) fn ctrl_truncated(_mhdr: &Msghdr) -> bool {
    false
}

// --- layout guards ----------------------------------------------------------

const _: () = assert!(mem::size_of::<Msghdr>() == 48);
const _: () = assert!(mem::size_of::<Iovec>() == 16);

#[cfg(test)]
mod layout_tests {
    use super::{Cmsghdr, Iovec, Msghdr};

    #[test]
    fn recvmsg_layout_offsets_match_illumos_abi() {
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
    }
}
