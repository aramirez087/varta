//! macOS FFI surface — `getsockopt(LOCAL_PEERTOKEN)` with `LOCAL_PEERPID` /
//! `LOCAL_PEERCRED` fallback.
//!
//! macOS does not deliver SCM-style ancillary credentials on pathname
//! `SOCK_DGRAM` sockets. `LOCAL_PEERTOKEN` works for connected local sockets
//! such as `UnixDatagram::pair`, but the observer's pathname datagram socket
//! remains unconnected so these calls return `ENOTCONN` in production and the
//! receive path safely downgrades to `BeatOrigin::SocketModeOnly`.
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

// SOL_LOCAL on macOS / XNU = 0 (<sys/un.h>) — level for LOCAL_* options.
pub(crate) const SOL_LOCAL: i32 = 0;
// LOCAL_PEERTOKEN = 0x006 (<sys/un.h>) — get the peer's audit token
pub(crate) const LOCAL_PEERTOKEN: i32 = 0x006;
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

// macOS derives peer identity from `getsockopt(LOCAL_PEERTOKEN)`, not from
// ancillary data, so no *legitimate* cmsg is ever expected here. But a peer
// can still attach `SCM_RIGHTS` to a datagram, and XNU installs those file
// descriptors into the observer on `recvmsg(2)` regardless of buffer size —
// empirically even with a NULL control buffer the fd is still installed
// (install-on-overflow). The only way to reclaim them is to give `recvmsg` a
// control buffer large enough to *enumerate* them, then walk and close every
// `SCM_RIGHTS` fd (see `reclaim_scm_rights`).
//
// XNU caps `SCM_RIGHTS` at 254 fds per message (a 255-fd `sendmsg` is rejected
// with EINVAL on the sender; verified empirically on Darwin 25.x — see the
// `scm_rights_fds_are_reclaimed_not_leaked_macos` boundary test). 254 fds
// occupy `CMSG_ALIGN(sizeof(cmsghdr) + 254 * sizeof(int))` = `12 + 1016` =
// 1028 bytes on XNU (cmsg alignment is to `sizeof(u32)` = 4). A 1024-byte
// buffer is *four bytes short*: `recvmsg` installs all 254 fds but truncates
// the control data to 1024 and sets `MSG_CTRUNC` — which macOS does not
// surface (see `ctrl_truncated`), so `reclaim_scm_rights` enumerates only 253
// and the 254th kernel-installed fd leaks permanently. One leaked fd per
// maximally-stuffed datagram is the fd-exhaustion DoS this buffer exists to
// prevent (the macOS twin of the Linux/BSD/illumos leak).
//
// Size to the kernel maximum *plus headroom* so a future cap increase cannot
// silently reopen the leak — the original 1024-byte sizing assumed a 253-fd
// cap that XNU has since raised, and exact-fitting a moving kernel constant is
// exactly what regressed it. The buffer is a per-call stack allocation
// (`recv::AncBuf`), so the slack is free. The compile-time floor below pins the
// buffer to the documented cap as a regression guard.
pub(crate) const SCM_RIGHTS_MAX_FDS: usize = 254;
pub(crate) const ANCILLARY_BUFFER_SIZE: usize = 2048;

/// `SOL_SOCKET` on macOS / XNU (`<sys/socket.h>`) — the cmsg level the kernel
/// stamps on `SCM_RIGHTS` ancillary data.
const SOL_SOCKET: i32 = 0xffff;
/// `SCM_RIGHTS` — the cmsg type for passed file descriptors (`<sys/socket.h>`,
/// `0x01` on XNU). Varta never sends fds, so any `SCM_RIGHTS` a peer attaches
/// is unsolicited and must be reclaimed.
const SCM_RIGHTS: i32 = 0x01;

/// macOS `struct cmsghdr` — `cmsg_len: u32`, `cmsg_level: i32`, `cmsg_type:
/// i32` (`<sys/socket.h>`). 12 bytes; `CMSG_ALIGN` rounds to `sizeof(u32)`.
#[repr(C)]
struct Cmsghdr {
    cmsg_len: u32,
    cmsg_level: i32,
    cmsg_type: i32,
}

extern "C" {
    fn close(fd: i32) -> i32;
}

/// `CMSG_ALIGN` on XNU rounds up to `sizeof(u32)` (4 bytes), unlike the
/// `sizeof(usize)` (8-byte) alignment the shared `cmsg` walker assumes for the
/// other platforms — which is why macOS keeps its own small walker here.
#[inline]
const fn cmsg_align(len: usize) -> usize {
    let a = core::mem::size_of::<u32>();
    (len + a - 1) & !(a - 1)
}

// Compile-time floor: the ancillary buffer must hold a maximally-stuffed
// `SCM_RIGHTS` message in full, or `recvmsg` truncates the tail fds and
// `reclaim_scm_rights` cannot close them — the fd-exhaustion leak this buffer
// exists to prevent. Pins `ANCILLARY_BUFFER_SIZE` to the documented kernel cap:
// shrinking it below the cap's footprint fails the build.
const _: () = assert!(
    ANCILLARY_BUFFER_SIZE
        >= cmsg_align(
            core::mem::size_of::<Cmsghdr>() + SCM_RIGHTS_MAX_FDS * core::mem::size_of::<i32>()
        )
);

/// Reclaim every peer-injected `SCM_RIGHTS` file descriptor XNU installed from
/// this datagram's ancillary data.
///
/// `recv_authenticated` calls this once per datagram, ahead of every return
/// path, on every credential-passing platform. On macOS the kernel installs
/// passed fds even though the observer never solicits ancillary data (it uses
/// `getsockopt` for credentials); left open they exhaust the long-lived
/// single-threaded observer's fd table and silently disable recovery
/// (fd-exhaustion DoS — the macOS twin of the Linux/BSD/illumos leak). The walk
/// is bounded by the kernel-reported `msg_controllen` and clamps each cmsg's
/// payload to the bytes actually present, so a truncated or malformed control
/// buffer can never drive an out-of-bounds read.
pub(crate) fn reclaim_scm_rights(mhdr: &Msghdr) {
    let base = mhdr.msg_control as *const u8;
    if base.is_null() {
        return;
    }
    let controllen = mhdr.msg_controllen as usize;
    let hdr_size = core::mem::size_of::<Cmsghdr>();
    let mut off = 0usize;
    while off + hdr_size <= controllen {
        // SAFETY: `base + off` is in-bounds (`off + hdr_size <= controllen`)
        // and points at kernel-initialised cmsg bytes from `recvmsg(2)`. The
        // ancillary buffer is `#[repr(align(8))]` in `recv.rs`, satisfying the
        // 4-byte alignment of `Cmsghdr`.
        let hdr = unsafe { &*(base.add(off) as *const Cmsghdr) };
        let cmsg_len = hdr.cmsg_len as usize;
        if cmsg_len < hdr_size {
            break;
        }
        if hdr.cmsg_level == SOL_SOCKET && hdr.cmsg_type == SCM_RIGHTS {
            // Clamp the payload to the bytes actually inside the buffer: a
            // peer (or a truncating kernel) can report a `cmsg_len` larger
            // than what was delivered.
            let declared_payload = cmsg_len - hdr_size;
            let avail_payload = controllen.saturating_sub(off + hdr_size);
            let payload = declared_payload.min(avail_payload);
            let fd_count = payload / core::mem::size_of::<i32>();
            for i in 0..fd_count {
                // SAFETY: `off + hdr_size + i*4 + 4 <= off + hdr_size + payload
                // <= controllen`, so the i32 is in bounds. `read_unaligned`
                // because the cmsg payload ABI only promises byte validity.
                let fd = unsafe {
                    base.add(off + hdr_size + i * core::mem::size_of::<i32>())
                        .cast::<i32>()
                        .read_unaligned()
                };
                if fd >= 0 {
                    // SAFETY: `recvmsg` installed this descriptor into our fd
                    // table; close it to reclaim. Close errors cannot be
                    // usefully recovered on the receive path.
                    let _ = unsafe { close(fd) };
                }
            }
        }
        // Advance by the aligned cmsg size; clamp to at least one header so a
        // malicious `cmsg_len` cannot stall the walk.
        let adv = cmsg_align(cmsg_len).max(hdr_size);
        off = match off.checked_add(adv) {
            Some(v) => v,
            None => break,
        };
    }
}

/// Extract peer PID and UID after a successful `recvmsg` on macOS.
///
/// Attempts `getsockopt(LOCAL_PEERTOKEN)` first; on failure or short return
/// falls back to `LOCAL_PEERPID` + `LOCAL_PEERCRED`. The single-threaded
/// observer guarantees no other datagram can arrive between `recvmsg(2)`
/// and these syscalls. Always returns `Some` on macOS — even when all three
/// mechanisms fail, the sentinel `(0, 0)` is returned so the caller can
/// distinguish "no kernel attestation" from "I/O error".
///
/// The syscall outcomes are produced by three small unsafe shims and then
/// combined by [`super::super::macos_fallback::pid_uid_from_results`],
/// which is pure logic and independently tested.
pub(crate) fn peer_pid_after_recv(
    fd: i32,
    _mhdr: &Msghdr,
) -> Option<(u32, u32, Option<super::super::types::PeerPidFd>)> {
    let token = get_token(fd);
    let pid = get_peer_pid(fd);
    let cred = get_peer_cred(fd);
    let (pid, uid) = super::super::macos_fallback::pid_uid_from_results(token, pid, cred);
    Some((pid, uid, None))
}

fn get_token(fd: i32) -> super::super::macos_fallback::TokenResult {
    let mut token = AuditToken { val: [0u32; 8] };
    let mut optlen: u32 = mem::size_of::<AuditToken>() as u32;
    // SAFETY: `getsockopt(2)` with `LOCAL_PEERTOKEN` (see `unix(4)`) writes
    // an `audit_token_t` of `optlen` bytes into `token` on success.
    // - `fd` is the observer's UDS receive socket (opened by the listener).
    // - `&mut token as *mut AuditToken as *mut c_void` is properly aligned
    //   (`#[repr(C)]`, 4-byte alignment of `u32`) and points to a stack
    //   buffer of `size_of::<AuditToken>() == 32` bytes (compile-time
    //   asserted below).
    // - `optlen` is initialised to the buffer's size before the call and
    //   updated in-place; the decision function checks
    //   `optlen >= size_of::<AuditToken>()` before trusting the result.
    let ret = unsafe {
        getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            &mut token as *mut AuditToken as *mut c_void,
            &mut optlen,
        )
    };
    // `val[5]` is `at_pid`, `val[1]` is `at_euid`; index positions are
    // documented at the `AuditToken` definition above.
    super::super::macos_fallback::TokenResult {
        ret,
        optlen,
        at_pid: token.val[5],
        at_euid: token.val[1],
    }
}

fn get_peer_pid(fd: i32) -> super::super::macos_fallback::PidResult {
    let mut pid: i32 = 0;
    let mut optlen: u32 = mem::size_of::<i32>() as u32;
    // SAFETY: `getsockopt(2)` with `LOCAL_PEERPID` writes an `i32` of
    // `optlen` bytes into `pid` on success.
    // - `&mut pid as *mut i32 as *mut c_void` is properly aligned (i32,
    //   4-byte alignment) and points to a stack buffer of 4 bytes.
    // - `optlen` is initialised to 4 bytes and updated in-place; the
    //   decision function checks `optlen >= 4` before trusting the result.
    let ret = unsafe {
        getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut i32 as *mut c_void,
            &mut optlen,
        )
    };
    super::super::macos_fallback::PidResult { ret, optlen, pid }
}

fn get_peer_cred(fd: i32) -> super::super::macos_fallback::CredResult {
    let mut cred = Xucred {
        cr_version: 0,
        cr_uid: 0,
        cr_ngroups: 0,
        cr_groups: [0u32; 16],
    };
    let mut optlen: u32 = mem::size_of::<Xucred>() as u32;
    // SAFETY: `getsockopt(2)` with `LOCAL_PEERCRED` writes an
    // `xucred` of `optlen` bytes into `cred` on success.
    // - `&mut cred as *mut Xucred as *mut c_void` is properly aligned
    //   (`#[repr(C)]`, 4-byte alignment) and points to a stack buffer of
    //   `size_of::<Xucred>() == 76` bytes (compile-time asserted below).
    // - `optlen` is initialised to the buffer's size and updated in-place;
    //   the decision function checks `optlen >= 8` (enough to cover
    //   `cr_version` + `cr_uid`) before trusting `cr_uid`.
    let ret = unsafe {
        getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERCRED,
            &mut cred as *mut Xucred as *mut c_void,
            &mut optlen,
        )
    };
    super::super::macos_fallback::CredResult {
        ret,
        optlen,
        cr_uid: cred.cr_uid,
    }
}

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

/// macOS does not set `MSG_CTRUNC` for UDS credential data — always `false`.
pub(crate) fn ctrl_truncated(_mhdr: &Msghdr) -> bool {
    false
}

// Compile-time invariant: macOS msghdr is 48 bytes on x86_64 + aarch64.
const _: () = assert!(mem::size_of::<Msghdr>() == 48);

// Compile-time invariant: audit_token_t is 8 × u32 = 32 bytes.
const _: () = assert!(mem::size_of::<AuditToken>() == 32);

// Compile-time invariant: xucred layout matches XNU's struct xucred
// (u32 + u32 + i16 + 2 pad + [u32; 16] = 76 bytes on LP64).
const _: () = assert!(mem::size_of::<Xucred>() == 76);

// Offset checks for every field the recvmsg path touches. Manual layouts are a
// tradeoff: we avoid the libc crate to satisfy the zero-dependency constraint,
// but field-order / padding mistakes would silently corrupt I/O. These guards
// catch divergence on any kernel/libc version during tests.
#[cfg(test)]
mod tests {
    use super::{get_peer_pid, get_token, Iovec, Msghdr};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn recvmsg_layout_offsets_match_xnu_abi() {
        assert_field_offset!(Msghdr, msg_name, 0);
        assert_field_offset!(Msghdr, msg_namelen, 8);
        assert_field_offset!(Msghdr, msg_iov, 16);
        assert_field_offset!(Msghdr, msg_iovlen, 24);
        assert_field_offset!(Msghdr, msg_control, 32);
        assert_field_offset!(Msghdr, msg_controllen, 40);
        assert_field_offset!(Msghdr, msg_flags, 44);

        assert_field_offset!(Iovec, iov_base, 0);
        assert_field_offset!(Iovec, iov_len, 8);
    }

    #[test]
    fn connected_datagram_pair_reports_peer_token() {
        let (left, right) = UnixDatagram::pair().expect("socket pair");
        right.send(&[1]).expect("send datagram");
        let mut buf = [0u8; 1];
        left.recv(&mut buf).expect("recv datagram");

        let token = get_token(left.as_raw_fd());
        assert_eq!(token.ret, 0);
        assert!(token.optlen >= core::mem::size_of::<super::AuditToken>() as u32);
        assert_eq!(token.at_pid, std::process::id());

        let pid = get_peer_pid(left.as_raw_fd());
        assert_eq!(pid.ret, 0);
        assert!(pid.optlen >= core::mem::size_of::<i32>() as u32);
        assert_eq!(pid.pid, std::process::id() as i32);
    }
}
