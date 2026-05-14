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
mod types;

pub(crate) use ns_inode::{observer_pid_namespace_inode, read_pid_namespace_inode};
pub(crate) use types::observer_uid;
pub use types::{BeatOrigin, RecvResult};

use std::io;

// ---------------------------------------------------------------------------
// CMSG alignment helpers (shared by all CMSG-using platforms)
// ---------------------------------------------------------------------------

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
))]
const fn cmsg_align(len: usize) -> usize {
    // On all supported 64-bit platforms, sizeof(size_t) == sizeof(long) == 8,
    // which matches CMSG_ALIGN.  On 32-bit both are 4.
    let align = core::mem::size_of::<usize>();
    (len + align - 1) & !(align - 1)
}

#[cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
))]
const fn cmsg_hdr_size() -> usize {
    cmsg_align(core::mem::size_of::<plat::Cmsghdr>())
}

// ---------------------------------------------------------------------------
// Platform-specific structs, constants, FFI
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod plat {
    use core::ffi::c_void;
    use core::mem;

    // --- structs ----------------------------------------------------------

    #[repr(C)]
    pub(super) struct Iovec {
        pub iov_base: *mut c_void,
        pub iov_len: usize,
    }

    #[repr(C)]
    pub(super) struct Msghdr {
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
    pub(super) struct Cmsghdr {
        pub cmsg_len: usize,
        pub cmsg_level: i32,
        pub cmsg_type: i32,
    }

    #[repr(C)]
    pub(super) struct Ucred {
        pub pid: i32,
        pub uid: u32,
        pub gid: u32,
    }

    // --- constants --------------------------------------------------------

    pub(super) const SOL_SOCKET: i32 = 1;
    pub(super) const SO_PASSCRED: i32 = 16;
    pub(super) const SCM_CREDENTIALS: i32 = 2;
    /// Set by the kernel when ancillary data was truncated (buffer too small).
    pub(super) const MSG_CTRUNC: i32 = 0x20;

    // --- FFI --------------------------------------------------------------

    extern "C" {
        pub(super) fn setsockopt(
            fd: i32,
            level: i32,
            optname: i32,
            optval: *const c_void,
            optlen: u32,
        ) -> i32;

        pub(super) fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;
    }

    // --- ancillary buffer sizing ------------------------------------------

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
    pub(super) const ANCILLARY_BUFFER_SIZE: usize = 256;

    // Compile-time guard: the ancillary buffer must fit at least one
    // SCM_CREDENTIALS message (aligned cmsghdr + struct ucred).
    const _: () =
        assert!(ANCILLARY_BUFFER_SIZE >= super::cmsg_hdr_size() + core::mem::size_of::<Ucred>());

    /// Extract peer PID and UID after a successful `recvmsg` — on Linux this is
    /// done via ancillary-data parsing.
    pub(super) fn peer_pid_after_recv(
        _fd: i32,
        mhdr: &Msghdr,
        anc_base: *const u8,
    ) -> Option<(u32, u32)> {
        debug_assert_eq!(
            mhdr.msg_control as *const u8, anc_base,
            "msg_control and ancillary buffer base must be the same address"
        );
        let hdr = unsafe { super::cmsg_firsthdr(mhdr) };
        unsafe { super::find_credential_pid(hdr, mhdr, anc_base) }
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
}

#[cfg(target_os = "macos")]
mod plat {
    use core::ffi::c_void;
    use core::mem;

    // --- structs ----------------------------------------------------------

    #[repr(C)]
    pub(super) struct Iovec {
        pub iov_base: *mut c_void,
        pub iov_len: usize,
    }

    #[repr(C)]
    pub(super) struct Msghdr {
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
    pub(super) struct AuditToken {
        pub val: [u32; 8],
    }

    // struct xucred from <sys/un.h> — returned by LOCAL_PEERCRED (0x0001).
    // NGROUPS is 16 on macOS / XNU.
    #[repr(C)]
    pub(super) struct Xucred {
        pub cr_version: u32,
        pub cr_uid: u32,
        pub cr_ngroups: i16,
        pub cr_groups: [u32; 16],
    }

    // --- constants --------------------------------------------------------

    // SOL_SOCKET on macOS / XNU = 0xffff (<sys/socket.h>)
    pub(super) const SOL_SOCKET: i32 = 0xffff;
    // LOCAL_PEERTOKEN = 0x0021 (<sys/un.h>) — get the peer's audit token
    pub(super) const LOCAL_PEERTOKEN: i32 = 0x0021;
    // LOCAL_PEERPID = 0x0002 (<sys/un.h>) — get the peer's PID
    pub(super) const LOCAL_PEERPID: i32 = 0x0002;
    // LOCAL_PEERCRED = 0x0001 (<sys/un.h>) — get the peer's xucred
    pub(super) const LOCAL_PEERCRED: i32 = 0x0001;

    // --- FFI --------------------------------------------------------------

    extern "C" {
        pub(super) fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;
        pub(super) fn getsockopt(
            fd: i32,
            level: i32,
            optname: i32,
            optval: *mut c_void,
            optlen: *mut u32,
        ) -> i32;
    }

    // --- ancillary buffer sizing ------------------------------------------

    pub(super) const ANCILLARY_BUFFER_SIZE: usize = 16;

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
    pub(super) fn peer_pid_after_recv(
        fd: i32,
        _mhdr: &Msghdr,
        _anc_base: *const u8,
    ) -> Option<(u32, u32)> {
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
}

// ---------------------------------------------------------------------------
// FreeBSD / DragonFly / NetBSD — SCM_CREDS via LOCAL_CREDS
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
mod plat {
    use core::ffi::c_void;
    use core::mem;

    // --- structs ----------------------------------------------------------

    #[repr(C)]
    pub(super) struct Iovec {
        pub iov_base: *mut c_void,
        pub iov_len: usize,
    }

    #[repr(C)]
    pub(super) struct Msghdr {
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
    pub(super) struct Cmsghdr {
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
    pub(super) struct Cmsgcred {
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

    // --- constants --------------------------------------------------------

    /// `SOL_SOCKET` on FreeBSD / XNU derivatives = `0xffff` (`<sys/socket.h>`).
    pub(super) const SOL_SOCKET: i32 = 0xffff;
    /// `LOCAL_CREDS` enables SCM_CREDS ancillary data on received datagrams.
    /// Value: 0x0002 on FreeBSD/DragonFly (`<sys/un.h>`),
    ///        0x0001 on NetBSD.
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    pub(super) const LOCAL_CREDS: i32 = 0x0002;
    #[cfg(target_os = "netbsd")]
    pub(super) const LOCAL_CREDS: i32 = 0x0001;
    /// `SCM_CREDS` — the CMSG type for cmsgcred ancillary data.
    pub(super) const SCM_CREDS: i32 = 0x03;

    // --- FFI --------------------------------------------------------------

    extern "C" {
        pub(super) fn setsockopt(
            fd: i32,
            level: i32,
            optname: i32,
            optval: *const c_void,
            optlen: u32,
        ) -> i32;

        pub(super) fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;
    }

    // --- ancillary buffer sizing ------------------------------------------

    // CMSG_SPACE(sizeof(struct cmsgcred)) on 64-bit BSD:
    //   cmsg_align(sizeof(Cmsghdr)) + cmsg_align(sizeof(Cmsgcred))
    //   = cmsg_align(12)           + cmsg_align(84)
    //   = 16                       + 88
    //   = 104 bytes
    //
    // 256 bytes provides generous headroom for kernel ancillary-data
    // extensions (e.g. future security labels) — same sizing as Linux.
    pub(super) const ANCILLARY_BUFFER_SIZE: usize = 256;

    const _: () =
        assert!(ANCILLARY_BUFFER_SIZE >= super::cmsg_hdr_size() + core::mem::size_of::<Cmsgcred>());

    /// Extract peer PID and effective UID after a successful `recvmsg` on BSD.
    ///
    /// Iterates ancillary data looking for an `SCM_CREDS` message containing
    /// a `struct cmsgcred`.  Returns `(cmcred_pid, cmcred_euid)`.
    pub(super) fn peer_pid_after_recv(
        _fd: i32,
        mhdr: &Msghdr,
        anc_base: *const u8,
    ) -> Option<(u32, u32)> {
        debug_assert_eq!(
            mhdr.msg_control as *const u8, anc_base,
            "msg_control and ancillary buffer base must be the same address"
        );
        let hdr = unsafe { super::cmsg_firsthdr(mhdr) };
        unsafe { super::find_credential_pid(hdr, mhdr, anc_base) }
    }

    // --- compile-time layout guards ---------------------------------------

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
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Enable the kernel to attach sender credentials to every received datagram.
///
/// Must be called once after the observer binds its socket and before the
/// first call to [`recv_authenticated`].
///
/// On Linux this sets `SO_PASSCRED` so the kernel includes `SCM_CREDENTIALS`
/// ancillary data on every datagram.  On FreeBSD / DragonFly / NetBSD this
/// sets `LOCAL_CREDS` so the kernel includes `SCM_CREDS` ancillary data
/// (struct cmsgcred).  On macOS this is a no-op — per-datagram peer PID is
/// obtained via `getsockopt(LOCAL_PEERTOKEN)` after each recvmsg.
pub(crate) fn enable_credential_passing(fd: i32) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let (level, optname) = (plat::SOL_SOCKET, plat::SO_PASSCRED);
        let one: i32 = 1;
        let ret = unsafe {
            plat::setsockopt(
                fd,
                level,
                optname,
                core::ptr::addr_of!(one) as *const core::ffi::c_void,
                core::mem::size_of::<i32>() as u32,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
    {
        let (level, optname) = (plat::SOL_SOCKET, plat::LOCAL_CREDS);
        let one: i32 = 1;
        let ret = unsafe {
            plat::setsockopt(
                fd,
                level,
                optname,
                core::ptr::addr_of!(one) as *const core::ffi::c_void,
                core::mem::size_of::<i32>() as u32,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
    )))]
    {
        let _ = fd;
        Ok(())
    }
}

/// Receive one datagram from `fd` and extract its kernel-attested sender PID.
///
/// Returns [`RecvResult::Authenticated`] with the peer PID and the 32-byte
/// frame payload. Timed-out reads yield [`RecvResult::WouldBlock`]; short
/// reads yield [`RecvResult::ShortRead`]; fatal errors yield
/// [`RecvResult::IoError`].
pub(crate) fn recv_authenticated(fd: i32) -> RecvResult {
    let mut data = [0u8; 32];

    #[repr(align(8))]
    struct AncBuf([u8; plat::ANCILLARY_BUFFER_SIZE]);
    let mut anc = AncBuf([0u8; plat::ANCILLARY_BUFFER_SIZE]);

    let mut iov = plat::Iovec {
        iov_base: data.as_mut_ptr() as *mut core::ffi::c_void,
        iov_len: 32,
    };

    let mut mhdr = {
        #[cfg(target_os = "linux")]
        {
            plat::Msghdr {
                msg_name: core::ptr::null_mut(),
                msg_namelen: 0,
                _pad1: 0,
                msg_iov: &mut iov,
                msg_iovlen: 1,
                msg_control: anc.0.as_mut_ptr() as *mut core::ffi::c_void,
                msg_controllen: plat::ANCILLARY_BUFFER_SIZE as _,
                msg_flags: 0,
                _pad2: 0,
            }
        }
        #[cfg(target_os = "macos")]
        {
            plat::Msghdr {
                msg_name: core::ptr::null_mut(),
                msg_namelen: 0,
                _pad1: 0,
                msg_iov: &mut iov,
                msg_iovlen: 1,
                _pad2: 0,
                msg_control: anc.0.as_mut_ptr() as *mut core::ffi::c_void,
                msg_controllen: plat::ANCILLARY_BUFFER_SIZE as _,
                msg_flags: 0,
            }
        }
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
        {
            plat::Msghdr {
                msg_name: core::ptr::null_mut(),
                msg_namelen: 0,
                _pad1: 0,
                msg_iov: &mut iov,
                msg_iovlen: 1,
                _pad2: 0,
                msg_control: anc.0.as_mut_ptr() as *mut core::ffi::c_void,
                msg_controllen: plat::ANCILLARY_BUFFER_SIZE as _,
                msg_flags: 0,
            }
        }
    };

    let n = loop {
        let ret = unsafe { plat::recvmsg(fd, &mut mhdr, 0) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    return RecvResult::WouldBlock;
                }
                io::ErrorKind::Interrupted => continue,
                _ => return RecvResult::IoError(err),
            }
        }
        break ret as isize;
    };

    #[cfg(target_os = "linux")]
    if mhdr.msg_flags & plat::MSG_CTRUNC != 0 {
        return RecvResult::CtrlTruncated(io::Error::new(
            io::ErrorKind::InvalidData,
            "ancillary data truncated by kernel (ANCILLARY_BUFFER_SIZE too small)",
        ));
    }
    let _ = mhdr.msg_flags;

    if n as usize != 32 {
        return RecvResult::ShortRead;
    }

    let (peer_pid, peer_uid) = match plat::peer_pid_after_recv(fd, &mhdr, anc.0.as_ptr()) {
        Some((pid, uid)) => (pid, uid),
        None => {
            return RecvResult::IoError(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel did not attach peer credentials",
            ));
        }
    };

    let my_uid = observer_uid();
    if peer_pid != 0 && peer_uid != my_uid {
        return RecvResult::IoError(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "peer credential UID mismatch: kernel reports uid {peer_uid}, expected uid {my_uid}"
            ),
        ));
    }

    // Resolve the peer's PID-namespace inode (Linux only). Done after the UID
    // check so the strongest signal (UID mismatch) fires first. Returns `None`
    // on non-Linux or when /proc/<pid>/ns/pid is unreadable — the cross-ns
    // gate downstream short-circuits to "match" in that case.
    let peer_pid_ns_inode = if peer_pid != 0 {
        read_pid_namespace_inode(peer_pid)
    } else {
        None
    };

    RecvResult::Authenticated {
        peer_pid,
        peer_uid,
        peer_pid_ns_inode,
        origin: BeatOrigin::KernelAttested,
        data,
    }
}

// ---------------------------------------------------------------------------
// Linux-specific CMSG helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
unsafe fn cmsg_firsthdr(mhdr: &plat::Msghdr) -> Option<&plat::Cmsghdr> {
    let control = mhdr.msg_control;
    if control.is_null() {
        return None;
    }
    if mhdr.msg_controllen < cmsg_hdr_size() {
        return None;
    }
    unsafe { Some(&*(control as *const plat::Cmsghdr)) }
}

#[cfg(target_os = "linux")]
unsafe fn cmsg_nxthdr<'a>(
    mhdr: &plat::Msghdr,
    cmsg: &'a plat::Cmsghdr,
    base: *const u8,
) -> Option<&'a plat::Cmsghdr> {
    let cur = (cmsg as *const plat::Cmsghdr) as *const u8;
    let offset = unsafe { cur.offset_from(base) } as usize;
    let advance = cmsg_align(cmsg.cmsg_len);
    let next_offset = offset + advance;

    if next_offset + cmsg_hdr_size() > mhdr.msg_controllen {
        return None;
    }
    let next = unsafe { &*(base.add(next_offset) as *const plat::Cmsghdr) };
    let remaining = mhdr.msg_controllen - next_offset;
    if next.cmsg_len > remaining {
        return None;
    }
    Some(next)
}

#[cfg(target_os = "linux")]
unsafe fn cmsg_data(cmsg: &plat::Cmsghdr) -> *const u8 {
    unsafe { (cmsg as *const plat::Cmsghdr as *const u8).add(cmsg_hdr_size()) }
}

#[cfg(target_os = "linux")]
unsafe fn find_credential_pid(
    mut hdr: Option<&plat::Cmsghdr>,
    mhdr: &plat::Msghdr,
    base: *const u8,
) -> Option<(u32, u32)> {
    let target_level = plat::SOL_SOCKET;
    let target_type = plat::SCM_CREDENTIALS;
    let needed = cmsg_hdr_size() + core::mem::size_of::<plat::Ucred>();

    while let Some(cmsg) = hdr {
        if cmsg.cmsg_level == target_level && cmsg.cmsg_type == target_type {
            if cmsg.cmsg_len < needed {
                return None;
            }
            let data_ptr = unsafe { cmsg_data(cmsg) };
            let ucred = unsafe { &*(data_ptr as *const plat::Ucred) };
            return Some((ucred.pid as u32, ucred.uid));
        }
        hdr = unsafe { cmsg_nxthdr(mhdr, cmsg, base) };
    }
    None
}

// ---------------------------------------------------------------------------
// BSD-specific CMSG helpers
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
unsafe fn cmsg_firsthdr(mhdr: &plat::Msghdr) -> Option<&plat::Cmsghdr> {
    let control = mhdr.msg_control;
    if control.is_null() {
        return None;
    }
    if (mhdr.msg_controllen as usize) < cmsg_hdr_size() {
        return None;
    }
    unsafe { Some(&*(control as *const plat::Cmsghdr)) }
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
unsafe fn cmsg_nxthdr<'a>(
    mhdr: &plat::Msghdr,
    cmsg: &'a plat::Cmsghdr,
    base: *const u8,
) -> Option<&'a plat::Cmsghdr> {
    let cur = (cmsg as *const plat::Cmsghdr) as *const u8;
    let offset = unsafe { cur.offset_from(base) } as usize;
    // cmsg_len is u32 on BSD — cast to usize for alignment math.
    let advance = cmsg_align(cmsg.cmsg_len as usize);
    let next_offset = offset + advance;

    if next_offset + cmsg_hdr_size() > mhdr.msg_controllen as usize {
        return None;
    }
    let next = unsafe { &*(base.add(next_offset) as *const plat::Cmsghdr) };
    let remaining = mhdr.msg_controllen as usize - next_offset;
    if next.cmsg_len as usize > remaining {
        return None;
    }
    Some(next)
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
unsafe fn cmsg_data(cmsg: &plat::Cmsghdr) -> *const u8 {
    unsafe { (cmsg as *const plat::Cmsghdr as *const u8).add(cmsg_hdr_size()) }
}

#[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
unsafe fn find_credential_pid(
    mut hdr: Option<&plat::Cmsghdr>,
    mhdr: &plat::Msghdr,
    base: *const u8,
) -> Option<(u32, u32)> {
    let target_level = plat::SOL_SOCKET;
    let target_type = plat::SCM_CREDS;
    let needed = cmsg_hdr_size() + core::mem::size_of::<plat::Cmsgcred>();

    while let Some(cmsg) = hdr {
        if cmsg.cmsg_level == target_level && cmsg.cmsg_type == target_type {
            // cmsg_len is u32 on BSD — compare as usize to match `needed`.
            if (cmsg.cmsg_len as usize) < needed {
                return None;
            }
            let data_ptr = unsafe { cmsg_data(cmsg) };
            let cred = unsafe { &*(data_ptr as *const plat::Cmsgcred) };
            return Some((cred.cmcred_pid as u32, cred.cmcred_euid));
        }
        hdr = unsafe { cmsg_nxthdr(mhdr, cmsg, base) };
    }
    None
}

/// Miri-compatible cmsg pointer-walk tests.
///
/// These tests fabricate the bytes that `recvmsg(2)` would produce — no
/// actual syscall, so Miri can execute the cmsg pointer arithmetic end-to-end
/// with `-Zmiri-strict-provenance` to catch int-to-pointer casts and
/// provenance violations.
///
/// Gated on `target_os = "linux"` because the Linux `plat` module is the
/// only one that exposes `Cmsghdr`/`Ucred`/`Msghdr`/`peer_pid_after_recv`
/// directly.  BSD cmsg parsing follows the same POSIX walking logic; Linux
/// coverage here provides strong structural validation for both.
#[cfg(all(test, target_os = "linux"))]
mod miri_cmsg_tests {
    use super::*;
    use core::mem;

    /// CMSG_SPACE for one `Ucred` on this platform.
    const fn cmsg_space_ucred() -> usize {
        cmsg_align(cmsg_hdr_size() + mem::size_of::<plat::Ucred>())
    }

    /// Write a single SCM_CREDENTIALS `cmsghdr + ucred` into `buf` starting
    /// at `offset`.  Returns the number of bytes written (== CMSG_SPACE).
    fn write_scm_credentials(buf: &mut [u8], offset: usize, pid: i32, uid: u32, gid: u32) {
        let hdr_size = cmsg_hdr_size();
        let total = cmsg_space_ucred();
        let slice = &mut buf[offset..offset + total];

        // Zero the region so padding bytes are deterministic.
        slice.fill(0);

        // Write cmsghdr fields at offset 0: cmsg_len, cmsg_level, cmsg_type.
        // On 64-bit Linux: cmsg_len is usize (8 bytes), then two i32 (4 bytes each).
        let cmsg_len: usize = hdr_size + mem::size_of::<plat::Ucred>();
        slice[..mem::size_of::<usize>()].copy_from_slice(&cmsg_len.to_ne_bytes());
        slice[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        slice[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&plat::SCM_CREDENTIALS.to_ne_bytes());

        // Write ucred at hdr_size: pid (i32), uid (u32), gid (u32).
        let ucred_off = hdr_size;
        slice[ucred_off..ucred_off + 4].copy_from_slice(&pid.to_ne_bytes());
        slice[ucred_off + 4..ucred_off + 8].copy_from_slice(&uid.to_ne_bytes());
        slice[ucred_off + 8..ucred_off + 12].copy_from_slice(&gid.to_ne_bytes());
    }

    /// Build a `plat::Msghdr` that points into `anc_buf` with `controllen` bytes
    /// of valid ancillary data.
    fn make_mhdr(anc_buf: &[u8], controllen: usize) -> plat::Msghdr {
        plat::Msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: core::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: anc_buf.as_ptr() as *mut _,
            msg_controllen: controllen,
            msg_flags: 0,
            _pad2: 0,
        }
    }

    #[test]
    fn empty_buffer_returns_none() {
        let buf = [];
        let mhdr = make_mhdr(&buf, 0);
        let result = plat::peer_pid_after_recv(0, &mhdr, buf.as_ptr());
        assert_eq!(result, None);
    }

    #[test]
    fn single_scm_credentials_returns_pid_uid() {
        let mut buf = [0u8; 256];
        write_scm_credentials(&mut buf, 0, 1234, 1000, 100);
        let controllen = cmsg_space_ucred();
        let mhdr = make_mhdr(&buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr, buf.as_ptr());
        assert_eq!(result, Some((1234, 1000)));
    }

    #[test]
    fn truncated_cmsg_length_returns_none() {
        // Write a cmsg whose cmsg_len is smaller than hdr+ucred.
        let mut buf = [0u8; 256];
        let hdr_size = cmsg_hdr_size();
        // cmsg_len = hdr_size only (no room for ucred).
        let truncated_len: usize = hdr_size;
        buf[..mem::size_of::<usize>()].copy_from_slice(&truncated_len.to_ne_bytes());
        buf[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        buf[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&plat::SCM_CREDENTIALS.to_ne_bytes());
        let controllen = cmsg_space_ucred();
        let mhdr = make_mhdr(&buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr, buf.as_ptr());
        assert_eq!(result, None, "truncated cmsg must not produce a pid");
    }

    #[test]
    fn unknown_cmsg_type_returns_none() {
        let mut buf = [0u8; 256];
        // Write a valid-length cmsg but with a different cmsg_type.
        let hdr_size = cmsg_hdr_size();
        let cmsg_len: usize = hdr_size + mem::size_of::<plat::Ucred>();
        buf[..mem::size_of::<usize>()].copy_from_slice(&cmsg_len.to_ne_bytes());
        buf[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        let wrong_type: i32 = 99;
        buf[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&wrong_type.to_ne_bytes());
        // controllen too small for a second cmsg → walk stops after one cmsg.
        let controllen = cmsg_space_ucred();
        let mhdr = make_mhdr(&buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr, buf.as_ptr());
        assert_eq!(result, None, "unknown cmsg_type must not produce a pid");
    }

    #[test]
    fn multiple_cmsgs_finds_credentials_in_second() {
        // First cmsg: unknown type, second cmsg: SCM_CREDENTIALS.
        let space = cmsg_space_ucred();
        let mut buf = [0u8; 512];

        // First cmsg — unknown type, valid length.
        let hdr_size = cmsg_hdr_size();
        let cmsg_len: usize = hdr_size + mem::size_of::<plat::Ucred>();
        buf[..mem::size_of::<usize>()].copy_from_slice(&cmsg_len.to_ne_bytes());
        buf[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        let wrong_type: i32 = 99;
        buf[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&wrong_type.to_ne_bytes());

        // Second cmsg — SCM_CREDENTIALS with pid=5678.
        write_scm_credentials(&mut buf, space, 5678, 2000, 200);

        let controllen = space * 2;
        let mhdr = make_mhdr(&buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr, buf.as_ptr());
        assert_eq!(result, Some((5678, 2000)));
    }

    #[test]
    fn trailing_padding_does_not_confuse_walker() {
        // A single SCM_CREDENTIALS cmsg followed by extra zero bytes.
        let mut buf = [0u8; 256];
        write_scm_credentials(&mut buf, 0, 999, 42, 42);
        // Report controllen as the full buffer — walker must stop at the
        // cmsg whose cmsg_len does not leave room for another header.
        let controllen = 128;
        let mhdr = make_mhdr(&buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr, buf.as_ptr());
        assert_eq!(result, Some((999, 42)));
    }
}
