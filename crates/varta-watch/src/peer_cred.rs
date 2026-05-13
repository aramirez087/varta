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

use std::io;
use std::sync::OnceLock;

extern "C" {
    fn getuid() -> u32;
}

/// Cached observer UID — called once at startup, then read from the static.
/// On platforms where `getuid()` isn't available as a direct symbol (e.g.
/// musl), caching avoids per-datagram syscall overhead and portability issues.
pub(crate) fn observer_uid() -> u32 {
    static UID: OnceLock<u32> = OnceLock::new();
    *UID.get_or_init(|| unsafe { getuid() })
}

// ---------------------------------------------------------------------------
// PID namespace inode reader (Linux only)
// ---------------------------------------------------------------------------
//
// PID namespaces are a Linux kernel concept (`pid_namespaces(7)`). The inode
// number of `/proc/<pid>/ns/pid` uniquely identifies the namespace a process
// belongs to. The observer reads its own inode once at startup and compares
// the peer's inode on every kernel-attested datagram to detect cross-namespace
// senders. macOS and the BSDs return `None` from these helpers — namespaces
// don't exist as a concept there, so the gate short-circuits to "match".

#[cfg(target_os = "linux")]
extern "C" {
    fn readlink(
        path: *const core::ffi::c_char,
        buf: *mut core::ffi::c_char,
        bufsiz: usize,
    ) -> isize;
}

/// Read the PID-namespace inode for `pid` via `readlink("/proc/<pid>/ns/pid")`.
///
/// Returns `Some(inode)` if the symlink resolves to the canonical `pid:[N]`
/// form. Returns `None` if the platform is not Linux, the symlink is
/// unreadable (peer died, permission denied via `ptrace_may_access`, `/proc`
/// not mounted), or the target string is malformed.
///
/// Zero allocations — uses two stack buffers (32 bytes for the path, 64 bytes
/// for the readlink target).
#[cfg(target_os = "linux")]
pub(crate) fn read_pid_namespace_inode(pid: u32) -> Option<u64> {
    let mut path = [0u8; 32];
    write_proc_pid_ns_pid(&mut path, pid)?;
    let mut link_buf = [0u8; 64];
    // SAFETY: `path` is NUL-terminated by `write_proc_pid_ns_pid`. `link_buf`
    // is a fixed-size stack buffer of known length. `readlink` does not write
    // a NUL terminator (we read only the returned length bytes).
    let ret = unsafe {
        readlink(
            path.as_ptr() as *const core::ffi::c_char,
            link_buf.as_mut_ptr() as *mut core::ffi::c_char,
            link_buf.len(),
        )
    };
    if ret <= 0 {
        return None;
    }
    parse_ns_inode(&link_buf[..ret as usize])
}

/// Format `/proc/<pid>/ns/pid\0` into `out` without allocation. Returns the
/// number of bytes written including the NUL terminator on success, or `None`
/// if the buffer is too small (statically impossible for u32 PIDs given the
/// 32-byte buffer, but defensive).
#[cfg(target_os = "linux")]
fn write_proc_pid_ns_pid(out: &mut [u8; 32], pid: u32) -> Option<usize> {
    let prefix = b"/proc/";
    let suffix = b"/ns/pid\0";
    let mut i = 0;
    for &b in prefix {
        if i >= out.len() {
            return None;
        }
        out[i] = b;
        i += 1;
    }
    // u32 decimal is at most 10 digits.
    let mut digit_buf = [0u8; 10];
    let mut n = pid;
    let mut len = 0usize;
    if n == 0 {
        digit_buf[0] = b'0';
        len = 1;
    } else {
        while n > 0 {
            digit_buf[len] = b'0' + (n % 10) as u8;
            n /= 10;
            len += 1;
        }
    }
    for k in 0..len {
        if i >= out.len() {
            return None;
        }
        out[i] = digit_buf[len - 1 - k];
        i += 1;
    }
    for &b in suffix {
        if i >= out.len() {
            return None;
        }
        out[i] = b;
        i += 1;
    }
    Some(i)
}

/// Parse the inode out of a `pid:[NNNNN]` readlink target.
#[cfg(target_os = "linux")]
fn parse_ns_inode(bytes: &[u8]) -> Option<u64> {
    let prefix = b"pid:[";
    if bytes.len() < prefix.len() + 2 || &bytes[..prefix.len()] != prefix {
        return None;
    }
    let after = &bytes[prefix.len()..];
    let close = after.iter().position(|&b| b == b']')?;
    let digits = &after[..close];
    if digits.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &c in digits {
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as u64)?;
    }
    Some(acc)
}

/// Non-Linux stub: PID namespaces are a Linux kernel concept.
#[cfg(not(target_os = "linux"))]
#[inline]
pub(crate) fn read_pid_namespace_inode(_pid: u32) -> Option<u64> {
    None
}

/// Cached observer PID-namespace inode. Linux processes cannot change PID
/// namespaces after `unshare`, so caching at first call is safe for the
/// observer's lifetime. On non-Linux platforms returns `None`.
pub(crate) fn observer_pid_namespace_inode() -> Option<u64> {
    static NS: OnceLock<Option<u64>> = OnceLock::new();
    *NS.get_or_init(|| {
        #[cfg(target_os = "linux")]
        {
            read_pid_namespace_inode(std::process::id())
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// Platform-agnostic result type
// ---------------------------------------------------------------------------

/// Classification of a received beat's transport origin.
///
/// This is the structural distinction between **kernel-attested** transports
/// (Unix Domain Sockets, where the kernel reports the sender's PID/UID per
/// datagram) and **network-unverified** transports (any UDP variant, where
/// the only authentication is cryptographic and the operator-controlled
/// `frame.pid` field cannot be tied back to a specific sending process).
///
/// Recovery commands fire safety-critical actions (`kill -9 {pid}`,
/// `systemctl restart agent@{pid}.service`) against the PID in the frame.
/// They must NEVER fire for a pid whose beat lifetime is not
/// kernel-attested — see `docs/architecture/peer-authentication.md`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum BeatOrigin {
    /// Beat arrived on a Unix Domain Socket with kernel credential passing
    /// enabled (`SO_PASSCRED` / `LOCAL_PEERTOKEN` / `SCM_CREDS`). The kernel
    /// attests the sender's PID and UID per-datagram; the observer has
    /// already verified `frame.pid == peer_pid`.
    KernelAttested,
    /// Beat arrived on a UDP listener (plain or secure). The wire bytes may
    /// be cryptographically authenticated (secure-udp), but the underlying
    /// transport has no notion of "sending process" — the `frame.pid` field
    /// is purely operator-controlled and cannot be tied back to a kernel
    /// attestation. Any holder of a shared PSK, or a leaked master key, can
    /// forge a beat for any pid.
    NetworkUnverified,
}

/// Outcome of a single `recvmsg(2)` call with credential extraction.
pub enum RecvResult {
    /// A full 32-byte frame was received along with credentials. `peer_pid`
    /// is the PID the kernel attributes the datagram to and `peer_uid` is
    /// the effective UID. On Linux this is derived from SCM_CREDENTIALS
    /// (SO_PASSCRED); on macOS it's obtained via `getsockopt(LOCAL_PEERTOKEN)`.
    ///
    /// `origin` is the transport-class classification: kernel-attested for
    /// UDS, network-unverified for any UDP variant. Plumbed end-to-end to
    /// gate recovery commands on transport trust — see [`BeatOrigin`].
    Authenticated {
        /// Kernel-attested PID of the sending process. Zero for transports
        /// without kernel credential passing (any UDP variant).
        peer_pid: u32,
        /// Kernel-attested effective UID of the sending process. Zero for
        /// transports without kernel credential passing.
        peer_uid: u32,
        /// PID-namespace inode of the sending process (Linux only).
        ///
        /// `None` when the platform doesn't expose PID namespaces (macOS,
        /// BSD), when the peer's `/proc/<pid>/ns/pid` symlink is unreadable
        /// (peer exited, `ptrace_may_access` denial, `/proc` not mounted), or
        /// for UDP transports where `peer_pid` is 0.
        peer_pid_ns_inode: Option<u64>,
        /// Transport-class classification of the beat.
        origin: BeatOrigin,
        /// Received frame payload (always 32 bytes).
        data: [u8; 32],
    },
    /// The read timed out (`EAGAIN` / `EWOULDBLOCK`).
    WouldBlock,
    /// A short (non-32-byte) read — dropped.
    ShortRead,
    /// Fatal I/O error.  Also surfaced when the kernel fails to attach
    /// `SCM_CREDENTIALS` despite `SO_PASSCRED` being set — that case is
    /// observable as `Event::Io` rather than a silent drop so operators
    /// can detect kernel/socket misconfiguration.
    IoError(io::Error),
    /// Ancillary data truncated by the kernel (`MSG_CTRUNC` on Linux).
    /// Indicates `ANCILLARY_BUFFER_SIZE` is too small for the kernel's
    /// per-message metadata — a kernel buffer sizing issue that operators
    /// should monitor separately from generic I/O errors.
    CtrlTruncated(io::Error),
}

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

#[cfg(all(test, target_os = "linux"))]
mod ns_tests {
    use super::*;

    #[test]
    fn parse_ns_inode_known_format() {
        assert_eq!(parse_ns_inode(b"pid:[4026531836]"), Some(4026531836));
        assert_eq!(parse_ns_inode(b"pid:[1]"), Some(1));
    }

    #[test]
    fn parse_ns_inode_rejects_malformed() {
        assert_eq!(parse_ns_inode(b"xxx"), None);
        assert_eq!(parse_ns_inode(b"pid:[]"), None);
        assert_eq!(parse_ns_inode(b"pid:[abc]"), None);
        assert_eq!(parse_ns_inode(b"pid:[42"), None); // missing close bracket
        assert_eq!(parse_ns_inode(b"net:[42]"), None); // wrong namespace prefix
    }

    #[test]
    fn write_proc_pid_ns_pid_formats_correctly() {
        let mut buf = [0u8; 32];
        let n = write_proc_pid_ns_pid(&mut buf, 12345).expect("fits");
        // Expect "/proc/12345/ns/pid\0" — 18 chars + NUL = 19 bytes.
        assert_eq!(n, 19);
        assert_eq!(&buf[..n], b"/proc/12345/ns/pid\0");
    }

    #[test]
    fn observer_can_read_its_own_namespace_inode() {
        // /proc/self/ns/pid is always readable for the running process on
        // Linux with /proc mounted. CI runners satisfy both.
        let inode = observer_pid_namespace_inode();
        assert!(
            inode.is_some(),
            "observer must resolve its own PID-ns inode"
        );
    }
}
