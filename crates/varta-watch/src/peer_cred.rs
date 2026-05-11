//! Kernel-level peer credential verification for Unix domain datagrams.
//!
//! On Linux the observer calls `recvmsg(2)` with `SO_PASSCRED` enabled so
//! the kernel attaches `SCM_CREDENTIALS` (containing `struct ucred`) to each
//! datagram.
//!
//! On macOS per-datagram peer PID is not available for unconnected
//! `SOCK_DGRAM` (`LOCAL_CREDS` is not supported and `LOCAL_PEERPID` only
//! works on connected sockets), so the observer falls back to a sentinel
//! PID and relies on `--socket-mode 0600` to restrict the trust boundary
//! to the owning UID.  See `docs/architecture/peer-authentication.md`.
//!
//! The module uses only inline `extern "C"` FFI — no `libc` crate — to
//! satisfy the workspace's zero-registry-dependency constraint.

use std::io;

// ---------------------------------------------------------------------------
// Platform-agnostic result type
// ---------------------------------------------------------------------------

/// Outcome of a single `recvmsg(2)` call with credential extraction.
pub enum RecvResult {
    /// A full 32-byte frame was received along with credentials; `peer_pid`
    /// is the PID the kernel attributes the datagram to. On Linux this is
    /// derived from SCM_CREDENTIALS (SO_PASSCRED); on macOS it's a sentinel
    /// since per-datagram PIDs are not available for unconnected SOCK_DGRAM.
    Authenticated {
        /// Kernel-attested PID of the sending process (Linux) or sentinel 0
        /// (macOS — no per-datagram credential support).
        peer_pid: u32,
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
}

// ---------------------------------------------------------------------------
// Linux-specific CMSG helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn cmsg_align(len: usize) -> usize {
    let align = core::mem::size_of::<usize>();
    (len + align - 1) & !(align - 1)
}

#[cfg(target_os = "linux")]
fn cmsg_hdr_size() -> usize {
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

    pub(super) const ANCILLARY_BUFFER_SIZE: usize = 64;

    /// Extract peer PID after a successful `recvmsg` — on Linux this is
    /// done via ancillary-data parsing.
    pub(super) fn peer_pid_after_recv(_fd: i32, mhdr: &Msghdr, anc_base: *const u8) -> Option<u32> {
        let hdr = unsafe { cmsg_firsthdr(mhdr) };
        unsafe { find_credential_pid(hdr, mhdr, anc_base) }
    }

    // Compile-time invariant: glibc/Linux msghdr is 56 bytes on every 64-bit
    // target Rust supports.  A Rust-side field reorder or padding mistake
    // becomes a hard compile error instead of UB at recvmsg time.
    const _: () = assert!(mem::size_of::<Msghdr>() == 56);
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

    // --- FFI --------------------------------------------------------------

    extern "C" {
        pub(super) fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;
    }

    // --- ancillary buffer sizing ------------------------------------------

    pub(super) const ANCILLARY_BUFFER_SIZE: usize = 16;

    /// Extract peer PID after a successful `recvmsg` on macOS.
    ///
    /// macOS does not expose a reliable per-datagram PID on the server side
    /// of an unconnected `SOCK_DGRAM` socket (LOCAL_PEERPID works for connected
    /// sockets only).  We return a sentinel so the observer can proceed — the
    /// primary defence on macOS is `--socket-mode 0600` which restricts access
    /// to the owning UID.
    pub(super) fn peer_pid_after_recv(
        _fd: i32,
        _mhdr: &Msghdr,
        _anc_base: *const u8,
    ) -> Option<u32> {
        Some(0)
    }

    // Compile-time invariant: macOS msghdr is 48 bytes on x86_64 + aarch64.
    const _: () = assert!(mem::size_of::<Msghdr>() == 48);
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
/// ancillary data on every datagram.  On macOS this is a no-op — per-datagram
/// peer PID is not exposed for unconnected `SOCK_DGRAM`, so the observer
/// relies on `--socket-mode 0600` to restrict the trust boundary by UID.
pub fn enable_credential_passing(fd: i32) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = fd;
        Ok(())
    }

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
}

/// Receive one datagram from `fd` and extract its kernel-attested sender PID.
///
/// Returns [`RecvResult::Authenticated`] with the peer PID and the 32-byte
/// frame payload. Timed-out reads yield [`RecvResult::WouldBlock`]; short
/// reads yield [`RecvResult::ShortRead`]; fatal errors yield
/// [`RecvResult::IoError`].
pub fn recv_authenticated(fd: i32) -> RecvResult {
    let mut data = [0u8; 32];

    #[repr(align(8))]
    struct AncBuf([u8; plat::ANCILLARY_BUFFER_SIZE]);
    let mut anc = AncBuf([0u8; plat::ANCILLARY_BUFFER_SIZE]);

    let mut iov = plat::Iovec {
        iov_base: data.as_mut_ptr() as *mut core::ffi::c_void,
        iov_len: 32,
    };

    let mut mhdr = plat::Msghdr {
        msg_name: core::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: anc.0.as_mut_ptr() as *mut core::ffi::c_void,
        msg_controllen: plat::ANCILLARY_BUFFER_SIZE as _,
        msg_flags: 0,
        #[cfg(target_os = "linux")]
        _pad1: 0,
        #[cfg(target_os = "linux")]
        _pad2: 0,
        #[cfg(target_os = "macos")]
        _pad1: 0,
        #[cfg(target_os = "macos")]
        _pad2: 0,
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

    if n as usize != 32 {
        return RecvResult::ShortRead;
    }

    let peer_pid = match plat::peer_pid_after_recv(fd, &mhdr, anc.0.as_ptr()) {
        Some(pid) => pid,
        None => {
            return RecvResult::IoError(io::Error::new(
                io::ErrorKind::InvalidData,
                "kernel did not attach SCM_CREDENTIALS ancillary data",
            ));
        }
    };

    RecvResult::Authenticated { peer_pid, data }
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
) -> Option<u32> {
    let target_level = plat::SOL_SOCKET;
    let target_type = plat::SCM_CREDENTIALS;
    // Minimum bytes a SCM_CREDENTIALS message must contain: aligned cmsghdr
    // followed by a struct ucred.  Anything shorter is malformed and would
    // cause an OOB read of the ancillary buffer if dereferenced.
    let needed = cmsg_hdr_size() + core::mem::size_of::<plat::Ucred>();

    while let Some(cmsg) = hdr {
        if cmsg.cmsg_level == target_level && cmsg.cmsg_type == target_type {
            if cmsg.cmsg_len < needed {
                return None;
            }
            let data_ptr = unsafe { cmsg_data(cmsg) };
            let ucred = unsafe { &*(data_ptr as *const plat::Ucred) };
            return Some(ucred.pid as u32);
        }
        hdr = unsafe { cmsg_nxthdr(mhdr, cmsg, base) };
    }
    None
}
