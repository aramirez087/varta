//! Public receive path — `enable_credential_passing` and `recv_authenticated`.
//!
//! These are the two functions the observer calls every iteration of its
//! poll loop: once at setup (`enable_credential_passing`) and once per
//! datagram (`recv_authenticated`). The body is intentionally
//! cfg-branched on `target_os` for the `Msghdr` field-order differences;
//! everything else delegates to `super::plat` and `super::cmsg_*`.

use std::io;

use super::plat;
use super::{observer_uid, read_pid_namespace_inode, BeatOrigin, RecvResult};

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

    let (peer_pid, peer_uid) = match plat::peer_pid_after_recv(fd, &mhdr) {
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
