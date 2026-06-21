//! Public receive path — `enable_credential_passing` and `recv_authenticated`.
//!
//! These are the two functions the observer calls every iteration of its
//! poll loop: once at setup (`enable_credential_passing`) and once per
//! datagram (`recv_authenticated`). The body is intentionally
//! cfg-branched on `target_os` for the `Msghdr` field-order differences;
//! everything else delegates to `super::plat` and `super::cmsg_*`.

use std::io;

use super::plat;
use super::{observer_uid, BeatOrigin, RecvResult};

const VLP_FRAME_LEN: usize = 32;
const VLP_FRAME_RECV_CAP: usize = VLP_FRAME_LEN + 1;

/// Classify a kernel-attested UDS beat by the PID the kernel attributed to it.
///
/// A nonzero `peer_pid` means the kernel named a concrete sending process, so
/// the observer can (and does) enforce the `frame.pid == peer_pid` binding the
/// [`BeatOrigin::KernelAttested`] contract promises — recovery is eligible.
///
/// A zero `peer_pid` is the macOS sentinel returned by
/// [`super::macos_fallback::pid_uid_from_results`] when every
/// `getsockopt` credential mechanism fails: the kernel attributed the datagram
/// to **no** recognisable peer. Tagging that `KernelAttested` would skip both
/// the UID check and the `frame.pid == peer_pid` binding (both guarded by
/// `peer_pid != 0`), letting any same-UID process forge `frame.pid` and drive
/// recovery for a victim pid. Collapse to [`BeatOrigin::SocketModeOnly`]
/// instead — trust derives from socket-file permissions only and the recovery
/// gate refuses it. See CLAUDE.md hard constraint #8.
// Unused on platforms that reach only the socket-mode fallback block (and
// under `force-socketmode-fallback`); the kernel-attested path is its sole
// caller.
#[allow(dead_code)]
fn origin_for_peer_pid(peer_pid: u32) -> BeatOrigin {
    if peer_pid != 0 {
        BeatOrigin::KernelAttested
    } else {
        BeatOrigin::SocketModeOnly
    }
}

/// Enable the kernel to attach sender credentials to every received datagram.
///
/// Must be called once after the observer binds its socket and before the
/// first call to [`recv_authenticated`].
///
/// On Linux this sets `SO_PASSCRED` so the kernel includes `SCM_CREDENTIALS`
/// ancillary data on every datagram. On FreeBSD this sets
/// `LOCAL_CREDS_PERSISTENT` so the kernel includes `SCM_CREDS2` with
/// `sockcred2.sc_pid`; on DragonFly it sets `SO_PASSCRED` so the kernel
/// includes `SCM_CREDS` with `cmsgcred.cmcred_pid`; on NetBSD it sets
/// `LOCAL_CREDS` so the kernel includes `SCM_CREDS` with `sockcred.sc_pid`.
/// On illumos / Solaris this sets `SO_RECVUCRED` so the kernel includes
/// `SCM_UCRED` ancillary data (opaque `ucred_t`). On macOS pathname UDS and
/// all other platforms this is a no-op; they fall back to socket-mode-only
/// defence.
pub(crate) fn enable_credential_passing(fd: i32) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let (level, optname) = (plat::SOL_SOCKET, plat::SO_PASSCRED);
        let one: i32 = 1;
        // SAFETY: `setsockopt(2)` with `SO_PASSCRED` (see `socket(7)` and
        // `unix(7)`) reads `optlen` bytes from `optval`.
        // - `fd` is the observer's UDS receive socket (freshly bound by the
        //   listener immediately before this call).
        // - `addr_of!(one)` produces a valid pointer to a stack-local i32
        //   that outlives the call.
        // - `optlen == size_of::<i32>()` matches what the kernel reads.
        // - The return value is checked; on error we surface the errno.
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

        // Linux 6.5+ can attach a pidfd (`SCM_PIDFD`) to each datagram. That
        // closes the PID-reuse race around deferred `/proc/<pid>` metadata
        // reads: a pidfd remains tied to the original sending task even if
        // the numeric PID is recycled before the observer reaches `/proc`.
        //
        // Older kernels return ENOPROTOOPT/EINVAL for this socket option; keep
        // `SO_PASSCRED` as the hard requirement and treat pidfd as an
        // opportunistic strengthening rather than a startup blocker.
        const ENOPROTOOPT: i32 = 92;
        const EINVAL: i32 = 22;
        let pidfd_ret = unsafe {
            plat::setsockopt(
                fd,
                level,
                plat::SO_PASSPIDFD,
                core::ptr::addr_of!(one) as *const core::ffi::c_void,
                core::mem::size_of::<i32>() as u32,
            )
        };
        if pidfd_ret != 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(ENOPROTOOPT | EINVAL) => {}
                _ => return Err(err),
            }
        }
        Ok(())
    }

    #[cfg(any(target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd"))]
    {
        // The BSD-family credential option is target-specific:
        //
        // - FreeBSD: `LOCAL_CREDS_PERSISTENT` at `SOL_LOCAL`, because plain
        //   `LOCAL_CREDS` emits `sockcred` with no PID.
        // - DragonFly: `SO_PASSCRED` at `SOL_SOCKET`; it has no receiver-side
        //   `LOCAL_CREDS` option.
        // - NetBSD: modern `LOCAL_CREDS` at `SOL_LOCAL`, delivering
        //   `sockcred` with `sc_pid`.
        //
        // Keep the constants centralized in `platform/bsd.rs` so the enabling
        // option stays paired with the cmsg decoder for that target.
        const LEVEL: i32 = plat::CREDENTIAL_PASS_LEVEL;
        const OPTNAME: i32 = plat::CREDENTIAL_PASS_OPTNAME;
        let one: i32 = 1;
        // SAFETY: `setsockopt(2)` with the target's credential-passing option
        // reads `optlen` bytes from `optval`. Same invariants as the Linux
        // branch above: `fd` is the freshly bound UDS receive socket,
        // `addr_of!` yields a valid pointer to a stack-local i32, and `optlen`
        // matches.
        let ret = unsafe {
            plat::setsockopt(
                fd,
                LEVEL,
                OPTNAME,
                core::ptr::addr_of!(one) as *const core::ffi::c_void,
                core::mem::size_of::<i32>() as u32,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    {
        let (level, optname) = (plat::SOL_SOCKET, plat::SO_RECVUCRED);
        let one: i32 = 1;
        // SAFETY: `setsockopt(2)` with `SO_RECVUCRED` (see `socket(3SOCKET)`
        // on illumos/Solaris) reads `optlen` bytes from `optval`. Same
        // invariants as the Linux branch above.
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
        target_os = "illumos",
        target_os = "solaris",
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
///
/// On platforms with per-datagram kernel credential passing (Linux, FreeBSD,
/// DragonFly, NetBSD, illumos, Solaris) a beat the kernel attributed to a
/// concrete peer (`peer_pid != 0`) carries `origin =
/// BeatOrigin::KernelAttested`. macOS pathname datagram sockets do not expose
/// per-datagram credentials to an unconnected observer socket, so they
/// downgrade to `origin = BeatOrigin::SocketModeOnly` through the zero-PID
/// sentinel path. On platforms with no kernel credential passing the beat
/// likewise carries `origin = BeatOrigin::SocketModeOnly` with `peer_pid = 0`.
/// Recovery commands are refused for every `SocketModeOnly` beat.
pub(crate) fn recv_authenticated(fd: i32) -> RecvResult {
    // --- recvmsg credential path (Linux / macOS / BSD / illumos / Solaris) -
    //
    // Suppressed when `force-socketmode-fallback` is active so that the
    // generic fallback block below is reached on any host — enabling the
    // integration test to exercise `BeatOrigin::SocketModeOnly` on Linux CI.
    #[cfg(all(
        not(feature = "force-socketmode-fallback"),
        any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "illumos",
            target_os = "solaris",
        )
    ))]
    {
        let mut data_with_slack = [0u8; VLP_FRAME_RECV_CAP];

        #[repr(align(8))]
        struct AncBuf([u8; plat::ANCILLARY_BUFFER_SIZE]);
        let mut anc = AncBuf([0u8; plat::ANCILLARY_BUFFER_SIZE]);

        let mut iov = plat::Iovec {
            iov_base: data_with_slack.as_mut_ptr() as *mut core::ffi::c_void,
            iov_len: data_with_slack.len(),
        };

        let mut mhdr = plat::msghdr_for_recv(
            &mut iov,
            anc.0.as_mut_ptr() as *mut core::ffi::c_void,
            plat::ANCILLARY_BUFFER_SIZE,
        );

        let n = loop {
            // SAFETY: `recvmsg(2)` reads from `fd` and writes:
            //   - up to `iov.iov_len` (= 33) bytes into the `data_with_slack`
            //     stack array via `iov.iov_base`;
            //   - up to `ANCILLARY_BUFFER_SIZE` bytes of ancillary data into
            //     the `anc` stack array via `mhdr.msg_control`;
            //   - the actual control length into `mhdr.msg_controllen` and the
            //     flags into `mhdr.msg_flags`.
            // All pointed-to buffers are stack-allocated for the duration of
            // this function. The `Msghdr` field layout is verified by layout
            // guards in `plat`. `&mut mhdr` is the single exclusive borrow for
            // the duration of the call. The return value is checked below:
            // `< 0` is errno, `>= 0` is byte count.
            #[cfg(target_os = "linux")]
            let flags = plat::MSG_CMSG_CLOEXEC;
            #[cfg(not(target_os = "linux"))]
            let flags = 0;
            let ret = unsafe { plat::recvmsg(fd, &mut mhdr, flags) };
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
            break ret;
        };

        // Reclaim any peer-injected `SCM_RIGHTS` file descriptors the kernel
        // installed from this datagram's ancillary data, before any return
        // path. Varta never sends fds, so SCM_RIGHTS is always unsolicited;
        // left open they exhaust the long-lived single-threaded observer's fd
        // table and silently disable recovery (fd-exhaustion DoS). This is the
        // single cross-platform reclamation point — the success, truncated, and
        // short-read paths below all run after it. (SCM_PIDFD is handled
        // separately: consumed on success, closed on early-drop.)
        plat::reclaim_scm_rights(&mhdr);

        if plat::ctrl_truncated(&mhdr) {
            #[cfg(target_os = "linux")]
            plat::close_received_fds(&mhdr);
            return RecvResult::CtrlTruncated(io::Error::new(
                io::ErrorKind::InvalidData,
                "ancillary data truncated by kernel (ANCILLARY_BUFFER_SIZE too small)",
            ));
        }

        if n as usize != VLP_FRAME_LEN {
            #[cfg(target_os = "linux")]
            plat::close_received_fds(&mhdr);
            return RecvResult::ShortRead;
        }

        let mut data = [0u8; VLP_FRAME_LEN];
        data.copy_from_slice(&data_with_slack[..VLP_FRAME_LEN]);

        let (peer_pid, peer_uid, peer_pidfd) = match plat::peer_pid_after_recv(fd, &mhdr) {
            Some((pid, uid, pidfd)) => (pid, uid, pidfd),
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

        // PID-namespace inode resolution is intentionally NOT done here.
        // It is deferred to the observer poll loop, which resolves it only
        // after the global rate limiter has admitted the frame. Resolving it
        // per recvmsg would let a datagram flood force one
        // readlink(/proc/<pid>/ns/pid) syscall per packet regardless of the
        // limiter — defeating its purpose of shedding namespace
        // classification work under a rotation attack. `None` here means
        // "unresolved"; the observer fills it in for kernel-attested peers
        // (`peer_pid != 0`). See `Observer::poll_pending`.
        RecvResult::Authenticated {
            peer_pid,
            peer_uid,
            peer_pid_ns_inode: None,
            peer_pidfd,
            // Derived from attestation — NOT hardcoded. A zero `peer_pid`
            // (macOS getsockopt sentinel) downgrades to SocketModeOnly so the
            // recovery gate refuses a beat whose `frame.pid` was never bound
            // to a kernel-attested peer. See `origin_for_peer_pid`.
            origin: origin_for_peer_pid(peer_pid),
            data,
        }
    }

    // --- Socket-mode-only fallback (OpenBSD, AIX, HP-UX, … or test mode) --
    //
    // Platforms without per-datagram kernel credential passing, and any
    // platform when `force-socketmode-fallback` is active. The only defence
    // is `--socket-mode 0600`; any process under the same UID can reach this
    // socket and forge `frame.pid`. Beats are tagged `SocketModeOnly`; the
    // recovery gate refuses to spawn commands for them.
    #[cfg(any(
        feature = "force-socketmode-fallback",
        not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "illumos",
            target_os = "solaris",
        ))
    ))]
    {
        extern "C" {
            fn recv(fd: i32, buf: *mut core::ffi::c_void, len: usize, flags: i32) -> isize;
        }

        let mut data_with_slack = [0u8; VLP_FRAME_RECV_CAP];
        let n = loop {
            // SAFETY: `recv(2)` writes up to `len` bytes into
            // `data_with_slack`, a stack-allocated 33-byte array. The buffer
            // outlives the call.
            // Return value: `< 0` is errno, `>= 0` is byte count.
            let ret = unsafe {
                recv(
                    fd,
                    data_with_slack.as_mut_ptr() as *mut core::ffi::c_void,
                    data_with_slack.len(),
                    0,
                )
            };
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

        if n as usize != VLP_FRAME_LEN {
            return RecvResult::ShortRead;
        }

        let mut data = [0u8; VLP_FRAME_LEN];
        data.copy_from_slice(&data_with_slack[..VLP_FRAME_LEN]);

        return RecvResult::Authenticated {
            peer_pid: 0,
            peer_uid: 0,
            peer_pid_ns_inode: None,
            peer_pidfd: None,
            origin: BeatOrigin::SocketModeOnly,
            data,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::{origin_for_peer_pid, BeatOrigin};
    #[cfg(target_os = "macos")]
    use std::sync::Mutex;

    /// Serializes macOS syscall tests that sample `/dev/fd`. Cargo runs lib tests
    /// in parallel; another test opening a transient fd between before/after
    /// samples produces a spurious +1. Zero-dep alternative to the `serial_test`
    /// crate. The Linux SCM_RIGHTS test uses readlink-target counting instead.
    #[cfg(target_os = "macos")]
    static FD_INVENTORY_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(target_os = "macos")]
    fn eventually_open_fd_count_at_most(expected: usize, sample: impl Fn() -> usize) -> usize {
        let mut last = sample();
        for _ in 0..50 {
            if last <= expected {
                return last;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
            last = sample();
        }
        last
    }

    /// A concrete kernel-attested PID earns `KernelAttested` — the observer
    /// will enforce `frame.pid == peer_pid` and recovery is eligible.
    #[test]
    fn nonzero_peer_pid_is_kernel_attested() {
        assert_eq!(origin_for_peer_pid(4321), BeatOrigin::KernelAttested);
        assert_eq!(origin_for_peer_pid(1), BeatOrigin::KernelAttested);
        assert_eq!(origin_for_peer_pid(u32::MAX), BeatOrigin::KernelAttested);
    }

    /// Regression: the macOS getsockopt sentinel `(0, 0)` — the kernel
    /// attributed the datagram to no recognisable peer — must NOT be tagged
    /// `KernelAttested`. Otherwise the `frame.pid == peer_pid` binding and the
    /// UID check (both guarded by `peer_pid != 0`) are skipped, and the
    /// recovery gate would accept a beat whose `frame.pid` any same-UID
    /// process can forge. Must collapse to `SocketModeOnly` (recovery
    /// refused). See CLAUDE.md hard constraint #8.
    #[test]
    fn zero_peer_pid_collapses_to_socket_mode_only() {
        assert_eq!(origin_for_peer_pid(0), BeatOrigin::SocketModeOnly);
        assert_ne!(origin_for_peer_pid(0), BeatOrigin::KernelAttested);
    }

    /// Regression (fd-exhaustion DoS): a peer datagram carrying an `SCM_RIGHTS`
    /// ancillary message must not leak the passed file descriptor into the
    /// long-lived observer. Before the fix the cmsg walk matched only
    /// `SCM_CREDENTIALS`/`SCM_PIDFD`, so peer-injected fds were silently
    /// installed by `recvmsg` and never closed — any same-UID process could
    /// exhaust the observer's fd table by sending well-formed beats with fds
    /// attached, disabling recovery while the process still appeared live.
    ///
    /// The datagram is sent in-process (sender and observer share this PID), so
    /// the kernel attests a nonzero peer PID and the beat is accepted normally;
    /// the discriminating assertion is that the observer's open-fd count does
    /// not grow across the `recv`.
    // Real-syscall test (bind/sendmsg/recvmsg + `/proc/self/fd` + `unlink`):
    // none of these are available under Miri's isolation, so gate it out of the
    // Miri run. The cmsg pointer-walk soundness Miri actually checks is covered
    // by the fabricated-buffer tests in `cmsg::miri_cmsg_tests`.
    #[cfg(all(
        target_os = "linux",
        not(feature = "force-socketmode-fallback"),
        not(miri)
    ))]
    #[test]
    fn scm_rights_fds_are_reclaimed_not_leaked() {
        use super::plat;
        use super::{enable_credential_passing, recv_authenticated, RecvResult};
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixDatagram;

        extern "C" {
            fn sendmsg(fd: i32, msg: *const plat::Msghdr, flags: i32) -> isize;
        }

        // One `SCM_RIGHTS` cmsg carrying a single fd: aligned cmsghdr (16) +
        // one i32 fd, padded to the next 8-byte boundary (24 total).
        #[repr(C, align(8))]
        struct ScmRightsCmsg {
            hdr: plat::Cmsghdr,
            fd: i32,
            _pad: i32,
        }

        /// Count open fds whose `/proc/self/fd/<n>` target matches `target`.
        /// Unlike a raw fd-table length, this stays stable when unrelated
        /// parallel lib tests open transient pipes or sockets.
        fn count_fds_with_readlink_target(target: &std::path::Path) -> usize {
            std::fs::read_dir("/proc/self/fd")
                .expect("read /proc/self/fd")
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let fd: i32 = e.file_name().to_string_lossy().parse().ok()?;
                    let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
                    (link == target).then_some(())
                })
                .count()
        }

        let path =
            std::env::temp_dir().join(format!("varta-scmrights-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let observer = UnixDatagram::bind(&path).expect("bind observer");
        enable_credential_passing(observer.as_raw_fd()).expect("enable credential passing");

        let sender = UnixDatagram::unbound().expect("sender socket");
        sender.connect(&path).expect("connect sender");

        // The fd whose recvmsg-installed duplicate must be reclaimed. We keep
        // `passed` open for the whole test; only its duplicate in the observer
        // is the leak candidate.
        let passed = std::fs::File::open("/dev/null").expect("open /dev/null");

        let mut beat = [0u8; super::VLP_FRAME_LEN];
        let mut iov = plat::Iovec {
            iov_base: beat.as_mut_ptr() as *mut core::ffi::c_void,
            iov_len: beat.len(),
        };
        let mut cmsg = ScmRightsCmsg {
            hdr: plat::Cmsghdr {
                // CMSG_LEN(sizeof(int)) on 64-bit Linux = 16 + 4 = 20.
                cmsg_len: core::mem::size_of::<plat::Cmsghdr>() + core::mem::size_of::<i32>(),
                cmsg_level: plat::SOL_SOCKET,
                cmsg_type: plat::SCM_RIGHTS,
            },
            fd: passed.as_raw_fd(),
            _pad: 0,
        };
        let mhdr = plat::Msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: &mut cmsg as *mut ScmRightsCmsg as *mut core::ffi::c_void,
            msg_controllen: core::mem::size_of::<ScmRightsCmsg>(),
            msg_flags: 0,
            _pad2: 0,
        };

        // SAFETY: `mhdr` describes the 32-byte `beat` iovec and an in-bounds
        // `SCM_RIGHTS` control buffer carrying one live fd; all buffers outlive
        // the call. `sendmsg(2)` only reads them.
        let sent = unsafe { sendmsg(sender.as_raw_fd(), &mhdr, 0) };
        assert_eq!(
            sent,
            super::VLP_FRAME_LEN as isize,
            "sendmsg should send the beat"
        );

        let dev_null = std::path::Path::new("/dev/null");
        let before = count_fds_with_readlink_target(dev_null);
        let result = recv_authenticated(observer.as_raw_fd());

        // Consume `result` by value before measuring: on Linux 6.5+ the kernel
        // also attaches an `SCM_PIDFD`, which `recv_authenticated` legitimately
        // returns (still open) inside the result. Bind `peer_pidfd` explicitly
        // and drop it here — a partial move out of the named `result` binding
        // leaves the unbound fields owned by `result` until end-of-scope, so
        // letting `..` swallow the pidfd would defer its close past the `after`
        // sample. Dropping it now isolates the peer-injected `SCM_RIGHTS` leak
        // the test actually targets.
        let (data, peer_pid) = match result {
            RecvResult::Authenticated {
                data,
                peer_pid,
                peer_pidfd,
                ..
            } => {
                drop(peer_pidfd);
                (data, peer_pid)
            }
            _ => panic!("expected an authenticated beat"),
        };
        let after = count_fds_with_readlink_target(dev_null);

        assert_eq!(data, beat, "beat payload should survive intact");
        assert_ne!(peer_pid, 0, "in-process send is kernel-attested");
        assert_eq!(
            after, before,
            "observer leaked a peer-injected SCM_RIGHTS duplicate of /dev/null \
             (before={before}, after={after})"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_pathname_uds_recv_is_socket_mode_only() {
        use super::{enable_credential_passing, recv_authenticated, RecvResult};
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixDatagram;
        use std::path::PathBuf;
        use std::time::{SystemTime, UNIX_EPOCH};

        struct TempDir {
            path: PathBuf,
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = TempDir {
            path: PathBuf::from(format!("/tmp/vmpc-{}-{unique}", std::process::id())),
        };
        std::fs::create_dir(&dir.path).expect("create temp dir");
        std::fs::set_permissions(&dir.path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod temp dir");
        let socket_path = dir.path.join("varta.sock");

        let server = UnixDatagram::bind(&socket_path).expect("bind server");
        enable_credential_passing(server.as_raw_fd()).expect("enable credential passing");

        let sender = UnixDatagram::unbound().expect("sender socket");
        sender.connect(&socket_path).expect("connect sender");
        sender.send(&[0u8; 32]).expect("send datagram");

        match recv_authenticated(server.as_raw_fd()) {
            RecvResult::Authenticated {
                peer_pid,
                peer_uid: _,
                peer_pid_ns_inode: _,
                peer_pidfd: _,
                origin,
                data,
            } => {
                assert_eq!(peer_pid, 0);
                assert_eq!(origin, BeatOrigin::SocketModeOnly);
                assert_eq!(data, [0u8; 32]);
            }
            _ => panic!("expected authenticated datagram"),
        }
    }

    /// Regression (fd-exhaustion DoS, macOS): a peer datagram carrying an
    /// `SCM_RIGHTS` ancillary message must not leak the passed fds into the
    /// observer. XNU installs passed fds on `recvmsg(2)` even though the macOS
    /// observer derives credentials from `getsockopt` and never solicits
    /// ancillary data — and it installs them even on control-buffer overflow.
    /// Before the fix `reclaim_scm_rights` was a no-op on macOS and the buffer
    /// was 16 bytes, so any same-UID process could exhaust the observer's fd
    /// table by attaching fds to well-formed beats. This sends a *maximally
    /// stuffed* message — exactly `SCM_RIGHTS_MAX_FDS` (XNU's per-message cap)
    /// fds — so it exercises the truncation boundary: a buffer even one fd short
    /// (the prior 1024-byte sizing) truncates the last fd and leaks it, failing
    /// this assertion. Locks `ANCILLARY_BUFFER_SIZE` against the cap.
    ///
    /// Real-syscall test (bind/sendmsg/recvmsg + `/dev/fd`); not available
    /// under Miri isolation. Raises `RLIMIT_NOFILE` first because installing the
    /// full cap of fds transiently exceeds the default soft limit.
    #[cfg(all(target_os = "macos", not(miri)))]
    #[test]
    fn scm_rights_fds_are_reclaimed_not_leaked_macos() {
        use super::plat;
        use super::{enable_credential_passing, recv_authenticated, RecvResult};
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixDatagram;

        let _guard = FD_INVENTORY_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        #[repr(C)]
        struct Rlimit {
            rlim_cur: u64,
            rlim_max: u64,
        }
        extern "C" {
            fn sendmsg(fd: i32, msg: *const plat::Msghdr, flags: i32) -> isize;
            fn dup(fd: i32) -> i32;
            fn close(fd: i32) -> i32;
            fn getrlimit(resource: i32, rlp: *mut Rlimit) -> i32;
            fn setrlimit(resource: i32, rlp: *const Rlimit) -> i32;
        }

        const SOL_SOCKET: i32 = 0xffff;
        const SCM_RIGHTS: i32 = 0x01;
        const RLIMIT_NOFILE: i32 = 8; // <sys/resource.h> on macOS/BSD

        // Maximally stuffed: XNU's per-message SCM_RIGHTS cap. A buffer one fd
        // short truncates the tail and leaks it — this is the boundary value.
        const NFDS: usize = plat::SCM_RIGHTS_MAX_FDS;

        // Installing NFDS fds, plus the NFDS sender-side dups still open at send
        // time, transiently needs ~2*NFDS descriptors — well over the default
        // 256 soft limit. Raise the soft limit toward the hard limit; if the
        // hard limit itself cannot accommodate the boundary, skip rather than
        // fail on an under-resourced host.
        let needed = (NFDS * 2 + 64) as u64;
        // SAFETY: `getrlimit`/`setrlimit` read/write a fully-initialised
        // `Rlimit` of the correct size; `RLIMIT_NOFILE` is a valid resource.
        let mut rl = Rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe { getrlimit(RLIMIT_NOFILE, &mut rl) };
        if rl.rlim_max < needed {
            eprintln!(
                "skipping: RLIMIT_NOFILE hard limit {} < {needed} needed for the {NFDS}-fd boundary",
                rl.rlim_max
            );
            return;
        }
        let target = needed.max(4096).min(rl.rlim_max);
        let new = Rlimit {
            rlim_cur: target,
            rlim_max: rl.rlim_max,
        };
        unsafe { setrlimit(RLIMIT_NOFILE, &new) };

        fn open_fd_count() -> usize {
            std::fs::read_dir("/dev/fd").expect("read /dev/fd").count()
        }

        let path =
            std::env::temp_dir().join(format!("varta-scmrights-macos-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let observer = UnixDatagram::bind(&path).expect("bind observer");
        enable_credential_passing(observer.as_raw_fd()).expect("enable credential passing");
        let sender = UnixDatagram::unbound().expect("sender socket");
        sender.connect(&path).expect("connect sender");

        // NFDS duplicate handles of /dev/null; the sender's copies are closed
        // after send so only the observer's recvmsg-installed duplicates are
        // leak candidates.
        let base = std::fs::File::open("/dev/null").expect("open /dev/null");
        let dups: Vec<i32> = (0..NFDS)
            .map(|_| unsafe { dup(base.as_raw_fd()) })
            .collect();

        // One SCM_RIGHTS cmsg carrying NFDS fds. macOS CMSG_ALIGN is 4 bytes;
        // cmsg_len = 12 (cmsghdr) + NFDS*4.
        let cmsg_len = 12 + NFDS * 4;
        let total = (cmsg_len + 3) & !3;
        let mut ctrl = vec![0u8; total];
        ctrl[0..4].copy_from_slice(&(cmsg_len as u32).to_le_bytes());
        ctrl[4..8].copy_from_slice(&SOL_SOCKET.to_le_bytes());
        ctrl[8..12].copy_from_slice(&SCM_RIGHTS.to_le_bytes());
        for (i, fd) in dups.iter().enumerate() {
            ctrl[12 + i * 4..16 + i * 4].copy_from_slice(&fd.to_le_bytes());
        }

        let mut beat = [0u8; super::VLP_FRAME_LEN];
        let mut iov = plat::Iovec {
            iov_base: beat.as_mut_ptr() as *mut core::ffi::c_void,
            iov_len: beat.len(),
        };
        let mhdr = plat::Msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            _pad2: 0,
            msg_control: ctrl.as_mut_ptr() as *mut core::ffi::c_void,
            msg_controllen: total as u32,
            msg_flags: 0,
        };
        // SAFETY: `mhdr` describes the 32-byte beat iovec and an in-bounds
        // SCM_RIGHTS control buffer carrying NFDS live fds; all buffers outlive
        // the call. `sendmsg(2)` only reads them.
        let sent = unsafe { sendmsg(sender.as_raw_fd(), &mhdr, 0) };
        assert_eq!(
            sent,
            super::VLP_FRAME_LEN as isize,
            "sendmsg should send the beat"
        );
        // Sender drops its own copies; only the observer's installed duplicates
        // remain as leak candidates.
        for d in &dups {
            unsafe { close(*d) };
        }

        let before = open_fd_count();
        let result = recv_authenticated(observer.as_raw_fd());
        let after = eventually_open_fd_count_at_most(before, open_fd_count);

        match result {
            RecvResult::Authenticated { data, origin, .. } => {
                assert_eq!(data, beat, "beat payload should survive intact");
                assert_eq!(origin, BeatOrigin::SocketModeOnly);
            }
            _ => panic!("expected an authenticated beat"),
        }
        assert!(
            after <= before,
            "observer leaked peer-injected SCM_RIGHTS fds (before={before}, after={after})"
        );

        let _ = std::fs::remove_file(&path);
    }
}
