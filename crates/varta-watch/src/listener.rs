//! Transport abstraction for receiving VLP frames.
//!
//! The [`BeatListener`] trait is the pluggable receive backend for [`Observer`].
//! [`UdsListener`] provides the default Unix Domain Socket implementation;
//! alternative transports (e.g. UDP) are available behind feature flags.
//!
//! [`Observer`]: crate::Observer

use core::marker::PhantomData;
use std::io::{self, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Count of `fsync_parent_dir` failures since process start.  Incremented on
/// every bind where the parent-directory fsync succeeds at the OS level but
/// returns an error (e.g. `EINVAL` on platforms that do not support directory
/// fsync).  Drained by [`drain_bind_dir_fsync_failures`].
static DIR_FSYNC_FAILED: AtomicU64 = AtomicU64::new(0);

/// Drain and reset the parent-directory fsync failure counter.
///
/// Returns the number of `fsync_parent_dir` calls that failed since the last
/// drain (typically since process start, because bind runs once).  Called by
/// the observer poll loop to surface `varta_socket_bind_dir_fsync_failed_total`
/// via the Prometheus exporter.
pub fn drain_bind_dir_fsync_failures() -> u64 {
    DIR_FSYNC_FAILED.swap(0, Ordering::Relaxed)
}

extern "C" {
    fn umask(mode: u32) -> u32;
}

// POSIX setsockopt / getsockopt for SO_RCVBUF tuning.
extern "C" {
    fn setsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *const core::ffi::c_void,
        optlen: u32,
    ) -> i32;
    fn getsockopt(
        fd: i32,
        level: i32,
        optname: i32,
        optval: *mut core::ffi::c_void,
        optlen: *mut u32,
    ) -> i32;
}

// SOL_SOCKET / SO_RCVBUF — platform-scoped FFI constants for setsockopt(2).
//
// Sources verified against vendor headers:
//   linux:   include/uapi/asm-generic/socket.h    (SOL_SOCKET=1,      SO_RCVBUF=8)
//   macOS:   xnu/bsd/sys/socket.h                 (SOL_SOCKET=0xffff, SO_RCVBUF=0x1002)
//   *BSD:    sys/socket.h                         (SOL_SOCKET=0xffff, SO_RCVBUF=0x1002)
//   illumos: usr/src/uts/common/sys/socket.h      (SOL_SOCKET=0xffff, SO_RCVBUF=0x1002)
//
// Adding a new target_os requires verifying these two constants against the
// platform's headers and extending the cfg-any lists below. The `compile_error!`
// fallback prevents silent drift to wrong values on an untested platform.
// Linux SOL_SOCKET/SO_RCVBUF are architecture-specific: mips/sparc use the
// BSD-style 0xffff / 0x1002, generic arches use 1 / 8 (rust-libc arch tables;
// same split as peer_cred/platform/linux.rs). A flat generic value on mips/sparc
// makes the SO_RCVBUF setsockopt fail (wrong level + wrong optname), so the UDS
// receive buffer is never enlarged from the small kernel default — dropping
// datagrams under burst on the core liveness path.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64",
    )
))]
const SOL_SOCKET: i32 = 0xffff_u32 as i32;
#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64",
    ))
))]
const SOL_SOCKET: i32 = 1;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "solaris",
))]
const SOL_SOCKET: i32 = 0xffff_u32 as i32;

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64",
    )
))]
const SO_RCVBUF: i32 = 0x1002;
#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64",
    ))
))]
const SO_RCVBUF: i32 = 8;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "solaris",
))]
const SO_RCVBUF: i32 = 0x1002;

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "illumos",
    target_os = "solaris",
)))]
compile_error!(
    "varta-watch has no verified SOL_SOCKET / SO_RCVBUF values for this target_os. \
     Verify against the platform's <sys/socket.h> and extend the cfg-any lists in \
     crates/varta-watch/src/listener.rs."
);

/// Attests that the process is single-threaded at construction time.
///
/// [`UdsListener::bind`] calls `umask(2)`, which is process-wide; any thread
/// creating filesystem objects during the bind window would inherit the
/// restricted umask. Holding a `&PreThreadAttestation` encodes the
/// single-threaded precondition in the type signature so the invariant is
/// enforced at compile time, not just by convention.
///
/// Construct exactly once at the top of `fn main`, before any thread spawn:
///
/// ```text
/// let pre_thread = PreThreadAttestation::new()?;
/// // … then pass &pre_thread to Observer::bind / UdsListener::bind
/// ```
///
/// The token is `!Send + !Sync` (via `PhantomData<*const ()>`) so it cannot
/// be moved into or shared across thread boundaries after construction.
#[derive(Debug)]
pub struct PreThreadAttestation {
    _no_send: PhantomData<*const ()>,
}

impl PreThreadAttestation {
    /// Probe the OS thread count and return a token if the process is
    /// single-threaded.
    ///
    /// On Linux counts `/proc/self/task/` entries. On macOS calls
    /// `pthread_is_threaded_np(3)`. On other platforms the runtime probe is
    /// skipped; the type-level structural guarantee still holds.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::Other`] if the process has more than one
    /// thread, or if the Linux `/proc/self/task` directory is unreadable.
    pub fn new() -> io::Result<Self> {
        Self::probe()?;
        Ok(Self {
            _no_send: PhantomData,
        })
    }

    /// Create a token without a runtime probe.
    ///
    /// Intended for test code where the multi-threaded test runner would
    /// incorrectly fail the probe even though the umask window is benign.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no concurrent thread creates filesystem
    /// objects during the `UdsListener::bind` window, or that any such race
    /// is acceptable in the calling context.
    pub unsafe fn new_unchecked() -> Self {
        Self {
            _no_send: PhantomData,
        }
    }

    #[cfg(target_os = "linux")]
    fn probe() -> io::Result<()> {
        let mut count: usize = 0;
        for entry in std::fs::read_dir("/proc/self/task")? {
            entry?;
            count += 1;
            if count > 1 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "process is multi-threaded; UdsListener::bind changes \
                     umask(2) process-wide and would race concurrent file creation",
                ));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn probe() -> io::Result<()> {
        extern "C" {
            // Available in macOS pthread.h since 10.0.
            // Returns 0 when single-threaded, 1 when multi-threaded.
            fn pthread_is_threaded_np() -> i32;
        }
        // SAFETY: pthread_is_threaded_np is a pure read of a per-process flag
        // with no side effects and a stable ABI across all macOS versions.
        if unsafe { pthread_is_threaded_np() } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "process is multi-threaded; UdsListener::bind changes \
                 umask(2) process-wide and would race concurrent file creation",
            ));
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn probe() -> io::Result<()> {
        // No per-platform thread-count probe is implemented here.
        // The type-level guarantee — UdsListener::bind requires a
        // &PreThreadAttestation that can only be soundly constructed before
        // the first thread spawn — remains the primary enforcement.
        Ok(())
    }
}

/// RAII guard that restores the process umask on drop, even if a panic
/// unwinds through the bind path.
struct UmaskGuard(u32);

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            umask(self.0);
        }
    }
}

use crate::peer_cred::{self, RecvResult};

/// Per-listener operator trust declaration for recovery eligibility.
///
/// Passed to a listener's builder method to promote UDP-origin beats from
/// [`BeatOrigin::NetworkUnverified`] to [`BeatOrigin::OperatorAttestedTransport`].
/// Recovery commands will then fire for stalls on that listener, as they
/// would for kernel-attested UDS beats.
///
/// This is a structural enforcement of per-listener trust — there is no
/// daemon-wide way to grant recovery trust to a UDP listener.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub enum TransportTrust {
    /// No operator declaration — beats from this listener are stamped
    /// [`BeatOrigin::NetworkUnverified`]. Recovery is refused for stalls.
    #[default]
    Untrusted,
    /// Operator has explicitly accepted the security risk for this listener.
    /// Beats are stamped [`BeatOrigin::OperatorAttestedTransport`] so the
    /// runtime recovery gate allows them to fire.
    Operator,
}

/// Abstraction over a source that can receive 32-byte VLP frames.
///
/// Implementations must be `Send + 'static` so [`Observer`] can be moved.
///
/// [`Observer`]: crate::Observer
pub trait BeatListener: Send + 'static {
    /// Receive one datagram. Returns the same `RecvResult` as
    /// `peer_cred::recv_authenticated` — callers see `Authenticated`,
    /// `WouldBlock`, `ShortRead`, or `IoError`.
    ///
    /// `now_ns` is the observer's operator-clock (`--clock-source`) timestamp
    /// for this poll iteration. Listeners that keep per-sender session state
    /// (the secure-UDP listener) measure their recycle/session-restart window
    /// in this clock domain so it stays in lockstep with the tracker's recycle
    /// reset across host suspend; stateless listeners ignore it.
    fn recv(&mut self, now_ns: u64) -> RecvResult;

    /// Whether the most recent [`Self::recv`] call dequeued a datagram.
    ///
    /// [`Observer`](crate::Observer) can infer this from any result other than
    /// [`RecvResult::WouldBlock`]. A listener that consumes and deliberately
    /// rejects a datagram while returning `WouldBlock` to suppress an event
    /// must override this method so the daemon does not mistake that work for
    /// an idle poll and sleep while more datagrams remain queued.
    fn last_recv_consumed(&self) -> bool {
        false
    }

    /// Drain and reset the AEAD decryption failure counter.
    ///
    /// The default implementation returns 0 — only listeners that perform
    /// authenticated decryption will override this.
    fn drain_decrypt_failures(&mut self) -> u64 {
        0
    }

    /// Drain and reset the replay-refused counter.
    ///
    /// Incremented when an authenticated frame from a *known* sender identity
    /// is refused because its VLP nonce / timestamp did not advance past the
    /// recorded replay high-water mark. Distinct from
    /// [`Self::drain_decrypt_failures`]: the AEAD tag verified, so this is a
    /// replay refusal, not a crypto failure. Only listeners that maintain
    /// per-sender replay state override this.
    fn drain_replay_refused(&mut self) -> u64 {
        0
    }

    /// Drain and reset the truncated-datagram counter.
    fn drain_truncated(&mut self) -> u64 {
        0
    }

    /// Drain and reset the sender-state-full counter.
    ///
    /// Incremented when the per-sender replay table is at capacity and a
    /// stale-sender sweep fails to free space for a new identity. Only
    /// listeners that maintain per-sender state will override this.
    fn drain_sender_state_full(&mut self) -> u64 {
        0
    }

    /// Drain and reset the AEAD-decryption-attempt counter.
    ///
    /// Counted by listeners that trial every loaded key on every frame
    /// without early-exit on success — the constant-trial-count poll that
    /// closes the key-rotation timing side-channel. Only the secure-UDP
    /// listener overrides this.
    fn drain_aead_attempts(&mut self) -> u64 {
        0
    }
}

/// Unix Domain Socket listener for local IPC.
///
/// Created via [`UdsListener::bind`] and used as the default backend for
/// [`Observer::bind`].
///
/// [`Observer::bind`]: crate::Observer::bind
pub struct UdsListener {
    sock: UnixDatagram,
    path: PathBuf,
    bound_dev: u64,
    bound_ino: u64,
    truncated_count: u64,
    /// Effective `SO_RCVBUF` granted by the kernel (may be less than
    /// requested due to `net.core.rmem_max`).  `0` means no tuning was
    /// attempted (`--uds-rcvbuf-bytes 0`).
    rcvbuf_bytes: u32,
}

impl UdsListener {
    /// Bind a Unix datagram socket at `path` and return a [`UdsListener`].
    ///
    /// The socket file permissions are set to `socket_mode` (octal, e.g.
    /// `0o600`) after a successful bind. Credential passing is enabled on
    /// the socket so that `recv` can verify the PID of every sender against
    /// the kernel's `SO_PASSCRED` / `LOCAL_CREDS` attestation.
    ///
    /// If a genuine stale socket exists at `path` (a socket inode with no
    /// listener), it is cleaned up and the bind succeeds. If another
    /// process is already listening at `path`, or if the path is occupied by
    /// a non-socket file, the call fails with `AddrInUse`.
    ///
    /// The socket is bound non-blocking so `recv` never waits on an idle
    /// queue (returns `WouldBlock` immediately), matching the observer's
    /// non-blocking round-robin `poll()` contract.
    pub fn bind(
        path: impl AsRef<Path>,
        socket_mode: u32,
        read_timeout: Duration,
        uds_rcvbuf_bytes: u32,
        _pre_thread: &PreThreadAttestation,
    ) -> io::Result<Self> {
        let path = path.as_ref();
        let owned_path: PathBuf = path.to_path_buf();

        let restrict_umask = !socket_mode & 0o777;
        let _umask_guard = UmaskGuard(unsafe { umask(restrict_umask) });
        let bind_result = UnixDatagram::bind(path);
        let sock = match bind_result {
            Ok(sock) => sock,
            Err(e) if e.kind() == ErrorKind::AddrInUse => {
                let PathOccupant::Socket(stale_socket) = path_occupant(path)? else {
                    return Err(io::Error::new(
                        ErrorKind::AddrInUse,
                        format!(
                            "cannot bind observer socket at {}: path exists and is not a socket",
                            path.display()
                        ),
                    ));
                };

                match probe_live(path) {
                    Ok(true) => {
                        return Err(io::Error::new(
                            ErrorKind::AddrInUse,
                            format!(
                                "another varta-watch is already running at {}",
                                path.display()
                            ),
                        ));
                    }
                    Ok(false) => {
                        match path_occupant(path)? {
                            PathOccupant::Socket(current) if current == stale_socket => {
                                std::fs::remove_file(path)?;
                            }
                            PathOccupant::Missing => {}
                            PathOccupant::Socket(_) => {
                                return Err(io::Error::new(
                                    ErrorKind::AddrInUse,
                                    format!(
                                        "observer socket path changed while probing {}; retry bind",
                                        path.display()
                                    ),
                                ));
                            }
                            PathOccupant::Other => {
                                return Err(io::Error::new(
                                    ErrorKind::AddrInUse,
                                    format!(
                                        "cannot bind observer socket at {}: path exists and is not a socket",
                                        path.display()
                                    ),
                                ));
                            }
                        }
                        let _umask_guard = UmaskGuard(unsafe { umask(restrict_umask) });
                        let sock = UnixDatagram::bind(path)?;
                        std::fs::set_permissions(
                            path,
                            std::fs::Permissions::from_mode(socket_mode),
                        )?;
                        return Self::finish_bind(sock, owned_path, read_timeout, uds_rcvbuf_bytes);
                    }
                    Err(e) => {
                        return Err(io::Error::new(
                            e.kind(),
                            format!("cannot probe socket at {}: {e}", path.display()),
                        ));
                    }
                }
            }
            Err(e) => return Err(e),
        };

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(socket_mode))?;
        Self::finish_bind(sock, owned_path, read_timeout, uds_rcvbuf_bytes)
    }

    fn finish_bind(
        sock: UnixDatagram,
        path: PathBuf,
        read_timeout: Duration,
        uds_rcvbuf_bytes: u32,
    ) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        // The observer's round-robin `poll()` is contractually non-blocking:
        // it pulls at most one datagram per listener per call and must never
        // wait on an idle socket (`book/.../observer-liveness.md`, p99 ≤ 5 ms).
        // A blocking-with-timeout UDS socket head-of-line-blocks every other
        // listener in the same poll loop for up to `read_timeout` (default
        // 100 ms) whenever it is idle — capping secure-UDP/UDP ingest at
        // <10 datagrams/s and, inside the recovery ingress pre-drain
        // (`RECOVERY_PREDRAIN_INGRESS_MAX_PER_TICK` poll() calls in one
        // DrainPending stage), overrunning the 2 s self-watchdog stage abort
        // and `process::abort()`-ing a HEALTHY observer. Match the UDP and
        // secure-UDP listeners: bind non-blocking so `recvmsg` returns EAGAIN
        // immediately (mapped to `WouldBlock`); idle pacing is the main loop's
        // 10 ms throttle, gated on `last_poll_consumed()`.
        sock.set_nonblocking(true)?;
        // Kept as a defensive no-op (SO_RCVTIMEO is inert on a non-blocking
        // socket): preserves the validated `--read-timeout-ms` config surface
        // and its floor/ceiling without changing recv semantics.
        sock.set_read_timeout(Some(read_timeout))?;
        let raw_fd = sock.as_raw_fd();
        peer_cred::enable_credential_passing(raw_fd)?;

        let meta = std::fs::metadata(&path)?;
        let bound_dev = meta.dev();
        let bound_ino = meta.ino();

        // Fsync the parent directory so the unlink+bind+chmod sequence is
        // durable across power loss or an unclean shutdown.  The bind has
        // already succeeded — a directory-fsync failure is treated as a soft
        // durability degradation rather than a startup failure (some exotic
        // platforms return EINVAL for directory fsync).
        if let Err(e) = crate::file_security::fsync_parent_dir(&path) {
            crate::varta_warn!(
                "uds bind: parent-directory fsync failed (durability degraded): {e}"
            );
            DIR_FSYNC_FAILED.fetch_add(1, Ordering::Relaxed);
        }

        let granted_rcvbuf = if uds_rcvbuf_bytes > 0 {
            set_rcvbuf(raw_fd, uds_rcvbuf_bytes).unwrap_or(0)
        } else {
            0
        };

        Ok(UdsListener {
            sock,
            path,
            bound_dev,
            bound_ino,
            truncated_count: 0,
            rcvbuf_bytes: granted_rcvbuf,
        })
    }
}

impl BeatListener for UdsListener {
    fn recv(&mut self, _now_ns: u64) -> RecvResult {
        // UDS carries no per-sender session state; the session-restart clock
        // is irrelevant here.
        match peer_cred::recv_authenticated(self.sock.as_raw_fd()) {
            RecvResult::ShortRead => {
                self.truncated_count = self.truncated_count.wrapping_add(1);
                RecvResult::ShortRead
            }
            other => other,
        }
    }

    fn drain_truncated(&mut self) -> u64 {
        let n = self.truncated_count;
        self.truncated_count = 0;
        n
    }
}

impl Drop for UdsListener {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.dev() == self.bound_dev && meta.ino() == self.bound_ino {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

impl UdsListener {
    /// Effective `SO_RCVBUF` size granted by the kernel for this socket,
    /// in bytes.  `0` if `--uds-rcvbuf-bytes 0` was used or tuning failed.
    pub fn rcvbuf_bytes(&self) -> u32 {
        self.rcvbuf_bytes
    }
}

/// Set and read back `SO_RCVBUF` on `fd`.  Returns the kernel-granted size
/// (which Linux doubles then clamps to `net.core.rmem_max`).  Fails soft on
/// `EPERM` (unprivileged observer, low `rmem_max`).
fn set_rcvbuf(fd: i32, bytes: u32) -> io::Result<u32> {
    use core::ffi::c_void;
    use core::mem;

    let val = bytes as i32;
    let ret = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVBUF,
            &val as *const i32 as *const c_void,
            mem::size_of::<i32>() as u32,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    // Read back the effective value (kernel may grant double the requested).
    let mut granted: i32 = 0;
    let mut optlen = mem::size_of::<i32>() as u32;
    let ret = unsafe {
        getsockopt(
            fd,
            SOL_SOCKET,
            SO_RCVBUF,
            &mut granted as *mut i32 as *mut c_void,
            &mut optlen,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(granted.max(0) as u32)
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SocketIdentity {
    dev: u64,
    ino: u64,
}

enum PathOccupant {
    Missing,
    Socket(SocketIdentity),
    Other,
}

fn path_occupant(path: &Path) -> io::Result<PathOccupant> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => Ok(PathOccupant::Socket(SocketIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        })),
        Ok(_) => Ok(PathOccupant::Other),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(PathOccupant::Missing),
        Err(e) => Err(e),
    }
}

/// Probe whether a live listener is bound at `path`.
fn probe_live(path: &Path) -> io::Result<bool> {
    let sock = UnixDatagram::unbound()?;

    match sock.connect(path) {
        Ok(()) => Ok(true),
        Err(e) => match e.kind() {
            ErrorKind::ConnectionRefused | ErrorKind::NotFound => Ok(false),
            ErrorKind::PermissionDenied => Err(e),
            _ => Err(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::probe_live;
    use std::io::ErrorKind;
    use std::os::unix::net::UnixDatagram;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_socket_path(label: &str) -> (PathBuf, PathBuf) {
        let mut dir = std::env::temp_dir();
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        dir.push(format!(
            "varta-listener-{label}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).expect("create temp socket dir");
        let path = dir.join("sock");
        (dir, path)
    }

    #[test]
    fn probe_live_returns_false_for_stale_socket_file() {
        let (dir, path) = temp_socket_path("stale");
        {
            let _server = UnixDatagram::bind(&path).expect("bind server");
        }

        assert!(
            path.exists(),
            "dropping a UnixDatagram leaves the socket path"
        );
        // Kernel teardown of a just-closed datagram socket is asynchronous:
        // under concurrent VFS load (e.g. directory fsyncs from parallel
        // tests) macOS `connect(2)` can still succeed for a short window
        // after `close(2)`, so a single immediate probe is racy. Production
        // never probes within microseconds of the owner's close — startup
        // probes sockets orphaned by a long-gone process — so poll until the
        // kernel settles (same retry-loop convention as the exporter's
        // serve_pending tests).
        let mut live = true;
        for _ in 0..200 {
            live = probe_live(&path).expect("probe stale socket");
            if !live {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!live, "stale socket must probe dead once teardown settles");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn probe_live_does_not_enqueue_empty_datagram() {
        let (dir, path) = temp_socket_path("live");
        let server = UnixDatagram::bind(&path).expect("bind server");
        server
            .set_nonblocking(true)
            .expect("make server recv nonblocking");

        assert!(probe_live(&path).expect("probe live socket"));

        let mut buf = [0u8; 32];
        match server.recv(&mut buf) {
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Ok(n) => panic!("probe_live must not enqueue a datagram, received {n} bytes"),
            Err(e) => panic!("unexpected recv error after probe_live: {e}"),
        }

        drop(server);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    // Regression: the production UDS listener MUST be non-blocking. A
    // blocking-with-timeout socket head-of-line-blocks every other listener
    // in the observer's round-robin poll loop for the full `read_timeout`
    // whenever it is idle, capping secure-UDP/UDP ingest at <10 datagrams/s
    // and, inside the recovery pre-drain, overrunning the 2 s DrainPending
    // self-watchdog stage and aborting a healthy observer. We assert that an
    // idle `recv()` returns `WouldBlock` essentially immediately even when a
    // multi-second `read_timeout` is configured.
    #[test]
    fn uds_listener_recv_is_nonblocking() {
        use super::{BeatListener, RecvResult, UdsListener};
        use std::time::Instant;

        // Bind a short, flat path under temp_dir(): UdsListener::bind enforces
        // SUN_LEN, so the nested temp_socket_path helper can be too long.
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("vw-nb-{}-{seq}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        // The test runner is multi-threaded; the umask-race probe would fail.
        let pre_thread = unsafe { super::PreThreadAttestation::new_unchecked() };
        let mut listener = UdsListener::bind(
            &path,
            0o600,
            // A deliberately huge read timeout: if the socket were still
            // blocking-with-timeout, this idle recv would stall ~5 s.
            std::time::Duration::from_secs(5),
            0,
            &pre_thread,
        )
        .expect("bind uds listener");

        let start = Instant::now();
        let result = listener.recv(0);
        let elapsed = start.elapsed();

        assert!(
            matches!(result, RecvResult::WouldBlock),
            "idle recv must return WouldBlock, got a non-WouldBlock result"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "idle recv must return promptly (non-blocking); took {elapsed:?} \
             — the UDS socket is blocking-with-timeout (head-of-line bug)"
        );

        drop(listener);
        let _ = std::fs::remove_file(&path);
    }
}

// ---------------------------------------------------------------------------
// Plaintext UDP listener (feature-gated behind `unsafe-plaintext-udp`)
//
// This transport has NO cryptographic authentication.  It is exposed only
// when the operator opts in at *both* compile time (Cargo feature flag whose
// name starts with `unsafe-`) and runtime (`--i-accept-plaintext-udp`).  In
// any other configuration the plaintext path is structurally unreachable.
// ---------------------------------------------------------------------------

#[cfg(feature = "unsafe-plaintext-udp")]
mod udp_impl {
    use std::io;
    use std::net::{SocketAddr, UdpSocket};

    use crate::peer_cred::{BeatOrigin, RecvResult};

    use super::BeatListener;

    const VLP_FRAME_LEN: usize = 32;
    const VLP_FRAME_RECV_CAP: usize = VLP_FRAME_LEN + 1;

    /// UDP listener for network-based observers.
    ///
    /// Receives 32-byte VLP frames over UDP from remote agents. Created via
    /// [`UdpListener::bind`] and used with [`Observer::from_listener`].
    ///
    /// # Security: no authentication
    ///
    /// Plain UDP has NO cryptographic authentication — any device on the
    /// local subnet can inject arbitrary frames. Frame-level PID
    /// verification is impossible because UDP lacks kernel credential
    /// attestation (`peer_pid` is always 0). **Do not use this transport in
    /// production without network segmentation (firewall, VPC) that limits
    /// which hosts can reach the observer port.**
    ///
    /// For authenticated transport, see [`SecureUdpListener`], which provides
    /// ChaCha20-Poly1305 AEAD per-agent and/or per-epoch master-key decryption
    /// behind the `secure-udp` feature flag.
    ///
    /// The observer emits a startup warning via stderr whenever plaintext UDP
    /// is in use.
    ///
    /// [`Observer::from_listener`]: crate::Observer::from_listener
    /// [`SecureUdpListener`]: crate::secure_listener::SecureUdpListener
    pub struct UdpListener {
        sock: UdpSocket,
        truncated_count: u64,
        recovery_trust: super::TransportTrust,
    }

    impl UdpListener {
        /// Bind a non-blocking UDP socket on `addr` and return a [`UdpListener`].
        ///
        /// # Errors
        ///
        /// Returns an [`io::Error`] if the socket cannot be bound or switched
        /// to non-blocking mode.
        pub fn bind(addr: SocketAddr) -> io::Result<Self> {
            let sock = UdpSocket::bind(addr)?;
            sock.set_nonblocking(true)?;
            Ok(UdpListener {
                sock,
                truncated_count: 0,
                recovery_trust: super::TransportTrust::Untrusted,
            })
        }

        /// Declare this listener recovery-eligible.
        ///
        /// When `trust` is [`TransportTrust::Operator`], beats received on
        /// this listener are stamped [`BeatOrigin::OperatorAttestedTransport`]
        /// so the runtime recovery gate allows them to fire.
        pub fn with_recovery_trust(mut self, trust: super::TransportTrust) -> Self {
            self.recovery_trust = trust;
            self
        }
    }

    impl BeatListener for UdpListener {
        fn recv(&mut self, _now_ns: u64) -> RecvResult {
            let mut buf_with_slack = [0u8; VLP_FRAME_RECV_CAP];
            let origin = match self.recovery_trust {
                super::TransportTrust::Operator => BeatOrigin::OperatorAttestedTransport,
                super::TransportTrust::Untrusted => BeatOrigin::NetworkUnverified,
            };
            loop {
                match self.sock.recv(&mut buf_with_slack) {
                    Ok(VLP_FRAME_LEN) => {
                        let mut data = [0u8; VLP_FRAME_LEN];
                        data.copy_from_slice(&buf_with_slack[..VLP_FRAME_LEN]);
                        return RecvResult::Authenticated {
                            peer_pid: 0,
                            peer_uid: 0,
                            // UDP carries no kernel-attested namespace identity.
                            peer_pid_ns_inode: None,
                            peer_pidfd: None,
                            origin,
                            data,
                        };
                    }
                    Ok(_) => {
                        self.truncated_count = self.truncated_count.wrapping_add(1);
                        // Match the observer's one-datagram poll contract:
                        // malformed UDP traffic must not keep this listener
                        // draining indefinitely inside one poll iteration.
                        return RecvResult::ShortRead;
                    }
                    Err(e) => match e.kind() {
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                            return RecvResult::WouldBlock;
                        }
                        io::ErrorKind::Interrupted => continue,
                        _ => return RecvResult::IoError(e),
                    },
                }
            }
        }

        fn drain_truncated(&mut self) -> u64 {
            let n = self.truncated_count;
            self.truncated_count = 0;
            n
        }
    }

    #[cfg(test)]
    mod tests {
        use std::net::UdpSocket;
        use std::time::{Duration, Instant};

        use varta_vlp::{Frame, Status};

        use super::*;

        #[test]
        fn rejects_overlong_valid_frame_prefix() {
            let mut listener =
                UdpListener::bind("127.0.0.1:0".parse().unwrap()).expect("bind listener");
            let target = listener.sock.local_addr().expect("listener local addr");
            let sender = UdpSocket::bind("127.0.0.1:0").expect("sender bind");

            let mut valid_prefix = [0u8; VLP_FRAME_LEN];
            Frame::new(Status::Ok, 77_777, 1, 1, 0).encode(&mut valid_prefix);
            let mut overlong = [0u8; VLP_FRAME_RECV_CAP];
            overlong[..VLP_FRAME_LEN].copy_from_slice(&valid_prefix);
            overlong[VLP_FRAME_LEN] = 0xEE;

            sender.send_to(&overlong, target).expect("send overlong");

            let deadline = Instant::now() + Duration::from_millis(500);
            loop {
                match listener.recv(0) {
                    RecvResult::WouldBlock if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    RecvResult::ShortRead => break,
                    RecvResult::Authenticated { .. } => {
                        panic!("overlong datagram with valid VLP prefix must be rejected")
                    }
                    RecvResult::WouldBlock => panic!("listener did not receive test datagram"),
                    RecvResult::CtrlTruncated(e) | RecvResult::IoError(e) => {
                        panic!("unexpected receive error: {e}")
                    }
                }
            }

            assert_eq!(listener.drain_truncated(), 1);
        }
    }
}

#[cfg(feature = "unsafe-plaintext-udp")]
pub use udp_impl::UdpListener;
