//! Transport abstraction for receiving VLP frames.
//!
//! The [`BeatListener`] trait is the pluggable receive backend for [`Observer`].
//! [`UdsListener`] provides the default Unix Domain Socket implementation;
//! alternative transports (e.g. UDP) are available behind feature flags.
//!
//! [`Observer`]: crate::Observer

use std::io::{self, ErrorKind};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::time::Duration;

extern "C" {
    fn umask(mode: u32) -> u32;
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

/// Abstraction over a source that can receive 32-byte VLP frames.
///
/// Implementations must be `Send + 'static` so [`Observer`] can be moved.
///
/// [`Observer`]: crate::Observer
pub trait BeatListener: Send + 'static {
    /// Receive one datagram. Returns the same `RecvResult` as
    /// `peer_cred::recv_authenticated` — callers see `Authenticated`,
    /// `WouldBlock`, `ShortRead`, or `IoError`.
    fn recv(&mut self) -> RecvResult;

    /// Drain and reset the AEAD decryption failure counter.
    ///
    /// The default implementation returns 0 — only listeners that perform
    /// authenticated decryption will override this.
    fn drain_decrypt_failures(&mut self) -> u64 {
        0
    }

    /// Drain and reset the truncated-datagram counter.
    fn drain_truncated(&mut self) -> u64 {
        0
    }

    /// Drain and reset the sender-state-full counter.
    ///
    /// Incremented when the per-sender replay map is at capacity and a
    /// stale-sender sweep fails to free space, forcing eviction of the
    /// oldest entry. Only listeners that maintain per-sender state will
    /// override this.
    fn drain_sender_state_full(&mut self) -> u64 {
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
    /// The socket is given a read timeout so `recv` cannot block
    /// indefinitely.
    pub fn bind(
        path: impl AsRef<Path>,
        socket_mode: u32,
        read_timeout: Duration,
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
                        return Self::finish_bind(sock, owned_path, read_timeout);
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
        Self::finish_bind(sock, owned_path, read_timeout)
    }

    fn finish_bind(sock: UnixDatagram, path: PathBuf, read_timeout: Duration) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        sock.set_read_timeout(Some(read_timeout))?;
        let raw_fd = sock.as_raw_fd();
        peer_cred::enable_credential_passing(raw_fd)?;

        let meta = std::fs::metadata(&path)?;
        let bound_dev = meta.dev();
        let bound_ino = meta.ino();

        Ok(UdsListener {
            sock,
            path,
            bound_dev,
            bound_ino,
            truncated_count: 0,
        })
    }
}

impl BeatListener for UdsListener {
    fn recv(&mut self) -> RecvResult {
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

/// Probe whether a live listener is accepting datagrams at `path`.
fn probe_live(path: &Path) -> io::Result<bool> {
    let sock = UnixDatagram::unbound()?;

    if let Err(e) = sock.connect(path) {
        return match e.kind() {
            ErrorKind::PermissionDenied => Err(e),
            _ => Ok(false),
        };
    }

    match sock.send(&[]) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => Err(e),
        Err(_) => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// UDP listener (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "udp")]
mod udp_impl {
    use std::io;
    use std::net::{SocketAddr, UdpSocket};

    use crate::peer_cred::RecvResult;

    use super::BeatListener;

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
            })
        }
    }

    impl BeatListener for UdpListener {
        fn recv(&mut self) -> RecvResult {
            let mut buf = [0u8; 32];
            loop {
                match self.sock.recv(&mut buf) {
                    Ok(32) => {
                        return RecvResult::Authenticated {
                            peer_pid: 0,
                            peer_uid: 0,
                            data: buf,
                        };
                    }
                    Ok(_) => {
                        self.truncated_count = self.truncated_count.wrapping_add(1);
                        continue;
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
}

#[cfg(feature = "udp")]
pub use udp_impl::UdpListener;
