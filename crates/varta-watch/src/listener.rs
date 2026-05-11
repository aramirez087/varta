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
}

impl UdsListener {
    /// Bind a Unix datagram socket at `path` and return a [`UdsListener`].
    ///
    /// The socket file permissions are set to `socket_mode` (octal, e.g.
    /// `0o600`) after a successful bind. Credential passing is enabled on
    /// the socket so that `recv` can verify the PID of every sender against
    /// the kernel's `SO_PASSCRED` / `LOCAL_CREDS` attestation.
    ///
    /// If a genuine stale socket exists at `path` (no one listening),
    /// it is cleaned up and the bind succeeds. If another process is
    /// already listening at `path`, the call fails with `AddrInUse`.
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

        let sock = match UnixDatagram::bind(path) {
            Ok(sock) => sock,
            Err(e) if e.kind() == ErrorKind::AddrInUse => match probe_live(path) {
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
                    std::fs::remove_file(path)?;
                    let sock = UnixDatagram::bind(path)?;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(socket_mode))?;
                    return Self::finish_bind(sock, owned_path, read_timeout);
                }
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("cannot probe socket at {}: {e}", path.display()),
                    ));
                }
            },
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
        })
    }
}

impl BeatListener for UdsListener {
    fn recv(&mut self) -> RecvResult {
        peer_cred::recv_authenticated(self.sock.as_raw_fd())
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
