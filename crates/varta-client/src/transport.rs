//! Transport abstraction for VLP frame emission.
//!
//! The [`BeatTransport`] trait is the pluggable backend for [`Varta`].
//! [`UdsTransport`] provides the default Unix Domain Socket implementation;
//! alternative transports (e.g. UDP) are available behind feature flags.

use std::io;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

/// Abstraction over a transport that can send 32-byte VLP frames.
///
/// Implementations must be `Send + 'static` so [`Varta`] can be moved across
/// threads. Every transport guarantees non-blocking sends; the caller
/// classifies errors via [`classify_send_error`].
///
/// [`classify_send_error`]: crate::classify_send_error
/// [`Varta`]: crate::Varta
pub trait BeatTransport: Send + 'static {
    /// Send a 32-byte frame buffer. Returns the number of bytes written on
    /// success, or an [`io::Error`] on failure.
    fn send(&mut self, buf: &[u8; 32]) -> io::Result<usize>;

    /// Re-create the underlying connection after an observer restart.
    ///
    /// Allocates a fresh socket or channel; only called on the cold reconnect
    /// path, never on the steady-state beat path.
    fn reconnect(&mut self) -> io::Result<()>;
}

/// Unix Domain Socket transport for local IPC.
///
/// Created via [`UdsTransport::connect`] and used as the default backend for
/// [`Varta::connect`].
///
/// [`Varta::connect`]: crate::Varta::connect
pub struct UdsTransport {
    sock: UnixDatagram,
    path: PathBuf,
}

impl UdsTransport {
    /// Create a non-blocking Unix datagram socket connected to `path`.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the socket cannot be created, the peer
    /// path cannot be reached, or non-blocking mode cannot be enabled.
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let sock = UnixDatagram::unbound()?;
        sock.connect(&path)?;
        sock.set_nonblocking(true)?;
        Ok(UdsTransport { sock, path })
    }
}

impl BeatTransport for UdsTransport {
    fn send(&mut self, buf: &[u8; 32]) -> io::Result<usize> {
        self.sock.send(buf)
    }

    fn reconnect(&mut self) -> io::Result<()> {
        let sock = UnixDatagram::unbound()?;
        sock.connect(&self.path)?;
        sock.set_nonblocking(true)?;
        self.sock = sock;
        Ok(())
    }
}
