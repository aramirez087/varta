//! Transport abstraction for VLP frame emission.
//!
//! The [`BeatTransport`] trait is the pluggable backend for [`Varta`].
//! [`UdsTransport`] provides the default Unix Domain Socket implementation;
//! alternative transports (e.g. UDP) are available behind feature flags.

use std::io;
#[cfg(any(feature = "udp", feature = "secure-udp"))]
use std::net::{SocketAddr, UdpSocket};
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
    ///
    /// A successful call must report exactly [`Self::expected_send_len`]
    /// bytes. Short `Ok(n)` results are protocol failures: [`Varta`] treats
    /// them as [`io::ErrorKind::WriteZero`] and does not commit beat state.
    ///
    /// [`Varta`]: crate::Varta
    fn send(&mut self, buf: &[u8; 32]) -> io::Result<usize>;

    /// Number of bytes the transport writes when one VLP frame is fully
    /// accepted by the kernel.
    ///
    /// Raw UDS/UDP transports send the 32-byte VLP frame unchanged. Wrapped
    /// transports such as secure UDP override this with their authenticated
    /// wire size.
    fn expected_send_len(&self) -> usize {
        32
    }

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

// ---------------------------------------------------------------------------
// Ephemeral UDP bind helper (shared across UDP transports)
// ---------------------------------------------------------------------------

/// Bind a UDP socket to an ephemeral port on the wildcard address matching
/// the target's address family (IPv4 or IPv6).
#[cfg(any(feature = "udp", feature = "secure-udp"))]
pub(crate) fn bind_ephemeral(addr: &SocketAddr) -> io::Result<UdpSocket> {
    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    UdpSocket::bind(bind_addr)
}

// ---------------------------------------------------------------------------
// UDP transport (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "udp")]
mod udp_impl {
    use std::io;
    use std::net::{SocketAddr, UdpSocket};

    use super::bind_ephemeral;
    use super::BeatTransport;

    /// UDP transport for network-based agents.
    ///
    /// Sends 32-byte VLP frames over UDP to a remote observer. Created via
    /// [`UdpTransport::connect`] and used with [`Varta::connect_udp`].
    ///
    /// [`Varta::connect_udp`]: crate::Varta::connect_udp
    pub struct UdpTransport {
        sock: UdpSocket,
        addr: SocketAddr,
    }

    impl UdpTransport {
        /// Create a non-blocking UDP socket connected to `addr`.
        ///
        /// The socket is bound to an ephemeral source port on the wildcard
        /// address matching the target's address family (IPv4 or IPv6). On a
        /// connected UDP socket, `send` writes to the fixed peer address and
        /// ICMP errors (e.g. port-unreachable) are surfaced as [`io::Error`].
        ///
        /// # Errors
        ///
        /// Returns an [`io::Error`] if the socket cannot be created,
        /// connected, or switched to non-blocking mode.
        pub fn connect(addr: SocketAddr) -> io::Result<Self> {
            let sock = bind_ephemeral(&addr)?;
            sock.connect(addr)?;
            sock.set_nonblocking(true)?;
            Ok(UdpTransport { sock, addr })
        }
    }

    impl BeatTransport for UdpTransport {
        fn send(&mut self, buf: &[u8; 32]) -> io::Result<usize> {
            self.sock.send(buf)
        }

        fn reconnect(&mut self) -> io::Result<()> {
            let sock = bind_ephemeral(&self.addr)?;
            sock.connect(self.addr)?;
            sock.set_nonblocking(true)?;
            self.sock = sock;
            Ok(())
        }
    }
}

#[cfg(feature = "udp")]
pub use udp_impl::UdpTransport;
