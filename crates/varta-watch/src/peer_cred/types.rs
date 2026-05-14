//! Core public types for the peer-credential subsystem.
//!
//! Defines the transport-origin classification ([`BeatOrigin`]) and the
//! recvmsg-with-credentials outcome ([`RecvResult`]), plus the cached
//! observer-UID accessor used by the receive path and by config validation.
//!
//! No platform `cfg` gates and no pointer math live here — this module is the
//! stable seam between the FFI surface and the rest of the crate.

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
    // SAFETY: `getuid(2)` is async-signal-safe per POSIX and always
    // succeeds: it takes no arguments and cannot fail. The return value is
    // the calling process's real UID. No pointers, no allocation, no
    // mutable shared state — the only "unsafe" aspect is the FFI boundary
    // itself.
    *UID.get_or_init(|| unsafe { getuid() })
}

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
/// kernel-attested — see `book/src/architecture/peer-authentication.md`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum BeatOrigin {
    /// Beat arrived on a Unix Domain Socket with kernel credential passing
    /// enabled (`SO_PASSCRED` / `LOCAL_PEERTOKEN` / `SCM_CREDS`). The kernel
    /// attests the sender's PID and UID per-datagram; the observer has
    /// already verified `frame.pid == peer_pid`.
    KernelAttested,
    /// Beat arrived on a UDP listener that the operator explicitly declared
    /// recovery-eligible at bind time (via
    /// `--secure-udp-i-accept-recovery-on-unauthenticated-transport` or
    /// `--plaintext-udp-i-accept-recovery-on-unauthenticated-transport`).
    ///
    /// The kernel cannot attest the sender, but the operator has accepted the
    /// risk *for this specific listener*. Recovery commands are allowed to
    /// fire for stalls on this transport, just as they would on UDS.
    OperatorAttestedTransport,
    /// Beat arrived on a UDP listener (plain or secure) with no operator
    /// trust declaration. Recovery commands must NOT fire — the `frame.pid`
    /// is purely operator-controlled and cannot be tied back to a kernel
    /// attestation. Any holder of a shared PSK, or a leaked master key, can
    /// forge a beat for any pid.
    NetworkUnverified,
    /// Beat arrived on a Unix Domain Socket on a platform that does not
    /// provide per-datagram kernel credential passing (OpenBSD, AIX, HP-UX,
    /// and any other Unix without `SO_PASSCRED` / `LOCAL_CREDS` /
    /// `LOCAL_PEERTOKEN` / `SO_RECVUCRED`).
    ///
    /// Trust derives from filesystem permissions only (`--socket-mode 0600`
    /// restricts access to the owning UID). Recovery commands MUST NOT fire
    /// for these beats — any process under the same UID can forge
    /// `frame.pid` with no kernel contradiction. Operators on these
    /// platforms see a startup warning and must treat the observer as
    /// socket-mode-only secured.
    SocketModeOnly,
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
