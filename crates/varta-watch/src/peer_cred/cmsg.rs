//! Ancillary-data (CMSG) walker for `SCM_CREDENTIALS` (Linux) and `SCM_CREDS`
//! (FreeBSD / DragonFly / NetBSD).
//!
//! This module concentrates **all unsafe pointer arithmetic** that walks the
//! kernel-supplied ancillary buffer produced by `recvmsg(2)`. The Linux and
//! BSD families share the same POSIX cmsg walking discipline; only the
//! `cmsg_len` integer width and the target `(level, type)` pair differ.
//! Those differences are abstracted by [`CmsgPlatform`], and the resulting
//! [`find_credential`] function is the only entry point used by
//! `super::plat::peer_pid_after_recv`.
//!
//! macOS uses `getsockopt(LOCAL_PEERTOKEN)` and does not pass through this
//! module.

#![cfg(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
))]

// ---------------------------------------------------------------------------
// CMSG alignment helpers
// ---------------------------------------------------------------------------

/// `CMSG_ALIGN(len)` from `<sys/socket.h>` — round `len` up to the platform's
/// natural alignment (`sizeof(size_t)` on all targets we support).
pub(super) const fn cmsg_align(len: usize) -> usize {
    // On all supported 64-bit platforms, sizeof(size_t) == sizeof(long) == 8,
    // which matches CMSG_ALIGN.  On 32-bit both are 4.
    let align = core::mem::size_of::<usize>();
    (len + align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// Platform abstraction
// ---------------------------------------------------------------------------

/// Per-platform parameters for the cmsg walker.
///
/// Implemented for Linux (`SCM_CREDENTIALS` / `struct ucred` /
/// `cmsg_len: usize`), the BSD family (`SCM_CREDS` / `struct cmsgcred` /
/// `cmsg_len: u32`), and illumos/Solaris (`SCM_UCRED` / opaque `ucred_t`).
///
/// # Safety
///
/// Implementors must guarantee:
///
/// - `Hdr` is `#[repr(C)]` and matches the kernel's `struct cmsghdr` layout
///   on the implementing platform. Verified by layout guards in `super::plat`.
/// - `Cred` is the platform's credential payload type. For typed payloads
///   (Linux `struct ucred`, BSD `struct cmsgcred`) it must be `#[repr(C)]`
///   with layout verified by layout guards. For
///   opaque payloads (illumos `ucred_t`) it may be the unit type `()` — in
///   that case `extract_pid_uid` receives a raw pointer and delegates to
///   libc accessors rather than casting.
/// - `Msghdr` is `#[repr(C)]` and matches the kernel's `struct msghdr` layout.
/// - `cmsg_len`, `cmsg_level`, `cmsg_type` read the kernel-reported integers
///   faithfully — `cmsg_len` widened to `usize` if narrower on the platform.
/// - `msg_control` returns the `msg_control` pointer cast to `*const u8`
///   (may be null when no ancillary data was passed).
/// - `msg_controllen` returns the kernel-reported byte count widened to
///   `usize`.
/// - `TARGET_LEVEL` / `TARGET_TYPE` are the `(level, type)` pair the kernel
///   uses for credential ancillary data on this platform.
/// - `extract_pid_uid` is called only while `data` (pointing into the
///   ancillary buffer on `recv_authenticated`'s stack frame) is still live.
///   It must not store `data` past the call.
pub(super) unsafe trait CmsgPlatform {
    /// Platform's `struct cmsghdr`.
    type Hdr;
    /// Platform's credential payload type.
    ///
    /// For typed payloads this is the concrete `#[repr(C)]` struct (`Ucred`,
    /// `Cmsgcred`). For opaque payloads (illumos `ucred_t`) use `()` — the
    /// `size_of::<Self::Cred>()` minimum-size guard in `find_credential` then
    /// evaluates to zero, and the implementor's `extract_pid_uid` handles
    /// any non-empty payload via libc accessors.
    type Cred;
    /// Platform's `struct msghdr`.
    type Msghdr;
    /// `level` the kernel sets on credential cmsg (e.g. `SOL_SOCKET`).
    const TARGET_LEVEL: i32;
    /// `type` the kernel sets on credential cmsg (e.g. `SCM_CREDENTIALS`).
    const TARGET_TYPE: i32;

    fn cmsg_len(hdr: &Self::Hdr) -> usize;
    fn cmsg_level(hdr: &Self::Hdr) -> i32;
    fn cmsg_type(hdr: &Self::Hdr) -> i32;
    fn msg_control(mhdr: &Self::Msghdr) -> *const u8;
    fn msg_controllen(mhdr: &Self::Msghdr) -> usize;

    /// Extract `(pid, effective_uid)` from the credential cmsg payload.
    ///
    /// `data` points to the first byte of the cmsg payload (after the
    /// `cmsghdr`); `len` is the payload byte count as reported by
    /// `cmsg_len - cmsg_hdr_size`. The `find_credential` entry point has
    /// already verified `len >= size_of::<Self::Cred>()`.
    ///
    /// Returns `None` when extraction fails (e.g. opaque libc accessor
    /// returns an error sentinel).
    ///
    /// # Safety
    ///
    /// `data` must point to at least `len` initialised bytes inside the
    /// ancillary buffer supplied to `CmsgIter::new`. The buffer must outlive
    /// this call (it lives on `recv_authenticated`'s stack frame — the normal
    /// calling convention). `data` must not be stored past the call.
    unsafe fn extract_pid_uid(data: *const u8, len: usize) -> Option<(u32, u32)>;

    /// Aligned size of one `cmsghdr` on this platform. Used for bounds
    /// checks and for computing the payload offset within a cmsg.
    fn cmsg_hdr_size() -> usize {
        cmsg_align(core::mem::size_of::<Self::Hdr>())
    }
}

// ---------------------------------------------------------------------------
// Iterator
// ---------------------------------------------------------------------------

/// Safe iterator over the cmsg sequence in a recvmsg ancillary buffer.
///
/// Each `next()` performs the bounds checks the POSIX walking discipline
/// requires (cursor + `cmsg_hdr_size` within `controllen`; `cmsg_len`
/// within remaining bytes) before dereferencing kernel-supplied bytes.
/// Defends against adversarial / corrupt `cmsg_len` values by clamping the
/// advance to at least `cmsg_hdr_size` and saturating cursor arithmetic, so
/// iteration always terminates regardless of input.
pub(super) struct CmsgIter<'a, P: CmsgPlatform> {
    base: *const u8,
    controllen: usize,
    cursor: usize,
    _marker: core::marker::PhantomData<&'a P::Msghdr>,
}

impl<'a, P: CmsgPlatform> CmsgIter<'a, P> {
    /// Construct an iterator from a populated msghdr.
    ///
    /// # Safety
    ///
    /// - `P::msg_control(mhdr)` must point to at least `P::msg_controllen(mhdr)`
    ///   bytes of readable memory aligned to `align_of::<usize>()`.
    /// - That region must have been initialised by `recvmsg(2)` (which the
    ///   kernel populates with a sequence of `cmsghdr + padding` records up
    ///   to `controllen` bytes), or by a test/fuzz harness that fabricates
    ///   equivalent bytes.
    /// - The caller must not mutate that region for `'a`.
    pub(super) unsafe fn new(mhdr: &'a P::Msghdr) -> Self {
        let base = P::msg_control(mhdr);
        let controllen = P::msg_controllen(mhdr);
        // Defensive sanity check — kernel never produces a non-null pointer
        // with controllen==0 followed by usable bytes, but null+nonzero is a
        // logic bug worth surfacing in debug builds.
        debug_assert!(
            !base.is_null() || controllen == 0,
            "msg_control is null but msg_controllen is non-zero"
        );
        Self {
            base,
            controllen,
            cursor: 0,
            _marker: core::marker::PhantomData,
        }
    }
}

impl<'a, P: CmsgPlatform> Iterator for CmsgIter<'a, P>
where
    P::Hdr: 'a,
{
    /// `(header, payload_data_ptr)` — `payload_data_ptr` is derived from
    /// `self.base` (full-buffer provenance) so that `extract_pid_uid`
    /// implementations can safely cast it past the header size without
    /// violating Stacked Borrows.
    type Item = (&'a P::Hdr, *const u8);

    fn next(&mut self) -> Option<(&'a P::Hdr, *const u8)> {
        if self.base.is_null() {
            return None;
        }
        // Bounds: cursor + cmsg_hdr_size must fit in controllen.
        // checked_add guards against pathological cursor values; in practice
        // the saturating math at the end of this function pins cursor to a
        // reasonable range, but defending against overflow is cheap.
        let next_min = self.cursor.checked_add(P::cmsg_hdr_size())?;
        if next_min > self.controllen {
            return None;
        }
        // SAFETY:
        // - `base + cursor` is in-bounds: `cursor + cmsg_hdr_size <= controllen`
        //   and `base` is valid for `controllen` readable bytes per `new`'s
        //   SAFETY contract.
        // - Alignment: the receive path's ancillary buffer is
        //   `#[repr(align(8))]` (see `recv::AncBuf`) and `cmsg_align` ensures
        //   `cursor` is on an 8-byte boundary; the platform's `Cmsghdr` has
        //   an alignment of at most `usize` (covered by layout guards in
        //   `super::plat`).
        // - The pointed-to bytes are initialised cmsghdr bytes per `recvmsg(2)`
        //   semantics (or equivalent fuzz/test fabrication).
        let hdr_ptr = unsafe { self.base.add(self.cursor) } as *const P::Hdr;
        let hdr: &P::Hdr = unsafe { &*hdr_ptr };
        let len = P::cmsg_len(hdr);
        // Validate the cmsg payload fits in the remaining buffer.
        if len > self.controllen - self.cursor {
            return None;
        }
        // Derive data_ptr from self.base (full-buffer provenance) before
        // advancing the cursor. Using self.base avoids narrowing provenance
        // to sizeof(Hdr) that would occur if derived from the `hdr` reference.
        let data_ptr = unsafe { self.base.add(self.cursor + P::cmsg_hdr_size()) };
        // Advance the cursor for the next iteration. Clamp the advance to
        // at least `cmsg_hdr_size` so an adversarial `cmsg_len == 0` (or
        // anything smaller than the header itself) cannot stall the walk in
        // an infinite loop. `saturating_add` prevents `usize` overflow from
        // wrapping into a small value that could look in-bounds.
        let advance = core::cmp::max(cmsg_align(len), P::cmsg_hdr_size());
        self.cursor = self.cursor.saturating_add(advance);
        Some((hdr, data_ptr))
    }
}

// ---------------------------------------------------------------------------
// Top-level entry point
// ---------------------------------------------------------------------------

/// Walk the ancillary data of `mhdr` and return the kernel-attested
/// `(pid, effective_uid)` from the first credential cmsg whose `(level,
/// type)` matches `P::TARGET_LEVEL` / `P::TARGET_TYPE`.
///
/// Returns `None` if no credential cmsg is present, if a candidate cmsg
/// has `cmsg_len` smaller than `cmsg_hdr_size + sizeof::<P::Cred>()`, if
/// the buffer is empty / malformed, or if `P::extract_pid_uid` returns
/// `None` (e.g. an opaque libc accessor returned an error sentinel).
///
/// # Notes
///
/// Although this function is *safe* to call from Rust, soundness relies on
/// `P::msg_control(mhdr)` and `P::msg_controllen(mhdr)` describing readable
/// memory initialised by `recvmsg(2)` — the normal contract observed by
/// `super::plat::peer_pid_after_recv`. Test and fuzz harnesses that
/// fabricate a `Msghdr` from a byte slice satisfy the same contract.
pub(super) fn find_credential<P: CmsgPlatform>(mhdr: &P::Msghdr) -> Option<(u32, u32)> {
    let needed = P::cmsg_hdr_size() + core::mem::size_of::<P::Cred>();
    // SAFETY: documented by this function's contract — callers commit that
    // `mhdr` was populated by `recvmsg(2)` (or an equivalent fabricator).
    let iter = unsafe { CmsgIter::<P>::new(mhdr) };
    for (hdr, data_ptr) in iter {
        if P::cmsg_level(hdr) != P::TARGET_LEVEL || P::cmsg_type(hdr) != P::TARGET_TYPE {
            continue;
        }
        if P::cmsg_len(hdr) < needed {
            return None;
        }
        // SAFETY:
        // - `cmsg_len(hdr) >= cmsg_hdr_size + sizeof::<P::Cred>()` checked
        //   immediately above.
        // - The iterator already proved `cursor + cmsg_len(hdr) <=
        //   controllen`, so the payload lies fully inside the readable region.
        // - `data_ptr` is derived from the iterator's `self.base` (full-buffer
        //   provenance) — not from the `hdr` reference — so retagging into a
        //   larger credential type is provenance-clean under Stacked Borrows.
        // - The buffer outlives this call (stack-allocated in
        //   `recv_authenticated`) — satisfying `extract_pid_uid`'s contract.
        let payload_len = P::cmsg_len(hdr).saturating_sub(P::cmsg_hdr_size());
        return unsafe { P::extract_pid_uid(data_ptr, payload_len) };
    }
    None
}

/// Close every file descriptor carried by an `SCM_RIGHTS` ancillary message.
///
/// Varta never sends ancillary file descriptors, so any `SCM_RIGHTS` a peer
/// attaches to a datagram is unsolicited. File-descriptor passing is
/// sender-driven: `recvmsg(2)` installs the passed fds into the observer
/// regardless of socket options, and `MSG_CMSG_CLOEXEC` (where the platform
/// even supports it) only sets `FD_CLOEXEC` — it does not close them. Left
/// open, they accumulate in the long-lived single-threaded observer until
/// `RLIMIT_NOFILE` is reached, after which `recvmsg`, `/metrics` accepts,
/// `/proc` reads, and audit-log rotation begin failing — silently disabling
/// recovery supervision while the process still appears live (fd-exhaustion
/// DoS). This walks the kernel-supplied ancillary buffer and hands each
/// `SCM_RIGHTS` fd to `close_fd` for immediate reclamation.
///
/// `scm_rights_type` is the platform's `SCM_RIGHTS` cmsg `type`; the `level`
/// filter reuses [`CmsgPlatform::TARGET_LEVEL`] (`SOL_SOCKET`), which is the
/// level the kernel sets on `SCM_RIGHTS` on every supported platform — the
/// same level as its credential cmsg.
///
/// This is the single cross-platform reclamation point invoked once per
/// datagram by `recv::recv_authenticated`, ahead of every success / truncated
/// / short-read return path.
///
/// # Notes
///
/// Soundness relies on `mhdr` having been populated by `recvmsg(2)` (or an
/// equivalent fabricator) — the same contract as [`find_credential`].
pub(super) fn reclaim_scm_rights<P: CmsgPlatform>(
    mhdr: &P::Msghdr,
    scm_rights_type: i32,
    mut close_fd: impl FnMut(i32),
) {
    // SAFETY: documented by this function's contract — callers commit that
    // `mhdr` was populated by `recvmsg(2)` (or an equivalent fabricator).
    let iter = unsafe { CmsgIter::<P>::new(mhdr) };
    for (hdr, data_ptr) in iter {
        if P::cmsg_level(hdr) != P::TARGET_LEVEL || P::cmsg_type(hdr) != scm_rights_type {
            continue;
        }
        let payload_len = P::cmsg_len(hdr).saturating_sub(P::cmsg_hdr_size());
        let fd_count = payload_len / core::mem::size_of::<i32>();
        for i in 0..fd_count {
            // SAFETY: the iterator proved the whole cmsg (header + `payload_len`
            // bytes) lies inside the kernel-supplied ancillary buffer, so the
            // i32 at byte offset `i * 4` is in bounds. `read_unaligned` because
            // the cmsg payload ABI only promises byte validity.
            let fd = unsafe {
                data_ptr
                    .add(i * core::mem::size_of::<i32>())
                    .cast::<i32>()
                    .read_unaligned()
            };
            if fd >= 0 {
                close_fd(fd);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Miri-compatible tests
// ---------------------------------------------------------------------------

/// Miri-compatible cmsg pointer-walk tests.
///
/// These tests fabricate the bytes that `recvmsg(2)` would produce — no
/// actual syscall, so Miri can execute the cmsg pointer arithmetic end-to-end
/// with `-Zmiri-strict-provenance` to catch int-to-pointer casts and
/// provenance violations.
///
/// Gated on `target_os = "linux"` because the Linux `plat` module is the
/// only one currently exposed on the test host.  The unified walker is
/// generic, so this single test surface validates pointer arithmetic for
/// both platform implementations.
#[cfg(all(test, target_os = "linux"))]
mod miri_cmsg_tests {
    use super::super::plat;
    use super::*;
    use core::mem;

    /// Local shim: the existing Linux test surface called the previously
    /// standalone `cmsg_hdr_size()`. After the walker was unified the
    /// authoritative size lives on the trait; this preserves the original
    /// call sites without a sweep of every test body.
    fn cmsg_hdr_size() -> usize {
        <plat::LinuxCmsg as CmsgPlatform>::cmsg_hdr_size()
    }

    /// CMSG_SPACE for one `Ucred` on this platform.
    fn cmsg_space_ucred() -> usize {
        cmsg_align(cmsg_hdr_size() + mem::size_of::<plat::Ucred>())
    }

    /// CMSG_SPACE for one integer fd payload (`SCM_PIDFD`) on Linux.
    fn cmsg_space_i32() -> usize {
        cmsg_align(cmsg_hdr_size() + mem::size_of::<i32>())
    }

    /// 8-byte-aligned scratch buffer for cmsg walker tests.
    ///
    /// Plain `[u8; N]` arrays guarantee only 1-byte alignment. Miri flags
    /// `unsafe { &*hdr_ptr }` (needs 8-byte alignment for `Cmsghdr.cmsg_len:
    /// usize`) as UB when the backing allocation has alignment 1.
    /// `#[repr(align(8))]` ensures `buf.as_ptr()` is 8-byte aligned; combined
    /// with `cmsg_align`-bounded cursor advances every `base + cursor` pointer
    /// meets the alignment requirement. Pattern matches production `AncBuf` in
    /// `recv.rs`. See cerebrum 2026-05-16.
    #[repr(align(8))]
    struct AlignedBuf([u8; 512]);

    /// Write a single SCM_CREDENTIALS `cmsghdr + ucred` into `buf` starting
    /// at `offset`.  Returns the number of bytes written (== CMSG_SPACE).
    fn write_scm_credentials(buf: &mut [u8], offset: usize, pid: i32, uid: u32, gid: u32) {
        let hdr_size = cmsg_hdr_size();
        let total = cmsg_space_ucred();
        let slice = &mut buf[offset..offset + total];

        // Zero the region so padding bytes are deterministic.
        slice.fill(0);

        // Write cmsghdr fields at offset 0: cmsg_len, cmsg_level, cmsg_type.
        // On 64-bit Linux: cmsg_len is usize (8 bytes), then two i32 (4 bytes each).
        let cmsg_len: usize = hdr_size + mem::size_of::<plat::Ucred>();
        slice[..mem::size_of::<usize>()].copy_from_slice(&cmsg_len.to_ne_bytes());
        slice[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        slice[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&plat::SCM_CREDENTIALS.to_ne_bytes());

        // Write ucred at hdr_size: pid (i32), uid (u32), gid (u32).
        let ucred_off = hdr_size;
        slice[ucred_off..ucred_off + 4].copy_from_slice(&pid.to_ne_bytes());
        slice[ucred_off + 4..ucred_off + 8].copy_from_slice(&uid.to_ne_bytes());
        slice[ucred_off + 8..ucred_off + 12].copy_from_slice(&gid.to_ne_bytes());
    }

    fn write_scm_pidfd(buf: &mut [u8], offset: usize, fd: i32) {
        let hdr_size = cmsg_hdr_size();
        let total = cmsg_space_i32();
        let slice = &mut buf[offset..offset + total];
        slice.fill(0);

        let cmsg_len: usize = hdr_size + mem::size_of::<i32>();
        slice[..mem::size_of::<usize>()].copy_from_slice(&cmsg_len.to_ne_bytes());
        slice[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        slice[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&plat::SCM_PIDFD.to_ne_bytes());

        let fd_off = hdr_size;
        slice[fd_off..fd_off + 4].copy_from_slice(&fd.to_ne_bytes());
    }

    fn assert_pid_uid_no_pidfd(
        result: Option<(u32, u32, Option<super::super::types::PeerPidFd>)>,
        pid: u32,
        uid: u32,
    ) {
        let (got_pid, got_uid, got_pidfd) = result.expect("expected credentials");
        assert_eq!((got_pid, got_uid), (pid, uid));
        assert!(
            got_pidfd.is_none(),
            "credential-only cmsg must not fabricate pidfd"
        );
    }

    /// Build a `plat::Msghdr` that points into `anc_buf` with `controllen` bytes
    /// of valid ancillary data.
    fn make_mhdr(anc_buf: &[u8], controllen: usize) -> plat::Msghdr {
        plat::Msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: core::ptr::null_mut(),
            msg_iovlen: 0,
            msg_control: anc_buf.as_ptr() as *mut _,
            msg_controllen: controllen,
            msg_flags: 0,
            _pad2: 0,
        }
    }

    #[test]
    fn empty_buffer_returns_none() {
        let buf = [];
        let mhdr = make_mhdr(&buf, 0);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert!(result.is_none());
    }

    #[test]
    fn single_scm_credentials_returns_pid_uid() {
        let mut abuf = AlignedBuf([0u8; 512]);
        write_scm_credentials(&mut abuf.0, 0, 1234, 1000, 100);
        let controllen = cmsg_space_ucred();
        let mhdr = make_mhdr(&abuf.0, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert_pid_uid_no_pidfd(result, 1234, 1000);
    }

    #[test]
    fn credentials_with_scm_pidfd_returns_owned_pidfd() {
        // Parser-level only: the SCM_PIDFD integer need not be a live kernel
        // descriptor. Avoid open(2) so Miri isolation can exercise the walker;
        // forget the wrapper so drop does not close(2) a synthetic fd.
        const SYNTHETIC_FD: i32 = 42;

        let mut abuf = AlignedBuf([0u8; 512]);
        write_scm_credentials(&mut abuf.0, 0, 1234, 1000, 100);
        write_scm_pidfd(&mut abuf.0, cmsg_space_ucred(), SYNTHETIC_FD);
        let controllen = cmsg_space_ucred() + cmsg_space_i32();
        let mhdr = make_mhdr(&abuf.0, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        let (pid, uid, pidfd) = result.expect("expected credentials");
        assert_eq!((pid, uid), (1234, 1000));
        let pidfd = pidfd.expect("SCM_PIDFD cmsg must be surfaced");
        std::mem::forget(pidfd);
    }

    #[test]
    fn truncated_cmsg_length_returns_none() {
        // Write a cmsg whose cmsg_len is smaller than hdr+ucred.
        let mut abuf = AlignedBuf([0u8; 512]);
        let buf = &mut abuf.0;
        let hdr_size = cmsg_hdr_size();
        // cmsg_len = hdr_size only (no room for ucred).
        let truncated_len: usize = hdr_size;
        buf[..mem::size_of::<usize>()].copy_from_slice(&truncated_len.to_ne_bytes());
        buf[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        buf[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&plat::SCM_CREDENTIALS.to_ne_bytes());
        let controllen = cmsg_space_ucred();
        let mhdr = make_mhdr(buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert!(result.is_none(), "truncated cmsg must not produce a pid");
    }

    #[test]
    fn unknown_cmsg_type_returns_none() {
        let mut abuf = AlignedBuf([0u8; 512]);
        let buf = &mut abuf.0;
        // Write a valid-length cmsg but with a different cmsg_type.
        let hdr_size = cmsg_hdr_size();
        let cmsg_len: usize = hdr_size + mem::size_of::<plat::Ucred>();
        buf[..mem::size_of::<usize>()].copy_from_slice(&cmsg_len.to_ne_bytes());
        buf[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        let wrong_type: i32 = 99;
        buf[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&wrong_type.to_ne_bytes());
        // controllen too small for a second cmsg → walk stops after one cmsg.
        let controllen = cmsg_space_ucred();
        let mhdr = make_mhdr(buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert!(result.is_none(), "unknown cmsg_type must not produce a pid");
    }

    #[test]
    fn multiple_cmsgs_finds_credentials_in_second() {
        // First cmsg: unknown type, second cmsg: SCM_CREDENTIALS.
        let space = cmsg_space_ucred();
        let mut abuf = AlignedBuf([0u8; 512]);
        let buf = &mut abuf.0;

        // First cmsg — unknown type, valid length.
        let hdr_size = cmsg_hdr_size();
        let cmsg_len: usize = hdr_size + mem::size_of::<plat::Ucred>();
        buf[..mem::size_of::<usize>()].copy_from_slice(&cmsg_len.to_ne_bytes());
        buf[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        let wrong_type: i32 = 99;
        buf[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&wrong_type.to_ne_bytes());

        // Second cmsg — SCM_CREDENTIALS with pid=5678.
        write_scm_credentials(buf, space, 5678, 2000, 200);

        let controllen = space * 2;
        let mhdr = make_mhdr(buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert_pid_uid_no_pidfd(result, 5678, 2000);
    }

    #[test]
    fn trailing_padding_does_not_confuse_walker() {
        // A single SCM_CREDENTIALS cmsg followed by extra zero bytes.
        let mut abuf = AlignedBuf([0u8; 512]);
        write_scm_credentials(&mut abuf.0, 0, 999, 42, 42);
        // Report controllen as the full buffer — walker must stop at the
        // cmsg whose cmsg_len does not leave room for another header.
        let controllen = 128;
        let mhdr = make_mhdr(&abuf.0, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert_pid_uid_no_pidfd(result, 999, 42);
    }

    /// Drives the unified walker through the BSD-family arm
    /// (`SCM_CREDS` + `struct cmsgcred`) on the Linux test host.
    ///
    /// The BSD `Cmsghdr` / `Cmsgcred` / `Msghdr` type definitions plus the
    /// `unsafe impl CmsgPlatform for BsdCmsg` body are compiled unconditionally
    /// on Linux (see `peer_cred/platform/mod.rs`). The FFI and `LOCAL_CREDS`
    /// constants stay gated to the actual BSD targets. This test fabricates a
    /// well-formed BSD ancillary buffer and asserts `find_credential::<BsdCmsg>`
    /// returns the expected `(pid, euid)` pair.
    ///
    /// Without this test, the BSD walker arm is only exercised on a real
    /// BSD CI host — which CI doesn't currently provide. Running it under
    /// Miri here proves the pointer arithmetic of the unified walker is
    /// provenance-clean for the BSD-shaped layout too.
    #[test]
    fn bsd_shape_buffer_returns_pid_euid() {
        use super::super::platform::bsd::{BsdCmsg, Cmsgcred, Cmsghdr, Msghdr};
        use core::mem;

        // BSD: cmsg_align uses sizeof(usize) on 64-bit, same as Linux.
        // BSD Cmsghdr is 12 bytes; cmsg_align(12) = 16.
        let bsd_hdr_size = <BsdCmsg as CmsgPlatform>::cmsg_hdr_size();
        assert_eq!(bsd_hdr_size, cmsg_align(mem::size_of::<Cmsghdr>()));
        assert_eq!(bsd_hdr_size, 16);

        let total = bsd_hdr_size + mem::size_of::<Cmsgcred>();
        let aligned_total = cmsg_align(total);
        // CRITICAL: Match recv.rs's AncBuf pattern — the buffer MUST be
        // aligned to 8 bytes. A Vec<u8> only guarantees 1-byte alignment,
        // which causes miri to detect unaligned pointer dereferences.
        // Use a stack array wrapped in #[repr(align(8))].
        #[repr(align(8))]
        struct AlignedBuf([u8; 256]);
        let mut buf_wrapper = AlignedBuf([0u8; 256]);
        let buf = &mut buf_wrapper.0[..aligned_total];

        // Write BSD cmsghdr at offset 0:
        //   cmsg_len (u32, 4 bytes), cmsg_level (i32, 4), cmsg_type (i32, 4)
        let cmsg_len: u32 = total as u32;
        let sol_socket: i32 = 0xffff; // SOL_SOCKET on BSD
        let scm_creds: i32 = 0x03; // SCM_CREDS
        buf[0..4].copy_from_slice(&cmsg_len.to_ne_bytes());
        buf[4..8].copy_from_slice(&sol_socket.to_ne_bytes());
        buf[8..12].copy_from_slice(&scm_creds.to_ne_bytes());

        // Write cmsgcred at offset bsd_hdr_size (16):
        //   cmcred_pid (i32, 4) @ 0, cmcred_uid (u32, 4) @ 4,
        //   cmcred_euid (u32, 4) @ 8, ... (rest zeroed)
        let expected_pid: i32 = 9999;
        let expected_uid: u32 = 33;
        let expected_euid: u32 = 1500;
        let cred_off = bsd_hdr_size;
        buf[cred_off..cred_off + 4].copy_from_slice(&expected_pid.to_ne_bytes());
        buf[cred_off + 4..cred_off + 8].copy_from_slice(&expected_uid.to_ne_bytes());
        buf[cred_off + 8..cred_off + 12].copy_from_slice(&expected_euid.to_ne_bytes());

        // Construct a BSD Msghdr pointing at the fabricated buffer. The
        // pure-data struct layout is identical to actual BSD on the Linux
        // test host (see compile-time offset asserts in platform/bsd.rs).
        let mhdr = Msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: core::ptr::null_mut(),
            msg_iovlen: 0,
            _pad2: 0,
            msg_control: buf.as_mut_ptr() as *mut _,
            msg_controllen: aligned_total as u32,
            msg_flags: 0,
        };

        let result = find_credential::<BsdCmsg>(&mhdr);
        assert_eq!(result, Some((expected_pid as u32, expected_euid)));
    }

    /// Drives the unified walker through the illumos/Solaris arm
    /// (`SCM_UCRED` + opaque `ucred_t`) on the Linux test host.
    ///
    /// The illumos `Cmsghdr` / `Msghdr` type definitions and the
    /// `unsafe impl CmsgPlatform for IllumosCmsg` body are compiled on Linux
    /// too (see `peer_cred/platform/mod.rs`). The `extern "C"` `ucred_getpid`
    /// / `ucred_geteuid` accessors are replaced by inline Rust shims that read
    /// PID at offset 0 (i32) and UID at offset 4 (u32) of the test buffer.
    ///
    /// Without this test the illumos walker arm is only exercised on a real
    /// illumos CI host.  Running it under Miri here proves pointer arithmetic
    /// is provenance-clean for the illumos-shaped layout too.
    #[test]
    fn illumos_shape_buffer_returns_pid_euid() {
        use super::super::platform::illumos::{Cmsghdr, IllumosCmsg, Msghdr};
        use core::mem;

        // illumos Cmsghdr is 12 bytes; cmsg_align(12) = 16 on LP64.
        let illumos_hdr_size = <IllumosCmsg as CmsgPlatform>::cmsg_hdr_size();
        assert_eq!(illumos_hdr_size, cmsg_align(mem::size_of::<Cmsghdr>()));
        assert_eq!(illumos_hdr_size, 16);

        // Payload: 4 bytes pid (i32) + 4 bytes uid (u32) = 8 bytes.
        // The shim reads pid at offset 0, uid at offset 4 of the payload.
        let payload_len = 8usize;
        let total = illumos_hdr_size + payload_len;
        let aligned_total = cmsg_align(total);
        // CRITICAL: Match recv.rs's AncBuf pattern — the buffer MUST be
        // aligned to 8 bytes. A Vec<u8> only guarantees 1-byte alignment,
        // which causes miri to detect unaligned pointer dereferences.
        // Use a stack array wrapped in #[repr(align(8))].
        #[repr(align(8))]
        struct AlignedBuf([u8; 256]);
        let mut buf_wrapper = AlignedBuf([0u8; 256]);
        let buf = &mut buf_wrapper.0[..aligned_total];

        // Write illumos cmsghdr: cmsg_len (u32), cmsg_level (i32), cmsg_type (i32)
        let cmsg_len: u32 = total as u32;
        let sol_socket: i32 = 0xffff; // SOL_SOCKET on illumos
        let scm_ucred: i32 = 0x1012; // SCM_UCRED
        buf[0..4].copy_from_slice(&cmsg_len.to_ne_bytes());
        buf[4..8].copy_from_slice(&sol_socket.to_ne_bytes());
        buf[8..12].copy_from_slice(&scm_ucred.to_ne_bytes());

        // Write test payload at illumos_hdr_size: pid at +0, uid at +4.
        let expected_pid: i32 = 4321;
        let expected_uid: u32 = 500;
        let pay_off = illumos_hdr_size;
        buf[pay_off..pay_off + 4].copy_from_slice(&expected_pid.to_ne_bytes());
        buf[pay_off + 4..pay_off + 8].copy_from_slice(&expected_uid.to_ne_bytes());

        let mhdr = Msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: core::ptr::null_mut(),
            msg_iovlen: 0,
            _pad2: 0,
            msg_control: buf.as_mut_ptr() as *mut _,
            msg_controllen: aligned_total as u32,
            msg_flags: 0,
        };

        let result = find_credential::<IllumosCmsg>(&mhdr);
        assert_eq!(result, Some((expected_pid as u32, expected_uid)));
    }

    /// `ucred_getpid` shim returns -1 when the buffer encodes a negative pid
    /// → `extract_pid_uid` returns `None`.
    #[test]
    fn illumos_opaque_extraction_returns_none_on_invalid() {
        use super::super::platform::illumos::{IllumosCmsg, Msghdr};

        let illumos_hdr_size = <IllumosCmsg as CmsgPlatform>::cmsg_hdr_size();
        let payload_len = 8usize;
        let total = illumos_hdr_size + payload_len;
        let aligned_total = cmsg_align(total);
        // CRITICAL: Match recv.rs's AncBuf pattern — the buffer MUST be
        // aligned to 8 bytes.
        #[repr(align(8))]
        struct AlignedBuf([u8; 256]);
        let mut buf_wrapper = AlignedBuf([0u8; 256]);
        let buf = &mut buf_wrapper.0[..aligned_total];

        let cmsg_len: u32 = total as u32;
        let sol_socket: i32 = 0xffff;
        let scm_ucred: i32 = 0x1012;
        buf[0..4].copy_from_slice(&cmsg_len.to_ne_bytes());
        buf[4..8].copy_from_slice(&sol_socket.to_ne_bytes());
        buf[8..12].copy_from_slice(&scm_ucred.to_ne_bytes());

        // Encode pid = -1 → shim returns -1 → extract_pid_uid returns None.
        let neg_pid: i32 = -1;
        let uid: u32 = 1000;
        let pay_off = illumos_hdr_size;
        buf[pay_off..pay_off + 4].copy_from_slice(&neg_pid.to_ne_bytes());
        buf[pay_off + 4..pay_off + 8].copy_from_slice(&uid.to_ne_bytes());

        let mhdr = Msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: core::ptr::null_mut(),
            msg_iovlen: 0,
            _pad2: 0,
            msg_control: buf.as_mut_ptr() as *mut _,
            msg_controllen: aligned_total as u32,
            msg_flags: 0,
        };

        let result = find_credential::<IllumosCmsg>(&mhdr);
        assert_eq!(result, None, "negative pid must produce None");
    }

    /// Boundary: a credential cmsg whose `cmsg_len` exactly equals the aligned
    /// header size carries a zero-length payload. It clears `find_credential`'s
    /// minimum-length gate (which adds only `size_of::<()> == 0` for the opaque
    /// `ucred_t`), so `extract_pid_uid` must refuse it via its own `len >= 8`
    /// floor rather than read the fixed-size shim payload past the declared
    /// bytes. Complements `illumos_walker_rejects_truncated_cmsg`, which only
    /// covers `cmsg_len < hdr_size`.
    #[test]
    fn illumos_walker_rejects_zero_length_ucred_payload() {
        use super::super::platform::illumos::{IllumosCmsg, Msghdr};

        let illumos_hdr_size = <IllumosCmsg as CmsgPlatform>::cmsg_hdr_size();
        // cmsg_len == hdr_size → payload_len = hdr_size - hdr_size = 0.
        let cmsg_len: u32 = illumos_hdr_size as u32;

        #[repr(align(8))]
        struct AlignedBuf([u8; 256]);
        let mut buf_wrapper = AlignedBuf([0u8; 256]);
        let buf = &mut buf_wrapper.0[..illumos_hdr_size];

        buf[0..4].copy_from_slice(&cmsg_len.to_ne_bytes());
        let sol_socket: i32 = 0xffff;
        let scm_ucred: i32 = 0x1012;
        buf[4..8].copy_from_slice(&sol_socket.to_ne_bytes());
        buf[8..12].copy_from_slice(&scm_ucred.to_ne_bytes());

        let mhdr = Msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: core::ptr::null_mut(),
            msg_iovlen: 0,
            _pad2: 0,
            msg_control: buf.as_mut_ptr() as *mut _,
            msg_controllen: illumos_hdr_size as u32,
            msg_flags: 0,
        };

        let result = find_credential::<IllumosCmsg>(&mhdr);
        assert_eq!(
            result, None,
            "header-only (zero-payload) ucred cmsg must produce None, not an over-read"
        );
    }

    /// `cmsg_len` smaller than the minimum (hdr_size + 0) must be rejected.
    #[test]
    fn illumos_walker_rejects_truncated_cmsg() {
        use super::super::platform::illumos::{IllumosCmsg, Msghdr};

        let illumos_hdr_size = <IllumosCmsg as CmsgPlatform>::cmsg_hdr_size();

        // Claim cmsg_len = hdr_size - 1 (strictly less than needed = hdr_size).
        let truncated_len: u32 = (illumos_hdr_size - 1) as u32;
        // CRITICAL: Match recv.rs's AncBuf pattern — the buffer MUST be
        // aligned to 8 bytes.
        #[repr(align(8))]
        struct AlignedBuf([u8; 256]);
        let mut buf_wrapper = AlignedBuf([0u8; 256]);
        let buf = &mut buf_wrapper.0[..illumos_hdr_size + 8];

        buf[0..4].copy_from_slice(&truncated_len.to_ne_bytes());
        let sol_socket: i32 = 0xffff;
        let scm_ucred: i32 = 0x1012;
        buf[4..8].copy_from_slice(&sol_socket.to_ne_bytes());
        buf[8..12].copy_from_slice(&scm_ucred.to_ne_bytes());

        let mhdr = Msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: core::ptr::null_mut(),
            msg_iovlen: 0,
            _pad2: 0,
            msg_control: buf.as_mut_ptr() as *mut _,
            msg_controllen: buf.len() as u32,
            msg_flags: 0,
        };

        let result = find_credential::<IllumosCmsg>(&mhdr);
        assert_eq!(
            result, None,
            "truncated illumos cmsg must not produce a pid"
        );
    }

    /// Defense-in-depth: an attacker-supplied cmsg_len of 0 must not loop
    /// forever. The walker advances by at least `cmsg_hdr_size` per step.
    #[test]
    fn zero_cmsg_len_does_not_infinite_loop() {
        let mut abuf = AlignedBuf([0u8; 512]);
        let buf = &mut abuf.0;
        // Write a cmsg with cmsg_len == 0 but otherwise valid header bytes.
        let zero_len: usize = 0;
        buf[..mem::size_of::<usize>()].copy_from_slice(&zero_len.to_ne_bytes());
        buf[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        buf[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&plat::SCM_CREDENTIALS.to_ne_bytes());
        let mhdr = make_mhdr(buf, buf.len());
        // Must return None — cmsg_len < needed; must terminate (test would
        // hang otherwise).
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert!(result.is_none());
    }

    /// Write one `SCM_RIGHTS` cmsg (Linux shape: usize `cmsg_len`) carrying
    /// `fds`. Returns CMSG_SPACE for the message.
    fn write_scm_rights_linux(buf: &mut [u8], offset: usize, fds: &[i32]) -> usize {
        let hdr_size = cmsg_hdr_size();
        let payload = mem::size_of_val(fds);
        let cmsg_len = hdr_size + payload;
        let total = cmsg_align(cmsg_len);
        let slice = &mut buf[offset..offset + total];
        slice.fill(0);
        slice[..mem::size_of::<usize>()].copy_from_slice(&cmsg_len.to_ne_bytes());
        slice[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        slice[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&plat::SCM_RIGHTS.to_ne_bytes());
        for (i, fd) in fds.iter().enumerate() {
            let off = hdr_size + i * mem::size_of::<i32>();
            slice[off..off + 4].copy_from_slice(&fd.to_ne_bytes());
        }
        total
    }

    /// `reclaim_scm_rights` hands every fd in an `SCM_RIGHTS` cmsg to the
    /// closure — including multiple fds in one cmsg — and ignores a
    /// co-resident credential cmsg (the fd-exhaustion DoS regression).
    #[test]
    fn reclaim_scm_rights_collects_every_passed_fd() {
        let mut abuf = AlignedBuf([0u8; 512]);
        // First: a credential cmsg the reclaimer must skip.
        write_scm_credentials(&mut abuf.0, 0, 1234, 1000, 100);
        let cred_space = cmsg_space_ucred();
        // Then: an SCM_RIGHTS cmsg with three fds.
        let rights_space = write_scm_rights_linux(&mut abuf.0, cred_space, &[7, 8, 9]);
        let controllen = cred_space + rights_space;
        let mhdr = make_mhdr(&abuf.0, controllen);

        let mut closed = Vec::new();
        reclaim_scm_rights::<plat::LinuxCmsg>(&mhdr, plat::SCM_RIGHTS, |fd| closed.push(fd));
        assert_eq!(closed, vec![7, 8, 9], "every passed fd must be reclaimed");
    }

    /// A datagram with only a credential cmsg (no `SCM_RIGHTS`) closes nothing.
    #[test]
    fn reclaim_scm_rights_ignores_credential_only() {
        let mut abuf = AlignedBuf([0u8; 512]);
        write_scm_credentials(&mut abuf.0, 0, 1234, 1000, 100);
        let mhdr = make_mhdr(&abuf.0, cmsg_space_ucred());

        let mut closed = Vec::new();
        reclaim_scm_rights::<plat::LinuxCmsg>(&mhdr, plat::SCM_RIGHTS, |fd| closed.push(fd));
        assert!(
            closed.is_empty(),
            "no SCM_RIGHTS present — nothing to close"
        );
    }

    /// Negative fd sentinels in an `SCM_RIGHTS` payload must be skipped, never
    /// passed to `close(2)`.
    #[test]
    fn reclaim_scm_rights_skips_negative_fds() {
        let mut abuf = AlignedBuf([0u8; 512]);
        let space = write_scm_rights_linux(&mut abuf.0, 0, &[-1, 5, -1, 6]);
        let mhdr = make_mhdr(&abuf.0, space);

        let mut closed = Vec::new();
        reclaim_scm_rights::<plat::LinuxCmsg>(&mhdr, plat::SCM_RIGHTS, |fd| closed.push(fd));
        assert_eq!(closed, vec![5, 6], "negative fd sentinels must be skipped");
    }

    /// Drives `reclaim_scm_rights` through the BSD-family arm (u32 `cmsg_len`,
    /// `SOL_SOCKET = 0xffff`) on the Linux test host, proving the pointer
    /// arithmetic is provenance-clean for the BSD-shaped layout. The BSD
    /// `recv_authenticated` path has no CI host; this is its only coverage.
    #[test]
    fn reclaim_scm_rights_bsd_shape() {
        use super::super::platform::bsd::{BsdCmsg, Msghdr};

        let hdr_size = <BsdCmsg as CmsgPlatform>::cmsg_hdr_size();
        let fds: [i32; 2] = [11, 12];
        let payload = mem::size_of_val(&fds);
        // CMSG_LEN: aligned header + payload (data starts at the aligned
        // offset `hdr_size`), matching the walker's payload-length arithmetic.
        let cmsg_len = hdr_size + payload;
        let total = cmsg_align(cmsg_len);

        #[repr(align(8))]
        struct AlignedBuf([u8; 128]);
        let mut buf_wrapper = AlignedBuf([0u8; 128]);
        let buf = &mut buf_wrapper.0[..total];

        buf[0..4].copy_from_slice(&(cmsg_len as u32).to_ne_bytes());
        let sol_socket: i32 = 0xffff;
        let scm_rights: i32 = 0x01;
        buf[4..8].copy_from_slice(&sol_socket.to_ne_bytes());
        buf[8..12].copy_from_slice(&scm_rights.to_ne_bytes());
        for (i, fd) in fds.iter().enumerate() {
            let off = hdr_size + i * mem::size_of::<i32>();
            buf[off..off + 4].copy_from_slice(&fd.to_ne_bytes());
        }

        let mhdr = Msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: core::ptr::null_mut(),
            msg_iovlen: 0,
            _pad2: 0,
            msg_control: buf.as_mut_ptr() as *mut _,
            msg_controllen: total as u32,
            msg_flags: 0,
        };

        let mut closed = Vec::new();
        reclaim_scm_rights::<BsdCmsg>(&mhdr, scm_rights, |fd| closed.push(fd));
        assert_eq!(closed, vec![11, 12]);
    }

    /// Drives `reclaim_scm_rights` through the illumos/Solaris arm
    /// (`SCM_RIGHTS = 0x1010`, distinct from `SCM_UCRED = 0x1012`) on the Linux
    /// test host — the illumos `recv_authenticated` path has no CI host.
    #[test]
    fn reclaim_scm_rights_illumos_shape() {
        use super::super::platform::illumos::{IllumosCmsg, Msghdr};

        let hdr_size = <IllumosCmsg as CmsgPlatform>::cmsg_hdr_size();
        let fds: [i32; 1] = [21];
        let payload = mem::size_of_val(&fds);
        // CMSG_LEN: aligned header + payload (data starts at the aligned
        // offset `hdr_size`), matching the walker's payload-length arithmetic.
        let cmsg_len = hdr_size + payload;
        let total = cmsg_align(cmsg_len);

        #[repr(align(8))]
        struct AlignedBuf([u8; 128]);
        let mut buf_wrapper = AlignedBuf([0u8; 128]);
        let buf = &mut buf_wrapper.0[..total];

        buf[0..4].copy_from_slice(&(cmsg_len as u32).to_ne_bytes());
        let sol_socket: i32 = 0xffff;
        let scm_rights: i32 = 0x1010;
        buf[4..8].copy_from_slice(&sol_socket.to_ne_bytes());
        buf[8..12].copy_from_slice(&scm_rights.to_ne_bytes());
        let off = hdr_size;
        buf[off..off + 4].copy_from_slice(&fds[0].to_ne_bytes());

        let mhdr = Msghdr {
            msg_name: core::ptr::null_mut(),
            msg_namelen: 0,
            _pad1: 0,
            msg_iov: core::ptr::null_mut(),
            msg_iovlen: 0,
            _pad2: 0,
            msg_control: buf.as_mut_ptr() as *mut _,
            msg_controllen: total as u32,
            msg_flags: 0,
        };

        let mut closed = Vec::new();
        reclaim_scm_rights::<IllumosCmsg>(&mhdr, scm_rights, |fd| closed.push(fd));
        assert_eq!(closed, vec![21]);
    }
}
