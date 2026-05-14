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
/// Implemented twice in this workspace: once for Linux (`SCM_CREDENTIALS` /
/// `struct ucred` / `cmsg_len: usize`) and once for the BSD family
/// (`SCM_CREDS` / `struct cmsgcred` / `cmsg_len: u32`).
///
/// # Safety
///
/// Implementors must guarantee:
///
/// - `Hdr` is `#[repr(C)]` and matches the kernel's `struct cmsghdr` layout
///   on the implementing platform. Verified by compile-time `offset_of!`
///   assertions in `super::plat`.
/// - `Cred` is `#[repr(C)]` and matches the kernel's credential payload
///   (`struct ucred` on Linux, `struct cmsgcred` on the BSDs).
/// - `Msghdr` is `#[repr(C)]` and matches the kernel's `struct msghdr` layout.
/// - `cmsg_len`, `cmsg_level`, `cmsg_type` read the kernel-reported integers
///   faithfully — `cmsg_len` widened to `usize` if narrower on the platform.
/// - `msg_control` returns the `msg_control` pointer cast to `*const u8`
///   (may be null when no ancillary data was passed).
/// - `msg_controllen` returns the kernel-reported byte count widened to
///   `usize`.
/// - `TARGET_LEVEL` / `TARGET_TYPE` are the `(level, type)` pair the kernel
///   uses for credential ancillary data on this platform.
/// - `extract_pid_uid` reads only fields whose layout was offset-asserted at
///   compile time and returns `(pid, effective_uid)`.
pub(super) unsafe trait CmsgPlatform {
    /// Platform's `struct cmsghdr`.
    type Hdr;
    /// Platform's credential payload struct.
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
    fn extract_pid_uid(cred: &Self::Cred) -> (u32, u32);

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
    type Item = &'a P::Hdr;

    fn next(&mut self) -> Option<&'a P::Hdr> {
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
        //   an alignment of at most `usize` (asserted by `offset_of!` macros
        //   in `super::plat`).
        // - The pointed-to bytes are initialised cmsghdr bytes per `recvmsg(2)`
        //   semantics (or equivalent fuzz/test fabrication).
        let hdr_ptr = unsafe { self.base.add(self.cursor) } as *const P::Hdr;
        let hdr: &P::Hdr = unsafe { &*hdr_ptr };
        let len = P::cmsg_len(hdr);
        // Validate the cmsg payload fits in the remaining buffer.
        if len > self.controllen - self.cursor {
            return None;
        }
        // Advance the cursor for the next iteration. Clamp the advance to
        // at least `cmsg_hdr_size` so an adversarial `cmsg_len == 0` (or
        // anything smaller than the header itself) cannot stall the walk in
        // an infinite loop. `saturating_add` prevents `usize` overflow from
        // wrapping into a small value that could look in-bounds.
        let advance = core::cmp::max(cmsg_align(len), P::cmsg_hdr_size());
        self.cursor = self.cursor.saturating_add(advance);
        Some(hdr)
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
/// has `cmsg_len` smaller than `cmsg_hdr_size + sizeof::<P::Cred>()`, or
/// if the buffer is empty / malformed.
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
    for hdr in iter {
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
        //   controllen`, so the `Cred` lies fully inside the readable region.
        // - `P::Cred` is `#[repr(C)]` and its field layout is offset-asserted
        //   at compile time in `super::plat` (the `CmsgPlatform`
        //   implementation's safety contract).
        let data_ptr = unsafe { (hdr as *const P::Hdr as *const u8).add(P::cmsg_hdr_size()) };
        let cred: &P::Cred = unsafe { &*(data_ptr as *const P::Cred) };
        return Some(P::extract_pid_uid(cred));
    }
    None
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
        assert_eq!(result, None);
    }

    #[test]
    fn single_scm_credentials_returns_pid_uid() {
        let mut buf = [0u8; 256];
        write_scm_credentials(&mut buf, 0, 1234, 1000, 100);
        let controllen = cmsg_space_ucred();
        let mhdr = make_mhdr(&buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert_eq!(result, Some((1234, 1000)));
    }

    #[test]
    fn truncated_cmsg_length_returns_none() {
        // Write a cmsg whose cmsg_len is smaller than hdr+ucred.
        let mut buf = [0u8; 256];
        let hdr_size = cmsg_hdr_size();
        // cmsg_len = hdr_size only (no room for ucred).
        let truncated_len: usize = hdr_size;
        buf[..mem::size_of::<usize>()].copy_from_slice(&truncated_len.to_ne_bytes());
        buf[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        buf[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&plat::SCM_CREDENTIALS.to_ne_bytes());
        let controllen = cmsg_space_ucred();
        let mhdr = make_mhdr(&buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert_eq!(result, None, "truncated cmsg must not produce a pid");
    }

    #[test]
    fn unknown_cmsg_type_returns_none() {
        let mut buf = [0u8; 256];
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
        let mhdr = make_mhdr(&buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert_eq!(result, None, "unknown cmsg_type must not produce a pid");
    }

    #[test]
    fn multiple_cmsgs_finds_credentials_in_second() {
        // First cmsg: unknown type, second cmsg: SCM_CREDENTIALS.
        let space = cmsg_space_ucred();
        let mut buf = [0u8; 512];

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
        write_scm_credentials(&mut buf, space, 5678, 2000, 200);

        let controllen = space * 2;
        let mhdr = make_mhdr(&buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert_eq!(result, Some((5678, 2000)));
    }

    #[test]
    fn trailing_padding_does_not_confuse_walker() {
        // A single SCM_CREDENTIALS cmsg followed by extra zero bytes.
        let mut buf = [0u8; 256];
        write_scm_credentials(&mut buf, 0, 999, 42, 42);
        // Report controllen as the full buffer — walker must stop at the
        // cmsg whose cmsg_len does not leave room for another header.
        let controllen = 128;
        let mhdr = make_mhdr(&buf, controllen);
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert_eq!(result, Some((999, 42)));
    }

    /// Defense-in-depth: an attacker-supplied cmsg_len of 0 must not loop
    /// forever. The walker advances by at least `cmsg_hdr_size` per step.
    #[test]
    fn zero_cmsg_len_does_not_infinite_loop() {
        let mut buf = [0u8; 256];
        // Write a cmsg with cmsg_len == 0 but otherwise valid header bytes.
        let zero_len: usize = 0;
        buf[..mem::size_of::<usize>()].copy_from_slice(&zero_len.to_ne_bytes());
        buf[mem::size_of::<usize>()..mem::size_of::<usize>() + 4]
            .copy_from_slice(&plat::SOL_SOCKET.to_ne_bytes());
        buf[mem::size_of::<usize>() + 4..mem::size_of::<usize>() + 8]
            .copy_from_slice(&plat::SCM_CREDENTIALS.to_ne_bytes());
        let mhdr = make_mhdr(&buf, buf.len());
        // Must return None — cmsg_len < needed; must terminate (test would
        // hang otherwise).
        let result = plat::peer_pid_after_recv(0, &mhdr);
        assert_eq!(result, None);
    }
}
