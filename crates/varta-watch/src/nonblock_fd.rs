//! Best-effort `O_NONBLOCK` setter for recovery child stdio pipes.
//!
//! Recovery captures the stdout/stderr of every spawned child so the
//! observer can attach the head of the output to the audit log. The drain
//! loop reads those pipes non-blockingly across many poll ticks; this
//! module is the single site in `varta-watch` that flips the captured fd
//! to `O_NONBLOCK` via raw `fcntl(2)`.
//!
//! # Why hand-rolled
//!
//! `varta-watch` carries no registry dependencies in production builds
//! (CLAUDE.md Hard Constraint #1). The standard alternatives — pulling in
//! the `libc` crate or probing values from `build.rs` — both violate that
//! invariant. The values below are therefore declared inline, per
//! platform, with the original `<fcntl.h>` source cited.
//!
//! # Defence against typo-class regressions
//!
//! The four POSIX fcntl commands `F_GETFD=1`, `F_SETFD=2`, `F_GETFL=3`,
//! `F_SETFL=4` are trivially confusable; a single transposition would
//! compile and silently mis-flip child pipes. To rule this out
//! structurally, this module declares all four constants and guards them
//! with named compile-time inequality assertions. A maintainer who swaps
//! any two values fails to build with an error naming the violated
//! invariant.
//!
//! # Failure mode is graceful
//!
//! `set_nonblocking_fd` is documented as best-effort. If the fcntl call
//! ever fails (or a future platform deviates from the pinned values), the
//! caller's drain loop in [`crate::recovery`] catches `WouldBlock` and
//! falls back to a single bounded blocking `read`. A broken probe can
//! never block the observer poll loop.
//!
//! # Per-platform value sources
//!
//! `F_GETFL=3`, `F_SETFL=4`, `F_GETFD=1`, `F_SETFD=2` are uniform across
//! every supported Unix; the per-`target_os` cfg gates below make that
//! platform-support story explicit and require an opt-in for a future
//! target rather than silently inheriting a default.
//!
//! | Platform        | Header                                       |
//! |-----------------|----------------------------------------------|
//! | Linux           | `include/uapi/asm-generic/fcntl.h`           |
//! | FreeBSD         | `sys/sys/fcntl.h`                            |
//! | NetBSD / OpenBSD| `sys/sys/fcntl.h`                            |
//! | macOS / iOS     | `xnu/bsd/sys/fcntl.h`                        |
//! | DragonFly BSD   | `sys/sys/fcntl.h`                            |
//! | Solaris/illumos | `usr/src/uts/common/sys/fcntl.h`             |
//!
//! `O_NONBLOCK` does vary across platforms; per-OS values are pinned below.

// ---------------------------------------------------------------------------
// fcntl(2) command constants — POSIX names, per-OS pinned values.
// ---------------------------------------------------------------------------
//
// Even though every supported Unix sets the F_* command constants to the
// same values, we follow the per-`target_os` cfg pattern of the
// `O_NONBLOCK_FCNTL` cascade below (and of `signal_install::linux::kernel_abi`)
// so that a new target requires an explicit opt-in rather than silently
// inheriting an unverified default.

// F_GETFD / F_SETFD are declared only to feed the compile-time inequality
// guards below — production code never references them. The structural
// guard catches a maintainer who swaps `F_SETFL = 4` with `F_SETFD = 2`.
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos",
))]
#[allow(dead_code)]
const F_GETFD: i32 = 1;

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos",
))]
#[allow(dead_code)]
const F_SETFD: i32 = 2;

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos",
))]
const F_GETFL: i32 = 3;

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos",
))]
const F_SETFL: i32 = 4;

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos",
)))]
compile_error!(
    "fcntl F_GETFD/F_SETFD/F_GETFL/F_SETFL values are unknown for this target \
     — add it to the cfg gates in nonblock_fd.rs after verifying against the \
     platform's <fcntl.h>"
);

// ---------------------------------------------------------------------------
// O_NONBLOCK — pinned per-platform from each <fcntl.h>.
// ---------------------------------------------------------------------------

// Linux O_NONBLOCK is architecture-specific (rust-libc per-arch tables): mips
// family = 0x80, sparc family = 0x4000, generic (x86/x86_64/arm/aarch64/riscv/
// powerpc/s390x/…) = 0x800. A flat 0x800 is WRONG on mips, where 0x800 is
// O_NOCTTY (an open-time flag F_SETFL silently ignores), so O_NONBLOCK is never
// set and recovery child stdio pipes stay BLOCKING — a drain read with no
// pending data then stalls the single-threaded observer poll loop.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
    )
))]
const O_NONBLOCK_FCNTL: i32 = 0x80;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "sparc", target_arch = "sparc64")
))]
const O_NONBLOCK_FCNTL: i32 = 0x4000;
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
const O_NONBLOCK_FCNTL: i32 = 0x800;

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
const O_NONBLOCK_FCNTL: i32 = 0x0004;

#[cfg(any(target_os = "solaris", target_os = "illumos"))]
const O_NONBLOCK_FCNTL: i32 = 0x80;

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "solaris",
    target_os = "illumos",
)))]
compile_error!(
    "O_NONBLOCK_FCNTL value is unknown for this target — add it to the cfg \
     gates in nonblock_fd.rs after verifying against the platform's <fcntl.h>"
);

// ---------------------------------------------------------------------------
// Compile-time typo-class guards — named so that a violation identifies
// the failing invariant directly in the build error.
// ---------------------------------------------------------------------------

const _F_GETFL_NEQ_F_SETFL: () = assert!(F_GETFL != F_SETFL);
const _F_GETFL_NEQ_F_SETFD: () = assert!(F_GETFL != F_SETFD);
const _F_GETFL_NEQ_F_GETFD: () = assert!(F_GETFL != F_GETFD);
const _F_SETFL_NEQ_F_SETFD: () = assert!(F_SETFL != F_SETFD);
const _F_SETFL_NEQ_F_GETFD: () = assert!(F_SETFL != F_GETFD);
const _F_GETFD_NEQ_F_SETFD: () = assert!(F_GETFD != F_SETFD);
const _O_NONBLOCK_NONZERO: () = assert!(O_NONBLOCK_FCNTL != 0);

// ---------------------------------------------------------------------------
// fcntl(2) FFI.
// ---------------------------------------------------------------------------
//
// Variadic signature is load-bearing: the `F_SETFL` call site passes a
// third `i32` argument (the new flag word). Dropping the `...` would be
// UB on that call. Keep this signature in lockstep with the call sites
// in `set_nonblocking_fd` below.

extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

/// Best-effort set `O_NONBLOCK` on a raw fd. Failure is logged-only — the
/// drain loop in [`crate::recovery`] checks `WouldBlock` and falls back
/// to a single bounded `read` if the flag could not be set, so a failing
/// fcntl never blocks the observer.
pub(crate) fn set_nonblocking_fd(fd: i32) -> bool {
    // SAFETY: F_GETFL / F_SETFL are standard fcntl commands. The fd is
    // owned by the ChildStdout / ChildStderr handle for the duration of
    // this call (the caller holds the handle by value across both
    // syscalls). The variadic extern matches the 2-arg F_GETFL form and
    // the 3-arg F_SETFL form.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 {
        return false;
    }
    let rc = unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK_FCNTL) };
    rc >= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" {
        fn pipe(fds: *mut [i32; 2]) -> i32;
        fn close(fd: i32) -> i32;
        fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    }

    /// Open a pipe via raw FFI for the test. Returns `(read_fd, write_fd)`.
    /// Caller closes both. Panics on error — this is a test scaffold.
    fn make_pipe() -> (i32, i32) {
        let mut fds: [i32; 2] = [-1, -1];
        // SAFETY: `fds` is a stack array of the correct shape; the call
        // either fills both slots or returns non-zero.
        let rc = unsafe { pipe(&mut fds as *mut [i32; 2]) };
        assert_eq!(rc, 0, "pipe(2) failed in test harness");
        (fds[0], fds[1])
    }

    fn close_fd(fd: i32) {
        // SAFETY: caller-owned fd; ignore the error from close on cleanup.
        unsafe {
            let _ = close(fd);
        }
    }

    #[test]
    fn set_nonblocking_fd_sets_o_nonblock_bit_on_pipe() {
        let (rfd, wfd) = make_pipe();

        // SAFETY: F_GETFL reads the file-status flags; no side effects.
        let initial = unsafe { fcntl(rfd, F_GETFL) };
        assert!(initial >= 0, "F_GETFL before set failed: {initial}");
        assert_eq!(
            initial & O_NONBLOCK_FCNTL,
            0,
            "pipe(2) read end should start in blocking mode"
        );

        assert!(set_nonblocking_fd(rfd), "set_nonblocking_fd returned false");

        // SAFETY: F_GETFL reads the file-status flags; no side effects.
        let after = unsafe { fcntl(rfd, F_GETFL) };
        assert!(after >= 0, "F_GETFL after set failed: {after}");
        assert_ne!(
            after & O_NONBLOCK_FCNTL,
            0,
            "O_NONBLOCK bit should be set after set_nonblocking_fd"
        );

        close_fd(rfd);
        close_fd(wfd);
    }

    #[test]
    fn pipe_read_after_set_nonblocking_returns_wouldblock() {
        let (rfd, wfd) = make_pipe();

        assert!(set_nonblocking_fd(rfd));

        // No data was written; a non-blocking read on an empty pipe must
        // return -1 with EAGAIN / EWOULDBLOCK rather than blocking.
        let mut buf = [0u8; 16];
        // SAFETY: rfd is a valid open fd; buf is a writable stack array.
        let n = unsafe { read(rfd, buf.as_mut_ptr(), buf.len()) };
        assert_eq!(n, -1, "non-blocking read of empty pipe should fail");
        let err = std::io::Error::last_os_error();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::WouldBlock,
            "expected WouldBlock, got {err:?}",
        );

        close_fd(rfd);
        close_fd(wfd);
    }
}
