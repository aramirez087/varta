/// Install SIGINT / SIGTERM handlers on macOS / FreeBSD by calling
/// libc's `sigaction(3)` wrapper. Neither platform has the `sa_restorer`
/// substitution issue that motivates the direct-syscall path on Linux, so
/// the libc wrapper is correct and idiomatic here.
use std::io;

// Per-platform sigaction struct: ABI-pinned with compile-time size assertions
// and test-time offset checks below.

#[cfg(target_os = "macos")]
#[repr(C)]
struct SigAction {
    sa_handler: *const (),
    /// sigset_t on macOS / XNU is `__uint32_t` (4 bytes).
    /// Defined in `<sys/_types/_sigset_t.h>`; verified against xnu sources
    /// (xnu-8792.81.2, xnu-11215.1.10).
    sa_mask: u32,
    sa_flags: i32,
}

#[cfg(target_os = "freebsd")]
#[repr(C)]
struct SigAction {
    sa_handler: *const (),
    sa_flags: i32,
    /// sigset_t on FreeBSD is `__uint32_t[4]` (16 bytes).
    /// Verified against `<sys/_sigset.h>` (FreeBSD 14.2).
    sa_mask: [u8; 16],
}

#[cfg(target_os = "macos")]
const _: () = assert!(core::mem::size_of::<SigAction>() == 16);
#[cfg(target_os = "freebsd")]
const _: () = assert!(core::mem::size_of::<SigAction>() == 32);

// `SA_RESTART` (0x0002) and `SA_SIGINFO` (0x0040) are identical across the
// 4.4BSD-derived `<sys/signal.h>` on macOS/XNU and FreeBSD — rust-libc defines
// them once for the whole BSD/Darwin family in `src/unix/bsd/mod.rs`. They are
// unconditional here on purpose: a per-`cfg` split is exactly what let the
// FreeBSD value drift to `0x0040` (= `SA_SIGINFO`) while macOS stayed at the
// correct `0x0002`.
//
// `SA_RESTART` makes interrupted syscalls auto-restart, upholding the
// `recvmsg(2)`-never-returns-`EINTR` invariant documented at `main.rs`.
// `SA_SIGINFO` selects the 3-argument `sa_sigaction` calling convention and
// MUST stay clear: `install` registers a 1-argument `extern "C" fn(i32)`.
const SA_RESTART: i32 = 0x0002;
const SA_SIGINFO: i32 = 0x0040;

/// Flags written to `sa_flags`: `SA_RESTART` only, `SA_SIGINFO` deliberately
/// absent (the handler takes one argument).
const SA_FLAGS: i32 = SA_RESTART;
// Regression guard: a 1-argument handler requires `SA_SIGINFO` to stay clear.
// The original bug set `SA_RESTART = 0x0040` (= `SA_SIGINFO`); this trips that
// at compile time on every target the module builds for.
const _: () = assert!(SA_FLAGS & SA_SIGINFO == 0);

extern "C" {
    fn sigaction(signum: i32, act: *const SigAction, oldact: *mut SigAction) -> i32;
}

pub(super) unsafe fn install(handler: extern "C" fn(i32)) -> io::Result<()> {
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    // SAFETY: zeroed MaybeUninit; we write sa_handler and sa_flags before use.
    let mut act = std::mem::MaybeUninit::<SigAction>::zeroed();
    unsafe {
        (*act.as_mut_ptr()).sa_handler = handler as *const ();
        (*act.as_mut_ptr()).sa_flags = SA_FLAGS;
    }
    let act = unsafe { act.assume_init() };

    for sig in [SIGINT, SIGTERM] {
        // SAFETY: `act` is initialised; null `oldact` is permitted.
        let rc = unsafe { sigaction(sig, &act, std::ptr::null_mut()) };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod layout_tests {
    use super::SigAction;

    #[test]
    fn sa_flags_request_restart_without_siginfo() {
        // Regression (bug-468): the FreeBSD `SA_RESTART` was mistyped as
        // `0x0040`, which is `SA_SIGINFO` — so SIGINT/SIGTERM were installed
        // WITHOUT auto-restart and WITH the 3-argument `sa_sigaction`
        // convention, while only a 1-argument `extern "C" fn(i32)` handler
        // exists. The flag values are identical across the BSD/Darwin family,
        // so this runs on the macOS CI host and guards both arms; reverting
        // `SA_RESTART` to `0x0040` turns it (and the compile-time guard) red.
        assert_eq!(super::SA_RESTART, 0x0002);
        assert_eq!(super::SA_SIGINFO, 0x0040);
        assert_eq!(super::SA_FLAGS & super::SA_SIGINFO, 0);
        assert_eq!(super::SA_FLAGS & super::SA_RESTART, super::SA_RESTART);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sigaction_offsets_match_xnu_layout() {
        assert_field_offset!(SigAction, sa_handler, 0);
        assert_field_offset!(SigAction, sa_mask, 8);
        assert_field_offset!(SigAction, sa_flags, 12);
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn sigaction_offsets_match_freebsd_layout() {
        assert_field_offset!(SigAction, sa_handler, 0);
        assert_field_offset!(SigAction, sa_flags, 8);
        assert_field_offset!(SigAction, sa_mask, 12);
    }
}
