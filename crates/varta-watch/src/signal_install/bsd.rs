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

#[cfg(target_os = "macos")]
const SA_RESTART: i32 = 0x0002;
#[cfg(target_os = "freebsd")]
const SA_RESTART: i32 = 0x0040;

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
        (*act.as_mut_ptr()).sa_flags = SA_RESTART;
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
