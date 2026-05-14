/// Install SIGINT / SIGTERM handlers on Linux via libc's `sigaction(3)`.
///
/// This is the opt-in fallback for operators running on a kernel that the
/// `direct` path has not been certified against. libc unconditionally
/// substitutes its own `__restore_rt` restorer — we accept that trade-off
/// here. No readback is performed because any readback would report libc's
/// restorer, not ours, and that is expected rather than informative.
use std::io;

// glibc / musl layout for `struct sigaction` on Linux. This is the
// **userspace** (libc) shape, not the kernel ABI struct in kernel_abi.rs.
//
//   field        offset  type           note
//   sa_handler        0  void (*)(int)
//   sa_mask           8  char[128]      sigset_t on glibc/musl is 128 bytes
//   sa_flags        136  int
//   _pad            140  int            natural alignment filler
//   sa_restorer     144  void (*)(void) libc fills this; we leave it null
//   total size      152
//
// Verified against glibc `<bits/sigaction.h>` (x86_64) and musl
// `<bits/alltypes.h>` + `struct sigaction` in `<signal.h>`.
#[repr(C)]
struct SigActionLibc {
    sa_handler: *const (),
    sa_mask: [u8; 128],
    sa_flags: i32,
    _pad: i32,
    sa_restorer: *const (),
}

const _: () = assert!(core::mem::size_of::<SigActionLibc>() == 152);
const _: () = assert!(core::mem::offset_of!(SigActionLibc, sa_handler) == 0);
const _: () = assert!(core::mem::offset_of!(SigActionLibc, sa_mask) == 8);
const _: () = assert!(core::mem::offset_of!(SigActionLibc, sa_flags) == 136);
const _: () = assert!(core::mem::offset_of!(SigActionLibc, sa_restorer) == 144);

extern "C" {
    fn sigaction(signum: i32, act: *const SigActionLibc, oldact: *mut SigActionLibc) -> i32;
}

/// `SA_RESTART` as i32 for the libc-wrapper struct where `sa_flags` is `int`.
/// Value `0x1000_0000` from `<asm-generic/signal-defs.h>` — same semantic as
/// the u64 constant in `linux/mod.rs`.
const SA_RESTART_LIBC: i32 = 0x1000_0000u32 as i32;

pub(super) unsafe fn install(handler: extern "C" fn(i32)) -> io::Result<()> {
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    // SAFETY: zeroed MaybeUninit; we write sa_handler and sa_flags before use.
    // sa_mask is zeroed (no additional signals blocked during the handler).
    // sa_restorer is zeroed (null) — libc will fill it in before calling
    // `rt_sigaction(2)`.
    let mut act = std::mem::MaybeUninit::<SigActionLibc>::zeroed();
    unsafe {
        (*act.as_mut_ptr()).sa_handler = handler as *const ();
        (*act.as_mut_ptr()).sa_flags = SA_RESTART_LIBC;
    }
    let act = unsafe { act.assume_init() };

    for sig in [SIGINT, SIGTERM] {
        // SAFETY: `act` is valid and initialised; null `oldact` is permitted.
        let rc = unsafe { sigaction(sig, &act, std::ptr::null_mut()) };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
