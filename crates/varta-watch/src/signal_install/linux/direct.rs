/// Install SIGINT / SIGTERM handlers on Linux by invoking the
/// `rt_sigaction(2)` syscall **directly** — bypassing the libc wrapper.
///
/// The libc wrapper (glibc, musl, ...) unconditionally replaces the
/// caller's `sa_restorer` with its own. To genuinely own the kernel ABI
/// — and to make this code work even with no libc, a minimal libc, or
/// a `LD_PRELOAD` shim — we issue the syscall ourselves through
/// `rt_sigaction_raw`. On x86_64 the kernel needs `SA_RESTORER` set and
/// `sa_restorer` pointing at our `varta_signal_restorer` trampoline; on
/// aarch64 and riscv64 signal-return is handled by the vDSO and the kernel
/// struct has no `sa_restorer` field at all.
///
/// The readback round-trips the same kernel ABI and asserts that the kernel
/// preserved exactly what we sent — including (on x86_64) our trampoline
/// pointer, which is the proof that no libc override is in the path.
use std::io;

use super::kernel_abi::KernelSigAction;
use super::syscall::rt_sigaction_raw;
use super::{SA_RESTART, SA_RESTORER};

#[cfg(target_arch = "x86_64")]
use super::trampoline::varta_signal_restorer;

pub(super) unsafe fn install(handler: extern "C" fn(i32)) -> io::Result<()> {
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    // SAFETY: MaybeUninit::zeroed() gives a zeroed stack slot; no
    // `KernelSigAction` value is constructed until `assume_init()`. We fill
    // fields through a raw pointer first. sa_mask = 0 leaves no additional
    // signals blocked during the handler. The handler is async-signal-safe
    // (single atomic store).
    let mut act = std::mem::MaybeUninit::<KernelSigAction>::zeroed();
    // SAFETY: writes through `as_mut_ptr()` are valid for the zeroed slot.
    unsafe {
        (*act.as_mut_ptr()).sa_handler = handler as *const ();
        #[cfg(target_arch = "x86_64")]
        {
            (*act.as_mut_ptr()).sa_flags = SA_RESTART | SA_RESTORER;
            (*act.as_mut_ptr()).sa_restorer = varta_signal_restorer as *const ();
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            (*act.as_mut_ptr()).sa_flags = SA_RESTART;
        }
    }
    // SAFETY: every field has been written; KernelSigAction is `#[repr(C)]`
    // with POD fields, so the struct is now fully initialised.
    let act = unsafe { act.assume_init() };

    let install_one = |sig: i32| -> io::Result<()> {
        // SAFETY: `act` lives on the stack for the duration of the call;
        // passing a null `oact` is permitted.
        let rc = unsafe { rt_sigaction_raw(sig, &act, std::ptr::null_mut()) };
        if rc < 0 {
            return Err(io::Error::from_raw_os_error(-rc as i32));
        }

        // Readback: re-read the installed action and assert the kernel
        // preserved exactly what we sent. Runs in every build (debug +
        // release). If a future kernel silently changes rt_sigreturn /
        // SA_RESTORER semantics, this field comparison disagrees and we
        // surface a typed io::Error at startup instead of crashing at
        // SIGTERM. Cost: one extra syscall per signal install (two total
        // at startup).
        let mut old = std::mem::MaybeUninit::<KernelSigAction>::zeroed();
        // SAFETY: `oact` is a writable, correctly-sized stack slot.
        let rc2 = unsafe { rt_sigaction_raw(sig, std::ptr::null(), old.as_mut_ptr()) };
        if rc2 < 0 {
            return Err(io::Error::from_raw_os_error(-rc2 as i32));
        }
        // SAFETY: a successful readback fully initialises the slot.
        let old = unsafe { old.assume_init() };

        if old.sa_handler != handler as *const () {
            return Err(io::Error::other(
                "rt_sigaction readback: kernel reports a different sa_handler than we installed",
            ));
        }
        if old.sa_flags & SA_RESTART == 0 {
            return Err(io::Error::other(
                "rt_sigaction readback: kernel did not preserve SA_RESTART",
            ));
        }
        #[cfg(target_arch = "x86_64")]
        {
            if old.sa_flags & SA_RESTORER == 0 {
                return Err(io::Error::other(
                    "rt_sigaction readback: SA_RESTORER not set in installed action \
                     (libc wrapper hijacked the syscall?)",
                ));
            }
            // `varta_signal_restorer` is a function item; the cast to
            // `*const ()` is a safe operation (taking the address of a
            // function does not require `unsafe`; only *calling* an
            // `unsafe extern "C"` function does).
            if old.sa_restorer != varta_signal_restorer as *const () {
                return Err(io::Error::other(
                    "rt_sigaction readback: kernel did not install our trampoline \
                     (libc override, or kernel rt_sigreturn ABI changed?)",
                ));
            }
        }
        Ok(())
    };

    install_one(SIGINT)?;
    install_one(SIGTERM)?;
    Ok(())
}

/// Install a single signal via the direct `rt_sigaction_raw` path.
/// Used by `verify_live_delivery` to install the transient SIGUSR1 smoke handler.
pub(super) unsafe fn install_one_direct(
    sig: i32,
    handler: extern "C" fn(i32),
    old_out: *mut KernelSigAction,
) -> io::Result<()> {
    let mut act = std::mem::MaybeUninit::<KernelSigAction>::zeroed();
    unsafe {
        (*act.as_mut_ptr()).sa_handler = handler as *const ();
        #[cfg(target_arch = "x86_64")]
        {
            (*act.as_mut_ptr()).sa_flags = SA_RESTART | SA_RESTORER;
            (*act.as_mut_ptr()).sa_restorer = varta_signal_restorer as *const ();
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            (*act.as_mut_ptr()).sa_flags = SA_RESTART;
        }
    }
    let act = unsafe { act.assume_init() };
    let rc = unsafe { rt_sigaction_raw(sig, &act, old_out) };
    if rc < 0 {
        return Err(io::Error::from_raw_os_error(-rc as i32));
    }
    Ok(())
}
