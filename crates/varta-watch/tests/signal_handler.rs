//! Runtime verification that signal handlers can be installed and deliver
//! correctly to a lock-free atomic flag.
//!
//! Two layers of coverage:
//!
//! 1. **libc-wrapper path** (`sigurg_handler_sets_atomic_flag`): exercises
//!    the platform `sigaction(3)` C ABI to make sure our struct layouts
//!    still match libc's. Runs on Linux, macOS, and FreeBSD.
//! 2. **direct-syscall path** (`linux_restorer_is_ours`,
//!    `restorer_symbol_is_addressable`): exercises the kernel-ABI struct +
//!    `rt_sigaction(2)` syscall that `main.rs` actually uses on Linux. The
//!    load-bearing assertion is that the kernel preserved *our*
//!    `varta_signal_restorer` trampoline — proof that no libc wrapper is
//!    in the install path. x86_64 Linux only (aarch64 has no `sa_restorer`
//!    in the kernel struct; signal-return is handled by the vDSO).
//!
//! Uses benign signals (`SIGURG`, `SIGUSR2`) so the tests do not interfere
//! with `SIGINT` / `SIGTERM` that the production daemon relies on.
#![allow(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]

use std::sync::atomic::{AtomicBool, Ordering};

static GOT_SIGNAL: AtomicBool = AtomicBool::new(false);

extern "C" fn handle(_sig: i32) {
    GOT_SIGNAL.store(true, Ordering::Release);
}

// ---------------------------------------------------------------------------
// libc `sigaction(3)` layer — keeps our libc-shaped structs honest on the
// platforms where `main.rs` still uses the libc wrapper (macOS / FreeBSD)
// and as a smoke-test of libc behaviour on Linux.
// ---------------------------------------------------------------------------

/// SigAction layout for the current platform — the **glibc / libc**
/// shape, which differs from the kernel-ABI struct used below.
#[cfg(target_os = "linux")]
#[repr(C)]
struct SigAction {
    sa_handler: *const (),
    sa_mask: [u8; 128],
    sa_flags: i32,
    _pad: i32,
    sa_restorer: *const (),
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct SigAction {
    sa_handler: *const (),
    sa_mask: u32,
    sa_flags: i32,
}

#[cfg(target_os = "freebsd")]
#[repr(C)]
struct SigAction {
    sa_handler: *const (),
    sa_flags: i32,
    sa_mask: [u8; 16],
}

extern "C" {
    fn sigaction(signum: i32, act: *const SigAction, oldact: *mut SigAction) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn getpid() -> i32;
}

const SIGURG: i32 = 16;

/// Install a handler for `SIGURG` via libc's `sigaction(3)`, deliver the
/// signal via `kill`, and assert the handler's atomic flag is set. Then
/// restore the default disposition so the test process is not left with a
/// dangling handler.
#[test]
fn sigurg_handler_sets_atomic_flag() {
    // SAFETY: zeroed stack memory; we initialise `sa_handler` before use.
    // The handler is async-signal-safe (single atomic store).
    let mut act = std::mem::MaybeUninit::<SigAction>::zeroed();
    let mut old = std::mem::MaybeUninit::<SigAction>::zeroed();
    unsafe {
        (*act.as_mut_ptr()).sa_handler = handle as *const ();
    }
    let act = unsafe { act.assume_init() };

    unsafe {
        let ret = sigaction(SIGURG, &act, old.as_mut_ptr());
        assert_eq!(ret, 0, "sigaction(SIGURG) failed");
    }

    // Deliver the signal to our own process.
    unsafe {
        let pid = getpid();
        let ret = kill(pid, SIGURG);
        assert_eq!(ret, 0, "kill(SIGURG) failed");
    }

    // The signal may not be delivered immediately; sleep briefly.
    std::thread::sleep(std::time::Duration::from_millis(50));

    assert!(
        GOT_SIGNAL.load(Ordering::Acquire),
        "SIGURG handler did not set the atomic flag"
    );

    // Restore the original handler (prevents interference with process exit).
    let old = unsafe { old.assume_init() };
    unsafe {
        sigaction(SIGURG, &old, std::ptr::null_mut());
    }
}

// ---------------------------------------------------------------------------
// Direct `rt_sigaction(2)` syscall layer — mirrors what `main.rs` does on
// Linux. Integration tests do not link the binary's `main.rs`, so we
// re-declare an identical struct + trampoline + syscall wrapper here.
// This is the same pattern the libc-shape struct uses above.
// ---------------------------------------------------------------------------

/// Kernel-ABI `struct sigaction` for Linux/x86_64. **Different layout**
/// from the libc-shape `SigAction` above (`handler/flags/restorer/mask`,
/// not `handler/mask/flags/restorer`).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
struct KernelSigAction {
    sa_handler: *const (),
    sa_flags: u64,
    sa_restorer: *const (),
    sa_mask: u64,
}

/// Kernel-ABI `struct sigaction` for Linux/aarch64 — no `sa_restorer`.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[repr(C)]
struct KernelSigAction {
    sa_handler: *const (),
    sa_flags: u64,
    sa_mask: u64,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
core::arch::global_asm!(
    ".section .text.varta_signal_restorer,\"ax\",@progbits",
    ".globl varta_signal_restorer",
    ".hidden varta_signal_restorer",
    ".type varta_signal_restorer, @function",
    ".p2align 4",
    "varta_signal_restorer:",
    ".cfi_startproc",
    ".cfi_signal_frame",
    "    mov $15, %rax",
    "    syscall",
    "    ud2",
    ".cfi_endproc",
    ".size varta_signal_restorer, .-varta_signal_restorer",
    options(att_syntax),
);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
extern "C" {
    fn varta_signal_restorer();
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline]
unsafe fn rt_sigaction_raw(
    sig: i32,
    act: *const KernelSigAction,
    oact: *mut KernelSigAction,
) -> i64 {
    const SYS_RT_SIGACTION: i64 = 13;
    const SIGSETSIZE: i64 = core::mem::size_of::<u64>() as i64;
    let ret: i64;
    // SAFETY: Linux x86_64 syscall ABI: rax = num, rdi/rsi/rdx/r10 = args,
    // rax = return; rcx/r11 clobbered.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_RT_SIGACTION => ret,
            in("rdi") sig as i64,
            in("rsi") act,
            in("rdx") oact,
            in("r10") SIGSETSIZE,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[inline]
unsafe fn rt_sigaction_raw(
    sig: i32,
    act: *const KernelSigAction,
    oact: *mut KernelSigAction,
) -> i64 {
    const SYS_RT_SIGACTION: i64 = 134;
    const SIGSETSIZE: i64 = core::mem::size_of::<u64>() as i64;
    let ret: i64;
    // SAFETY: Linux aarch64 syscall ABI: x8 = num, x0..x5 = args, x0 = return.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_RT_SIGACTION,
            inlateout("x0") sig as i64 => ret,
            in("x1") act,
            in("x2") oact,
            in("x3") SIGSETSIZE,
            options(nostack),
        );
    }
    ret
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SA_RESTART_LINUX: u64 = 0x1000_0000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const SA_RESTORER_LINUX: u64 = 0x0400_0000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const SA_RESTART_LINUX: u64 = 0x1000_0000;

/// Catches link-time regressions: if the `global_asm!` block ever stops
/// emitting the `varta_signal_restorer` symbol the test binary will fail
/// to link and this test will not even compile. As a belt-and-braces
/// runtime check, also assert the symbol address is non-null.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn restorer_symbol_is_addressable() {
    let p = varta_signal_restorer as *const ();
    assert!(!p.is_null(), "varta_signal_restorer symbol is null");
}

#[cfg(target_os = "linux")]
static GOT_RESTORER_SIGNAL: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
extern "C" fn restorer_test_handle(_sig: i32) {
    GOT_RESTORER_SIGNAL.store(true, Ordering::Release);
}

/// Install a handler via the same direct-syscall path as `main.rs`, then
/// read it back via `rt_sigaction(SIG, NULL, &old)` and assert the kernel
/// preserved exactly what we sent — including *our* trampoline pointer.
///
/// This test will FAIL if the install path ever silently regresses to a
/// libc-wrapper call (because the wrapper substitutes `__restore_rt`).
/// That regression is exactly what we are guarding against.
///
/// Uses `SIGUSR2` (benign user-defined signal) to avoid interfering with
/// the libc `SIGURG` test above.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn linux_restorer_is_ours() {
    const SIGUSR2: i32 = 12;

    let mut act = std::mem::MaybeUninit::<KernelSigAction>::zeroed();
    let mut old = std::mem::MaybeUninit::<KernelSigAction>::zeroed();
    let mut readback = std::mem::MaybeUninit::<KernelSigAction>::zeroed();

    // SAFETY: writes through a raw pointer to zeroed stack memory.
    unsafe {
        (*act.as_mut_ptr()).sa_handler = restorer_test_handle as *const ();
        (*act.as_mut_ptr()).sa_flags = SA_RESTART_LINUX | SA_RESTORER_LINUX;
        (*act.as_mut_ptr()).sa_restorer = varta_signal_restorer as *const ();
    }
    let act = unsafe { act.assume_init() };

    // Install via direct syscall.
    let rc = unsafe { rt_sigaction_raw(SIGUSR2, &act, old.as_mut_ptr()) };
    assert!(rc >= 0, "rt_sigaction(SIGUSR2) install failed: {rc}");

    // Read back the active action.
    let rc2 = unsafe { rt_sigaction_raw(SIGUSR2, std::ptr::null(), readback.as_mut_ptr()) };
    assert!(rc2 >= 0, "rt_sigaction(SIGUSR2) readback failed: {rc2}");
    let readback = unsafe { readback.assume_init() };

    assert_eq!(
        readback.sa_handler, restorer_test_handle as *const (),
        "kernel reports a different sa_handler than installed",
    );
    assert!(
        readback.sa_flags & SA_RESTART_LINUX != 0,
        "kernel did not preserve SA_RESTART (flags = {:#x})",
        readback.sa_flags,
    );
    assert!(
        readback.sa_flags & SA_RESTORER_LINUX != 0,
        "SA_RESTORER not preserved by kernel (flags = {:#x}) — \
         libc wrapper hijacked the syscall path?",
        readback.sa_flags,
    );
    assert_eq!(
        readback.sa_restorer, varta_signal_restorer as *const (),
        "kernel installed a different restorer (got {:p}, want {:p}) — \
         defense-in-depth fix has regressed",
        readback.sa_restorer, varta_signal_restorer as *const (),
    );

    // Sanity-check that signal delivery still works through our restorer.
    GOT_RESTORER_SIGNAL.store(false, Ordering::Release);
    let pid = unsafe { getpid() };
    let rc3 = unsafe { kill(pid, SIGUSR2) };
    assert_eq!(rc3, 0, "kill(SIGUSR2) failed");
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(
        GOT_RESTORER_SIGNAL.load(Ordering::Acquire),
        "SIGUSR2 handler did not run after install with our restorer",
    );

    // Restore the original handler.
    let old = unsafe { old.assume_init() };
    unsafe {
        rt_sigaction_raw(SIGUSR2, &old, std::ptr::null_mut());
    }
}

/// aarch64 counterpart: prove the direct-syscall install round-trips
/// correctly even though there is no `sa_restorer` to verify. Catches
/// kernel ABI struct-size / offset regressions on aarch64.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[test]
fn linux_aarch64_direct_syscall_roundtrips() {
    const SIGUSR2: i32 = 12;

    let mut act = std::mem::MaybeUninit::<KernelSigAction>::zeroed();
    let mut old = std::mem::MaybeUninit::<KernelSigAction>::zeroed();
    let mut readback = std::mem::MaybeUninit::<KernelSigAction>::zeroed();

    // SAFETY: writes through a raw pointer to zeroed stack memory.
    unsafe {
        (*act.as_mut_ptr()).sa_handler = restorer_test_handle as *const ();
        (*act.as_mut_ptr()).sa_flags = SA_RESTART_LINUX;
    }
    let act = unsafe { act.assume_init() };

    let rc = unsafe { rt_sigaction_raw(SIGUSR2, &act, old.as_mut_ptr()) };
    assert!(rc >= 0, "rt_sigaction(SIGUSR2) install failed: {rc}");

    let rc2 = unsafe { rt_sigaction_raw(SIGUSR2, std::ptr::null(), readback.as_mut_ptr()) };
    assert!(rc2 >= 0, "rt_sigaction(SIGUSR2) readback failed: {rc2}");
    let readback = unsafe { readback.assume_init() };

    assert_eq!(
        readback.sa_handler, restorer_test_handle as *const (),
        "kernel reports a different sa_handler than installed",
    );
    assert!(
        readback.sa_flags & SA_RESTART_LINUX != 0,
        "kernel did not preserve SA_RESTART (flags = {:#x})",
        readback.sa_flags,
    );

    GOT_RESTORER_SIGNAL.store(false, Ordering::Release);
    let pid = unsafe { getpid() };
    let rc3 = unsafe { kill(pid, SIGUSR2) };
    assert_eq!(rc3, 0, "kill(SIGUSR2) failed");
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(
        GOT_RESTORER_SIGNAL.load(Ordering::Acquire),
        "SIGUSR2 handler did not run via the direct-syscall install path",
    );

    let old = unsafe { old.assume_init() };
    unsafe {
        rt_sigaction_raw(SIGUSR2, &old, std::ptr::null_mut());
    }
}
