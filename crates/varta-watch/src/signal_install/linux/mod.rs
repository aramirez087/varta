// When `libc-signal-mode` is active, the direct-syscall path is excised from
// compilation entirely (no KernelSigAction, no inline-asm trampoline, no
// rt_sigaction_raw wrapper). The libc wrapper is always compiled and is the
// only signal-install path in that build.
//
// Refuse to compile on Linux architectures we have not pinned the direct-
// syscall ABI for — but ONLY when the direct path is included (feature off).
// The libc `sigaction(3)` wrapper works on any Linux architecture.
#[cfg(all(
    not(feature = "libc-signal-mode"),
    not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ))
))]
compile_error!(
    "varta-watch on Linux currently supports x86_64, aarch64, and riscv64 only — \
     add KernelSigAction + rt_sigaction_raw arms for this architecture \
     (see book/src/architecture/signal-install.md for the extension recipe). \
     Alternatively, enable the `libc-signal-mode` Cargo feature to skip the \
     direct-syscall path entirely."
);

#[cfg(not(feature = "libc-signal-mode"))]
pub(super) mod direct;
#[cfg(not(feature = "libc-signal-mode"))]
pub(super) mod kernel_abi;
pub(super) mod libc_wrapper;
#[cfg(not(feature = "libc-signal-mode"))]
pub(super) mod syscall;
#[cfg(not(feature = "libc-signal-mode"))]
pub(super) mod trampoline;

use std::io;

use super::mode::SignalHandlerMode;
#[cfg(not(feature = "libc-signal-mode"))]
use kernel_abi::KernelSigAction;
#[cfg(not(feature = "libc-signal-mode"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(feature = "libc-signal-mode"))]
use syscall::rt_sigaction_raw;

/// `SA_RESTART`: restart syscalls interrupted by this signal (no `EINTR`).
/// Verified against `<asm-generic/signal-defs.h>`.
#[cfg(not(feature = "libc-signal-mode"))]
pub const SA_RESTART: u64 = 0x1000_0000;

/// `SA_RESTORER`: kernel uses `sa_restorer` as the signal-return trampoline.
/// x86_64 requires this; on aarch64 / riscv64 the field is absent from the
/// kernel struct, so we do not set this flag.
#[cfg(all(not(feature = "libc-signal-mode"), target_arch = "x86_64"))]
pub const SA_RESTORER: u64 = 0x0400_0000;
/// `SA_RESTORER`: not applicable on non-x86_64 architectures.
#[cfg(all(not(feature = "libc-signal-mode"), not(target_arch = "x86_64")))]
pub const SA_RESTORER: u64 = 0;

/// Install SIGINT / SIGTERM handlers on Linux.
///
/// `mode = Direct`: direct `rt_sigaction(2)` syscall with full kernel-ABI
/// ownership. A startup readback verifies the kernel preserved every field we
/// sent, followed by a live SIGUSR1 smoke test that proves signal delivery
/// and trampoline return actually work. Not available when `libc-signal-mode`
/// feature is enabled — the whole direct path is excised at compile time.
///
/// `mode = Libc`: libc `sigaction(3)` wrapper. The restorer is libc's own
/// `__restore_rt`; we accept that trade-off. No smoke test is run — libc's
/// trampoline is always correct, and the `sigaction(3)` call's return code
/// is the definitive check.
///
/// # Safety
/// Must be called only once, before any other threads are spawned, with no
/// concurrent installs of SIGINT / SIGTERM.
pub(super) unsafe fn install(
    mode: SignalHandlerMode,
    handler: extern "C" fn(i32),
) -> io::Result<()> {
    #[cfg(not(feature = "libc-signal-mode"))]
    match mode {
        SignalHandlerMode::Direct => {
            unsafe { direct::install(handler) }?;
            unsafe { verify_live_delivery() }?;
        }
        SignalHandlerMode::Libc => {
            unsafe { libc_wrapper::install(handler) }?;
        }
    }
    #[cfg(feature = "libc-signal-mode")]
    {
        let _ = mode; // always Libc when feature is on; rejected at argv if "direct" passed
        unsafe { libc_wrapper::install(handler) }?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Live-delivery smoke test (direct path only)
// ---------------------------------------------------------------------------
//
// After installing the SIGINT / SIGTERM handlers via the Direct path, we
// install a transient SIGUSR1 handler (also via the direct path), deliver
// SIGUSR1 to ourselves, verify the handler ran, then restore the previous
// SIGUSR1 disposition.
//
// This test proves:
//   1. The kernel can deliver a signal to this process.
//   2. The signal handler returns correctly through our trampoline — if the
//      trampoline is broken the process would SIGSEGV here rather than at the
//      first real SIGTERM hours later in production.
//
// Cost: one extra `rt_sigaction` + `kill` + 50 ms poll at startup.
// Only runs in Direct mode (libc's __restore_rt is always trustworthy).
// Excised entirely when `libc-signal-mode` feature is enabled.

#[cfg(not(feature = "libc-signal-mode"))]
static SMOKE_TEST_FIRED: AtomicBool = AtomicBool::new(false);

#[cfg(not(feature = "libc-signal-mode"))]
extern "C" fn smoke_handler(_: i32) {
    SMOKE_TEST_FIRED.store(true, Ordering::Release);
}

/// SIGUSR1 signal number on Linux (all architectures we support).
#[cfg(not(feature = "libc-signal-mode"))]
const SIGUSR1: i32 = 10;

#[cfg(not(feature = "libc-signal-mode"))]
extern "C" {
    fn getpid() -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}

#[cfg(not(feature = "libc-signal-mode"))]
unsafe fn verify_live_delivery() -> io::Result<()> {
    SMOKE_TEST_FIRED.store(false, Ordering::SeqCst);

    let mut old = std::mem::MaybeUninit::<KernelSigAction>::zeroed();

    // Install transient SIGUSR1 handler via the same direct-syscall path,
    // saving the previous disposition into `old`.
    // SAFETY: zeroed MaybeUninit; old_out is a valid mutable pointer.
    unsafe { direct::install_one_direct(SIGUSR1, smoke_handler, old.as_mut_ptr()) }?;

    // Deliver SIGUSR1 to this process. On Linux, kill(getpid(), sig) marks
    // the signal pending; it is delivered at the next return from kernel mode
    // (e.g. at the start of the sleep below).
    // SAFETY: getpid() and kill() are async-signal-safe POSIX syscalls.
    let pid = unsafe { getpid() };
    unsafe { kill(pid, SIGUSR1) };

    // Wait up to 50 ms for delivery. The signal is delivered in the kernel
    // transition below; the first sleep return almost certainly fires it.
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
    loop {
        if SMOKE_TEST_FIRED.load(Ordering::Acquire) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            // Restore before returning error so SIGUSR1 disposition is clean.
            // SAFETY: old.as_mut_ptr() was fully initialised by install_one_direct.
            let old_init = unsafe { old.assume_init() };
            unsafe { rt_sigaction_raw(SIGUSR1, &old_init, std::ptr::null_mut()) };
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "signal smoke test: SIGUSR1 not delivered within 50 ms — \
                 trampoline ABI broken or kernel signal delivery disabled?",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    // Restore previous SIGUSR1 disposition.
    // SAFETY: old was fully initialised by the install_one_direct call above.
    let old_init = unsafe { old.assume_init() };
    let rc = unsafe { rt_sigaction_raw(SIGUSR1, &old_init, std::ptr::null_mut()) };
    if rc < 0 {
        return Err(io::Error::from_raw_os_error(-rc as i32));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Test re-export gate
// ---------------------------------------------------------------------------
//
// Integration tests in `crates/varta-watch/tests/signal_handler.rs` need
// access to the kernel-ABI structs and the syscall wrapper to test them
// independently. Exposing them under `__test_signal_abi` (cf.
// `__fuzz_internals` in lib.rs) lets the tests consume the *real*
// definitions rather than maintaining parallel duplicates.
//
// Excised when `libc-signal-mode` is active — the kernel-ABI types and the
// direct-syscall wrapper do not exist in that build.

#[cfg(all(any(test, feature = "test-hooks"), not(feature = "libc-signal-mode")))]
pub(crate) mod test_abi {
    pub use super::kernel_abi::KernelSigAction;
    pub use super::syscall::rt_sigaction_raw;
    #[cfg(target_arch = "x86_64")]
    pub use super::trampoline::varta_signal_restorer;
    pub use super::{SA_RESTART, SA_RESTORER};
}
