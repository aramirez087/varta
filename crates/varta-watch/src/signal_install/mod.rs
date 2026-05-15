// SAFETY: unsafe_code is legitimately required for `rt_sigaction(2)` FFI and
// the per-architecture inline assembly. All unsafe sites carry per-block
// SAFETY comments and are guarded by compile-time layout assertions.
#![allow(unsafe_code)]

//! Signal-handler installation for `varta-watch`.
//!
//! The single public entry point is [`install`], which installs handlers for
//! `SIGINT` and `SIGTERM` that flip an atomic shutdown latch provided by the
//! caller.
//!
//! On Linux the default path (`mode = Direct`) issues `rt_sigaction(2)`
//! directly through inline assembly, bypassing the libc wrapper (which
//! unconditionally substitutes its own `__restore_rt`). A startup readback
//! asserts the kernel preserved every field, and a live SIGUSR1 smoke test
//! proves the trampoline round-trips correctly before the first real signal
//! arrives. An operator opt-in (`mode = Libc`) delegates to libc's
//! `sigaction(3)` for kernels not yet certified against the direct path.
//!
//! On macOS and FreeBSD libc's `sigaction(3)` is always used (no restorer
//! issue exists on those platforms). On other Unix targets the POSIX
//! `signal(2)` fallback is used.

/// Signal-handler mode selection (`Direct` vs `Libc`).
pub mod mode;

#[cfg(target_os = "linux")]
pub(crate) mod linux;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bsd;

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))
))]
mod sysv;

pub use mode::SignalHandlerMode;

use std::io;

/// Install `SIGINT` and `SIGTERM` handlers that call `handler(sig)`.
///
/// `mode` selects the installation path on Linux:
/// - `Direct` (default): direct `rt_sigaction(2)` syscall — owns the kernel
///   ABI end-to-end, including the x86_64 signal-return trampoline. A
///   readback + live-delivery smoke test run at startup.
/// - `Libc`: libc `sigaction(3)` wrapper — the restorer is libc's own
///   `__restore_rt`. Use when running on a kernel not yet certified for the
///   direct path.
///
/// On macOS, FreeBSD, and other Unix, `mode` is ignored; libc / POSIX APIs
/// are the only option.
///
/// # Safety
///
/// Must be called exactly once, before any other threads are spawned and
/// before any competing code installs handlers for `SIGINT` or `SIGTERM`.
/// `handler` must be async-signal-safe; storing to an `AtomicI32` that is
/// `is_always_lock_free()` qualifies — richer operations (allocation, locking,
/// non-reentrant libc) do not.
#[allow(clippy::needless_return)] // cfg-gated returns prevent fall-through to dead branches
pub unsafe fn install(mode: SignalHandlerMode, handler: extern "C" fn(i32)) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    return unsafe { linux::install(mode, handler) };

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let _ = mode;
        return unsafe { bsd::install(handler) };
    }

    #[cfg(all(
        unix,
        not(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))
    ))]
    {
        let _ = mode;
        return unsafe { sysv::install(handler) };
    }

    #[cfg(not(unix))]
    {
        let _ = (mode, handler);
        Ok(())
    }
}
