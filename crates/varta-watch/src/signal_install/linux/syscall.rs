/// Direct `rt_sigaction(2)` syscall — bypasses any libc wrapper.
///
/// Returns the raw kernel return value: `0` on success, negative `-errno` on
/// failure.  Callers convert with `io::Error::from_raw_os_error(-ret as i32)`.
///
/// # Safety
/// Caller is responsible for the validity of `act` / `oact` pointers and for
/// ensuring no concurrent thread races on the same signal disposition.
use super::kernel_abi::KernelSigAction;

// ---------------------------------------------------------------------------
// x86_64
// ---------------------------------------------------------------------------
//
// Syscall ABI: number in `rax`; args in `rdi, rsi, rdx, r10`; result in
// `rax` (negative `-errno` on failure, `0` on success). `syscall` clobbers
// `rcx` (saved RIP) and `r11` (saved RFLAGS).
//
// `__NR_rt_sigaction` = 13 (x86_64 native syscall table).
// `sigsetsize` (4th arg) = 8 bytes — one `unsigned long` on 64-bit Linux.

/// Invoke the Linux `rt_sigaction(2)` syscall directly, bypassing any libc wrapper.
///
/// Returns `0` on success or a negative `-errno` value on failure.
///
/// # Safety
/// - `act` must be a valid pointer to an initialised [`KernelSigAction`], or null.
/// - `oact` must be a valid writable pointer to a [`KernelSigAction`]-sized slot, or null.
/// - No concurrent thread may race on the same signal disposition while this call executes.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn rt_sigaction_raw(
    sig: i32,
    act: *const KernelSigAction,
    oact: *mut KernelSigAction,
) -> i64 {
    const SYS_RT_SIGACTION: i64 = 13;
    const SIGSETSIZE: i64 = core::mem::size_of::<u64>() as i64; // 8
    let ret: i64;
    // SAFETY: see function-level comment.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_RT_SIGACTION => ret,
            in("rdi") sig as i64,
            in("rsi") act,
            in("rdx") oact,
            in("r10") SIGSETSIZE,
            lateout("rcx") _,   // clobbered: saved RIP
            lateout("r11") _,   // clobbered: saved RFLAGS
            options(nostack),
        );
    }
    ret
}

// ---------------------------------------------------------------------------
// aarch64
// ---------------------------------------------------------------------------
//
// Syscall ABI: number in `x8`; args in `x0..x5`; result in `x0`.
// `__NR_rt_sigaction` = 134 (generic Linux ABI, same as riscv64).

/// Invoke the Linux `rt_sigaction(2)` syscall directly, bypassing any libc wrapper.
///
/// Returns `0` on success or a negative `-errno` value on failure.
///
/// # Safety
/// - `act` must be a valid pointer to an initialised [`KernelSigAction`], or null.
/// - `oact` must be a valid writable pointer to a [`KernelSigAction`]-sized slot, or null.
/// - No concurrent thread may race on the same signal disposition while this call executes.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn rt_sigaction_raw(
    sig: i32,
    act: *const KernelSigAction,
    oact: *mut KernelSigAction,
) -> i64 {
    const SYS_RT_SIGACTION: i64 = 134;
    const SIGSETSIZE: i64 = core::mem::size_of::<u64>() as i64; // 8
    let ret: i64;
    // SAFETY: see function-level comment.
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

// ---------------------------------------------------------------------------
// riscv64
// ---------------------------------------------------------------------------
//
// Syscall ABI: number in `a7`; args in `a0..a5`; result in `a0`.
// `__NR_rt_sigaction` = 134 (same generic Linux ABI as aarch64).
// References: arch/riscv/include/uapi/asm/unistd.h (via <asm-generic/unistd.h>)

/// Invoke the Linux `rt_sigaction(2)` syscall directly, bypassing any libc wrapper.
///
/// Returns `0` on success or a negative `-errno` value on failure.
///
/// # Safety
/// - `act` must be a valid pointer to an initialised [`KernelSigAction`], or null.
/// - `oact` must be a valid writable pointer to a [`KernelSigAction`]-sized slot, or null.
/// - No concurrent thread may race on the same signal disposition while this call executes.
#[cfg(target_arch = "riscv64")]
#[inline]
pub unsafe fn rt_sigaction_raw(
    sig: i32,
    act: *const KernelSigAction,
    oact: *mut KernelSigAction,
) -> i64 {
    const SYS_RT_SIGACTION: i64 = 134;
    const SIGSETSIZE: i64 = core::mem::size_of::<u64>() as i64; // 8
    let ret: i64;
    // SAFETY: see function-level comment.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SYS_RT_SIGACTION,
            inlateout("a0") sig as i64 => ret,
            in("a1") act,
            in("a2") oact,
            in("a3") SIGSETSIZE,
            options(nostack),
        );
    }
    ret
}

// ---------------------------------------------------------------------------
// rt_sigprocmask(2) — examine/change the process blocked-signal mask.
// ---------------------------------------------------------------------------
//
// `how` is SIG_BLOCK(0) / SIG_UNBLOCK(1) / SIG_SETMASK(2). `set`/`oldset` point
// at a kernel sigset — a single 64-bit word covering signals 1..=64 (bit N-1
// for signal N); `sigsetsize` = 8. `__NR_rt_sigprocmask` = 14 (x86_64), 135
// (aarch64/riscv64 generic ABI). Used at startup to temporarily unblock SIGUSR1
// for the live-delivery smoke test, since blocked masks survive execve.

/// Invoke the Linux `rt_sigprocmask(2)` syscall directly.
///
/// Returns `0` on success or a negative `-errno` value on failure.
///
/// # Safety
/// - `set` must be a valid pointer to an initialised `u64` sigset, or null.
/// - `oldset` must be a valid writable pointer to a `u64` slot, or null.
#[cfg(target_arch = "x86_64")]
#[inline]
pub unsafe fn rt_sigprocmask_raw(how: i32, set: *const u64, oldset: *mut u64) -> i64 {
    const SYS_RT_SIGPROCMASK: i64 = 14;
    const SIGSETSIZE: i64 = core::mem::size_of::<u64>() as i64; // 8
    let ret: i64;
    // SAFETY: see function-level comment.
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_RT_SIGPROCMASK => ret,
            in("rdi") how as i64,
            in("rsi") set,
            in("rdx") oldset,
            in("r10") SIGSETSIZE,
            lateout("rcx") _,   // clobbered: saved RIP
            lateout("r11") _,   // clobbered: saved RFLAGS
            options(nostack),
        );
    }
    ret
}

/// Invoke the Linux `rt_sigprocmask(2)` syscall directly.
///
/// Returns `0` on success or a negative `-errno` value on failure.
///
/// # Safety
/// - `set` must be a valid pointer to an initialised `u64` sigset, or null.
/// - `oldset` must be a valid writable pointer to a `u64` slot, or null.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn rt_sigprocmask_raw(how: i32, set: *const u64, oldset: *mut u64) -> i64 {
    const SYS_RT_SIGPROCMASK: i64 = 135;
    const SIGSETSIZE: i64 = core::mem::size_of::<u64>() as i64; // 8
    let ret: i64;
    // SAFETY: see function-level comment.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") SYS_RT_SIGPROCMASK,
            inlateout("x0") how as i64 => ret,
            in("x1") set,
            in("x2") oldset,
            in("x3") SIGSETSIZE,
            options(nostack),
        );
    }
    ret
}

/// Invoke the Linux `rt_sigprocmask(2)` syscall directly.
///
/// Returns `0` on success or a negative `-errno` value on failure.
///
/// # Safety
/// - `set` must be a valid pointer to an initialised `u64` sigset, or null.
/// - `oldset` must be a valid writable pointer to a `u64` slot, or null.
#[cfg(target_arch = "riscv64")]
#[inline]
pub unsafe fn rt_sigprocmask_raw(how: i32, set: *const u64, oldset: *mut u64) -> i64 {
    const SYS_RT_SIGPROCMASK: i64 = 135;
    const SIGSETSIZE: i64 = core::mem::size_of::<u64>() as i64; // 8
    let ret: i64;
    // SAFETY: see function-level comment.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SYS_RT_SIGPROCMASK,
            inlateout("a0") how as i64 => ret,
            in("a1") set,
            in("a2") oldset,
            in("a3") SIGSETSIZE,
            options(nostack),
        );
    }
    ret
}
