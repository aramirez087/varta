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

#[cfg(target_arch = "x86_64")]
#[inline]
pub(super) unsafe fn rt_sigaction_raw(
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

#[cfg(target_arch = "aarch64")]
#[inline]
pub(super) unsafe fn rt_sigaction_raw(
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

#[cfg(target_arch = "riscv64")]
#[inline]
pub(super) unsafe fn rt_sigaction_raw(
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
