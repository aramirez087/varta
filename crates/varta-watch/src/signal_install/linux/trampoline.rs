// Kernel-ABI signal-return trampoline for Linux/x86_64.
//
// On x86_64 the kernel's `__setup_rt_frame` (arch/x86/kernel/signal_64.c)
// requires `SA_RESTORER` set and `sa_restorer` pointing at a userspace
// `rt_sigreturn(2)` trampoline — otherwise it returns `-EFAULT` and the
// process gets `SIGSEGV` on signal-handler return. glibc and musl ship
// `__restore_rt`; we ship our own equivalent here so that we own the kernel
// ABI end-to-end and are not implicitly dependent on libc.
//
// Two-instruction trampoline. Stack is already pointing at the rt_sigframe
// the kernel set up before jumping to the handler; `rt_sigreturn` reads it.
//
// `.cfi_signal_frame` tells gdb / perf / Rust unwinders that this is a
// signal trampoline so backtraces step past the interrupted context
// correctly. `.hidden` keeps the symbol private to this binary.
//
// Note: aarch64 and riscv64 have no userspace restorer. On aarch64 the
// kernel sets x30 (LR) to the vDSO `__kernel_rt_sigreturn` trampoline;
// on riscv64 the kernel similarly routes signal-return through the vDSO.
// `<asm-generic/signal.h>` does not include `sa_restorer` for either arch
// because `__ARCH_HAS_SA_RESTORER` is undefined. No trampoline is needed
// or possible on those architectures — the kernel/vDSO owns the path.
//
// References:
//   * arch/x86/kernel/signal_64.c::__setup_rt_frame
//   * arch/x86/entry/syscalls/syscall_64.tbl  (__NR_rt_sigreturn = 15)
//   * glibc sysdeps/unix/sysv/linux/x86_64/sigaction.c::restore_rt
//   * musl src/signal/x86_64/restore.s

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    ".section .text.varta_signal_restorer,\"ax\",@progbits",
    ".globl varta_signal_restorer",
    ".hidden varta_signal_restorer",
    ".type varta_signal_restorer, @function",
    ".p2align 4",
    "varta_signal_restorer:",
    ".cfi_startproc",
    ".cfi_signal_frame",
    "    mov $15, %rax", // __NR_rt_sigreturn
    "    syscall",
    "    ud2", // never reached: rt_sigreturn does not return
    ".cfi_endproc",
    ".size varta_signal_restorer, .-varta_signal_restorer",
    options(att_syntax),
);

#[cfg(target_arch = "x86_64")]
extern "C" {
    /// Kernel-ABI signal-return trampoline defined by the `global_asm!`
    /// block above. Never invoked from Rust — only by the kernel as the
    /// `sa_restorer` callee when a signal handler returns. Issues
    /// `__NR_rt_sigreturn` and does not return to userspace.
    // SAFETY: only ever taken as a function-pointer value
    // (`varta_signal_restorer as *const ()`) and handed to `rt_sigaction(2)`.
    pub(crate) fn varta_signal_restorer();
}
