// Kernel ABI for `struct sigaction` on Linux — **different** from any
// libc userspace layout. Sourced from `<asm-generic/signal.h>` and the
// per-arch `<asm/signal.h>` overrides in the Linux kernel source tree.
//
// Layout summary:
//
//   x86_64  (has __ARCH_HAS_SA_RESTORER)
//     field        offset  type           note
//     sa_handler        0  void (*)(int)
//     sa_flags          8  unsigned long
//     sa_restorer      16  void (*)(void)
//     sa_mask          24  sigset_t       1×unsigned long on 64-bit Linux
//     total size       32
//
//   aarch64  (no __ARCH_HAS_SA_RESTORER — signal-return via vDSO)
//     field        offset  type           note
//     sa_handler        0  void (*)(int)
//     sa_flags          8  unsigned long
//     sa_mask          16  sigset_t       1×unsigned long
//     total size       24
//
//   riscv64  (no __ARCH_HAS_SA_RESTORER — signal-return via vDSO)
//     field        offset  type           note
//     sa_handler        0  void (*)(int)
//     sa_flags          8  unsigned long
//     sa_mask          16  sigset_t       1×unsigned long
//     total size       24
//
// Compile-time size assertions and test-time offset checks follow each struct
// definition.

// ---------------------------------------------------------------------------
// x86_64
// ---------------------------------------------------------------------------

/// Kernel `struct sigaction` layout for x86_64 Linux (32 bytes).
///
/// Matches the kernel ABI from `<asm-generic/signal.h>` with the x86_64
/// `__ARCH_HAS_SA_RESTORER` override.  This layout differs from the libc
/// userspace layout (`handler / mask / flags / restorer`).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub struct KernelSigAction {
    /// Signal handler function pointer (`void (*sa_handler)(int)`).
    pub sa_handler: *const (),
    /// Signal action flags (e.g. `SA_RESTART`, `SA_RESTORER`).
    pub sa_flags: u64,
    /// Signal-return trampoline (`SA_RESTORER` must be set when non-null).
    pub sa_restorer: *const (),
    /// Blocked-signals mask during handler execution (one `unsigned long`).
    pub sa_mask: u64,
}

#[cfg(target_arch = "x86_64")]
const _: () = assert!(core::mem::size_of::<KernelSigAction>() == 32);

// ---------------------------------------------------------------------------
// aarch64 — no sa_restorer field
// ---------------------------------------------------------------------------

/// Kernel `struct sigaction` layout for aarch64 Linux (24 bytes).
///
/// No `sa_restorer` field — signal return is handled by the vDSO
/// `__kernel_rt_sigreturn` entry point.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
pub struct KernelSigAction {
    /// Signal handler function pointer (`void (*sa_handler)(int)`).
    pub sa_handler: *const (),
    /// Signal action flags (e.g. `SA_RESTART`).
    pub sa_flags: u64,
    /// Blocked-signals mask during handler execution (one `unsigned long`).
    pub sa_mask: u64,
}

#[cfg(target_arch = "aarch64")]
const _: () = assert!(core::mem::size_of::<KernelSigAction>() == 24);

// ---------------------------------------------------------------------------
// riscv64 — same asm-generic layout as aarch64, no sa_restorer field.
// The riscv64 vDSO provides __vdso_rt_sigreturn; the kernel sets ra (x1)
// to that vDSO symbol before jumping to the handler.
// References: arch/riscv/kernel/signal.c, arch/riscv/include/uapi/asm/signal.h
// ---------------------------------------------------------------------------

/// Kernel `struct sigaction` layout for riscv64 Linux (24 bytes).
///
/// Same `asm-generic` layout as aarch64; signal return is handled by
/// the vDSO `__vdso_rt_sigreturn` entry point via the `ra` register.
#[cfg(target_arch = "riscv64")]
#[repr(C)]
pub struct KernelSigAction {
    /// Signal handler function pointer (`void (*sa_handler)(int)`).
    pub sa_handler: *const (),
    /// Signal action flags (e.g. `SA_RESTART`).
    pub sa_flags: u64,
    /// Blocked-signals mask during handler execution (one `unsigned long`).
    pub sa_mask: u64,
}

#[cfg(target_arch = "riscv64")]
const _: () = assert!(core::mem::size_of::<KernelSigAction>() == 24);

#[cfg(all(
    test,
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )
))]
mod layout_tests {
    use super::KernelSigAction;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn kernel_sigaction_offsets_match_x86_64_layout() {
        assert_field_offset!(KernelSigAction, sa_handler, 0);
        assert_field_offset!(KernelSigAction, sa_flags, 8);
        assert_field_offset!(KernelSigAction, sa_restorer, 16);
        assert_field_offset!(KernelSigAction, sa_mask, 24);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn kernel_sigaction_offsets_match_aarch64_layout() {
        assert_field_offset!(KernelSigAction, sa_handler, 0);
        assert_field_offset!(KernelSigAction, sa_flags, 8);
        assert_field_offset!(KernelSigAction, sa_mask, 16);
    }

    #[cfg(target_arch = "riscv64")]
    #[test]
    fn kernel_sigaction_offsets_match_riscv64_layout() {
        assert_field_offset!(KernelSigAction, sa_handler, 0);
        assert_field_offset!(KernelSigAction, sa_flags, 8);
        assert_field_offset!(KernelSigAction, sa_mask, 16);
    }
}
