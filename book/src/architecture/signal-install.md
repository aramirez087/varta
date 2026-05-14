# Signal-Handler Installation

`varta-watch` installs `SIGINT` and `SIGTERM` handlers that flip a process-wide
`AtomicBool` shutdown latch.  The installation path is more subtle than a plain
`signal(2)` call because glibc and musl silently rewrite the `sa_restorer` field
of `struct sigaction` — which is load-bearing on x86_64.

## Background: why libc cannot be trusted for sa_restorer

When a Linux process receives a signal, the kernel pushes a signal frame onto
the user stack and jumps to the registered handler.  On signal-handler return,
the CPU executes the instruction at `sa_restorer`; the kernel expects this to
call the `rt_sigreturn(2)` syscall to tear down the frame.

The standard libc wrappers (`glibc::sigaction`, `musl::sigaction`) unconditionally
overwrite `sa_restorer` with their own internal `__restore_rt` symbol before
passing the action to the kernel.  This is correct for libc-linked programs, but
means **the kernel ABI is not end-to-end owned** — any change to libc's
`__restore_rt` (or a statically linked binary that lacks it) would produce a
`SIGSEGV` on signal return.

For a safety-critical daemon that must detect stalls and trigger recovery, this
libc substitution is an unacceptable black-box dependency.  The direct path owns
the trampoline.

## Module layout

```
crates/varta-watch/src/signal_install/
├── mod.rs               — public install(mode, handler) -> io::Result<()>
├── mode.rs              — SignalHandlerMode { Direct, Libc }
├── linux/
│   ├── mod.rs           — dispatch + compile_error! arch gate + smoke test
│   ├── direct.rs        — rt_sigaction(2) direct-syscall path + readback
│   ├── libc_wrapper.rs  — libc sigaction(3) fallback (no sa_restorer check)
│   ├── kernel_abi.rs    — KernelSigAction per-arch structs + offset asserts
│   ├── syscall.rs       — rt_sigaction_raw inline-asm per arch
│   └── trampoline.rs    — varta_signal_restorer global_asm! (x86_64 only)
├── bsd.rs               — macOS + FreeBSD libc sigaction(3)
└── sysv.rs              — other-Unix POSIX signal(2) fallback
```

## Supported Linux architectures

| Arch    | KernelSigAction size | sa_restorer | vDSO signal-return |
|---------|---------------------|-------------|--------------------|
| x86_64  | 32 B                | yes         | no (trampoline req'd) |
| aarch64 | 24 B                | no          | yes (`__vdso_rt_sigreturn`) |
| riscv64 | 24 B                | no          | yes (`__vdso_rt_sigreturn`) |

On any other Linux target the build fails with an explicit `compile_error!`
listing the accepted architectures.

## Direct mode (default)

`SignalHandlerMode::Direct` issues `rt_sigaction(2)` via inline assembly,
bypassing libc entirely.  After installation:

1. **Readback**: re-reads the active action via `rt_sigaction(sig, null, &old)`
   and asserts every field matches what was written (handler pointer, `SA_RESTART`
   flag, and on x86_64 the `SA_RESTORER` flag and restorer pointer).

2. **Live-delivery smoke test**: installs a transient `SIGUSR1` handler via the
   same direct path, delivers `SIGUSR1` to the process via `kill(getpid(), SIGUSR1)`,
   waits up to 50 ms for the handler to set an atomic flag, then restores the
   previous `SIGUSR1` disposition.  A failure here means the trampoline ABI is
   broken and the error is surfaced at startup rather than at the first real
   SIGTERM hours later in production.

## Libc fallback mode

`SignalHandlerMode::Libc` calls `sigaction(3)` through an `extern "C"` declaration
(no `libc` crate — zero registry dependencies preserved).  libc substitutes its
own `__restore_rt`; no readback or smoke test is performed because the check would
measure libc's restorer rather than ours.

This mode is off by default and is intended for operators running on a kernel not
yet certified against the direct path.

**SRE builds**: pass `--signal-handler-mode=libc` on the command line.

**Class-A builds** (`compile-time-config`): set `signal_handler_mode = libc` in
the baked config file (default is `direct`).

## Observability

On SRE builds with the `prometheus-exporter` feature, the active mode is exported
as:

```text
# HELP varta_signal_handler_install_total ...
# TYPE varta_signal_handler_install_total counter
varta_signal_handler_install_total{mode="direct"} 1
```

The value is always 1 in steady state.  A dashboard alert on `mode != "direct"`
catches any inadvertent deployment with the libc fallback.

On Class-A builds (no `/metrics` endpoint), a single `varta_info!` log line at
startup records the active mode.

## Adding a fourth Linux architecture

Follow this checklist:

1. **`kernel_abi.rs`**: add a `#[cfg(target_arch = "...")]` arm with the
   `KernelSigAction` struct.  Check `<asm/signal.h>` for the layout.
   Add `const` size and `offset_of!` assertions matching every field.

2. **`syscall.rs`**: add `rt_sigaction_raw` for the new arch.  Consult the
   architecture's syscall ABI (syscall number, register convention, instruction).
   `__NR_rt_sigaction = 134` on all architectures using the generic Linux ABI
   (aarch64, riscv64, and most others); x86_64 uses 13.

3. **`trampoline.rs`**: add a `global_asm!` trampoline only if the arch defines
   `__ARCH_HAS_SA_RESTORER` in its `<asm/signal.h>`.  For architectures where
   signal-return goes through the vDSO (aarch64, riscv64, and the generic ABI),
   no trampoline is needed and `SA_RESTORER` must not be set.

4. **`mod.rs` `compile_error!`**: add the new arch to the `not(any(...))` list.

5. **`tests/signal_handler.rs`**: add a `linux_<arch>_direct_syscall_roundtrips`
   test gated on `#[cfg(all(target_os = "linux", target_arch = "..."))]`.  The
   types and syscall wrapper come from `varta_watch::__test_signal_abi`.

6. **`.github/workflows/ci.yml`**: add `rustup target add <target>` and a
   `cargo check --locked -p varta-watch --target <target>` step to
   `cross-compile-checks`.

7. **`.github/workflows/kernel-rc.yml`**: add a matrix row if a GitHub-hosted
   runner is available for the architecture.
