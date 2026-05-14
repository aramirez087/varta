/// Whether to install signal handlers via a direct kernel syscall or via the
/// libc wrapper.
///
/// The default (`Direct`) issues `rt_sigaction(2)` directly through inline
/// assembly, bypasses any libc wrapper, and owns the kernel ABI
/// end-to-end — including the x86_64 signal-return trampoline. This is the
/// IEC 62304-grade path: every byte sent to the kernel is under our control.
///
/// `Libc` calls libc's `sigaction(3)`, which unconditionally substitutes its
/// own `__restore_rt` for the caller's `sa_restorer`. It is an opt-in
/// fallback for operators running on a kernel that the `Direct` path has not
/// been certified against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SignalHandlerMode {
    /// Direct `rt_sigaction(2)` syscall — full kernel-ABI ownership (default).
    #[default]
    Direct,
    /// libc `sigaction(3)` wrapper — libc's `__restore_rt` trampoline.
    Libc,
}

impl core::str::FromStr for SignalHandlerMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "direct" => Ok(Self::Direct),
            "libc" => Ok(Self::Libc),
            _ => Err(()),
        }
    }
}

impl SignalHandlerMode {
    /// The canonical lower-case string used in CLI flags and Prometheus labels.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Libc => "libc",
        }
    }
}
