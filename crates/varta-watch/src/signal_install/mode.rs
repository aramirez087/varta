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
///
/// When the `libc-signal-mode` Cargo feature is enabled, the `Direct` variant
/// is excised from compilation entirely — the build cannot produce a binary
/// that contains the inline-asm trampoline. `Libc` becomes the only variant
/// and the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SignalHandlerMode {
    /// Direct `rt_sigaction(2)` syscall — full kernel-ABI ownership (default
    /// when `libc-signal-mode` is not enabled).
    #[cfg(not(feature = "libc-signal-mode"))]
    #[cfg_attr(not(feature = "libc-signal-mode"), default)]
    Direct,
    /// libc `sigaction(3)` wrapper — libc's `__restore_rt` trampoline.
    /// Default and only option when `libc-signal-mode` is enabled.
    #[cfg_attr(feature = "libc-signal-mode", default)]
    Libc,
}

impl core::str::FromStr for SignalHandlerMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            #[cfg(not(feature = "libc-signal-mode"))]
            "direct" => Ok(Self::Direct),
            #[cfg(feature = "libc-signal-mode")]
            "direct" => Err(()),
            "libc" => Ok(Self::Libc),
            _ => Err(()),
        }
    }
}

impl SignalHandlerMode {
    /// The canonical lower-case string used in CLI flags and Prometheus labels.
    pub fn as_str(self) -> &'static str {
        match self {
            #[cfg(not(feature = "libc-signal-mode"))]
            Self::Direct => "direct",
            Self::Libc => "libc",
        }
    }
}
