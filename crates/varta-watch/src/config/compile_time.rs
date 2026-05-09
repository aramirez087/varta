// --- compile-time-config integration ----------------------------------------
//
// When `--features compile-time-config` is active, the runtime binary skips
// argv parsing entirely and uses a `Config` constant produced by `build.rs`
// from the operator's static configuration file ($VARTA_CONFIG_FILE).  The
// generated file lives in $OUT_DIR and is `include!`-ed here so the build
// graph remains feature-gated cleanly: there is no parser anywhere in the
// Class-A binary, only a literal constructor.

#[cfg(feature = "compile-time-config")]
mod compile_time_blob {
    include!(concat!(env!("OUT_DIR"), "/compile_time_config.rs"));
}

#[cfg(feature = "compile-time-config")]
impl super::types::Config {
    /// Return the compile-time-baked `Config` after running the same
    /// cross-field validation that [`Config::from_args`] applies in
    /// default builds.  Always called exactly once, at startup, from
    /// `main.rs`.
    pub fn compile_time() -> Result<super::types::Config, super::types::ConfigError> {
        let cfg = compile_time_blob::build_compile_time_config();
        cfg.validate_runtime()
    }
}

#[cfg(feature = "compile-time-config")]
impl super::types::Config {
    /// Runtime cross-field validator for Class-A builds.  Default builds
    /// run the same checks inline in `Config::from_args`; the method
    /// exists only to share the platform-dependent rules with
    /// `Config::compile_time()`, which has no argv path of its own.
    ///
    /// Returning `Ok(self)` lets the caller chain `?` against the
    /// validation step without an extra `let` binding.
    pub(crate) fn validate_runtime(
        self,
    ) -> Result<super::types::Config, super::types::ConfigError> {
        // H7 — platform-restricted clock sources must fail loudly rather
        // than silently picking a clock that pauses on suspend:
        // `boottime` is Linux-only (CLOCK_BOOTTIME = 7), `monotonic-raw`
        // is macOS/iOS-only (CLOCK_MONOTONIC_RAW = 4 = mach_continuous_time).
        // `clk_id()` returns `None` for the wrong-platform combinations.
        if self.clock_source.clk_id().is_none() {
            return Err(super::types::ConfigError::ClockSourceUnsupported {
                source: self.clock_source,
                platform: std::env::consts::OS,
            });
        }
        Ok(self)
    }
}
