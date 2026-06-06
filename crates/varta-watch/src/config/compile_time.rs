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
        use super::types::{
            max_read_timeout_ms, ConfigError, MAX_AUDIT_ROTATION_BUDGET_MS,
            MAX_ITERATION_BUDGET_MS, MAX_RECOVERY_CAPTURE_BYTES, MAX_SCRAPE_BUDGET_MS,
            MIN_ITERATION_BUDGET_MS, MIN_SCRAPE_BUDGET_MS, MIN_SELF_WATCHDOG_SECS,
            MIN_SHUTDOWN_GRACE_MS, MIN_THRESHOLD_MS,
        };

        if self.threshold < std::time::Duration::from_millis(MIN_THRESHOLD_MS) {
            return Err(ConfigError::ThresholdTooLow {
                value: duration_ms_saturating(self.threshold),
                min: MIN_THRESHOLD_MS,
            });
        }
        if self.shutdown_grace < std::time::Duration::from_millis(MIN_SHUTDOWN_GRACE_MS) {
            return Err(ConfigError::ShutdownGraceTooLow {
                value: duration_ms_saturating(self.shutdown_grace),
                min: MIN_SHUTDOWN_GRACE_MS,
            });
        }
        if self.recovery_capture_bytes > MAX_RECOVERY_CAPTURE_BYTES {
            return Err(ConfigError::RecoveryCaptureBytesTooLarge {
                value: self.recovery_capture_bytes,
                max: MAX_RECOVERY_CAPTURE_BYTES,
            });
        }
        let has_recovery = self.recovery_exec_cmd.is_some() || self.recovery_exec_file.is_some();
        if self.recovery_exec_cmd.is_some() && self.recovery_exec_file.is_some() {
            return Err(ConfigError::CompileTimeConfigInvalid {
                reason: "multiple recovery command sources configured",
            });
        }
        if self.recovery_capture_stdio && !has_recovery {
            return Err(ConfigError::RecoveryCaptureRequiresRecovery);
        }

        if !(MIN_ITERATION_BUDGET_MS..=MAX_ITERATION_BUDGET_MS)
            .contains(&duration_ms_saturating(self.iteration_budget))
        {
            return Err(ConfigError::IterationBudgetOutOfRange {
                value: duration_ms_saturating(self.iteration_budget),
                min: MIN_ITERATION_BUDGET_MS,
                max: MAX_ITERATION_BUDGET_MS,
            });
        }
        if !(MIN_SCRAPE_BUDGET_MS..=MAX_SCRAPE_BUDGET_MS)
            .contains(&duration_ms_saturating(self.scrape_budget))
        {
            return Err(ConfigError::ScrapeBudgetOutOfRange {
                value: duration_ms_saturating(self.scrape_budget),
                min: MIN_SCRAPE_BUDGET_MS,
                max: MAX_SCRAPE_BUDGET_MS,
            });
        }
        // A `--self-watchdog-secs` of 0 bakes a zero-nanosecond deadline that
        // self-aborts a healthy observer on the first watchdog tick. Mirror the
        // argv parser's floor so the compile-time-config path enforces the same
        // documented minimum. `None` means "no watchdog" and is left untouched.
        if let Some(d) = self.self_watchdog {
            if d.as_secs() < MIN_SELF_WATCHDOG_SECS {
                return Err(ConfigError::SelfWatchdogTooLow {
                    value: d.as_secs(),
                    min: MIN_SELF_WATCHDOG_SECS,
                });
            }
        }
        // The idle Poll stage blocks ≈ one UDS recv(2) of `read_timeout`.
        // Mirror the argv parser's active ceiling: static Poll-stage cap when
        // no self-watchdog is configured, or half the full-iteration watchdog
        // deadline when that deadline is tighter.
        let read_timeout_ms = duration_ms_saturating(self.read_timeout);
        let read_timeout_ceiling_ms = max_read_timeout_ms(self.self_watchdog);
        if read_timeout_ms > read_timeout_ceiling_ms {
            return Err(ConfigError::ReadTimeoutTooLarge {
                value: read_timeout_ms,
                max: read_timeout_ceiling_ms,
            });
        }

        // H7 — platform-restricted clock sources must fail loudly rather
        // than silently picking a clock that pauses on suspend:
        // `boottime` is Linux-only (CLOCK_BOOTTIME = 7), `monotonic-raw`
        // is macOS/iOS-only (CLOCK_MONOTONIC_RAW = 4 = mach_continuous_time).
        // `clk_id()` returns `None` for the wrong-platform combinations.
        if self.clock_source.clk_id().is_none() {
            return Err(ConfigError::ClockSourceUnsupported {
                source: self.clock_source,
                platform: std::env::consts::OS,
            });
        }
        if !(1..=crate::tracker::MAX_CAPACITY).contains(&self.tracker_capacity) {
            return Err(ConfigError::TrackerCapacityOutOfRange {
                value: self.tracker_capacity,
                min: 1,
                max: crate::tracker::MAX_CAPACITY,
            });
        }
        if !(crate::tracker::MIN_EVICTION_SCAN_WINDOW..=crate::tracker::MAX_EVICTION_SCAN_WINDOW)
            .contains(&self.eviction_scan_window)
        {
            return Err(ConfigError::EvictionScanWindowOutOfRange {
                value: self.eviction_scan_window,
                min: crate::tracker::MIN_EVICTION_SCAN_WINDOW,
                max: crate::tracker::MAX_EVICTION_SCAN_WINDOW,
            });
        }
        if self.recovery_audit_sync_every == 0 {
            return Err(ConfigError::CompileTimeConfigInvalid {
                reason: "recovery audit sync cadence must be nonzero",
            });
        }
        if self.audit_fsync_budget_ms == 0 {
            return Err(ConfigError::CompileTimeConfigInvalid {
                reason: "audit fsync budget must be nonzero",
            });
        }
        if self.audit_rotation_budget_ms == 0 {
            return Err(ConfigError::CompileTimeConfigInvalid {
                reason: "audit rotation budget must be nonzero",
            });
        }
        // A rotation budget at/above the Maintenance-stage self-watchdog abort
        // lets a normal rotation overrun the watchdog and self-abort a healthy
        // observer. Mirror the argv parser's ceiling so the compile-time-config
        // path enforces the same invariant.
        if self.audit_rotation_budget_ms > MAX_AUDIT_ROTATION_BUDGET_MS {
            return Err(ConfigError::AuditRotationBudgetTooLarge {
                value: self.audit_rotation_budget_ms as u64,
                max: MAX_AUDIT_ROTATION_BUDGET_MS as u64,
            });
        }

        let has_udp = self.udp_port.is_some();
        let has_secure_key = self.secure_key_file.is_some()
            || self.accepted_key_file.is_some()
            || self.master_key_file.is_some();
        if has_udp && !has_secure_key {
            return Err(ConfigError::CompileTimeConfigInvalid {
                reason: "UDP listener requires a secure key source",
            });
        }
        if has_recovery && has_udp && has_secure_key && !self.i_accept_recovery_on_secure_udp {
            return Err(ConfigError::CompileTimeConfigInvalid {
                reason: "recovery on secure UDP requires explicit acknowledgement",
            });
        }
        if has_udp && has_secure_key {
            if let Some(ip) = self.udp_bind_addr {
                if !ip.is_loopback() && !self.i_accept_secure_udp_non_loopback {
                    return Err(ConfigError::CompileTimeConfigInvalid {
                        reason: "non-loopback secure UDP requires explicit acknowledgement",
                    });
                }
            }
        }

        Ok(self)
    }
}

#[cfg(feature = "compile-time-config")]
fn duration_ms_saturating(d: std::time::Duration) -> u64 {
    d.as_millis().min(u64::MAX as u128) as u64
}

#[cfg(all(test, feature = "compile-time-config"))]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use crate::clock::ClockSource;
    use crate::signal_install::SignalHandlerMode;
    use crate::tracker::EvictionPolicy;

    use super::super::types::{Config, ConfigError};

    fn valid_config() -> Config {
        Config {
            socket: PathBuf::from("/tmp/varta-test.sock"),
            threshold: Duration::from_millis(5_000),
            recovery_exec_cmd: None,
            recovery_exec_file: None,
            recovery_debounce: Duration::from_millis(1_000),
            recovery_env: Vec::new(),
            recovery_inherit_env: false,
            file_export: None,
            export_file_max_bytes: None,
            export_file_sync_every: 0,
            prom_addr: None,
            prom_token_file: None,
            shutdown_after: None,
            shutdown_grace: Duration::from_millis(5_000),
            recovery_timeout: None,
            socket_mode: 0o600,
            read_timeout: Duration::from_millis(100),
            tracker_capacity: 256,
            tracker_eviction_policy: EvictionPolicy::Strict,
            eviction_scan_window: 256,
            udp_port: None,
            udp_bind_addr: None,
            secure_key_file: None,
            accepted_key_file: None,
            master_key_file: None,
            max_beat_rate: Some(100),
            global_beat_rate: 5_000,
            global_beat_burst: 10_000,
            uds_rcvbuf_bytes: 1_048_576,
            heartbeat_file: None,
            self_watchdog: None,
            hw_watchdog: None,
            prom_rate_limit_per_sec: 5,
            prom_rate_limit_burst: 10,
            i_accept_plaintext_udp: false,
            i_accept_recovery_on_secure_udp: false,
            i_accept_recovery_on_plaintext_udp: false,
            i_accept_secure_udp_non_loopback: false,
            allow_cross_namespace_agents: false,
            strict_namespace_check: false,
            recovery_audit_file: None,
            recovery_audit_max_bytes: None,
            recovery_audit_sync_every: 1,
            recovery_capture_stdio: false,
            recovery_capture_bytes: 4096,
            iteration_budget: Duration::from_millis(250),
            scrape_budget: Duration::from_millis(250),
            audit_fsync_budget_ms: 50,
            audit_sync_interval_ms: 0,
            audit_rotation_budget_ms: 50,
            #[cfg(feature = "test-hooks")]
            inject_wedge_ms: None,
            clock_source: ClockSource::Monotonic,
            signal_handler_mode: SignalHandlerMode::Direct,
        }
    }

    #[test]
    fn validate_runtime_rejects_secure_udp_recovery_without_ack() {
        let mut cfg = valid_config();
        cfg.udp_port = Some(8443);
        cfg.secure_key_file = Some(PathBuf::from("/etc/varta/agent.key"));
        cfg.recovery_exec_cmd = Some("/usr/bin/true".to_string());

        assert!(matches!(
            cfg.validate_runtime(),
            Err(ConfigError::CompileTimeConfigInvalid {
                reason: "recovery on secure UDP requires explicit acknowledgement"
            })
        ));
    }

    #[test]
    fn validate_runtime_rejects_self_watchdog_too_low() {
        let mut cfg = valid_config();
        cfg.self_watchdog = Some(Duration::from_secs(0));

        assert!(matches!(
            cfg.validate_runtime(),
            Err(ConfigError::SelfWatchdogTooLow { value: 0, min: 1 })
        ));
    }

    #[test]
    fn validate_runtime_rejects_read_timeout_that_consumes_watchdog_window() {
        let mut cfg = valid_config();
        cfg.self_watchdog = Some(Duration::from_secs(1));
        cfg.read_timeout = Duration::from_millis(501);

        assert!(matches!(
            cfg.validate_runtime(),
            Err(ConfigError::ReadTimeoutTooLarge {
                value: 501,
                max: 500
            })
        ));
    }

    #[test]
    fn validate_runtime_rejects_audit_rotation_budget_too_large() {
        let mut cfg = valid_config();
        cfg.audit_rotation_budget_ms = super::super::types::MAX_AUDIT_ROTATION_BUDGET_MS + 1;

        assert!(matches!(
            cfg.validate_runtime(),
            Err(ConfigError::AuditRotationBudgetTooLarge { .. })
        ));
    }

    #[test]
    fn validate_runtime_rejects_secure_udp_non_loopback_without_ack() {
        let mut cfg = valid_config();
        cfg.udp_port = Some(8443);
        cfg.udp_bind_addr = Some("0.0.0.0".parse().unwrap());
        cfg.secure_key_file = Some(PathBuf::from("/etc/varta/agent.key"));

        assert!(matches!(
            cfg.validate_runtime(),
            Err(ConfigError::CompileTimeConfigInvalid {
                reason: "non-loopback secure UDP requires explicit acknowledgement"
            })
        ));
    }
}
