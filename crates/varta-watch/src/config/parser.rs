// All imports below are only used inside `Config::from_args`, which is
// excluded when `--features compile-time-config` is active.  Gate every
// use-declaration at the same level to keep `-D warnings` clean.
#[cfg(not(feature = "compile-time-config"))]
use std::net::SocketAddr;
#[cfg(not(feature = "compile-time-config"))]
use std::path::PathBuf;
#[cfg(not(feature = "compile-time-config"))]
use std::time::Duration;

#[cfg(not(feature = "compile-time-config"))]
use crate::clock::ClockSource;
#[cfg(not(feature = "compile-time-config"))]
use crate::tracker::EvictionPolicy;
// Tracker capacity / eviction-window constants are only referenced from
// the argv parser (`Config::from_args`) and its bounds checks.  When
// `--features compile-time-config` is active those callers are excluded
// from compilation; re-importing the constants would surface as
// unused-imports under `-D warnings`.
#[cfg(not(feature = "compile-time-config"))]
use crate::tracker::{
    DEFAULT_CAPACITY, DEFAULT_EVICTION_SCAN_WINDOW, MAX_CAPACITY, MAX_EVICTION_SCAN_WINDOW,
    MIN_EVICTION_SCAN_WINDOW,
};

#[cfg(not(feature = "compile-time-config"))]
use super::parse_helpers::{parse_octal, parse_u16, parse_u64};
#[cfg(not(feature = "compile-time-config"))]
use super::types::{
    max_read_timeout_ms, Config, ConfigError, DEFAULT_PROM_RATE_LIMIT_BURST,
    DEFAULT_PROM_RATE_LIMIT_PER_SEC, DEFAULT_READ_TIMEOUT_MS, DEFAULT_RECOVERY_CAPTURE_BYTES,
    DEFAULT_RECOVERY_DEBOUNCE_MS, DEFAULT_SHUTDOWN_GRACE_MS, DEFAULT_SOCKET_MODE,
    MAX_AUDIT_ROTATION_BUDGET_MS, MAX_ITERATION_BUDGET_MS, MAX_RECOVERY_CAPTURE_BYTES,
    MAX_SCRAPE_BUDGET_MS, MIN_EXPORT_FILE_MAX_BYTES, MIN_ITERATION_BUDGET_MS, MIN_READ_TIMEOUT_MS,
    MIN_RECOVERY_AUDIT_MAX_BYTES, MIN_RECOVERY_CAPTURE_BYTES, MIN_RECOVERY_TIMEOUT_MS,
    MIN_SCRAPE_BUDGET_MS, MIN_SELF_WATCHDOG_SECS, MIN_SHUTDOWN_GRACE_MS, MIN_THRESHOLD_MS,
};

#[cfg(not(feature = "compile-time-config"))]
impl Config {
    /// Parse a token stream (typically `std::env::args().skip(1)`).
    ///
    /// Excluded from compilation when `--features compile-time-config` is
    /// active — the Class-A binary intentionally has no argv parser linked.
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Config, ConfigError> {
        let mut socket: Option<PathBuf> = None;
        let mut threshold_ms: Option<u64> = None;
        let mut recovery_exec_cmd: Option<String> = None;
        let mut recovery_exec_file: Option<PathBuf> = None;
        let mut recovery_debounce_ms: Option<u64> = None;
        let mut recovery_env: Vec<String> = Vec::new();
        let mut recovery_inherit_env: bool = false;
        let mut file_export: Option<PathBuf> = None;
        let mut export_file_max_bytes: Option<u64> = None;
        let mut export_file_sync_every: u32 = 0;
        // `prom_*` locals are mutated only by `--prom-*` arms gated under
        // `feature = "prometheus-exporter"`.  Without the feature the
        // arms vanish and the `mut` becomes redundant; allow the lint so
        // the parser body keeps the same shape across feature
        // permutations.
        #[allow(unused_mut)]
        let mut prom_addr: Option<SocketAddr> = None;
        #[allow(unused_mut)]
        let mut prom_token_file: Option<PathBuf> = None;
        let mut shutdown_after_secs: Option<u64> = None;
        let mut recovery_timeout_ms: Option<u64> = None;
        let mut shutdown_grace_ms: Option<u64> = None;
        let mut socket_mode: Option<u32> = None;
        let mut read_timeout_ms: Option<u64> = None;
        let mut tracker_capacity: Option<usize> = None;
        let mut tracker_eviction_policy: Option<EvictionPolicy> = None;
        let mut clock_source: Option<ClockSource> = None;
        let mut eviction_scan_window: Option<usize> = None;
        let mut udp_port: Option<u16> = None;
        let mut udp_bind_addr: Option<std::net::IpAddr> = None;
        let mut secure_key_file: Option<PathBuf> = None;
        let mut accepted_key_file: Option<PathBuf> = None;
        let mut master_key_file: Option<PathBuf> = None;
        let mut max_beat_rate: Option<u32> = None;
        let mut global_beat_rate: Option<u32> = None;
        let mut global_beat_burst: Option<u32> = None;
        let mut uds_rcvbuf_bytes: Option<u32> = None;
        let mut heartbeat_file: Option<PathBuf> = None;
        let mut self_watchdog: Option<Duration> = None;
        let mut hw_watchdog: Option<PathBuf> = None;
        #[allow(unused_mut)]
        let mut prom_rate_limit_per_sec: Option<u32> = None;
        #[allow(unused_mut)]
        let mut prom_rate_limit_burst: Option<u32> = None;
        let mut i_accept_plaintext_udp = false;
        let mut i_accept_recovery_on_secure_udp = false;
        let mut i_accept_recovery_on_plaintext_udp = false;
        let mut i_accept_secure_udp_non_loopback = false;
        let mut allow_cross_namespace_agents = false;
        let mut strict_namespace_check = false;
        let mut recovery_audit_file: Option<PathBuf> = None;
        let mut recovery_audit_max_bytes: Option<u64> = None;
        let mut recovery_audit_sync_every: Option<u32> = None;
        let mut recovery_capture_stdio = false;
        let mut recovery_capture_bytes: Option<u32> = None;
        let mut iteration_budget_ms: Option<u64> = None;
        let mut scrape_budget_ms: Option<u64> = None;
        let mut audit_fsync_budget_ms: Option<u32> = None;
        let mut audit_sync_interval_ms: Option<u32> = None;
        let mut audit_rotation_budget_ms: Option<u32> = None;
        #[cfg(feature = "test-hooks")]
        let mut inject_wedge_ms: Option<u64> = None;
        let mut signal_handler_mode: Option<crate::signal_install::SignalHandlerMode> = None;

        let mut iter = args.into_iter();
        while let Some(tok) = iter.next() {
            match tok.as_str() {
                "--help" | "-h" => return Err(ConfigError::HelpRequested),
                "--socket" => {
                    let v = iter.next().ok_or(ConfigError::MissingValue("--socket"))?;
                    socket = Some(PathBuf::from(v));
                }
                "--threshold-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--threshold-ms"))?;
                    threshold_ms = Some(parse_u64("--threshold-ms", &v)?);
                }
                "--recovery-cmd" => {
                    return Err(ConfigError::RemovedFlag {
                        flag: "--recovery-cmd",
                        replacement: "--recovery-exec",
                    });
                }
                "--recovery-cmd-file" => {
                    return Err(ConfigError::RemovedFlag {
                        flag: "--recovery-cmd-file",
                        replacement: "--recovery-exec-file",
                    });
                }
                "--i-accept-shell-risk" => {
                    return Err(ConfigError::RemovedFlag {
                        flag: "--i-accept-shell-risk",
                        replacement: "--recovery-exec",
                    });
                }
                "--recovery-exec" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-exec"))?;
                    recovery_exec_cmd = Some(v);
                }
                "--recovery-exec-file" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-exec-file"))?;
                    recovery_exec_file = Some(PathBuf::from(v));
                }
                "--recovery-debounce-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-debounce-ms"))?;
                    recovery_debounce_ms = Some(parse_u64("--recovery-debounce-ms", &v)?);
                }
                "--recovery-env" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-env"))?;
                    recovery_env.push(v);
                }
                "--recovery-inherit-env" => {
                    recovery_inherit_env = true;
                }
                "--socket-mode" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--socket-mode"))?;
                    socket_mode = Some(parse_octal(&v)?);
                }
                "--export-file" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--export-file"))?;
                    file_export = Some(PathBuf::from(v));
                }
                "--export-file-max-bytes" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--export-file-max-bytes"))?;
                    let parsed = parse_u64("--export-file-max-bytes", &v)?;
                    if parsed < MIN_EXPORT_FILE_MAX_BYTES {
                        return Err(ConfigError::ExportFileMaxBytesTooLow {
                            value: parsed,
                            min: MIN_EXPORT_FILE_MAX_BYTES,
                        });
                    }
                    export_file_max_bytes = Some(parsed);
                }
                "--export-file-sync-every" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--export-file-sync-every"))?;
                    let parsed = parse_u64("--export-file-sync-every", &v)?;
                    if parsed > u32::MAX as u64 {
                        return Err(ConfigError::BadValue {
                            flag: "--export-file-sync-every",
                            raw: v,
                        });
                    }
                    export_file_sync_every = parsed as u32;
                }
                #[cfg(feature = "prometheus-exporter")]
                "--prom-addr" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--prom-addr"))?;
                    prom_addr = Some(
                        v.parse::<SocketAddr>()
                            .map_err(|_| ConfigError::BadAddr(v))?,
                    );
                }
                #[cfg(feature = "prometheus-exporter")]
                "--prom-token-file" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--prom-token-file"))?;
                    prom_token_file = Some(PathBuf::from(v));
                }
                "--recovery-timeout-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-timeout-ms"))?;
                    let parsed = parse_u64("--recovery-timeout-ms", &v)?;
                    if parsed < MIN_RECOVERY_TIMEOUT_MS {
                        return Err(ConfigError::RecoveryTimeoutTooLow {
                            value: parsed,
                            min: MIN_RECOVERY_TIMEOUT_MS,
                        });
                    }
                    recovery_timeout_ms = Some(parsed);
                }
                "--shutdown-grace-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--shutdown-grace-ms"))?;
                    shutdown_grace_ms = Some(parse_u64("--shutdown-grace-ms", &v)?);
                }
                "--read-timeout-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--read-timeout-ms"))?;
                    read_timeout_ms = Some(parse_u64("--read-timeout-ms", &v)?);
                }
                "--tracker-capacity" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--tracker-capacity"))?;
                    tracker_capacity =
                        Some(v.parse::<usize>().map_err(|_| ConfigError::BadInteger {
                            flag: "--tracker-capacity",
                            raw: v,
                        })?);
                }
                "--eviction-scan-window" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--eviction-scan-window"))?;
                    eviction_scan_window =
                        Some(v.parse::<usize>().map_err(|_| ConfigError::BadInteger {
                            flag: "--eviction-scan-window",
                            raw: v,
                        })?);
                }
                "--tracker-eviction-policy" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--tracker-eviction-policy"))?;
                    tracker_eviction_policy = Some(match v.as_str() {
                        "strict" => EvictionPolicy::Strict,
                        "balanced" => EvictionPolicy::Balanced,
                        _ => {
                            return Err(ConfigError::BadValue {
                                flag: "--tracker-eviction-policy",
                                raw: v,
                            })
                        }
                    });
                }
                "--clock-source" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--clock-source"))?;
                    clock_source =
                        Some(
                            v.parse::<ClockSource>()
                                .map_err(|_| ConfigError::BadValue {
                                    flag: "--clock-source",
                                    raw: v,
                                })?,
                        );
                }
                "--signal-handler-mode" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--signal-handler-mode"))?;
                    signal_handler_mode = Some(
                        v.parse::<crate::signal_install::SignalHandlerMode>()
                            .map_err(|_| ConfigError::BadValue {
                                flag: "--signal-handler-mode",
                                raw: v,
                            })?,
                    );
                }
                "--shutdown-after-secs" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--shutdown-after-secs"))?;
                    shutdown_after_secs = Some(parse_u64("--shutdown-after-secs", &v)?);
                }
                "--udp-port" => {
                    let v = iter.next().ok_or(ConfigError::MissingValue("--udp-port"))?;
                    udp_port = Some(parse_u16("--udp-port", &v)?);
                }
                "--udp-bind-addr" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--udp-bind-addr"))?;
                    udp_bind_addr = Some(
                        v.parse::<std::net::IpAddr>()
                            .map_err(|_| ConfigError::BadAddr(v))?,
                    );
                }
                "--key-file" => {
                    let v = iter.next().ok_or(ConfigError::MissingValue("--key-file"))?;
                    secure_key_file = Some(PathBuf::from(v));
                }
                "--accepted-key-file" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--accepted-key-file"))?;
                    accepted_key_file = Some(PathBuf::from(v));
                }
                "--master-key-file" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--master-key-file"))?;
                    master_key_file = Some(PathBuf::from(v));
                }
                "--key-env" | "--master-key-env" | "--accepted-key-env" => {
                    // Removed for security: env-var keys are exposed via
                    // /proc/<pid>/environ and `docker inspect`. See
                    // book/src/architecture/peer-authentication.md.
                    let flag = match tok.as_str() {
                        "--key-env" => "--key-env",
                        "--master-key-env" => "--master-key-env",
                        _ => "--accepted-key-env",
                    };
                    return Err(ConfigError::RemovedFlag {
                        flag,
                        replacement: "--key-file (mode 0600, owned by the observer UID)",
                    });
                }
                "--max-beat-rate" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--max-beat-rate"))?;
                    max_beat_rate =
                        Some(v.parse::<u32>().map_err(|_| ConfigError::BadInteger {
                            flag: "--max-beat-rate",
                            raw: v,
                        })?);
                }
                "--global-beat-rate" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--global-beat-rate"))?;
                    global_beat_rate =
                        Some(v.parse::<u32>().map_err(|_| ConfigError::BadInteger {
                            flag: "--global-beat-rate",
                            raw: v,
                        })?);
                }
                "--global-beat-burst" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--global-beat-burst"))?;
                    global_beat_burst =
                        Some(v.parse::<u32>().map_err(|_| ConfigError::BadInteger {
                            flag: "--global-beat-burst",
                            raw: v,
                        })?);
                }
                "--uds-rcvbuf-bytes" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--uds-rcvbuf-bytes"))?;
                    uds_rcvbuf_bytes =
                        Some(v.parse::<u32>().map_err(|_| ConfigError::BadInteger {
                            flag: "--uds-rcvbuf-bytes",
                            raw: v,
                        })?);
                }
                "--heartbeat-file" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--heartbeat-file"))?;
                    heartbeat_file = Some(PathBuf::from(v));
                }
                "--self-watchdog-secs" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--self-watchdog-secs"))?;
                    let secs = v.parse::<u64>().map_err(|_| ConfigError::BadInteger {
                        flag: "--self-watchdog-secs",
                        raw: v,
                    })?;
                    if secs < MIN_SELF_WATCHDOG_SECS {
                        return Err(ConfigError::SelfWatchdogTooLow {
                            value: secs,
                            min: MIN_SELF_WATCHDOG_SECS,
                        });
                    }
                    self_watchdog = Some(Duration::from_secs(secs));
                }
                "--hw-watchdog" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--hw-watchdog"))?;
                    hw_watchdog = Some(PathBuf::from(v));
                }
                #[cfg(feature = "test-hooks")]
                "--inject-wedge-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--inject-wedge-ms"))?;
                    let ms = v.parse::<u64>().map_err(|_| ConfigError::BadInteger {
                        flag: "--inject-wedge-ms",
                        raw: v,
                    })?;
                    inject_wedge_ms = Some(ms);
                }
                #[cfg(feature = "prometheus-exporter")]
                "--prom-rate-limit-per-sec" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--prom-rate-limit-per-sec"))?;
                    prom_rate_limit_per_sec =
                        Some(v.parse::<u32>().map_err(|_| ConfigError::BadInteger {
                            flag: "--prom-rate-limit-per-sec",
                            raw: v,
                        })?);
                }
                #[cfg(feature = "prometheus-exporter")]
                "--prom-rate-limit-burst" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--prom-rate-limit-burst"))?;
                    prom_rate_limit_burst =
                        Some(v.parse::<u32>().map_err(|_| ConfigError::BadInteger {
                            flag: "--prom-rate-limit-burst",
                            raw: v,
                        })?);
                }
                "--i-accept-plaintext-udp" => {
                    i_accept_plaintext_udp = true;
                }
                "--secure-udp-i-accept-recovery-on-unauthenticated-transport" => {
                    i_accept_recovery_on_secure_udp = true;
                }
                "--plaintext-udp-i-accept-recovery-on-unauthenticated-transport" => {
                    i_accept_recovery_on_plaintext_udp = true;
                }
                "--i-accept-secure-udp-non-loopback" => {
                    i_accept_secure_udp_non_loopback = true;
                }
                "--allow-cross-namespace-agents" => {
                    allow_cross_namespace_agents = true;
                }
                "--strict-namespace-check" => {
                    strict_namespace_check = true;
                }
                "--recovery-audit-file" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-audit-file"))?;
                    recovery_audit_file = Some(PathBuf::from(v));
                }
                "--recovery-audit-max-bytes" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-audit-max-bytes"))?;
                    let parsed = parse_u64("--recovery-audit-max-bytes", &v)?;
                    if parsed < MIN_RECOVERY_AUDIT_MAX_BYTES {
                        return Err(ConfigError::RecoveryAuditMaxBytesTooLow {
                            value: parsed,
                            min: MIN_RECOVERY_AUDIT_MAX_BYTES,
                        });
                    }
                    recovery_audit_max_bytes = Some(parsed);
                }
                "--recovery-audit-sync-every" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-audit-sync-every"))?;
                    let parsed = v.parse::<u32>().map_err(|_| ConfigError::BadInteger {
                        flag: "--recovery-audit-sync-every",
                        raw: v.clone(),
                    })?;
                    if parsed == 0 {
                        return Err(ConfigError::BadInteger {
                            flag: "--recovery-audit-sync-every",
                            raw: v,
                        });
                    }
                    recovery_audit_sync_every = Some(parsed);
                }
                "--recovery-capture-stdio" => {
                    recovery_capture_stdio = true;
                }
                "--recovery-capture-bytes" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-capture-bytes"))?;
                    recovery_capture_bytes =
                        Some(v.parse::<u32>().map_err(|_| ConfigError::BadInteger {
                            flag: "--recovery-capture-bytes",
                            raw: v,
                        })?);
                }
                "--iteration-budget-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--iteration-budget-ms"))?;
                    iteration_budget_ms = Some(parse_u64("--iteration-budget-ms", &v)?);
                }
                "--scrape-budget-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--scrape-budget-ms"))?;
                    scrape_budget_ms = Some(parse_u64("--scrape-budget-ms", &v)?);
                }
                "--audit-fsync-budget-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--audit-fsync-budget-ms"))?;
                    let parsed = v.parse::<u32>().map_err(|_| ConfigError::BadInteger {
                        flag: "--audit-fsync-budget-ms",
                        raw: v.clone(),
                    })?;
                    if parsed == 0 {
                        return Err(ConfigError::BadInteger {
                            flag: "--audit-fsync-budget-ms",
                            raw: v,
                        });
                    }
                    audit_fsync_budget_ms = Some(parsed);
                }
                "--audit-sync-interval-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--audit-sync-interval-ms"))?;
                    audit_sync_interval_ms =
                        Some(v.parse::<u32>().map_err(|_| ConfigError::BadInteger {
                            flag: "--audit-sync-interval-ms",
                            raw: v,
                        })?);
                }
                "--audit-rotation-budget-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--audit-rotation-budget-ms"))?;
                    let parsed = v.parse::<u32>().map_err(|_| ConfigError::BadInteger {
                        flag: "--audit-rotation-budget-ms",
                        raw: v.clone(),
                    })?;
                    if parsed == 0 {
                        return Err(ConfigError::BadInteger {
                            flag: "--audit-rotation-budget-ms",
                            raw: v,
                        });
                    }
                    if parsed > MAX_AUDIT_ROTATION_BUDGET_MS {
                        return Err(ConfigError::AuditRotationBudgetTooLarge {
                            value: parsed as u64,
                            max: MAX_AUDIT_ROTATION_BUDGET_MS as u64,
                        });
                    }
                    audit_rotation_budget_ms = Some(parsed);
                }
                other => return Err(ConfigError::UnknownFlag(other.to_string())),
            }
        }

        let socket = socket.ok_or(ConfigError::MissingRequired("--socket"))?;
        let threshold_ms = threshold_ms.ok_or(ConfigError::MissingRequired("--threshold-ms"))?;

        if threshold_ms < MIN_THRESHOLD_MS {
            return Err(ConfigError::ThresholdTooLow {
                value: threshold_ms,
                min: MIN_THRESHOLD_MS,
            });
        }

        // /metrics has no anonymous access.  A reverse proxy doing TLS
        // termination + auth is fine — but it must still inject the bearer
        // token on the upstream scrape, which means the operator owns the
        // token file regardless of the network topology.
        if prom_addr.is_some() && prom_token_file.is_none() {
            return Err(ConfigError::PromAddrRequiresToken);
        }
        if prom_token_file.is_some() && prom_addr.is_none() {
            return Err(ConfigError::MutuallyExclusive {
                a: "--prom-token-file",
                b: "(missing --prom-addr)",
            });
        }

        let shutdown_grace_ms = shutdown_grace_ms.unwrap_or(DEFAULT_SHUTDOWN_GRACE_MS);
        if shutdown_grace_ms < MIN_SHUTDOWN_GRACE_MS {
            return Err(ConfigError::ShutdownGraceTooLow {
                value: shutdown_grace_ms,
                min: MIN_SHUTDOWN_GRACE_MS,
            });
        }

        let recovery_debounce =
            Duration::from_millis(recovery_debounce_ms.unwrap_or(DEFAULT_RECOVERY_DEBOUNCE_MS));

        let recovery_capture_bytes_resolved =
            recovery_capture_bytes.unwrap_or(DEFAULT_RECOVERY_CAPTURE_BYTES);
        if recovery_capture_bytes_resolved < MIN_RECOVERY_CAPTURE_BYTES {
            return Err(ConfigError::RecoveryCaptureBytesTooLow {
                value: recovery_capture_bytes_resolved,
                min: MIN_RECOVERY_CAPTURE_BYTES,
            });
        }
        if recovery_capture_bytes_resolved > MAX_RECOVERY_CAPTURE_BYTES {
            return Err(ConfigError::RecoveryCaptureBytesTooLarge {
                value: recovery_capture_bytes_resolved,
                max: MAX_RECOVERY_CAPTURE_BYTES,
            });
        }

        // Capture is meaningless without a recovery command. Reject the flag
        // at parse time so a misconfiguration surfaces at startup rather than
        // hiding silently in a runbook.
        if recovery_capture_stdio && recovery_exec_cmd.is_none() && recovery_exec_file.is_none() {
            return Err(ConfigError::RecoveryCaptureRequiresRecovery);
        }

        // H2 mitigation — recovery commands are operator-controlled actions
        // (`kill -9 {pid}`, `systemctl restart agent@{pid}.service`).  UDP
        // transports cannot attest the sending process; a holder of the AEAD
        // key can forge a beat for any pid, then stop sending to trigger the
        // recovery command against that pid.  Refuse to start when both a UDP
        // listener and a recovery command are configured unless the operator
        // passes the matching per-listener flag.
        //
        // Trust is per-listener: --secure-udp-i-accept-recovery-on-
        // unauthenticated-transport covers the secure-UDP listener only;
        // --plaintext-udp-i-accept-recovery-on-unauthenticated-transport
        // covers the plaintext-UDP listener only. They are independent.
        let any_recovery_configured = recovery_exec_cmd.is_some() || recovery_exec_file.is_some();
        if any_recovery_configured {
            if let Some(port) = udp_port {
                let bind_ip =
                    udp_bind_addr.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                let udp_addr = format!("{bind_ip}:{port}");
                // Is a secure-UDP listener being configured (any key file)?
                let secure_udp = secure_key_file.is_some()
                    || accepted_key_file.is_some()
                    || master_key_file.is_some();
                // Is a plaintext-UDP listener being configured (no keys, explicit opt-in)?
                let plaintext_udp = i_accept_plaintext_udp && !secure_udp;

                if secure_udp && !i_accept_recovery_on_secure_udp {
                    return Err(ConfigError::RecoveryRequiresAuthenticatedTransport { udp_addr });
                }
                if plaintext_udp && !i_accept_recovery_on_plaintext_udp {
                    return Err(ConfigError::RecoveryRequiresAuthenticatedTransport { udp_addr });
                }
            }
        }

        // H4 mitigation — secure-UDP replay state is bounded and fail-closed
        // for unknown senders at capacity. Loopback keeps that admission
        // pressure local; any reachable network must be explicitly accepted.
        // Defers to the runtime layer for the implicit "no --udp-bind-addr +
        // secure-UDP keys → loopback default" case (resolved in main.rs).
        if let Some(port) = udp_port {
            let secure_udp = secure_key_file.is_some()
                || accepted_key_file.is_some()
                || master_key_file.is_some();
            if secure_udp {
                if let Some(ip) = udp_bind_addr {
                    if !ip.is_loopback() && !i_accept_secure_udp_non_loopback {
                        return Err(ConfigError::SecureUdpRequiresLoopbackBind {
                            udp_addr: format!("{ip}:{port}"),
                        });
                    }
                }
            }
        }

        // --iteration-budget-ms resolution and bounds check.  The default
        // lives in the exporter so that production builds without metrics
        // still link the constant for tests.  Bounds reject the noise-floor
        // case (every iteration overruns) and the never-fires case (budget
        // overlaps --self-watchdog-secs).
        let iteration_budget = match iteration_budget_ms {
            Some(ms) => {
                if !(MIN_ITERATION_BUDGET_MS..=MAX_ITERATION_BUDGET_MS).contains(&ms) {
                    return Err(ConfigError::IterationBudgetOutOfRange {
                        value: ms,
                        min: MIN_ITERATION_BUDGET_MS,
                        max: MAX_ITERATION_BUDGET_MS,
                    });
                }
                Duration::from_millis(ms)
            }
            None => crate::exporter::DEFAULT_ITERATION_BUDGET,
        };

        // --scrape-budget-ms — same bounds story as --iteration-budget-ms:
        // reject the noise-floor case (overlaps serve_pending's own 200 ms
        // structural cap) and the never-fires case (overlaps the self-
        // watchdog).  The two budgets are independent: scrape-storm alarms
        // fire on scrape_budget; beat-path alarms fire on iteration_budget.
        let scrape_budget = match scrape_budget_ms {
            Some(ms) => {
                if !(MIN_SCRAPE_BUDGET_MS..=MAX_SCRAPE_BUDGET_MS).contains(&ms) {
                    return Err(ConfigError::ScrapeBudgetOutOfRange {
                        value: ms,
                        min: MIN_SCRAPE_BUDGET_MS,
                        max: MAX_SCRAPE_BUDGET_MS,
                    });
                }
                Duration::from_millis(ms)
            }
            None => crate::exporter::DEFAULT_SCRAPE_BUDGET,
        };

        let eviction_scan_window_resolved = match eviction_scan_window {
            Some(v) => {
                if !(MIN_EVICTION_SCAN_WINDOW..=MAX_EVICTION_SCAN_WINDOW).contains(&v) {
                    return Err(ConfigError::EvictionScanWindowOutOfRange {
                        value: v,
                        min: MIN_EVICTION_SCAN_WINDOW,
                        max: MAX_EVICTION_SCAN_WINDOW,
                    });
                }
                v
            }
            None => DEFAULT_EVICTION_SCAN_WINDOW,
        };
        let tracker_capacity_resolved = match tracker_capacity {
            Some(v) => {
                if !(1..=MAX_CAPACITY).contains(&v) {
                    return Err(ConfigError::TrackerCapacityOutOfRange {
                        value: v,
                        min: 1,
                        max: MAX_CAPACITY,
                    });
                }
                v
            }
            None => DEFAULT_CAPACITY,
        };

        // H7: reject platform-restricted clock sources (`boottime` on
        // non-Linux, `monotonic-raw` on non-macOS) before any listener
        // bind so the operator sees the misconfiguration immediately.
        if let Some(src) = clock_source {
            if src.clk_id().is_none() {
                return Err(ConfigError::ClockSourceUnsupported {
                    source: src,
                    platform: std::env::consts::OS,
                });
            }
        }

        // --read-timeout-ms ceiling. The idle Poll stage spends ≈ one blocking
        // UDS recv(2) of this duration. The static cap protects the
        // prometheus-enabled per-stage Poll abort; a configured
        // --self-watchdog-secs can be smaller, so lower the cap again to half
        // of that full-iteration deadline.
        let read_timeout_ms_resolved = read_timeout_ms.unwrap_or(DEFAULT_READ_TIMEOUT_MS);
        let read_timeout_ceiling_ms = max_read_timeout_ms(self_watchdog);
        if read_timeout_ms_resolved > read_timeout_ceiling_ms {
            return Err(ConfigError::ReadTimeoutTooLarge {
                value: read_timeout_ms_resolved,
                max: read_timeout_ceiling_ms,
            });
        }
        // --read-timeout-ms floor. A `0` becomes `Duration::ZERO`, which
        // `UnixDatagram::set_read_timeout` rejects (`cannot set a 0 duration
        // timeout`), failing the bind and preventing the observer from
        // starting. The default is reached by omitting the flag, never by `0`.
        if read_timeout_ms_resolved < MIN_READ_TIMEOUT_MS {
            return Err(ConfigError::ReadTimeoutTooLow {
                value: read_timeout_ms_resolved,
                min: MIN_READ_TIMEOUT_MS,
            });
        }

        Ok(Config {
            socket,
            threshold: Duration::from_millis(threshold_ms),
            recovery_exec_cmd,
            recovery_exec_file,
            recovery_debounce,
            recovery_env,
            recovery_inherit_env,
            file_export,
            export_file_max_bytes,
            export_file_sync_every,
            prom_addr,
            prom_token_file,
            shutdown_after: shutdown_after_secs.map(Duration::from_secs),
            recovery_timeout: recovery_timeout_ms.map(Duration::from_millis),
            shutdown_grace: Duration::from_millis(shutdown_grace_ms),
            socket_mode: socket_mode.unwrap_or(DEFAULT_SOCKET_MODE),
            read_timeout: Duration::from_millis(read_timeout_ms_resolved),
            tracker_capacity: tracker_capacity_resolved,
            tracker_eviction_policy: tracker_eviction_policy.unwrap_or(EvictionPolicy::Strict),
            eviction_scan_window: eviction_scan_window_resolved,
            udp_port,
            udp_bind_addr,
            secure_key_file,
            accepted_key_file,
            master_key_file,
            max_beat_rate: match max_beat_rate {
                None => Some(super::types::DEFAULT_MAX_BEAT_RATE),
                Some(0) => None,
                Some(n) => Some(n),
            },
            global_beat_rate: global_beat_rate.unwrap_or(super::types::DEFAULT_GLOBAL_BEAT_RATE),
            global_beat_burst: global_beat_burst.unwrap_or(super::types::DEFAULT_GLOBAL_BEAT_BURST),
            uds_rcvbuf_bytes: uds_rcvbuf_bytes.unwrap_or(super::types::DEFAULT_UDS_RCVBUF_BYTES),
            heartbeat_file,
            self_watchdog,
            hw_watchdog,
            prom_rate_limit_per_sec: prom_rate_limit_per_sec
                .unwrap_or(DEFAULT_PROM_RATE_LIMIT_PER_SEC),
            prom_rate_limit_burst: prom_rate_limit_burst.unwrap_or(DEFAULT_PROM_RATE_LIMIT_BURST),
            i_accept_plaintext_udp,
            i_accept_recovery_on_secure_udp,
            i_accept_recovery_on_plaintext_udp,
            i_accept_secure_udp_non_loopback,
            allow_cross_namespace_agents,
            strict_namespace_check,
            recovery_audit_file,
            recovery_audit_max_bytes,
            recovery_audit_sync_every: recovery_audit_sync_every.unwrap_or(1),
            recovery_capture_stdio,
            recovery_capture_bytes: recovery_capture_bytes_resolved,
            iteration_budget,
            scrape_budget,
            audit_fsync_budget_ms: audit_fsync_budget_ms
                .unwrap_or(super::types::DEFAULT_AUDIT_FSYNC_BUDGET_MS),
            audit_sync_interval_ms: audit_sync_interval_ms
                .unwrap_or(super::types::DEFAULT_AUDIT_SYNC_INTERVAL_MS),
            audit_rotation_budget_ms: audit_rotation_budget_ms
                .unwrap_or(super::types::DEFAULT_AUDIT_ROTATION_BUDGET_MS),
            #[cfg(feature = "test-hooks")]
            inject_wedge_ms,
            clock_source: clock_source.unwrap_or(ClockSource::Monotonic),
            signal_handler_mode: signal_handler_mode.unwrap_or_default(),
        })
    }
}
