#[cfg(feature = "prometheus-exporter")]
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::clock::ClockSource;
use crate::tracker::MAX_CAPACITY;

use super::types::{
    Config, ConfigError, DEFAULT_PROM_RATE_LIMIT_BURST, DEFAULT_PROM_RATE_LIMIT_PER_SEC,
    DEFAULT_SHUTDOWN_GRACE_MS, MIN_SHUTDOWN_GRACE_MS, MIN_THRESHOLD_MS,
};
use super::validate::{parse_exec_cmd, validate_secret_file};

fn args(toks: &[&str]) -> Vec<String> {
    toks.iter().map(|s| s.to_string()).collect()
}

#[test]
fn parses_minimal_required_flags() {
    let cfg = Config::from_args(args(&["--socket", "/tmp/x.sock", "--threshold-ms", "250"]))
        .expect("parse");
    assert_eq!(cfg.socket, PathBuf::from("/tmp/x.sock"));
    assert_eq!(cfg.threshold, Duration::from_millis(250));
    assert_eq!(cfg.recovery_debounce, Duration::from_millis(1000));
    assert_eq!(cfg.socket_mode, 0o600);
    assert!(cfg.recovery_exec_cmd.is_none());
    assert!(cfg.prom_addr.is_none());
}

/// `--recovery-cmd` is a removed flag; the parser must reject it with
/// `RemovedFlag` and point the operator to `--recovery-exec`.
#[test]
fn recovery_cmd_flag_is_rejected_as_removed() {
    match Config::from_args(args(&[
        "--socket",
        "/tmp/x.sock",
        "--threshold-ms",
        "100",
        "--recovery-cmd",
        "foo",
    ])) {
        Err(ConfigError::RemovedFlag { flag, replacement }) => {
            assert_eq!(flag, "--recovery-cmd");
            assert!(
                replacement.contains("--recovery-exec"),
                "replacement hint must mention --recovery-exec, got: {replacement}"
            );
        }
        other => panic!("expected RemovedFlag for --recovery-cmd, got {other:?}"),
    }
}

/// `--i-accept-shell-risk` is a removed flag; the parser must reject it.
#[test]
fn i_accept_shell_risk_flag_is_rejected_as_removed() {
    match Config::from_args(args(&[
        "--socket",
        "/tmp/x.sock",
        "--threshold-ms",
        "100",
        "--i-accept-shell-risk",
    ])) {
        Err(ConfigError::RemovedFlag { .. }) => {}
        other => panic!("expected RemovedFlag for --i-accept-shell-risk, got {other:?}"),
    }
}

/// `--read-timeout-ms` must be rejected once it would exceed the Poll-stage
/// self-watchdog abort. The idle Poll stage blocks ≈ read_timeout in one UDS
/// `recv(2)`, so a timeout at/above the abort threshold self-aborts a healthy
/// idle observer. Regression for the previously-unbounded `--read-timeout-ms`.
#[test]
fn read_timeout_above_ceiling_is_rejected() {
    let too_big = super::types::MAX_READ_TIMEOUT_MS + 1;
    let too_big_s = too_big.to_string();
    match Config::from_args(args(&[
        "--socket",
        "/tmp/x.sock",
        "--threshold-ms",
        "100",
        "--read-timeout-ms",
        &too_big_s,
    ])) {
        Err(ConfigError::ReadTimeoutTooLarge { value, max }) => {
            assert_eq!(value, too_big);
            assert_eq!(max, super::types::MAX_READ_TIMEOUT_MS);
            assert!(
                max < super::types::POLL_STAGE_ABORT_MS,
                "the ceiling must stay below the Poll-stage self-watchdog abort"
            );
        }
        other => panic!("expected ReadTimeoutTooLarge, got {other:?}"),
    }

    // The ceiling value itself parses cleanly.
    let max_s = super::types::MAX_READ_TIMEOUT_MS.to_string();
    let cfg = Config::from_args(args(&[
        "--socket",
        "/tmp/x.sock",
        "--threshold-ms",
        "100",
        "--read-timeout-ms",
        &max_s,
    ]))
    .expect("ceiling value must parse");
    assert_eq!(
        cfg.read_timeout,
        Duration::from_millis(super::types::MAX_READ_TIMEOUT_MS)
    );
}

/// `--self-watchdog-secs 0` must be rejected. A zero deadline makes the
/// watchdog `process::abort()` a healthy observer on the first tick after
/// startup (host reboot under `--hw-watchdog`); help text documents
/// "Minimum 1". `0` is the disable idiom for sibling rate flags, so an
/// operator could plausibly reach for it — reject it rather than self-abort.
/// Regression for the previously-unbounded lower end of `--self-watchdog-secs`.
#[test]
fn self_watchdog_below_minimum_is_rejected() {
    match Config::from_args(args(&[
        "--socket",
        "/tmp/x.sock",
        "--threshold-ms",
        "100",
        "--self-watchdog-secs",
        "0",
    ])) {
        Err(ConfigError::SelfWatchdogTooLow { value, min }) => {
            assert_eq!(value, 0);
            assert_eq!(min, super::types::MIN_SELF_WATCHDOG_SECS);
        }
        other => panic!("expected SelfWatchdogTooLow, got {other:?}"),
    }

    // The floor value itself parses cleanly.
    let min_s = super::types::MIN_SELF_WATCHDOG_SECS.to_string();
    let cfg = Config::from_args(args(&[
        "--socket",
        "/tmp/x.sock",
        "--threshold-ms",
        "100",
        "--self-watchdog-secs",
        &min_s,
    ]))
    .expect("floor value must parse");
    assert_eq!(
        cfg.self_watchdog,
        Some(Duration::from_secs(super::types::MIN_SELF_WATCHDOG_SECS))
    );
}

/// `--audit-rotation-budget-ms` must be rejected once it would reach the
/// Maintenance-stage self-watchdog abort. `drive_audit_rotation` runs up to its
/// full budget inside the Maintenance stage every tick, so a budget at/above
/// that abort lets a normal rotation `process::abort()` a healthy observer (a
/// host reboot under `--hw-watchdog`). Regression for the previously
/// upper-unbounded `--audit-rotation-budget-ms` (only `0` was rejected).
#[test]
fn audit_rotation_budget_above_ceiling_is_rejected() {
    let too_big = super::types::MAX_AUDIT_ROTATION_BUDGET_MS + 1;
    let too_big_s = too_big.to_string();
    match Config::from_args(args(&[
        "--socket",
        "/tmp/x.sock",
        "--threshold-ms",
        "100",
        "--audit-rotation-budget-ms",
        &too_big_s,
    ])) {
        Err(ConfigError::AuditRotationBudgetTooLarge { value, max }) => {
            assert_eq!(value, u64::from(too_big));
            assert_eq!(max, u64::from(super::types::MAX_AUDIT_ROTATION_BUDGET_MS));
            assert!(
                u64::from(super::types::MAX_AUDIT_ROTATION_BUDGET_MS)
                    < super::types::MAINTENANCE_STAGE_ABORT_MS,
                "the ceiling must stay below the Maintenance-stage self-watchdog abort"
            );
        }
        other => panic!("expected AuditRotationBudgetTooLarge, got {other:?}"),
    }

    // The ceiling value itself parses cleanly.
    let max_s = super::types::MAX_AUDIT_ROTATION_BUDGET_MS.to_string();
    let cfg = Config::from_args(args(&[
        "--socket",
        "/tmp/x.sock",
        "--threshold-ms",
        "100",
        "--audit-rotation-budget-ms",
        &max_s,
    ]))
    .expect("ceiling value must parse");
    assert_eq!(
        cfg.audit_rotation_budget_ms,
        super::types::MAX_AUDIT_ROTATION_BUDGET_MS
    );

    // `0` stays rejected as `BadInteger` — the lower-bound contract is unchanged.
    assert!(matches!(
        Config::from_args(args(&[
            "--socket",
            "/tmp/x.sock",
            "--threshold-ms",
            "100",
            "--audit-rotation-budget-ms",
            "0",
        ])),
        Err(ConfigError::BadInteger {
            flag: "--audit-rotation-budget-ms",
            ..
        })
    ));
}

#[cfg(feature = "prometheus-exporter")]
#[test]
fn parses_full_flag_surface() {
    // --prom-addr now requires --prom-token-file; the file does not
    // need to exist at parse time (it's only validated when load_prom_token
    // is actually called by main()).
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--recovery-exec",
        "echo {pid}",
        "--recovery-debounce-ms",
        "750",
        "--export-file",
        "/tmp/e.log",
        "--prom-addr",
        "127.0.0.1:9090",
        "--prom-token-file",
        "/tmp/varta-prom.token",
        "--shutdown-after-secs",
        "3",
    ]))
    .expect("parse");
    assert_eq!(cfg.recovery_exec_cmd.as_deref(), Some("echo {pid}"));
    assert_eq!(cfg.recovery_debounce, Duration::from_millis(750));
    assert_eq!(cfg.file_export, Some(PathBuf::from("/tmp/e.log")));
    assert_eq!(
        cfg.prom_addr,
        Some("127.0.0.1:9090".parse::<SocketAddr>().unwrap())
    );
    assert_eq!(
        cfg.prom_token_file,
        Some(PathBuf::from("/tmp/varta-prom.token"))
    );
    assert_eq!(cfg.shutdown_after, Some(Duration::from_secs(3)));
}

#[test]
fn help_returns_help_requested() {
    match Config::from_args(args(&["--help"])) {
        Err(ConfigError::HelpRequested) => {}
        other => panic!("expected HelpRequested, got {other:?}"),
    }
}

#[test]
fn unknown_flag_is_rejected() {
    match Config::from_args(args(&["--nope"])) {
        Err(ConfigError::UnknownFlag(s)) => assert_eq!(s, "--nope"),
        other => panic!("expected UnknownFlag, got {other:?}"),
    }
}

#[test]
fn missing_required_socket_is_rejected() {
    match Config::from_args(args(&["--threshold-ms", "100"])) {
        Err(ConfigError::MissingRequired("--socket")) => {}
        other => panic!("expected MissingRequired(--socket), got {other:?}"),
    }
}

/// Every CLI flag in the catalogue must appear somewhere in the help text.
/// This replaces the former hand-written list and is automatically kept in
/// sync as new entries are added to FLAGS.
///
/// Flags gated behind features are skipped when those features are not
/// compiled in — this mirrors the parser's own `#[cfg(feature = "...")]` arms.
#[test]
fn catalogue_covers_help_text() {
    use super::flag_catalogue::{FlagKind, FLAGS};

    // Flags that intentionally do NOT appear in the help output:
    //   - test-hooks flags (never in production help)
    //   - Bool flags whose help appears under a merged heading rather than
    //     the individual --flag-name substring (none today)
    const EXEMPT_FROM_HELP: &[&str] = &["--inject-wedge-ms"];

    for spec in FLAGS {
        if spec.cli.is_empty() {
            continue;
        }
        if EXEMPT_FROM_HELP.contains(&spec.cli) {
            continue;
        }
        // Skip feature-gated flags when the feature is not compiled in.
        // We cannot gate test code on arbitrary feature strings at runtime,
        // so we enumerate the known gates explicitly.
        let skip = match spec.feature {
            "prometheus-exporter" => !cfg!(feature = "prometheus-exporter"),
            "unsafe-plaintext-udp" => !cfg!(feature = "unsafe-plaintext-udp"),
            "secure-udp" => !cfg!(feature = "secure-udp"),
            "test-hooks" => true, // always skip test-only flags
            _ => false,
        };
        if skip {
            continue;
        }
        // Bool flags with a `key` are treated as `true/false` in the config
        // file.  Check the CLI name appears in the help text.
        if matches!(spec.kind, FlagKind::Bool) {
            // Some long bool flags span multiple lines; just check the
            // leading substring that appears on the first line.
            let prefix = spec.cli;
            assert!(
                Config::HELP.contains(prefix),
                "Config::HELP missing bool flag {prefix}"
            );
        } else {
            assert!(
                Config::HELP.contains(spec.cli),
                "Config::HELP missing flag {}",
                spec.cli
            );
        }
    }
    // --help / -h is not in FLAGS (it is handled inline in the parser before
    // the flag dispatch loop) but must still appear in the help text.
    assert!(
        Config::HELP.contains("--help"),
        "Config::HELP missing --help"
    );
}

/// The catalogue must have no two entries with the same non-empty `cli` name.
#[test]
fn catalogue_has_no_duplicate_cli_names() {
    use super::flag_catalogue::FLAGS;
    let mut seen: Vec<&'static str> = Vec::new();
    for spec in FLAGS {
        if spec.cli.is_empty() {
            continue;
        }
        assert!(
            !seen.contains(&spec.cli),
            "duplicate cli name in FLAGS: {}",
            spec.cli
        );
        seen.push(spec.cli);
    }
}

/// The catalogue must have no two entries with the same non-empty `key` name.
#[test]
fn catalogue_has_no_duplicate_keys() {
    use super::flag_catalogue::FLAGS;
    let mut seen: Vec<&'static str> = Vec::new();
    for spec in FLAGS {
        if spec.key.is_empty() {
            continue;
        }
        assert!(
            !seen.contains(&spec.key),
            "duplicate key in FLAGS: {}",
            spec.key
        );
        seen.push(spec.key);
    }
}

#[test]
fn parses_recovery_timeout_ms() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--recovery-timeout-ms",
        "2500",
    ]))
    .expect("parse");
    assert_eq!(cfg.recovery_timeout, Some(Duration::from_millis(2500)));
}

#[test]
fn recovery_timeout_omitted_is_none() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    assert!(cfg.recovery_timeout.is_none());
}

#[test]
fn parses_socket_mode_octal() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--socket-mode",
        "660",
    ]))
    .expect("parse");
    assert_eq!(cfg.socket_mode, 0o660);
}

#[test]
fn socket_mode_rejects_non_octal() {
    match Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--socket-mode",
        "999",
    ])) {
        Err(ConfigError::BadSocketMode(_)) => {}
        other => panic!("expected BadSocketMode, got {other:?}"),
    }
}

#[test]
fn socket_mode_accepts_0o_prefix() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--socket-mode",
        "0o640",
    ]))
    .expect("parse");
    assert_eq!(cfg.socket_mode, 0o640);
}

#[test]
fn socket_mode_accepts_uppercase_0o_prefix() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--socket-mode",
        "0O640",
    ]))
    .expect("parse");
    assert_eq!(cfg.socket_mode, 0o640);
}

#[test]
fn socket_mode_accepts_leading_zero() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--socket-mode",
        "0644",
    ]))
    .expect("parse");
    assert_eq!(cfg.socket_mode, 0o644);
}

#[test]
fn socket_mode_rejects_empty_after_prefix() {
    match Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--socket-mode",
        "0o",
    ])) {
        Err(ConfigError::BadSocketMode(raw)) => assert_eq!(raw, "0o"),
        other => panic!("expected BadSocketMode, got {other:?}"),
    }
}

#[cfg(feature = "prometheus-exporter")]
#[test]
fn prom_addr_without_token_file_is_rejected() {
    match Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--prom-addr",
        "127.0.0.1:9100",
    ])) {
        Err(ConfigError::PromAddrRequiresToken) => {}
        other => panic!("expected PromAddrRequiresToken, got {other:?}"),
    }
}

#[cfg(feature = "prometheus-exporter")]
#[test]
fn prom_token_file_without_prom_addr_is_rejected() {
    match Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--prom-token-file",
        "/dev/null",
    ])) {
        Err(ConfigError::MutuallyExclusive { a, b: _ }) => {
            assert_eq!(a, "--prom-token-file");
        }
        other => panic!("expected MutuallyExclusive(--prom-token-file, ..), got {other:?}"),
    }
}

#[test]
fn parses_shutdown_grace_ms() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--shutdown-grace-ms",
        "1500",
    ]))
    .expect("parse");
    assert_eq!(cfg.shutdown_grace, Duration::from_millis(1500));
}

#[test]
fn shutdown_grace_omitted_is_default() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    assert_eq!(
        cfg.shutdown_grace,
        Duration::from_millis(DEFAULT_SHUTDOWN_GRACE_MS)
    );
}

#[test]
fn shutdown_grace_below_minimum_is_rejected() {
    match Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--shutdown-grace-ms",
        "50",
    ])) {
        Err(ConfigError::ShutdownGraceTooLow { value, min }) => {
            assert_eq!(value, 50);
            assert_eq!(min, MIN_SHUTDOWN_GRACE_MS);
        }
        other => panic!("expected ShutdownGraceTooLow, got {other:?}"),
    }
}

#[test]
fn key_env_flag_returns_removed_flag_error() {
    match Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--key-env",
        "VARTA_KEY",
    ])) {
        Err(ConfigError::RemovedFlag { flag, replacement }) => {
            assert_eq!(flag, "--key-env");
            assert!(replacement.contains("--key-file"));
        }
        other => panic!("expected RemovedFlag(--key-env, ..), got {other:?}"),
    }
}

#[test]
fn parses_read_timeout_ms() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--read-timeout-ms",
        "50",
    ]))
    .expect("parse");
    assert_eq!(cfg.read_timeout, Duration::from_millis(50));
}

#[test]
fn read_timeout_omitted_is_default() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    assert_eq!(cfg.read_timeout, Duration::from_millis(100));
}

#[test]
fn read_timeout_rejects_non_numeric() {
    match Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--read-timeout-ms",
        "abc",
    ])) {
        Err(ConfigError::BadInteger { flag, .. }) => assert_eq!(flag, "--read-timeout-ms"),
        other => panic!("expected BadInteger, got {other:?}"),
    }
}

#[test]
fn threshold_zero_is_rejected() {
    match Config::from_args(args(&["--socket", "/s", "--threshold-ms", "0"])) {
        Err(ConfigError::ThresholdTooLow { value, min }) => {
            assert_eq!(value, 0);
            assert_eq!(min, MIN_THRESHOLD_MS);
        }
        other => panic!("expected ThresholdTooLow, got {other:?}"),
    }
}

#[test]
fn threshold_below_min_is_rejected() {
    match Config::from_args(args(&["--socket", "/s", "--threshold-ms", "5"])) {
        Err(ConfigError::ThresholdTooLow { value, .. }) => assert_eq!(value, 5),
        other => panic!("expected ThresholdTooLow, got {other:?}"),
    }
}

#[test]
fn threshold_at_min_is_accepted() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        &MIN_THRESHOLD_MS.to_string(),
    ]))
    .expect("parse");
    assert_eq!(cfg.threshold, Duration::from_millis(MIN_THRESHOLD_MS));
}

#[test]
fn parses_recovery_exec_cmd() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--recovery-exec",
        "/usr/bin/kill -HUP {pid}",
    ]))
    .expect("parse");
    assert!(cfg.recovery_exec_cmd.is_some());
    let mode = cfg.resolve_recovery_mode().expect("resolve").expect("some");
    #[allow(unreachable_patterns)]
    match mode {
        crate::recovery::RecoveryMode::Exec { program, args } => {
            assert_eq!(program, "/usr/bin/kill");
            assert_eq!(args, vec!["-HUP", "{pid}"]);
        }
        other => panic!("expected Exec mode, got {other:?}"),
    }
}

/// Regression: removed flags must be rejected at parse time with a helpful message
/// pointing to the replacement flag.
#[test]
fn recovery_cmd_flag_is_removed() {
    let err = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--recovery-cmd",
        "echo $1",
    ]))
    .expect_err("--recovery-cmd must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("--recovery-cmd"),
        "error must name the removed flag, got: {msg}"
    );
    assert!(
        msg.contains("--recovery-exec"),
        "error must recommend --recovery-exec, got: {msg}"
    );
}

#[test]
fn recovery_cmd_file_flag_is_removed() {
    let err = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--recovery-cmd-file",
        "/nonexistent",
    ]))
    .expect_err("--recovery-cmd-file must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("--recovery-cmd-file"),
        "error must name the removed flag, got: {msg}"
    );
    assert!(
        msg.contains("--recovery-exec"),
        "error must recommend --recovery-exec, got: {msg}"
    );
}

#[test]
fn i_accept_shell_risk_flag_is_removed() {
    let err = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--i-accept-shell-risk",
    ]))
    .expect_err("--i-accept-shell-risk must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("--i-accept-shell-risk"),
        "error must name the removed flag, got: {msg}"
    );
}

#[test]
fn exec_mode_does_not_require_shell_risk_flag() {
    // --recovery-exec is the safe path; no accept flag should be needed.
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--recovery-exec",
        "/bin/true",
    ]))
    .expect("parse");
    let mode = cfg.resolve_recovery_mode().expect("resolve").expect("some");
    #[allow(unreachable_patterns)]
    match mode {
        crate::recovery::RecoveryMode::Exec { program, .. } => {
            assert_eq!(program, "/bin/true");
        }
        other => panic!("expected Exec mode, got {other:?}"),
    }
}

#[test]
fn parses_i_accept_plaintext_udp_flag() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--i-accept-plaintext-udp",
    ]))
    .expect("parse");
    assert!(cfg.i_accept_plaintext_udp);
}

#[test]
fn i_accept_plaintext_udp_defaults_to_false() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    assert!(!cfg.i_accept_plaintext_udp);
}

#[test]
fn parses_secure_udp_i_accept_recovery_flag() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--secure-udp-i-accept-recovery-on-unauthenticated-transport",
    ]))
    .expect("parse");
    assert!(cfg.i_accept_recovery_on_secure_udp);
    assert!(!cfg.i_accept_recovery_on_plaintext_udp);
}

#[test]
fn parses_plaintext_udp_i_accept_recovery_flag() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--plaintext-udp-i-accept-recovery-on-unauthenticated-transport",
    ]))
    .expect("parse");
    assert!(!cfg.i_accept_recovery_on_secure_udp);
    assert!(cfg.i_accept_recovery_on_plaintext_udp);
}

#[test]
fn recovery_accept_flags_default_to_false() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    assert!(!cfg.i_accept_recovery_on_secure_udp);
    assert!(!cfg.i_accept_recovery_on_plaintext_udp);
}

#[test]
fn parses_allow_cross_namespace_agents_flag() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--allow-cross-namespace-agents",
    ]))
    .expect("parse");
    assert!(cfg.allow_cross_namespace_agents);
    assert!(!cfg.strict_namespace_check);
}

#[test]
fn parses_strict_namespace_check_flag() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--strict-namespace-check",
    ]))
    .expect("parse");
    assert!(cfg.strict_namespace_check);
    assert!(!cfg.allow_cross_namespace_agents);
}

#[test]
fn namespace_flags_default_to_false() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    assert!(!cfg.allow_cross_namespace_agents);
    assert!(!cfg.strict_namespace_check);
}

#[test]
fn recovery_plus_plaintext_udp_without_accept_flag_is_rejected() {
    // H2 mitigation: plaintext UDP + recovery without per-listener flag must fail.
    let err = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--i-accept-plaintext-udp",
        "--recovery-exec",
        "/bin/true",
    ]))
    .expect_err("must reject");
    match err {
        ConfigError::RecoveryRequiresAuthenticatedTransport { ref udp_addr } => {
            assert!(udp_addr.contains(":9000"), "udp_addr = {udp_addr}");
        }
        other => panic!("expected RecoveryRequiresAuthenticatedTransport, got {other:?}"),
    }
    assert!(err
        .to_string()
        .contains("--plaintext-udp-i-accept-recovery-on-unauthenticated-transport"));
}

#[test]
fn recovery_plus_secure_udp_without_accept_flag_is_rejected() {
    // H2 mitigation: secure UDP + recovery without per-listener flag must fail.
    let err = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--key-file",
        "/nonexistent-key",
        "--recovery-exec",
        "/bin/true",
    ]))
    .expect_err("must reject");
    match err {
        ConfigError::RecoveryRequiresAuthenticatedTransport { ref udp_addr } => {
            assert!(udp_addr.contains(":9000"), "udp_addr = {udp_addr}");
        }
        other => panic!("expected RecoveryRequiresAuthenticatedTransport, got {other:?}"),
    }
    assert!(err
        .to_string()
        .contains("--secure-udp-i-accept-recovery-on-unauthenticated-transport"));
}

#[test]
fn recovery_plus_plaintext_udp_with_accept_flag_succeeds() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--i-accept-plaintext-udp",
        "--recovery-exec",
        "/bin/true",
        "--plaintext-udp-i-accept-recovery-on-unauthenticated-transport",
    ]))
    .expect("parse");
    assert!(cfg.i_accept_recovery_on_plaintext_udp);
    assert!(!cfg.i_accept_recovery_on_secure_udp);
    assert_eq!(cfg.udp_port, Some(9000));
}

#[test]
fn recovery_plus_secure_udp_with_accept_flag_succeeds() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--key-file",
        "/nonexistent-key",
        "--recovery-exec",
        "/bin/true",
        "--secure-udp-i-accept-recovery-on-unauthenticated-transport",
    ]))
    .expect("parse");
    assert!(cfg.i_accept_recovery_on_secure_udp);
    assert!(!cfg.i_accept_recovery_on_plaintext_udp);
    assert_eq!(cfg.udp_port, Some(9000));
}

#[test]
fn recovery_without_udp_port_does_not_require_accept_flag() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--recovery-exec",
        "/bin/true",
    ]))
    .expect("parse");
    assert!(!cfg.i_accept_recovery_on_secure_udp);
    assert!(!cfg.i_accept_recovery_on_plaintext_udp);
    assert!(cfg.udp_port.is_none());
}

// ----- H4: secure-UDP non-loopback bind requires explicit opt-in -----

#[test]
fn parses_i_accept_secure_udp_non_loopback_flag() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--i-accept-secure-udp-non-loopback",
    ]))
    .expect("parse");
    assert!(cfg.i_accept_secure_udp_non_loopback);
}

#[test]
fn i_accept_secure_udp_non_loopback_defaults_to_false() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    assert!(!cfg.i_accept_secure_udp_non_loopback);
}

#[test]
fn secure_udp_non_loopback_without_accept_flag_is_rejected() {
    // H4: any non-loopback --udp-bind-addr + secure-UDP keys must fail.
    let err = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--udp-bind-addr",
        "0.0.0.0",
        "--key-file",
        "/nonexistent-key",
    ]))
    .expect_err("must reject");
    match err {
        ConfigError::SecureUdpRequiresLoopbackBind { ref udp_addr } => {
            assert!(udp_addr.contains("0.0.0.0:9000"), "udp_addr = {udp_addr}");
        }
        other => panic!("expected SecureUdpRequiresLoopbackBind, got {other:?}"),
    }
    let msg = err.to_string();
    assert!(
        msg.contains("--i-accept-secure-udp-non-loopback"),
        "error must name the accept flag, got: {msg}"
    );
}

#[test]
fn secure_udp_non_loopback_ipv6_unspecified_is_rejected() {
    // Defensive: ::0 (IPv6 wildcard) is not a loopback address.
    let err = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--udp-bind-addr",
        "::",
        "--key-file",
        "/nonexistent-key",
    ]))
    .expect_err("must reject ::");
    assert!(matches!(
        err,
        ConfigError::SecureUdpRequiresLoopbackBind { .. }
    ));
}

#[test]
fn secure_udp_loopback_bind_is_accepted_without_flag() {
    // 127.0.0.1 (and any 127.0.0.0/8) is the safe default.
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--udp-bind-addr",
        "127.0.0.1",
        "--key-file",
        "/nonexistent-key",
    ]))
    .expect("loopback bind must parse cleanly");
    assert_eq!(cfg.udp_port, Some(9000));
    assert!(!cfg.i_accept_secure_udp_non_loopback);
}

#[test]
fn secure_udp_ipv6_loopback_is_accepted_without_flag() {
    // ::1 is the IPv6 loopback equivalent of 127.0.0.1.
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--udp-bind-addr",
        "::1",
        "--key-file",
        "/nonexistent-key",
    ]))
    .expect("::1 bind must parse cleanly");
    assert_eq!(cfg.udp_port, Some(9000));
}

#[test]
fn secure_udp_non_loopback_with_accept_flag_succeeds() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--udp-bind-addr",
        "0.0.0.0",
        "--key-file",
        "/nonexistent-key",
        "--i-accept-secure-udp-non-loopback",
    ]))
    .expect("non-loopback with explicit opt-in must parse");
    assert!(cfg.i_accept_secure_udp_non_loopback);
    assert_eq!(cfg.udp_port, Some(9000));
}

#[test]
fn plaintext_udp_non_loopback_does_not_require_secure_udp_accept_flag() {
    // The H4 gate is specific to secure UDP — plaintext is gated by
    // --i-accept-plaintext-udp regardless of bind address.
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--udp-bind-addr",
        "0.0.0.0",
        "--i-accept-plaintext-udp",
    ]))
    .expect("plaintext UDP non-loopback must parse without secure-UDP flag");
    assert!(!cfg.i_accept_secure_udp_non_loopback);
}

#[test]
fn secure_udp_no_bind_addr_parses_cleanly() {
    // When --udp-bind-addr is omitted, the Config layer leaves it as
    // None — main.rs resolves the default (127.0.0.1 for secure UDP).
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--key-file",
        "/nonexistent-key",
    ]))
    .expect("absent bind addr must defer to runtime default");
    assert!(cfg.udp_bind_addr.is_none());
}

#[cfg(feature = "prometheus-exporter")]
#[test]
fn parses_prom_rate_limit_flags() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--prom-rate-limit-per-sec",
        "20",
        "--prom-rate-limit-burst",
        "50",
    ]))
    .expect("parse");
    assert_eq!(cfg.prom_rate_limit_per_sec, 20);
    assert_eq!(cfg.prom_rate_limit_burst, 50);
}

#[test]
fn prom_rate_limit_defaults() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    assert_eq!(cfg.prom_rate_limit_per_sec, DEFAULT_PROM_RATE_LIMIT_PER_SEC);
    assert_eq!(cfg.prom_rate_limit_burst, DEFAULT_PROM_RATE_LIMIT_BURST);
}

#[test]
fn no_recovery_flags_yields_none() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    let mode = cfg.resolve_recovery_mode().expect("resolve");
    assert!(mode.is_none());
}

#[test]
fn parse_exec_cmd_splits_whitespace() {
    let (program, args) = parse_exec_cmd("kill -HUP {pid}").expect("parse");
    assert_eq!(program, "kill");
    assert_eq!(args, vec!["-HUP", "{pid}"]);
}

#[test]
fn parse_exec_cmd_rejects_empty() {
    assert!(parse_exec_cmd("").is_err());
    assert!(parse_exec_cmd("   ").is_err());
}

#[test]
fn parses_recovery_env_repeatable() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--recovery-exec",
        "/bin/true",
        "--recovery-env",
        "FOO=bar",
        "--recovery-env",
        "BAZ=qux",
    ]))
    .expect("parse");
    assert_eq!(cfg.recovery_env, vec!["FOO=bar", "BAZ=qux"]);
}

#[test]
fn recovery_env_defaults_to_empty() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    assert!(cfg.recovery_env.is_empty());
}

#[test]
fn parses_recovery_inherit_env_flag() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--recovery-exec",
        "/bin/true",
        "--recovery-inherit-env",
    ]))
    .expect("parse");
    assert!(cfg.recovery_inherit_env, "flag must enable inherit");
}

#[test]
fn recovery_inherit_env_defaults_to_false() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    assert!(
        !cfg.recovery_inherit_env,
        "recovery_inherit_env must default to false (secure)"
    );
}

#[test]
fn parses_heartbeat_file() {
    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--heartbeat-file",
        "/tmp/varta-hb",
    ]))
    .expect("parse");
    assert_eq!(cfg.heartbeat_file, Some(PathBuf::from("/tmp/varta-hb")));
}

#[test]
fn heartbeat_file_omitted_is_none() {
    let cfg = Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
    assert!(cfg.heartbeat_file.is_none());
}

#[cfg(feature = "secure-udp")]
#[test]
fn load_secure_keys_loads_accepted_key_file_without_primary() {
    let dir = mk_tmpdir("accepted-only");
    let accepted = dir.join("accepted.keys");
    write_mode(
        &accepted,
        b"# rotation keys\n1111111111111111111111111111111111111111111111111111111111111111\n2222222222222222222222222222222222222222222222222222222222222222\n",
        0o600,
    );

    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--accepted-key-file",
        accepted.to_str().expect("utf8 path"),
    ]))
    .expect("parse");
    let keys = cfg
        .load_secure_keys()
        .expect("accepted key file should load")
        .expect("accepted key file should configure secure UDP");

    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].as_bytes(), &[0x11; 32]);
    assert_eq!(keys[1].as_bytes(), &[0x22; 32]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "secure-udp")]
#[test]
fn load_secure_keys_preserves_primary_then_accepted_order() {
    let dir = mk_tmpdir("primary-plus-accepted");
    let primary = dir.join("primary.key");
    let accepted = dir.join("accepted.keys");
    write_mode(
        &primary,
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        0o600,
    );
    write_mode(
        &accepted,
        b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\ncccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\n",
        0o600,
    );

    let cfg = Config::from_args(args(&[
        "--socket",
        "/s",
        "--threshold-ms",
        "100",
        "--udp-port",
        "9000",
        "--key-file",
        primary.to_str().expect("utf8 path"),
        "--accepted-key-file",
        accepted.to_str().expect("utf8 path"),
    ]))
    .expect("parse");
    let keys = cfg
        .load_secure_keys()
        .expect("key files should load")
        .expect("key files should configure secure UDP");

    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0].as_bytes(), &[0xaa; 32]);
    assert_eq!(keys[1].as_bytes(), &[0xbb; 32]);
    assert_eq!(keys[2].as_bytes(), &[0xcc; 32]);
    let _ = std::fs::remove_dir_all(&dir);
}

// ----- validate_secret_file tests (M2: TOCTOU hardening) -----

/// Mint a unique tempdir under `$TMPDIR` for a single test. Tests cannot
/// rely on a shared dir because some of them deliberately set permissions
/// other tests would race on.
fn mk_tmpdir(tag: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("varta-vsf-{tag}-{pid}-{nanos}"));
    std::fs::create_dir(&dir).expect("create tempdir");
    // A parallel `UnixDatagram::bind` in another test installs a
    // 0o177 umask that strips the `x` bit from new directories,
    // breaking subsequent open() inside this dir. Restore explicitly.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod tempdir");
    dir
}

fn write_mode(path: &std::path::Path, content: &[u8], mode: u32) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .expect("open mode");
    f.write_all(content).expect("write");
    // Reassert mode (umask may have masked it on create).
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set perms");
}

#[test]
fn validate_secret_file_reads_content_after_validation() {
    let dir = mk_tmpdir("happy");
    let p = dir.join("secret");
    write_mode(&p, b"hello-world\n", 0o600);
    let out = validate_secret_file(&p).expect("validate");
    assert_eq!(out, "hello-world\n");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_secret_file_rejects_symlink() {
    let dir = mk_tmpdir("sym");
    let target = dir.join("real");
    write_mode(&target, b"x", 0o600);
    let link = dir.join("link");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let err = validate_secret_file(&link).expect_err("should reject symlink");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(
        err.to_string().contains("must not be a symlink"),
        "unexpected error: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_secret_file_rejects_bad_mode() {
    let dir = mk_tmpdir("mode");
    let p = dir.join("perms");
    write_mode(&p, b"x", 0o644);
    let err = validate_secret_file(&p).expect_err("should reject 0644");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        err.to_string().contains("insecure permissions"),
        "unexpected error: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn validate_secret_file_rejects_non_regular_file() {
    // A unix-domain socket bound at a path is a non-regular inode.
    // O_NOFOLLOW lets it through (it's not a symlink) so the post-open
    // file_type check is what defends us.
    let dir = mk_tmpdir("sock");
    let p = dir.join("sock");
    let _listener = std::os::unix::net::UnixListener::bind(&p).expect("bind sock");
    // Tighten mode so we exercise the regular-file check rather than
    // the mode check.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    let err = validate_secret_file(&p).expect_err("should reject socket");
    // On platforms that block open(2) on a UDS path entirely we accept
    // either InvalidInput (our check) or whatever errno the kernel
    // returns from open(); the important property is "does not succeed".
    assert_ne!(err.kind(), std::io::ErrorKind::Other);
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_dir_all(&dir);
}

/// TOCTOU stress: race a writer that swaps the file between a
/// well-formed 0600 secret and a symlink to a sensitive path, while a
/// reader loops `validate_secret_file`. The reader must never return
/// content from the symlink target.
///
/// The test is probabilistic (relies on scheduling); marked `#[ignore]`
/// so it does not flake the normal test run. Invoke via
/// `cargo test -p varta-watch validate_secret_file_toctou_stress -- --ignored --nocapture`.
#[test]
#[ignore = "probabilistic stress test; run with --ignored"]
fn validate_secret_file_toctou_stress() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let dir = mk_tmpdir("toctou");
    let target = dir.join("file");
    let attacker_target = dir.join("attacker-content");
    write_mode(&target, b"GOOD\n", 0o600);
    write_mode(&attacker_target, b"BAD-DO-NOT-READ\n", 0o600);

    let stop = Arc::new(AtomicBool::new(false));
    let stop_w = stop.clone();
    let target_w = target.clone();
    let atk = attacker_target.clone();
    let writer = std::thread::spawn(move || {
        while !stop_w.load(Ordering::Relaxed) {
            // Try to swap GOOD ⇄ symlink-to-BAD as fast as we can.
            let tmp = target_w.with_extension("swap");
            let _ = std::fs::remove_file(&tmp);
            if std::os::unix::fs::symlink(&atk, &tmp).is_ok() {
                let _ = std::fs::rename(&tmp, &target_w);
            }
            let _ = std::fs::remove_file(&target_w);
            write_mode(&target_w, b"GOOD\n", 0o600);
        }
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    let mut iters = 0u64;
    while std::time::Instant::now() < deadline {
        // Any error is fine — race lost on the writer's swap window.
        if let Ok(s) = validate_secret_file(&target) {
            assert!(
                !s.contains("BAD"),
                "TOCTOU: validate_secret_file returned attacker content after {iters} iters"
            );
        }
        iters += 1;
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().expect("writer thread");
    eprintln!("toctou_stress: {iters} validate calls");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parses_eviction_scan_window() {
    let args = [
        "--socket",
        "/tmp/t.sock",
        "--threshold-ms",
        "100",
        "--eviction-scan-window",
        "64",
    ];
    let cfg = Config::from_args(args.iter().map(|s| s.to_string())).unwrap();
    assert_eq!(cfg.eviction_scan_window, 64);
}

#[test]
fn rejects_eviction_scan_window_zero() {
    let args = [
        "--socket",
        "/tmp/t.sock",
        "--threshold-ms",
        "100",
        "--eviction-scan-window",
        "0",
    ];
    let err = Config::from_args(args.iter().map(|s| s.to_string())).unwrap_err();
    assert!(
        matches!(
            err,
            ConfigError::EvictionScanWindowOutOfRange { value: 0, .. }
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_eviction_scan_window_above_max() {
    let args = [
        "--socket",
        "/tmp/t.sock",
        "--threshold-ms",
        "100",
        "--eviction-scan-window",
        "9999",
    ];
    let err = Config::from_args(args.iter().map(|s| s.to_string())).unwrap_err();
    assert!(
        matches!(
            err,
            ConfigError::EvictionScanWindowOutOfRange { value: 9999, .. }
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn parses_tracker_capacity_inside_bounds() {
    let args = [
        "--socket",
        "/tmp/t.sock",
        "--threshold-ms",
        "100",
        "--tracker-capacity",
        "1024",
    ];
    let cfg = Config::from_args(args.iter().map(|s| s.to_string())).unwrap();
    assert_eq!(cfg.tracker_capacity, 1024);
}

#[test]
fn rejects_tracker_capacity_zero() {
    let args = [
        "--socket",
        "/tmp/t.sock",
        "--threshold-ms",
        "100",
        "--tracker-capacity",
        "0",
    ];
    let err = Config::from_args(args.iter().map(|s| s.to_string())).unwrap_err();
    assert!(
        matches!(err, ConfigError::TrackerCapacityOutOfRange { value: 0, .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_tracker_capacity_above_max() {
    let raw = (MAX_CAPACITY + 1).to_string();
    let args = [
        "--socket".to_string(),
        "/tmp/t.sock".to_string(),
        "--threshold-ms".to_string(),
        "100".to_string(),
        "--tracker-capacity".to_string(),
        raw,
    ];
    let err = Config::from_args(args).unwrap_err();
    assert!(
        matches!(
            err,
            ConfigError::TrackerCapacityOutOfRange { value, .. } if value == MAX_CAPACITY + 1
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn clock_source_default_is_monotonic() {
    let args = ["--socket", "/tmp/t.sock", "--threshold-ms", "100"];
    let cfg = Config::from_args(args.iter().map(|s| s.to_string())).unwrap();
    assert_eq!(cfg.clock_source, ClockSource::Monotonic);
}

#[test]
fn clock_source_parses_monotonic() {
    let args = [
        "--socket",
        "/tmp/t.sock",
        "--threshold-ms",
        "100",
        "--clock-source",
        "monotonic",
    ];
    let cfg = Config::from_args(args.iter().map(|s| s.to_string())).unwrap();
    assert_eq!(cfg.clock_source, ClockSource::Monotonic);
}

#[cfg(target_os = "linux")]
#[test]
fn clock_source_parses_boottime_on_linux() {
    let args = [
        "--socket",
        "/tmp/t.sock",
        "--threshold-ms",
        "100",
        "--clock-source",
        "boottime",
    ];
    let cfg = Config::from_args(args.iter().map(|s| s.to_string())).unwrap();
    assert_eq!(cfg.clock_source, ClockSource::Boottime);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn clock_source_boottime_rejected_on_unsupported_platform() {
    let args = [
        "--socket",
        "/tmp/t.sock",
        "--threshold-ms",
        "100",
        "--clock-source",
        "boottime",
    ];
    let err = Config::from_args(args.iter().map(|s| s.to_string())).unwrap_err();
    match err {
        ConfigError::ClockSourceUnsupported { source, .. } => {
            assert_eq!(source, ClockSource::Boottime);
        }
        other => panic!("expected ClockSourceUnsupported, got {other}"),
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[test]
fn clock_source_parses_monotonic_raw_on_macos() {
    let args = [
        "--socket",
        "/tmp/t.sock",
        "--threshold-ms",
        "100",
        "--clock-source",
        "monotonic-raw",
    ];
    let cfg = Config::from_args(args.iter().map(|s| s.to_string())).unwrap();
    assert_eq!(cfg.clock_source, ClockSource::MonotonicRaw);
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
#[test]
fn clock_source_monotonic_raw_rejected_off_macos() {
    let args = [
        "--socket",
        "/tmp/t.sock",
        "--threshold-ms",
        "100",
        "--clock-source",
        "monotonic-raw",
    ];
    let err = Config::from_args(args.iter().map(|s| s.to_string())).unwrap_err();
    match err {
        ConfigError::ClockSourceUnsupported { source, .. } => {
            assert_eq!(source, ClockSource::MonotonicRaw);
        }
        other => panic!("expected ClockSourceUnsupported, got {other}"),
    }
}

#[test]
fn clock_source_rejects_unknown_value() {
    let args = [
        "--socket",
        "/tmp/t.sock",
        "--threshold-ms",
        "100",
        "--clock-source",
        "wallclock",
    ];
    let err = Config::from_args(args.iter().map(|s| s.to_string())).unwrap_err();
    match err {
        ConfigError::BadValue { flag, raw } => {
            assert_eq!(flag, "--clock-source");
            assert_eq!(raw, "wallclock");
        }
        other => panic!("expected BadValue, got {other}"),
    }
}
