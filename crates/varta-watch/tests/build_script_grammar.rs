//! Unit tests for the `varta-watch` `build.rs` KEY=VALUE parser.
//!
//! Imports the parser module directly via `#[path = "../build.rs"]` so
//! there is a single source of truth for the grammar AND for these
//! tests.  Build scripts cannot be invoked by `cargo test`, but their
//! source is plain Rust and can be `#[path]`-included into a test
//! crate.

#[path = "../build.rs"]
#[allow(dead_code, unused_imports)]
mod build_inner;

use build_inner::parse_kv;

const MINIMAL: &str = "\
socket = /run/varta/varta.sock
threshold_ms = 5000
";

#[test]
fn parses_minimal_required_keys() {
    let parsed = parse_kv(MINIMAL).expect("parse minimal");
    assert!(parsed.singletons.contains_key("socket"));
    assert!(parsed.singletons.contains_key("threshold_ms"));
}

#[test]
fn rejects_unknown_key() {
    let bad = format!("{MINIMAL}not_a_real_key = 1\n");
    let err = parse_kv(&bad).expect_err("unknown key must error");
    assert!(err.contains("unknown key"), "got: {err}");
}

#[test]
fn rejects_missing_required_key_socket() {
    let bad = "threshold_ms = 5000\n";
    let err = parse_kv(bad).expect_err("missing socket must error");
    assert!(err.contains("socket"), "got: {err}");
}

#[test]
fn rejects_missing_required_key_threshold_ms() {
    let bad = "socket = /tmp/x.sock\n";
    let err = parse_kv(bad).expect_err("missing threshold_ms must error");
    assert!(err.contains("threshold_ms"), "got: {err}");
}

#[test]
fn rejects_threshold_below_minimum() {
    let bad = "socket = /tmp/x.sock\nthreshold_ms = 1\n";
    let err = parse_kv(bad).expect_err("threshold below minimum must error");
    assert!(err.contains("threshold_ms"), "got: {err}");
}

#[test]
fn comments_and_blank_lines_are_ignored() {
    let with_comments = "\
# this is a comment

socket = /tmp/x.sock

# another comment
threshold_ms = 1000
";
    let parsed = parse_kv(with_comments).expect("parse with comments");
    assert_eq!(parsed.singletons.get("socket").unwrap(), "/tmp/x.sock");
    assert_eq!(parsed.singletons.get("threshold_ms").unwrap(), "1000");
}

#[test]
fn duplicate_singleton_key_is_rejected() {
    let bad = "\
socket = /tmp/a
socket = /tmp/b
threshold_ms = 5000
";
    let err = parse_kv(bad).expect_err("duplicate singleton must error");
    assert!(err.contains("duplicate"), "got: {err}");
}

#[test]
fn list_key_accumulates() {
    let cfg = "\
socket = /tmp/x.sock
threshold_ms = 5000
recovery_env = HOME=/root
recovery_env = LANG=C.UTF-8
";
    let parsed = parse_kv(cfg).expect("parse list");
    let envs = parsed.lists.get("recovery_env").expect("recovery_env list");
    assert_eq!(envs.len(), 2);
    assert_eq!(envs[0], "HOME=/root");
    assert_eq!(envs[1], "LANG=C.UTF-8");
}

#[test]
fn recovery_env_missing_equals_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
recovery_env = HOME
";
    let err = parse_kv(bad).expect_err("recovery_env without '=' must error");
    assert!(err.contains("recovery_env"), "got: {err}");
}

#[test]
fn recovery_env_empty_key_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
recovery_env = =/root
";
    let err = parse_kv(bad).expect_err("recovery_env with empty key must error");
    assert!(err.contains("recovery_env"), "got: {err}");
}

#[test]
fn recovery_env_nul_byte_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
recovery_env = HOME=/root\0bad
";
    let err = parse_kv(bad).expect_err("recovery_env with NUL must error");
    assert!(err.contains("recovery_env"), "got: {err}");
}

#[test]
fn out_of_range_iteration_budget_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
iteration_budget_ms = 5
";
    let err = parse_kv(bad).expect_err("budget out of range must error");
    assert!(err.contains("iteration_budget_ms"), "got: {err}");
}

#[test]
fn recovery_inherit_env_is_accepted_as_bool() {
    let cfg = "\
socket = /tmp/x.sock
threshold_ms = 5000
recovery_inherit_env = true
";
    let parsed = parse_kv(cfg).expect("parse recovery_inherit_env=true");
    assert_eq!(
        parsed
            .singletons
            .get("recovery_inherit_env")
            .map(String::as_str),
        Some("true")
    );
}

#[test]
fn recovery_inherit_env_default_is_absent() {
    let cfg = "\
socket = /tmp/x.sock
threshold_ms = 5000
";
    let parsed = parse_kv(cfg).expect("parse without recovery_inherit_env");
    assert!(!parsed.singletons.contains_key("recovery_inherit_env"));
}

#[test]
fn invalid_bool_value_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
strict_namespace_check = maybe
";
    let err = parse_kv(bad).expect_err("invalid bool value must error");
    assert!(err.contains("strict_namespace_check"), "got: {err}");
}

#[test]
fn invalid_clock_source_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
clock_source = bootime
";
    let err = parse_kv(bad).expect_err("invalid clock source must error");
    assert!(err.contains("clock_source"), "got: {err}");
}

#[test]
fn invalid_eviction_policy_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
tracker_eviction_policy = balance
";
    let err = parse_kv(bad).expect_err("invalid eviction policy must error");
    assert!(err.contains("tracker_eviction_policy"), "got: {err}");
}

#[test]
fn recovery_cmd_is_rejected_as_unknown_key() {
    // `recovery_cmd` was removed; operators must use `recovery_exec_cmd`.
    // The config-file parser must reject it so a stale config file is
    // surfaced at build time rather than silently ignored.
    let bad = format!("{MINIMAL}recovery_cmd = systemctl restart myapp\n");
    let err = parse_kv(&bad).expect_err("removed key recovery_cmd must error");
    assert!(err.contains("unknown key"), "got: {err}");
}

#[test]
fn recovery_cmd_file_is_rejected_as_unknown_key() {
    let bad = format!("{MINIMAL}recovery_cmd_file = /etc/varta/cmd\n");
    let err = parse_kv(&bad).expect_err("removed key recovery_cmd_file must error");
    assert!(err.contains("unknown key"), "got: {err}");
}

#[test]
fn self_watchdog_secs_zero_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
self_watchdog_secs = 0
";
    let err = parse_kv(bad).expect_err("self_watchdog_secs=0 must error");
    assert!(err.contains("self_watchdog_secs"), "got: {err}");
}

#[test]
fn audit_rotation_budget_ms_above_max_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
audit_rotation_budget_ms = 251
";
    let err = parse_kv(bad).expect_err("audit_rotation_budget_ms=251 must error");
    assert!(err.contains("audit_rotation_budget_ms"), "got: {err}");
}

#[test]
fn read_timeout_ms_above_max_is_rejected() {
    // The runtime ceiling (Config::validate_runtime, MAX_READ_TIMEOUT_MS=1000)
    // rejects this; mirror it at build time so a sealed Class-A image cannot
    // build successfully and then fail to start.
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
read_timeout_ms = 1001
";
    let err = parse_kv(bad).expect_err("read_timeout_ms=1001 must error");
    assert!(err.contains("read_timeout_ms"), "got: {err}");
}

#[test]
fn read_timeout_ms_at_max_is_accepted() {
    let cfg = "\
socket = /tmp/x.sock
threshold_ms = 5000
read_timeout_ms = 1000
";
    parse_kv(cfg).expect("read_timeout_ms=1000 at the ceiling should parse");
}

#[test]
fn recovery_audit_sync_every_zero_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
recovery_audit_sync_every = 0
";
    let err = parse_kv(bad).expect_err("sync_every=0 must error");
    assert!(err.contains("recovery_audit_sync_every"), "got: {err}");
}

#[test]
fn recovery_timeout_ms_below_minimum_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
recovery_timeout_ms = 0
";
    let err = parse_kv(bad).expect_err("recovery_timeout_ms=0 must error");
    assert!(err.contains("recovery_timeout_ms"), "got: {err}");
}

#[test]
fn recovery_audit_max_bytes_below_minimum_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
recovery_audit_max_bytes = 100
";
    let err = parse_kv(bad).expect_err("recovery_audit_max_bytes=100 must error");
    assert!(err.contains("recovery_audit_max_bytes"), "got: {err}");
}

#[test]
fn tracker_capacity_zero_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
tracker_capacity = 0
";
    let err = parse_kv(bad).expect_err("tracker_capacity=0 must error");
    assert!(err.contains("tracker_capacity"), "got: {err}");
}

#[test]
fn tracker_capacity_above_max_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
tracker_capacity = 4097
";
    let err = parse_kv(bad).expect_err("tracker_capacity above max must error");
    assert!(err.contains("tracker_capacity"), "got: {err}");
}

#[test]
fn recovery_secure_udp_without_accept_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
udp_port = 8443
secure_key_file = /etc/varta/agent.key
recovery_exec_cmd = /usr/bin/true
";
    let err = parse_kv(bad).expect_err("recovery on secure UDP must require accept key");
    assert!(
        err.contains("i_accept_recovery_on_secure_udp"),
        "got: {err}"
    );
}

#[test]
fn recovery_secure_udp_with_accept_is_allowed() {
    let cfg = "\
socket = /tmp/x.sock
threshold_ms = 5000
udp_port = 8443
secure_key_file = /etc/varta/agent.key
recovery_exec_cmd = /usr/bin/true
i_accept_recovery_on_secure_udp = true
";
    parse_kv(cfg).expect("explicitly accepted secure-UDP recovery should parse");
}

#[test]
fn secure_udp_non_loopback_without_accept_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
udp_port = 8443
udp_bind_addr = 0.0.0.0
secure_key_file = /etc/varta/agent.key
";
    let err = parse_kv(bad).expect_err("non-loopback secure UDP must require accept key");
    assert!(
        err.contains("i_accept_secure_udp_non_loopback"),
        "got: {err}"
    );
}

#[test]
fn secure_udp_loopback_without_accept_is_allowed() {
    let cfg = "\
socket = /tmp/x.sock
threshold_ms = 5000
udp_port = 8443
udp_bind_addr = 127.0.0.1
secure_key_file = /etc/varta/agent.key
";
    parse_kv(cfg).expect("loopback secure UDP should not require non-loopback accept key");
}

#[test]
fn udp_port_without_secure_key_is_rejected_in_compile_time_config() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
udp_port = 8443
";
    let err = parse_kv(bad).expect_err("compile-time UDP must have a secure key source");
    assert!(err.contains("secure_key_file"), "got: {err}");
}

#[test]
fn recovery_capture_stdio_without_recovery_is_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
recovery_capture_stdio = true
";
    let err = parse_kv(bad).expect_err("capture without recovery must error");
    assert!(err.contains("recovery_capture_stdio"), "got: {err}");
}

#[test]
fn duplicate_recovery_sources_are_rejected() {
    let bad = "\
socket = /tmp/x.sock
threshold_ms = 5000
recovery_exec_cmd = /usr/bin/true
recovery_exec_file = /etc/varta/recover.cmd
";
    let err = parse_kv(bad).expect_err("duplicate recovery sources must error");
    assert!(err.contains("mutually exclusive"), "got: {err}");
}
