//! Std-only build script for `varta-watch`.
//!
//! Two responsibilities:
//!
//! 1. **`compile-time-config` feature ON:** Read the operator's static
//!    configuration file from `$VARTA_CONFIG_FILE`, parse a tiny `KEY = VALUE`
//!    grammar with the std library only, and emit a generated Rust source
//!    (`$OUT_DIR/compile_time_config.rs`) that defines
//!    `fn build_compile_time_config() -> Config` returning a `Config` literal
//!    populated from the file.  `config.rs` `include!`-s this file under
//!    the same feature gate so the runtime binary has zero argv parsing
//!    and zero config-file parsing.
//!
//! 2. **`compile-time-config` feature OFF (default):** Write an empty stub to
//!    `$OUT_DIR/compile_time_config.rs` so `config.rs`'s feature-gated
//!    `include!` call always points at a valid file.  This keeps the build
//!    graph stable across feature permutations.
//!
//! The build script never depends on any registry crate — only `std`.  This
//! preserves the "zero registry dependencies" invariant for the production
//! crate.  See `book/src/architecture/compile-time-config.md` for the canonical
//! grammar and key catalogue.

use std::env;
use std::fs;
use std::path::PathBuf;

// Pull in FlagKind, FlagSpec, and FLAGS from the flag catalogue.  The catalogue
// is the single source of truth for both the CLI parser and the build script.
// It uses only `std`-level identifiers so it compiles cleanly here.
include!("src/config/flag_catalogue.rs");

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set by Cargo"));
    let target = out_dir.join("compile_time_config.rs");

    // Always rerun when the feature flag flips (Cargo exports
    // `CARGO_FEATURE_<UPPERCASE_FEATURE>=1` for every active feature; the
    // var is absent when the feature is off).
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_COMPILE_TIME_CONFIG");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_HOOKS");

    if env::var_os("CARGO_FEATURE_COMPILE_TIME_CONFIG").is_none() {
        // Stub: an empty file is enough — `config.rs` only includes this
        // path under `#[cfg(feature = "compile-time-config")]`, so the
        // contents are ignored in default builds.
        fs::write(&target, b"// compile-time-config disabled\n")
            .expect("write empty compile_time_config.rs stub");
        return;
    }

    // Feature active — operator must point us at a config file.
    println!("cargo:rerun-if-env-changed=VARTA_CONFIG_FILE");

    let config_path = match env::var_os("VARTA_CONFIG_FILE") {
        Some(p) => PathBuf::from(p),
        None => panic!(
            "VARTA_CONFIG_FILE must be set when building with \
             --features compile-time-config.  See \
             book/src/architecture/compile-time-config.md for the canonical \
             KEY=VALUE grammar."
        ),
    };
    println!("cargo:rerun-if-changed={}", config_path.display());

    let raw = fs::read_to_string(&config_path).unwrap_or_else(|e| {
        panic!(
            "VARTA_CONFIG_FILE={}: cannot read file: {e}",
            config_path.display()
        )
    });

    let parsed = parse_kv(&raw)
        .unwrap_or_else(|e| panic!("VARTA_CONFIG_FILE={}: {e}", config_path.display()));

    let test_hooks_active = env::var_os("CARGO_FEATURE_TEST_HOOKS").is_some();
    let rust = render_constructor(&parsed, test_hooks_active);
    fs::write(&target, rust).expect("write generated compile_time_config.rs");
}

// FlagKind, FlagSpec, and FLAGS are provided by the `include!` above.
// The catalogue replaces the former local `KeyType` / `KNOWN_KEYS` pair.
// Config-file keys are looked up by `FlagSpec::key`; CLI flags are looked
// up by `FlagSpec::cli` (used only by the runtime parser, not by build.rs).

// Parsed shape — string-keyed for simplicity.  Singleton vs list semantics
// are enforced in [`parse_kv`] using the FlagKind from the catalogue.
//
// `pub` so that the unit-test crate
// (`tests/build_script_grammar.rs`) can `#[path]`-include build.rs and
// exercise the parser without re-shipping the grammar.
#[derive(Default, Debug)]
pub struct ParsedConfig {
    pub singletons: std::collections::BTreeMap<String, String>,
    pub lists: std::collections::BTreeMap<String, Vec<String>>,
}

pub fn parse_kv(input: &str) -> Result<ParsedConfig, String> {
    let mut out = ParsedConfig::default();
    for (lineno, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k_raw, v_raw) = match line.split_once('=') {
            Some(pair) => pair,
            None => {
                return Err(format!(
                    "line {}: expected `KEY=VALUE`, got: {:?}",
                    lineno + 1,
                    line
                ));
            }
        };
        let key = k_raw.trim();
        let value = v_raw.trim();

        // Look up the key in the catalogue using the `key` field (config-file
        // form, underscored).  Entries whose `key` is empty are CLI-only flags
        // with no config-file equivalent and are not valid here.
        let spec = match FLAGS.iter().find(|s| !s.key.is_empty() && s.key == key) {
            Some(s) => s,
            None => {
                let mut catalogue = String::new();
                for s in FLAGS.iter().filter(|s| !s.key.is_empty()) {
                    catalogue.push_str(s.key);
                    catalogue.push(' ');
                }
                return Err(format!(
                    "line {}: unknown key {:?}. Accepted keys: {}",
                    lineno + 1,
                    key,
                    catalogue.trim()
                ));
            }
        };

        match spec.kind {
            FlagKind::List => {
                out.lists
                    .entry(key.to_string())
                    .or_default()
                    .push(value.to_string());
            }
            _ => {
                if out.singletons.contains_key(key) {
                    return Err(format!(
                        "line {}: duplicate singleton key {:?}",
                        lineno + 1,
                        key
                    ));
                }
                out.singletons.insert(key.to_string(), value.to_string());
            }
        }
    }

    // Required keys.
    for required in ["socket", "threshold_ms"] {
        if !out.singletons.contains_key(required) {
            return Err(format!("missing required key: {required}"));
        }
    }

    // Cheap numeric-bound checks (mirrored at runtime by `Config::validate`).
    if let Some(v) = out.singletons.get("threshold_ms") {
        let n: u64 = v
            .parse()
            .map_err(|_| format!("threshold_ms: not a valid u64: {v:?}"))?;
        if n < 10 {
            return Err(format!("threshold_ms: {n} is below the minimum (10)"));
        }
    }
    if let Some(v) = out.singletons.get("iteration_budget_ms") {
        let n: u64 = v
            .parse()
            .map_err(|_| format!("iteration_budget_ms: not a valid u64: {v:?}"))?;
        if !(50..=60_000).contains(&n) {
            return Err(format!("iteration_budget_ms: {n} out of range [50, 60000]"));
        }
    }
    if let Some(v) = out.singletons.get("scrape_budget_ms") {
        let n: u64 = v
            .parse()
            .map_err(|_| format!("scrape_budget_ms: not a valid u64: {v:?}"))?;
        if !(50..=60_000).contains(&n) {
            return Err(format!("scrape_budget_ms: {n} out of range [50, 60000]"));
        }
    }
    if let Some(v) = out.singletons.get("recovery_capture_bytes") {
        let n: u32 = v
            .parse()
            .map_err(|_| format!("recovery_capture_bytes: not a valid u32: {v:?}"))?;
        if n > 1_048_576 {
            return Err(format!(
                "recovery_capture_bytes: {n} exceeds maximum (1048576)"
            ));
        }
    }
    if let Some(v) = out.singletons.get("shutdown_grace_ms") {
        let n: u64 = v
            .parse()
            .map_err(|_| format!("shutdown_grace_ms: not a valid u64: {v:?}"))?;
        if n < 100 {
            return Err(format!("shutdown_grace_ms: {n} is below the minimum (100)"));
        }
    }
    if let Some(v) = out.singletons.get("recovery_audit_sync_every") {
        let n: u32 = v
            .parse()
            .map_err(|_| format!("recovery_audit_sync_every: not a valid u32: {v:?}"))?;
        if n == 0 {
            return Err("recovery_audit_sync_every must be >= 1".into());
        }
    }
    if let Some(v) = out.singletons.get("eviction_scan_window") {
        let n: usize = v
            .parse()
            .map_err(|_| format!("eviction_scan_window: not a valid usize: {v:?}"))?;
        if !(1..=4096).contains(&n) {
            return Err(format!("eviction_scan_window: {n} out of range [1, 4096]"));
        }
    }

    Ok(out)
}

// Render a Rust constructor that emits a `Config` literal.  All emitted
// values are escaped via `{:?}` for strings, which produces a Rust-syntax
// quoted string literal — sufficient for arbitrary UTF-8 content.
fn render_constructor(parsed: &ParsedConfig, test_hooks_active: bool) -> String {
    let mut s = String::new();
    s.push_str("// generated by build.rs from $VARTA_CONFIG_FILE — do not edit\n\n");
    s.push_str("pub(crate) fn build_compile_time_config() -> crate::config::Config {\n");
    s.push_str("    use std::path::PathBuf;\n");
    s.push_str("    use std::time::Duration;\n");
    s.push_str("    crate::config::Config {\n");

    // Required.
    let socket = parsed.singletons.get("socket").expect("socket required");
    s.push_str(&format!("        socket: PathBuf::from({socket:?}),\n"));
    let threshold_ms: u64 = parsed
        .singletons
        .get("threshold_ms")
        .expect("threshold_ms required")
        .parse()
        .expect("threshold_ms validated");
    s.push_str(&format!(
        "        threshold: Duration::from_millis({threshold_ms}),\n"
    ));

    // Optionals with defaults — read each accepted key and emit either the
    // parsed value or the documented default.
    emit_option_string(&mut s, parsed, "recovery_cmd");
    emit_option_string(&mut s, parsed, "recovery_exec_cmd");
    emit_option_path(&mut s, parsed, "recovery_cmd_file");
    emit_option_path(&mut s, parsed, "recovery_exec_file");
    let debounce_ms: u64 = singleton_u64(parsed, "recovery_debounce_ms", 1000);
    s.push_str(&format!(
        "        recovery_debounce: Duration::from_millis({debounce_ms}),\n"
    ));
    // recovery_env list
    let envs = parsed.lists.get("recovery_env");
    if let Some(list) = envs {
        s.push_str("        recovery_env: vec![");
        for v in list {
            s.push_str(&format!("{v:?}.to_string(), "));
        }
        s.push_str("],\n");
    } else {
        s.push_str("        recovery_env: Vec::new(),\n");
    }
    emit_option_path(&mut s, parsed, "file_export");
    emit_option_u64(&mut s, parsed, "export_file_max_bytes");
    let export_sync_every: u32 = singleton_u32(parsed, "export_file_sync_every", 0);
    s.push_str(&format!(
        "        export_file_sync_every: {export_sync_every},\n"
    ));
    // prom_addr / prom_token_file etc. — these fields exist on Config
    // unconditionally, but the prometheus-exporter feature is mutually
    // exclusive with compile-time-config (compile_error in lib.rs), so the
    // values are unreachable at runtime.  Emit `None` / defaults.
    s.push_str("        prom_addr: None,\n");
    s.push_str("        prom_token_file: None,\n");
    // shutdown_after / recovery_timeout
    emit_option_secs(&mut s, parsed, "shutdown_after_secs", "shutdown_after");
    let recovery_timeout_ms_field = "recovery_timeout";
    match parsed.singletons.get("recovery_timeout_ms") {
        Some(v) => {
            let n: u64 = v.parse().expect("recovery_timeout_ms is u64");
            s.push_str(&format!(
                "        {recovery_timeout_ms_field}: Some(Duration::from_millis({n})),\n"
            ));
        }
        None => s.push_str(&format!("        {recovery_timeout_ms_field}: None,\n")),
    };
    let shutdown_grace_ms: u64 = singleton_u64(parsed, "shutdown_grace_ms", 5000);
    s.push_str(&format!(
        "        shutdown_grace: Duration::from_millis({shutdown_grace_ms}),\n"
    ));
    let socket_mode: u32 = match parsed.singletons.get("socket_mode") {
        Some(v) => parse_octal_str(v).expect("socket_mode parses as octal"),
        None => 0o600,
    };
    s.push_str(&format!("        socket_mode: 0o{socket_mode:o},\n"));
    let read_timeout_ms: u64 = singleton_u64(parsed, "read_timeout_ms", 100);
    s.push_str(&format!(
        "        read_timeout: Duration::from_millis({read_timeout_ms}),\n"
    ));
    let tracker_capacity: usize = singleton_usize(parsed, "tracker_capacity", 256);
    s.push_str(&format!("        tracker_capacity: {tracker_capacity},\n"));
    let eviction_policy = match parsed
        .singletons
        .get("tracker_eviction_policy")
        .map(String::as_str)
    {
        Some("balanced") => "crate::tracker::EvictionPolicy::Balanced",
        _ => "crate::tracker::EvictionPolicy::Strict",
    };
    s.push_str(&format!(
        "        tracker_eviction_policy: {eviction_policy},\n"
    ));
    let eviction_scan_window: usize = singleton_usize(parsed, "eviction_scan_window", 256);
    s.push_str(&format!(
        "        eviction_scan_window: {eviction_scan_window},\n"
    ));
    emit_option_u16(&mut s, parsed, "udp_port");
    match parsed.singletons.get("udp_bind_addr") {
        Some(v) => {
            // Validate at build time.
            let _: std::net::IpAddr = v
                .parse()
                .unwrap_or_else(|_| panic!("udp_bind_addr: not a valid IP address: {v:?}"));
            s.push_str(&format!(
                "        udp_bind_addr: Some({v:?}.parse::<std::net::IpAddr>().unwrap()),\n"
            ));
        }
        None => s.push_str("        udp_bind_addr: None,\n"),
    };
    emit_option_path(&mut s, parsed, "secure_key_file");
    emit_option_path(&mut s, parsed, "accepted_key_file");
    emit_option_path(&mut s, parsed, "master_key_file");
    emit_option_u32(&mut s, parsed, "max_beat_rate");
    emit_option_path(&mut s, parsed, "heartbeat_file");
    // self_watchdog
    match parsed.singletons.get("self_watchdog_secs") {
        Some(v) => {
            let n: u64 = v.parse().expect("self_watchdog_secs is u64");
            s.push_str(&format!(
                "        self_watchdog: Some(Duration::from_secs({n})),\n"
            ));
        }
        None => s.push_str("        self_watchdog: None,\n"),
    };
    emit_option_path(&mut s, parsed, "hw_watchdog");
    // prom rate limit defaults (unreachable when compile-time-config is on,
    // but the struct fields exist).
    s.push_str("        prom_rate_limit_per_sec: 5,\n");
    s.push_str("        prom_rate_limit_burst: 10,\n");
    emit_bool(&mut s, parsed, "i_accept_plaintext_udp");
    emit_bool(&mut s, parsed, "i_accept_shell_risk");
    emit_bool(&mut s, parsed, "i_accept_recovery_on_secure_udp");
    emit_bool(&mut s, parsed, "i_accept_recovery_on_plaintext_udp");
    emit_bool(&mut s, parsed, "i_accept_secure_udp_non_loopback");
    emit_bool(&mut s, parsed, "allow_cross_namespace_agents");
    emit_bool(&mut s, parsed, "strict_namespace_check");
    emit_option_path(&mut s, parsed, "recovery_audit_file");
    emit_option_u64(&mut s, parsed, "recovery_audit_max_bytes");
    let sync_every: u32 = singleton_u32(parsed, "recovery_audit_sync_every", 1);
    s.push_str(&format!(
        "        recovery_audit_sync_every: {sync_every},\n"
    ));
    emit_bool(&mut s, parsed, "recovery_capture_stdio");
    let capture_bytes: u32 = singleton_u32(parsed, "recovery_capture_bytes", 4096);
    s.push_str(&format!(
        "        recovery_capture_bytes: {capture_bytes},\n"
    ));
    let iteration_budget_ms: u64 = singleton_u64(parsed, "iteration_budget_ms", 250);
    s.push_str(&format!(
        "        iteration_budget: Duration::from_millis({iteration_budget_ms}),\n"
    ));
    let scrape_budget_ms: u64 = singleton_u64(parsed, "scrape_budget_ms", 250);
    s.push_str(&format!(
        "        scrape_budget: Duration::from_millis({scrape_budget_ms}),\n"
    ));
    let clock_source = match parsed.singletons.get("clock_source").map(String::as_str) {
        Some("boottime") => "crate::clock::ClockSource::Boottime",
        Some("monotonic-raw") | Some("monotonic_raw") => "crate::clock::ClockSource::MonotonicRaw",
        _ => "crate::clock::ClockSource::Monotonic",
    };
    if test_hooks_active {
        match parsed.singletons.get("inject_wedge_ms") {
            Some(v) => {
                let n: u64 = v.parse().expect("inject_wedge_ms is u64");
                s.push_str(&format!("        inject_wedge_ms: Some({n}),\n"));
            }
            None => s.push_str("        inject_wedge_ms: None,\n"),
        }
    }
    let signal_handler_mode = match parsed
        .singletons
        .get("signal_handler_mode")
        .map(String::as_str)
    {
        Some("libc") => "crate::signal_install::SignalHandlerMode::Libc",
        _ => "crate::signal_install::SignalHandlerMode::Direct",
    };
    s.push_str(&format!("        clock_source: {clock_source},\n"));
    s.push_str(&format!(
        "        signal_handler_mode: {signal_handler_mode},\n"
    ));
    s.push_str("    }\n");
    s.push_str("}\n");
    s
}

// --- emit helpers -----------------------------------------------------------

fn emit_option_string(s: &mut String, parsed: &ParsedConfig, key: &str) {
    match parsed.singletons.get(key) {
        Some(v) => s.push_str(&format!("        {key}: Some({v:?}.to_string()),\n")),
        None => s.push_str(&format!("        {key}: None,\n")),
    };
}

fn emit_option_path(s: &mut String, parsed: &ParsedConfig, key: &str) {
    match parsed.singletons.get(key) {
        Some(v) => s.push_str(&format!("        {key}: Some(PathBuf::from({v:?})),\n")),
        None => s.push_str(&format!("        {key}: None,\n")),
    };
}

fn emit_option_u64(s: &mut String, parsed: &ParsedConfig, key: &str) {
    match parsed.singletons.get(key) {
        Some(v) => {
            let n: u64 = v.parse().unwrap_or_else(|_| panic!("{key}: not a u64"));
            s.push_str(&format!("        {key}: Some({n}),\n"));
        }
        None => s.push_str(&format!("        {key}: None,\n")),
    };
}

fn emit_option_u32(s: &mut String, parsed: &ParsedConfig, key: &str) {
    match parsed.singletons.get(key) {
        Some(v) => {
            let n: u32 = v.parse().unwrap_or_else(|_| panic!("{key}: not a u32"));
            s.push_str(&format!("        {key}: Some({n}),\n"));
        }
        None => s.push_str(&format!("        {key}: None,\n")),
    };
}

fn emit_option_u16(s: &mut String, parsed: &ParsedConfig, key: &str) {
    match parsed.singletons.get(key) {
        Some(v) => {
            let n: u16 = v.parse().unwrap_or_else(|_| panic!("{key}: not a u16"));
            s.push_str(&format!("        {key}: Some({n}),\n"));
        }
        None => s.push_str(&format!("        {key}: None,\n")),
    };
}

fn emit_option_secs(s: &mut String, parsed: &ParsedConfig, key: &str, field: &str) {
    match parsed.singletons.get(key) {
        Some(v) => {
            let n: u64 = v.parse().unwrap_or_else(|_| panic!("{key}: not a u64"));
            s.push_str(&format!(
                "        {field}: Some(Duration::from_secs({n})),\n"
            ));
        }
        None => s.push_str(&format!("        {field}: None,\n")),
    };
}

fn emit_bool(s: &mut String, parsed: &ParsedConfig, key: &str) {
    let v = parsed.singletons.get(key).map(String::as_str);
    let b = matches!(v, Some(x) if x.eq_ignore_ascii_case("true"));
    s.push_str(&format!("        {key}: {b},\n"));
}

fn singleton_u64(parsed: &ParsedConfig, key: &str, default: u64) -> u64 {
    parsed
        .singletons
        .get(key)
        .map(|v| v.parse().unwrap_or_else(|_| panic!("{key}: not a u64")))
        .unwrap_or(default)
}

fn singleton_u32(parsed: &ParsedConfig, key: &str, default: u32) -> u32 {
    parsed
        .singletons
        .get(key)
        .map(|v| v.parse().unwrap_or_else(|_| panic!("{key}: not a u32")))
        .unwrap_or(default)
}

fn singleton_usize(parsed: &ParsedConfig, key: &str, default: usize) -> usize {
    parsed
        .singletons
        .get(key)
        .map(|v| v.parse().unwrap_or_else(|_| panic!("{key}: not a usize")))
        .unwrap_or(default)
}

fn parse_octal_str(raw: &str) -> Option<u32> {
    let digits = raw
        .strip_prefix("0o")
        .or_else(|| raw.strip_prefix("0O"))
        .unwrap_or(raw);
    u32::from_str_radix(digits, 8).ok()
}
