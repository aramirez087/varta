// flag_catalogue.rs — single source of truth for every CLI flag accepted by
// varta-watch and every config-file key accepted by the compile-time-config
// build script.
//
// PORTABILITY RULE: this file MUST compile with NO `use crate::...` imports.
// It is `include!()`-d directly by `build.rs`, which is a completely
// separate compilation unit that has no access to the crate's types.
// Only `std`-level identifiers and items defined in this file may appear here.
//
// CONVENTIONS:
//   `cli`  — the `--flag-name` form used on the command line.
//   `key`  — the `key_name` form (underscores) used in compile-time-config
//             files.  Maps 1-to-1 with build.rs's former `KNOWN_KEYS` table.
//   `kind` — the value type, expressed via `FlagKind`.
//
// Adding a new Config field:
//   1. Add a `FlagSpec` entry to `FLAGS`.
//   2. Add a matching `match` arm in `config/parser.rs` (`from_args`).
//   3. Add a matching emitter arm in `build.rs` (`render_constructor`).
//   4. The catalogue integrity test in `config/tests.rs` will fail until all
//      three steps are complete, keeping the table authoritative.

/// Value-type classification for a CLI flag or compile-time-config key.
///
/// The variants mirror `build.rs`'s former `KeyType` enum exactly — this type
/// replaces it.  `build.rs` switches from its own `KeyType` to this one by
/// `include!()`-ing this file.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagKind {
    /// Path on disk.  CLI: stores as `PathBuf`.  Config file: bare string.
    Path,
    /// Free-form string (e.g. recovery command template).
    Str,
    /// `true` / `false`, case-insensitive.  CLI: bare flag (no value).
    Bool,
    /// Unsigned 64-bit decimal integer.
    U64,
    /// Unsigned 32-bit decimal integer.
    U32,
    /// Unsigned 16-bit decimal integer.
    U16,
    /// `usize` decimal.
    Usize,
    /// Octal file-mode string (e.g. `0600`, `0o600`, `600`).
    Octal,
    /// `IP:PORT` socket address.
    SocketAddr,
    /// IP address (no port).
    IpAddr,
    /// `monotonic` | `boottime` | `monotonic-raw`.
    ClockSource,
    /// `strict` | `balanced`.
    EvictionPolicy,
    /// `direct` | `libc`.
    SignalHandlerMode,
    /// Repeatable string; values accumulate into a `Vec<String>`.
    List,
}

/// One entry in the flag catalogue.
///
/// Every flag or config-file key is described by exactly one `FlagSpec`.
/// Flags that are CLI-only (`bool` flags and removed flags) carry an empty
/// `key` field (`""`); config-file-only keys would carry an empty `cli` field
/// (none exist today).
#[derive(Clone, Copy, Debug)]
pub struct FlagSpec {
    /// Long CLI flag name, including the leading `--`.
    /// Empty string for config-file-only keys (none today).
    pub cli: &'static str,
    /// Config-file key name (underscore form, no leading `--`).
    /// Empty string for CLI-only flags that have no config-file equivalent.
    pub key: &'static str,
    /// Value type.
    pub kind: FlagKind,
    /// Feature gate string, or `""` for unconditional flags.
    /// Used only for documentation / help generation — the actual `#[cfg]`
    /// gates are in the parser and in `build.rs`.
    pub feature: &'static str,
}

/// Complete flag catalogue.  One entry per accepted CLI flag.  Removed /
/// renamed flags (e.g. `--key-env`) are NOT listed here — they are handled
/// as explicit `ConfigError::RemovedFlag` arms in the parser.
///
/// Order within sections is cosmetically alphabetical; the parser does not
/// rely on order.
pub const FLAGS: &[FlagSpec] = &[
    // -------------------------------------------------------------------------
    // Required
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--socket",
        key: "socket",
        kind: FlagKind::Path,
        feature: "",
    },
    FlagSpec {
        cli: "--threshold-ms",
        key: "threshold_ms",
        kind: FlagKind::U64,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Transport — UDS
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--socket-mode",
        key: "socket_mode",
        kind: FlagKind::Octal,
        feature: "",
    },
    FlagSpec {
        cli: "--read-timeout-ms",
        key: "read_timeout_ms",
        kind: FlagKind::U64,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Transport — UDP
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--udp-port",
        key: "udp_port",
        kind: FlagKind::U16,
        feature: "",
    },
    FlagSpec {
        cli: "--udp-bind-addr",
        key: "udp_bind_addr",
        kind: FlagKind::IpAddr,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Transport — secure-UDP keys
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--key-file",
        key: "secure_key_file",
        kind: FlagKind::Path,
        feature: "secure-udp",
    },
    FlagSpec {
        cli: "--accepted-key-file",
        key: "accepted_key_file",
        kind: FlagKind::Path,
        feature: "secure-udp",
    },
    FlagSpec {
        cli: "--master-key-file",
        key: "master_key_file",
        kind: FlagKind::Path,
        feature: "secure-udp",
    },
    // -------------------------------------------------------------------------
    // Recovery — command sources
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--recovery-cmd",
        key: "recovery_cmd",
        kind: FlagKind::Str,
        feature: "unsafe-shell-recovery",
    },
    FlagSpec {
        cli: "--recovery-exec",
        key: "recovery_exec_cmd",
        kind: FlagKind::Str,
        feature: "",
    },
    FlagSpec {
        cli: "--recovery-cmd-file",
        key: "recovery_cmd_file",
        kind: FlagKind::Path,
        feature: "unsafe-shell-recovery",
    },
    FlagSpec {
        cli: "--recovery-exec-file",
        key: "recovery_exec_file",
        kind: FlagKind::Path,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Recovery — tuning
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--recovery-debounce-ms",
        key: "recovery_debounce_ms",
        kind: FlagKind::U64,
        feature: "",
    },
    FlagSpec {
        cli: "--recovery-env",
        key: "recovery_env",
        kind: FlagKind::List,
        feature: "",
    },
    FlagSpec {
        cli: "--recovery-timeout-ms",
        key: "recovery_timeout_ms",
        kind: FlagKind::U64,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Recovery — audit log
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--recovery-audit-file",
        key: "recovery_audit_file",
        kind: FlagKind::Path,
        feature: "",
    },
    FlagSpec {
        cli: "--recovery-audit-max-bytes",
        key: "recovery_audit_max_bytes",
        kind: FlagKind::U64,
        feature: "",
    },
    FlagSpec {
        cli: "--recovery-audit-sync-every",
        key: "recovery_audit_sync_every",
        kind: FlagKind::U32,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Recovery — stdio capture
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--recovery-capture-stdio",
        key: "recovery_capture_stdio",
        kind: FlagKind::Bool,
        feature: "",
    },
    FlagSpec {
        cli: "--recovery-capture-bytes",
        key: "recovery_capture_bytes",
        kind: FlagKind::U32,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Exporters — file
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--export-file",
        key: "file_export",
        kind: FlagKind::Path,
        feature: "",
    },
    FlagSpec {
        cli: "--export-file-max-bytes",
        key: "export_file_max_bytes",
        kind: FlagKind::U64,
        feature: "",
    },
    FlagSpec {
        cli: "--export-file-sync-every",
        key: "export_file_sync_every",
        kind: FlagKind::U32,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Exporters — Prometheus
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--prom-addr",
        key: "",
        kind: FlagKind::SocketAddr,
        feature: "prometheus-exporter",
    },
    FlagSpec {
        cli: "--prom-token-file",
        key: "",
        kind: FlagKind::Path,
        feature: "prometheus-exporter",
    },
    FlagSpec {
        cli: "--prom-rate-limit-per-sec",
        key: "",
        kind: FlagKind::U32,
        feature: "prometheus-exporter",
    },
    FlagSpec {
        cli: "--prom-rate-limit-burst",
        key: "",
        kind: FlagKind::U32,
        feature: "prometheus-exporter",
    },
    // -------------------------------------------------------------------------
    // Tracker / observer
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--tracker-capacity",
        key: "tracker_capacity",
        kind: FlagKind::Usize,
        feature: "",
    },
    FlagSpec {
        cli: "--eviction-scan-window",
        key: "eviction_scan_window",
        kind: FlagKind::Usize,
        feature: "",
    },
    FlagSpec {
        cli: "--tracker-eviction-policy",
        key: "tracker_eviction_policy",
        kind: FlagKind::EvictionPolicy,
        feature: "",
    },
    FlagSpec {
        cli: "--clock-source",
        key: "clock_source",
        kind: FlagKind::ClockSource,
        feature: "",
    },
    FlagSpec {
        cli: "--max-beat-rate",
        key: "max_beat_rate",
        kind: FlagKind::U32,
        feature: "",
    },
    FlagSpec {
        cli: "--iteration-budget-ms",
        key: "iteration_budget_ms",
        kind: FlagKind::U64,
        feature: "",
    },
    FlagSpec {
        cli: "--scrape-budget-ms",
        key: "scrape_budget_ms",
        kind: FlagKind::U64,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Heartbeat / watchdogs / shutdown
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--heartbeat-file",
        key: "heartbeat_file",
        kind: FlagKind::Path,
        feature: "",
    },
    FlagSpec {
        cli: "--self-watchdog-secs",
        key: "self_watchdog_secs",
        kind: FlagKind::U64,
        feature: "",
    },
    FlagSpec {
        cli: "--hw-watchdog",
        key: "hw_watchdog",
        kind: FlagKind::Path,
        feature: "",
    },
    FlagSpec {
        cli: "--shutdown-after-secs",
        key: "shutdown_after_secs",
        kind: FlagKind::U64,
        feature: "",
    },
    FlagSpec {
        cli: "--shutdown-grace-ms",
        key: "shutdown_grace_ms",
        kind: FlagKind::U64,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Safety acknowledgements (boolean flags, no config-file equivalent)
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--i-accept-plaintext-udp",
        key: "i_accept_plaintext_udp",
        kind: FlagKind::Bool,
        feature: "unsafe-plaintext-udp",
    },
    FlagSpec {
        cli: "--i-accept-shell-risk",
        key: "i_accept_shell_risk",
        kind: FlagKind::Bool,
        feature: "unsafe-shell-recovery",
    },
    FlagSpec {
        cli: "--secure-udp-i-accept-recovery-on-unauthenticated-transport",
        key: "i_accept_recovery_on_secure_udp",
        kind: FlagKind::Bool,
        feature: "",
    },
    FlagSpec {
        cli: "--plaintext-udp-i-accept-recovery-on-unauthenticated-transport",
        key: "i_accept_recovery_on_plaintext_udp",
        kind: FlagKind::Bool,
        feature: "",
    },
    FlagSpec {
        cli: "--i-accept-secure-udp-non-loopback",
        key: "i_accept_secure_udp_non_loopback",
        kind: FlagKind::Bool,
        feature: "",
    },
    FlagSpec {
        cli: "--allow-cross-namespace-agents",
        key: "allow_cross_namespace_agents",
        kind: FlagKind::Bool,
        feature: "",
    },
    FlagSpec {
        cli: "--strict-namespace-check",
        key: "strict_namespace_check",
        kind: FlagKind::Bool,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Signal handling
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--signal-handler-mode",
        key: "signal_handler_mode",
        kind: FlagKind::SignalHandlerMode,
        feature: "",
    },
    // -------------------------------------------------------------------------
    // Test hooks (compiled only under `test-hooks` feature)
    // -------------------------------------------------------------------------
    FlagSpec {
        cli: "--inject-wedge-ms",
        key: "inject_wedge_ms",
        kind: FlagKind::U64,
        feature: "test-hooks",
    },
];
