//! Hand-rolled GNU-style argv parser for the `varta-watch` binary.
//!
//! No `clap`, no `getopts`, no proc-macros — the parser is a single pass
//! over an iterator of [`String`] tokens. The [`Config::HELP`] constant is
//! the single source of truth for `--help` output and the
//! `cli_help_lists_every_documented_flag` acceptance test.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::tracker::DEFAULT_CAPACITY;

/// Default per-pid debounce window applied when `--recovery-cmd` is set
/// without an explicit `--recovery-debounce-ms`.
pub const DEFAULT_RECOVERY_DEBOUNCE_MS: u64 = 1000;

/// Default UDS file permissions applied after bind (octal 0600 — owner-only
/// read and write). Tightens the blast radius so only the owning UID can
/// speak to the observer socket.
pub const DEFAULT_SOCKET_MODE: u32 = 0o600;

/// Default UDS read timeout in milliseconds. Capped so a stalled peer
/// cannot hold the observer poll loop indefinitely.
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 100;

/// Minimum allowed value for `--threshold-ms`. A threshold of 0 ms would
/// cause every agent to be perpetually stalled, triggering recovery commands
/// on every poll cycle.
pub const MIN_THRESHOLD_MS: u64 = 10;

/// Parsed daemon configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Filesystem path the observer's UDS will be bound at.
    pub socket: PathBuf,
    /// Per-pid silence window before the observer surfaces `Event::Stall`.
    pub threshold: Duration,
    /// Optional shell-fragment template invoked on each unique stall. The
    /// stalled pid is passed as `$1` (positional argument, not string-replaced).
    pub recovery_cmd: Option<String>,
    /// Optional exec command line invoked on each unique stall. `{pid}` in
    /// any argument is replaced with the numeric PID. No shell is spawned.
    pub recovery_exec_cmd: Option<String>,
    /// Optional path to a file containing the `--recovery-cmd` shell template.
    /// The file must be owned by the observer's UID and have mode 0600 or
    /// stricter. Mutually exclusive with `recovery_cmd`.
    pub recovery_cmd_file: Option<PathBuf>,
    /// Optional path to a file containing the `--recovery-exec` command line.
    /// Same permission requirements as `recovery_cmd_file`. Mutually
    /// exclusive with `recovery_exec_cmd`.
    pub recovery_exec_file: Option<PathBuf>,
    /// Per-pid debounce window for `recovery_cmd` invocations.
    pub recovery_debounce: Duration,
    /// Environment variables passed to recovery child processes. Each entry
    /// is in `KEY=VALUE` format. When set, the child's environment is cleared
    /// to `PATH=/usr/bin:/bin` plus these explicit variables. When empty,
    /// no environment variables are set (child inherits the observer's env).
    pub recovery_env: Vec<String>,
    /// Optional path the file exporter appends one event-line per record to.
    pub file_export: Option<PathBuf>,
    /// Optional byte limit for the file export. When exceeded, the current
    /// file is rotated (up to 5 generations) and a new one is opened.
    pub export_file_max_bytes: Option<u64>,
    /// Optional listening address for the Prometheus exporter.
    pub prom_addr: Option<SocketAddr>,
    /// Optional deadline after which the daemon shuts itself down. Used by
    /// integration tests to bound run time without relying on signals.
    pub shutdown_after: Option<Duration>,
    /// Optional kill-after deadline for outstanding recovery children.
    /// `None` (the default) preserves v0.1.0 semantics: children are
    /// reaped on completion but never killed. Set via
    /// `--recovery-timeout-ms`.
    pub recovery_timeout: Option<Duration>,
    /// UDS file mode applied after bind (octal, e.g. `0o600`).
    /// Defaults to [`DEFAULT_SOCKET_MODE`].
    pub socket_mode: u32,
    /// UDS read timeout for the bound socket. Defaults to
    /// [`DEFAULT_READ_TIMEOUT_MS`] milliseconds.
    pub read_timeout: Duration,
    /// Maximum number of distinct agent pids tracked concurrently.
    /// Defaults to [`crate::tracker::DEFAULT_CAPACITY`] (64). Beats for
    /// new pids beyond this limit are dropped.
    pub tracker_capacity: usize,
    /// Optional UDP port for network-based observers. When set, the observer
    /// also binds a UDP listener alongside the UDS socket.
    pub udp_port: Option<u16>,
    /// IP address to bind the UDP listener on. Defaults to `0.0.0.0` when
    /// `--udp-port` is set. Ignored when `--udp-port` is not set.
    pub udp_bind_addr: Option<std::net::IpAddr>,
    /// Path to a file containing a 64-character hex key for secure UDP
    /// (requires `--features secure-udp`).
    pub secure_key_file: Option<PathBuf>,
    /// Path to a file with one hex key per line for zero-downtime key
    /// rotation (requires `--features secure-udp`).
    pub accepted_key_file: Option<PathBuf>,
    /// Path to a file containing a 64-character hex master key for
    /// per-agent key derivation (requires `--features secure-udp`).
    /// The observer derives agent-specific keys from the PID in each
    /// frame's `iv_random` prefix.
    pub master_key_file: Option<PathBuf>,
    /// Environment variable name to read the primary key from (default
    /// `VARTA_KEY`). Ignored when `--key-file` is set.
    pub key_env: String,
    /// Optional per-pid maximum beat rate in beats per second.
    /// `None` (the default) means no rate limiting. Beats arriving
    /// faster than this rate from the same pid are dropped and counted
    /// via `varta_rate_limited_total`.
    pub max_beat_rate: Option<u32>,
}

/// Failure modes for [`Config::from_args`].
#[derive(Debug)]
pub enum ConfigError {
    /// A flag that requires a value was passed without one.
    MissingValue(&'static str),
    /// A required flag (e.g. `--socket`, `--threshold-ms`) was omitted.
    MissingRequired(&'static str),
    /// An unknown flag token was encountered.
    UnknownFlag(String),
    /// A numeric flag carried a value that would not parse as `u64`.
    BadInteger {
        /// The flag whose value failed to parse.
        flag: &'static str,
        /// The raw string that did not parse.
        raw: String,
    },
    /// A value on `--socket-mode` could not be parsed as octal.
    BadSocketMode(String),
    /// `--prom-addr` value did not parse as `IP:PORT`.
    BadAddr(String),
    /// The user passed `--help` / `-h`. Not a true error; `main` prints
    /// [`Config::HELP`] and exits 0.
    HelpRequested,
    /// `--threshold-ms` value is below [`MIN_THRESHOLD_MS`].
    ThresholdTooLow {
        /// The value that was provided.
        value: u64,
        /// The minimum allowed value.
        min: u64,
    },
    /// Two or more mutually exclusive recovery flags were specified.
    MutuallyExclusive {
        /// The pair of conflicting flags (e.g. `("--recovery-cmd", "--recovery-exec")`).
        a: &'static str,
        /// Second conflicting flag.
        b: &'static str,
    },
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::MissingValue(flag) => write!(f, "{flag} requires a value"),
            ConfigError::MissingRequired(flag) => write!(f, "missing required flag {flag}"),
            ConfigError::UnknownFlag(s) => write!(f, "unknown flag {s}"),
            ConfigError::BadInteger { flag, raw } => {
                write!(f, "{flag}: not a valid unsigned integer: {raw:?}")
            }
            ConfigError::BadSocketMode(raw) => {
                write!(
                    f,
                    "--socket-mode: expected octal digits (e.g. 600, 0600, or 0o600), got: {raw:?}"
                )
            }
            ConfigError::BadAddr(raw) => {
                write!(f, "--prom-addr: not a valid socket address: {raw:?}")
            }
            ConfigError::HelpRequested => f.write_str("--help"),
            ConfigError::ThresholdTooLow { value, min } => {
                write!(
                    f,
                    "--threshold-ms: {value} is below the minimum allowed value ({min} ms)"
                )
            }
            ConfigError::MutuallyExclusive { a, b } => {
                write!(f, "{a} and {b} are mutually exclusive")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Verbatim `--help` text. The acceptance test asserts that every
    /// documented long-flag substring appears in this body.
    pub const HELP: &'static str = "\
varta-watch — observe Varta Lifeline Protocol agents over configurable transports.

USAGE:
    varta-watch --socket <PATH> --threshold-ms <MS> [OPTIONS]

REQUIRED:
    --socket <PATH>                Path to bind the observer's UDS.
    --threshold-ms <MS>            Per-pid silence window before a stall is
                                    surfaced (milliseconds).

OPTIONAL:
    --recovery-cmd <TEMPLATE>      Shell fragment run on each unique stall
                                     via /bin/sh -c with the stalled pid
                                     passed as $1. SECURITY: the template
                                     body is under full operator control;
                                     never accept it from an untrusted
                                     source.
    --recovery-exec <CMD>          Command and arguments invoked via execvp
                                     on each unique stall. Split on
                                     whitespace into argv; {pid} in any
                                     argument is replaced with the numeric
                                     PID. No shell — metacharacters have
                                     no effect. Mutually exclusive with
                                     --recovery-cmd.
    --recovery-cmd-file <PATH>     Read --recovery-cmd template from a file.
                                     File must be owned by the observer's
                                     UID and mode 0600 or stricter.
    --recovery-exec-file <PATH>    Read --recovery-exec command from a file
                                     with the same permission requirements
                                     as --recovery-cmd-file.
    --recovery-debounce-ms <MS>    Per-pid debounce window for recovery
                                     invocations (default 1000).
    --recovery-env <KEY=VALUE>     Repeatable. Pass an environment variable
                                     to recovery child processes. When set,
                                     the child's environment is cleared and
                                     only PATH=/usr/bin:/bin plus these
                                     explicit variables are set. Without this
                                     flag the child inherits the observer's
                                     environment.
    --socket-mode <OCTAL>           File mode for the observer socket
                                     (default 0600 — owner-only r/w).
    --export-file <PATH>            Append one tab-separated event line per
                                     observer event to this file.
    --export-file-max-bytes <N>     Rotate export file when its size exceeds
                                     N bytes (keeps up to 5 generations:
                                     PATH.1 .. PATH.5).  Without this flag
                                     the file grows without bound.
    --prom-addr <IP:PORT>          Bind a Prometheus text-format endpoint at
                                    GET /metrics on this address.
    --recovery-timeout-ms <MS>     Kill-after deadline for recovery children;
                                     if a child runs longer than this it is
                                     killed via kill(2) (default: none —
                                     child runs until completion).
    --read-timeout-ms <MS>         UDS read timeout per poll call
                                     (default 100).  Bounded so a stalled peer
                                     cannot hold the observer loop indefinitely.
    --tracker-capacity <N>          Maximum number of distinct agent pids
                                     tracked concurrently (default 64).
                                     Beats for new pids beyond this limit are
                                     dropped.
    --shutdown-after-secs <SECS>   Exit cleanly after the given uptime
                                     (used by integration tests).
    --udp-port <PORT>              Bind a UDP listener on this port for
                                     network-based agents (requires --features
                                     udp at build time). Combine with UDS or
                                     use alone.
    --udp-bind-addr <IP>           IP address to bind the UDP listener on
                                     (default 0.0.0.0). Requires --udp-port.
    --key-file <PATH>              Path to a file containing a 64-hex-char
                                     key for secure UDP (requires --features
                                     secure-udp at build time).
    --accepted-key-file <PATH>     Path to a file with one hex key per line
                                     for zero-downtime rotation (requires
                                     --features secure-udp).
    --master-key-file <PATH>       Path to a file containing a 64-hex-char
                                     master key for per-agent key derivation
                                     (requires --features secure-udp).
    --key-env <NAME>               Environment variable to read the primary
                                     key from (default VARTA_KEY).
    --max-beat-rate <N>            Per-pid maximum beat rate in beats/sec.
                                     Beats arriving faster than this rate
                                     from the same pid are dropped.
                                     Default: unlimited.

    -h, --help                     Print this message and exit.
";

    /// Parse a token stream (typically `std::env::args().skip(1)`).
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Config, ConfigError> {
        let mut socket: Option<PathBuf> = None;
        let mut threshold_ms: Option<u64> = None;
        let mut recovery_cmd: Option<String> = None;
        let mut recovery_exec_cmd: Option<String> = None;
        let mut recovery_cmd_file: Option<PathBuf> = None;
        let mut recovery_exec_file: Option<PathBuf> = None;
        let mut recovery_debounce_ms: Option<u64> = None;
        let mut recovery_env: Vec<String> = Vec::new();
        let mut file_export: Option<PathBuf> = None;
        let mut export_file_max_bytes: Option<u64> = None;
        let mut prom_addr: Option<SocketAddr> = None;
        let mut shutdown_after_secs: Option<u64> = None;
        let mut recovery_timeout_ms: Option<u64> = None;
        let mut socket_mode: Option<u32> = None;
        let mut read_timeout_ms: Option<u64> = None;
        let mut tracker_capacity: Option<usize> = None;
        let mut udp_port: Option<u16> = None;
        let mut udp_bind_addr: Option<std::net::IpAddr> = None;
        let mut secure_key_file: Option<PathBuf> = None;
        let mut accepted_key_file: Option<PathBuf> = None;
        let mut master_key_file: Option<PathBuf> = None;
        let mut key_env: String = String::from("VARTA_KEY");
        let mut max_beat_rate: Option<u32> = None;

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
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-cmd"))?;
                    recovery_cmd = Some(v);
                }
                "--recovery-exec" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-exec"))?;
                    recovery_exec_cmd = Some(v);
                }
                "--recovery-cmd-file" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-cmd-file"))?;
                    recovery_cmd_file = Some(PathBuf::from(v));
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
                    export_file_max_bytes = Some(parse_u64("--export-file-max-bytes", &v)?);
                }
                "--prom-addr" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--prom-addr"))?;
                    prom_addr = Some(
                        v.parse::<SocketAddr>()
                            .map_err(|_| ConfigError::BadAddr(v))?,
                    );
                }
                "--recovery-timeout-ms" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--recovery-timeout-ms"))?;
                    recovery_timeout_ms = Some(parse_u64("--recovery-timeout-ms", &v)?);
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
                "--key-env" => {
                    key_env = iter.next().ok_or(ConfigError::MissingValue("--key-env"))?;
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

        let recovery_debounce =
            Duration::from_millis(recovery_debounce_ms.unwrap_or(DEFAULT_RECOVERY_DEBOUNCE_MS));

        Ok(Config {
            socket,
            threshold: Duration::from_millis(threshold_ms),
            recovery_cmd,
            recovery_exec_cmd,
            recovery_cmd_file,
            recovery_exec_file,
            recovery_debounce,
            recovery_env,
            file_export,
            export_file_max_bytes,
            prom_addr,
            shutdown_after: shutdown_after_secs.map(Duration::from_secs),
            recovery_timeout: recovery_timeout_ms.map(Duration::from_millis),
            socket_mode: socket_mode.unwrap_or(DEFAULT_SOCKET_MODE),
            read_timeout: Duration::from_millis(read_timeout_ms.unwrap_or(DEFAULT_READ_TIMEOUT_MS)),
            tracker_capacity: tracker_capacity.unwrap_or(DEFAULT_CAPACITY),
            udp_port,
            udp_bind_addr,
            secure_key_file,
            accepted_key_file,
            master_key_file,
            key_env,
            max_beat_rate,
        })
    }

    /// Resolve recovery mode from CLI flags, enforcing mutual exclusion
    /// and loading/validating any file-based templates.
    ///
    /// Returns `Ok(None)` when no recovery is configured. Returns
    /// `Ok(Some(RecoveryMode::Shell(_)))` when `--recovery-cmd` or
    /// `--recovery-cmd-file` is set. Returns `Ok(Some(RecoveryMode::Exec{..}))`
    /// when `--recovery-exec` or `--recovery-exec-file` is set.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if a file cannot be read, its permissions are
    /// too open, or mutually exclusive flags are specified.
    pub fn resolve_recovery_mode(&self) -> std::io::Result<Option<crate::recovery::RecoveryMode>> {
        use crate::recovery::RecoveryMode;

        // Collect which sources are configured
        let has_cmd = self.recovery_cmd.is_some();
        let has_exec = self.recovery_exec_cmd.is_some();
        let has_cmd_file = self.recovery_cmd_file.is_some();
        let has_exec_file = self.recovery_exec_file.is_some();

        let shell_any = has_cmd || has_cmd_file;
        let exec_any = has_exec || has_exec_file;

        // Shell and exec are mutually exclusive
        if shell_any && exec_any {
            let shell_flag = if has_cmd {
                "--recovery-cmd"
            } else {
                "--recovery-cmd-file"
            };
            let exec_flag = if has_exec {
                "--recovery-exec"
            } else {
                "--recovery-exec-file"
            };
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{shell_flag} and {exec_flag} are mutually exclusive"),
            ));
        }

        // --recovery-cmd and --recovery-cmd-file are mutually exclusive
        if has_cmd && has_cmd_file {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--recovery-cmd and --recovery-cmd-file are mutually exclusive",
            ));
        }

        // --recovery-exec and --recovery-exec-file are mutually exclusive
        if has_exec && has_exec_file {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--recovery-exec and --recovery-exec-file are mutually exclusive",
            ));
        }

        // Shell mode
        if let Some(ref tpl) = self.recovery_cmd {
            return Ok(Some(RecoveryMode::Shell(tpl.clone())));
        }
        if let Some(ref path) = self.recovery_cmd_file {
            let template = validate_recovery_file(path)?;
            return Ok(Some(RecoveryMode::Shell(template)));
        }

        // Exec mode
        if let Some(ref cmd) = self.recovery_exec_cmd {
            let mut parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "--recovery-exec: command must not be empty",
                ));
            }
            let program = parts.remove(0).to_string();
            let args: Vec<String> = parts.into_iter().map(|s| s.to_string()).collect();
            return Ok(Some(RecoveryMode::Exec { program, args }));
        }
        if let Some(ref path) = self.recovery_exec_file {
            let cmd = validate_recovery_file(path)?;
            let mut parts: Vec<&str> = cmd.split_whitespace().collect();
            if parts.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{}: file is empty", path.display()),
                ));
            }
            let program = parts.remove(0).to_string();
            let args: Vec<String> = parts.into_iter().map(|s| s.to_string()).collect();
            return Ok(Some(RecoveryMode::Exec { program, args }));
        }

        Ok(None)
    }

    /// Load the primary and accepted secure keys for AEAD transport.
    ///
    /// Priority: `--key-file` > `--key-env` (default `VARTA_KEY`).
    /// Returns `Ok(None)` when neither is configured (UDP without AEAD).
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file cannot be read, the key(s) cannot
    /// be parsed as 64-character hex strings, or the primary key file contains
    /// more than one key.
    #[cfg(feature = "secure-udp")]
    pub fn load_secure_keys(
        &self,
    ) -> std::io::Result<Option<(varta_vlp::crypto::Key, Vec<varta_vlp::crypto::Key>)>> {
        use std::io;
        use varta_vlp::crypto::Key;

        // Load primary key
        let primary = if let Some(ref path) = self.secure_key_file {
            let content = std::fs::read_to_string(path)?;
            let mut key: Option<Key> = None;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if key.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}: multiple primary keys found (expected exactly one)",
                            path.display()
                        ),
                    ));
                }
                key = Some(Key::from_hex(line).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: {e}", path.display()),
                    )
                })?);
            }
            key
        } else {
            match Key::from_env(&self.key_env) {
                Ok(key) => Some(key),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            }
        };

        let primary = match primary {
            Some(k) => k,
            None => return Ok(None),
        };

        // Load accepted (rotation) keys
        let mut accepted = Vec::new();
        if let Some(ref path) = self.accepted_key_file {
            let content = std::fs::read_to_string(path)?;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let key = Key::from_hex(line).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{}: {e}", path.display()),
                    )
                })?;
                accepted.push(key);
            }
        }

        Ok(Some((primary, accepted)))
    }

    /// Load the master key for per-agent key derivation.
    ///
    /// Returns `Ok(None)` when `--master-key-file` is not set.
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file cannot be read or the key cannot
    /// be parsed as a 64-character hex string.
    #[cfg(feature = "secure-udp")]
    pub fn load_master_key(&self) -> std::io::Result<Option<varta_vlp::crypto::Key>> {
        use varta_vlp::crypto::Key;

        match self.master_key_file {
            Some(ref path) => Key::from_file(path).map(Some),
            None => Ok(None),
        }
    }
}

fn parse_u64(flag: &'static str, raw: &str) -> Result<u64, ConfigError> {
    raw.parse::<u64>().map_err(|_| ConfigError::BadInteger {
        flag,
        raw: raw.to_string(),
    })
}

fn parse_u16(flag: &'static str, raw: &str) -> Result<u16, ConfigError> {
    raw.parse::<u16>().map_err(|_| ConfigError::BadInteger {
        flag,
        raw: raw.to_string(),
    })
}

fn parse_octal(raw: &str) -> Result<u32, ConfigError> {
    // Accept the three forms a user might naturally type: bare octal (`600`),
    // leading-zero octal (`0600`), or Rust-literal octal (`0o600` / `0O600`).
    // `from_str_radix` only handles the first two; the prefix is stripped here.
    let digits = raw
        .strip_prefix("0o")
        .or_else(|| raw.strip_prefix("0O"))
        .unwrap_or(raw);
    if digits.is_empty() {
        return Err(ConfigError::BadSocketMode(raw.to_string()));
    }
    u32::from_str_radix(digits, 8).map_err(|_| ConfigError::BadSocketMode(raw.to_string()))
}

/// Validate that a recovery command file meets security requirements.
///
/// Checks:
/// 1. The file is a regular file (not a symlink, directory, or device).
/// 2. The file is owned by the current process's UID.
/// 3. The file has no group or other permissions (mode `0o600` or stricter).
///
/// Returns the trimmed file contents on success.
fn validate_recovery_file(path: &Path) -> std::io::Result<String> {
    use std::os::unix::fs::MetadataExt;

    extern "C" {
        fn getuid() -> u32;
    }

    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{}: must be a regular file", path.display()),
        ));
    }

    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{}: insecure permissions {:03o} (must be 0600 or stricter)",
                path.display(),
                mode
            ),
        ));
    }

    let my_uid = unsafe { getuid() };
    let file_uid = meta.uid();
    if file_uid != my_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{}: owned by uid {file_uid}, expected uid {my_uid}",
                path.display()
            ),
        ));
    }

    let content = std::fs::read_to_string(path)?;
    Ok(content.trim().to_string())
}

/// Parse a recovery command line into (program, args).
///
/// Splits on whitespace. Returns an error if the command line is empty.
pub fn parse_exec_cmd(cmd: &str) -> std::io::Result<(String, Vec<String>)> {
    let mut parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "recovery command must not be empty",
        ));
    }
    let program = parts.remove(0).to_string();
    let args: Vec<String> = parts.into_iter().map(|s| s.to_string()).collect();
    Ok((program, args))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(cfg.recovery_cmd.is_none());
        assert!(cfg.prom_addr.is_none());
    }

    #[test]
    fn parses_full_flag_surface() {
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--recovery-cmd",
            "echo $1",
            "--recovery-debounce-ms",
            "750",
            "--export-file",
            "/tmp/e.log",
            "--prom-addr",
            "127.0.0.1:9090",
            "--shutdown-after-secs",
            "3",
        ]))
        .expect("parse");
        assert_eq!(cfg.recovery_cmd.as_deref(), Some("echo $1"));
        assert_eq!(cfg.recovery_debounce, Duration::from_millis(750));
        assert_eq!(cfg.file_export, Some(PathBuf::from("/tmp/e.log")));
        assert_eq!(
            cfg.prom_addr,
            Some("127.0.0.1:9090".parse::<SocketAddr>().unwrap())
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

    #[test]
    fn help_text_lists_every_known_flag() {
        for flag in [
            "--socket",
            "--threshold-ms",
            "--recovery-cmd",
            "--recovery-exec",
            "--recovery-cmd-file",
            "--recovery-exec-file",
            "--recovery-debounce-ms",
            "--recovery-env",
            "--recovery-timeout-ms",
            "--read-timeout-ms",
            "--tracker-capacity",
            "--export-file",
            "--prom-addr",
            "--socket-mode",
            "--shutdown-after-secs",
            "--udp-port",
            "--udp-bind-addr",
            "--key-file",
            "--accepted-key-file",
            "--master-key-file",
            "--key-env",
            "--max-beat-rate",
            "--help",
        ] {
            assert!(
                Config::HELP.contains(flag),
                "Config::HELP missing flag {flag}"
            );
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
        let cfg =
            Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
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
        let cfg =
            Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
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
        assert!(cfg.recovery_cmd.is_none());
        let mode = cfg.resolve_recovery_mode().expect("resolve").expect("some");
        match mode {
            crate::recovery::RecoveryMode::Exec { program, args } => {
                assert_eq!(program, "/usr/bin/kill");
                assert_eq!(args, vec!["-HUP", "{pid}"]);
            }
            other => panic!("expected Exec mode, got {other:?}"),
        }
    }

    #[test]
    fn recovery_exec_and_recovery_cmd_are_mutually_exclusive() {
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--recovery-cmd",
            "echo $1",
            "--recovery-exec",
            "true",
        ]))
        .expect("parse");
        let err = cfg.resolve_recovery_mode().unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "expected mutual exclusion error, got: {err}"
        );
    }

    #[test]
    fn recovery_cmd_and_cmd_file_are_mutually_exclusive() {
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--recovery-cmd",
            "echo $1",
            "--recovery-cmd-file",
            "/nonexistent",
        ]))
        .expect("parse");
        let err = cfg.resolve_recovery_mode().unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "expected mutual exclusion error, got: {err}"
        );
    }

    #[test]
    fn resolve_shell_mode_from_cmd_flag() {
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--recovery-cmd",
            "echo $1",
        ]))
        .expect("parse");
        let mode = cfg.resolve_recovery_mode().expect("resolve").expect("some");
        match mode {
            crate::recovery::RecoveryMode::Shell(tpl) => assert_eq!(tpl, "echo $1"),
            other => panic!("expected Shell mode, got {other:?}"),
        }
    }

    #[test]
    fn no_recovery_flags_yields_none() {
        let cfg =
            Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
        let mode = cfg.resolve_recovery_mode().expect("resolve");
        assert!(mode.is_none());
    }

    #[test]
    fn parse_exec_cmd_splits_whitespace() {
        let (program, args) = super::parse_exec_cmd("kill -HUP {pid}").expect("parse");
        assert_eq!(program, "kill");
        assert_eq!(args, vec!["-HUP", "{pid}"]);
    }

    #[test]
    fn parse_exec_cmd_rejects_empty() {
        assert!(super::parse_exec_cmd("").is_err());
        assert!(super::parse_exec_cmd("   ").is_err());
    }

    #[test]
    fn parses_recovery_env_repeatable() {
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--recovery-cmd",
            "echo $1",
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
        let cfg =
            Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
        assert!(cfg.recovery_env.is_empty());
    }
}
