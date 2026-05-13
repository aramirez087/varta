//! Hand-rolled GNU-style argv parser for the `varta-watch` binary.
//!
//! No `clap`, no `getopts`, no proc-macros — the parser is a single pass
//! over an iterator of [`String`] tokens. The [`Config::HELP`] constant is
//! the single source of truth for `--help` output and the
//! `cli_help_lists_every_documented_flag` acceptance test.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::tracker::{EvictionPolicy, DEFAULT_CAPACITY};

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

/// Default per-source-IP refill rate (connections per second) for the
/// Prometheus `/metrics` endpoint token bucket.  Comfortably above the
/// 1-per-15-second cadence used by typical Prometheus scrapers; low enough
/// that a hostile actor on the same network cannot exhaust file descriptors
/// or saturate the observer's poll loop with a flood of opens.
pub const DEFAULT_PROM_RATE_LIMIT_PER_SEC: u32 = 5;

/// Default burst capacity for the per-source-IP token bucket.  Tolerates a
/// short cluster of legitimate scrapes (e.g. dashboard refresh) while still
/// shutting down a sustained flood within a few seconds.
pub const DEFAULT_PROM_RATE_LIMIT_BURST: u32 = 10;

/// Default wall-clock budget (in milliseconds) [`crate::recovery::Recovery`]
/// blocks in its [`Drop`] impl waiting for outstanding recovery children to
/// exit after a `kill(2)`. Five seconds preserves the v0.1 hard-coded
/// constant.  systemd `TimeoutStopSec` must be at least this value plus a
/// small reap margin.
pub const DEFAULT_SHUTDOWN_GRACE_MS: u64 = 5_000;

/// Minimum accepted value for `--shutdown-grace-ms`.  Below this the
/// shutdown poll loop cannot complete even one [`std::process::Child::try_wait`]
/// round under load, which would orphan every outstanding child to PID 1.
pub const MIN_SHUTDOWN_GRACE_MS: u64 = 100;

/// Default per-child cap for combined stdout+stderr capture when
/// `--recovery-capture-stdio` is enabled.  4 KiB is enough to fit a typical
/// systemctl/journalctl output snippet without risking pipe-buffer pressure
/// on a chatty recovery command.
pub const DEFAULT_RECOVERY_CAPTURE_BYTES: u32 = 4096;

/// Maximum value accepted by `--recovery-capture-bytes`.  Values above this
/// risk holding too much child output in observer memory and making the
/// non-blocking pipe drain expensive per tick.
pub const MAX_RECOVERY_CAPTURE_BYTES: u32 = 1024 * 1024;

/// Minimum accepted value for `--iteration-budget-ms`.  Below this the
/// budget overlaps the noise floor of the work itself — `serve_pending`
/// alone can spend up to ~200 ms by design — and every iteration would be
/// flagged as an overrun, making the metric useless.
pub const MIN_ITERATION_BUDGET_MS: u64 = 50;

/// Maximum accepted value for `--iteration-budget-ms`.  Above this the
/// soft budget can no longer fire before `--self-watchdog-secs` would
/// abort the daemon, so the metric ceases to be a useful early signal.
pub const MAX_ITERATION_BUDGET_MS: u64 = 60_000;

/// Minimum accepted value for `--scrape-budget-ms`.  Below this the budget
/// overlaps the structural cap of `serve_pending` itself (100 ms serve +
/// 100 ms drain = 200 ms worst case), so it would fire spuriously.  Bounds
/// chosen on the same logic as `--iteration-budget-ms`.
pub const MIN_SCRAPE_BUDGET_MS: u64 = 50;

/// Maximum accepted value for `--scrape-budget-ms`.  Above this the
/// scrape budget can no longer fire before `--self-watchdog-secs` would
/// abort the daemon, so the metric ceases to be a useful signal.
pub const MAX_SCRAPE_BUDGET_MS: u64 = 60_000;

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
    /// Path to a file containing the 32-byte (64-hex-character) bearer token
    /// for the Prometheus `/metrics` endpoint.  Required whenever
    /// [`Self::prom_addr`] is set: `/metrics` has no anonymous access.  The
    /// file must be a regular file (no symlinks), owned by the observer's
    /// UID, mode `0o600` or stricter — see [`validate_secret_file`].
    pub prom_token_file: Option<PathBuf>,
    /// Optional deadline after which the daemon shuts itself down. Used by
    /// integration tests to bound run time without relying on signals.
    pub shutdown_after: Option<Duration>,
    /// Maximum wall-clock time [`crate::recovery::Recovery::drop`] blocks
    /// waiting for outstanding recovery children after issuing `kill(2)`.
    /// Defaults to [`DEFAULT_SHUTDOWN_GRACE_MS`]; minimum
    /// [`MIN_SHUTDOWN_GRACE_MS`].  systemd `TimeoutStopSec` must be at
    /// least this value plus a small reap margin (~2 s).
    pub shutdown_grace: Duration,
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
    /// Defaults to [`crate::tracker::DEFAULT_CAPACITY`] (256). Beats for
    /// new pids beyond this limit are dropped.
    pub tracker_capacity: usize,
    /// Eviction policy applied when the tracker is at capacity and a
    /// new pid arrives. Defaults to [`EvictionPolicy::Strict`].
    pub tracker_eviction_policy: EvictionPolicy,
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
    /// Optional per-pid maximum beat rate in beats per second.
    /// `None` (the default) means no rate limiting. Beats arriving
    /// faster than this rate from the same pid are dropped and counted
    /// via `varta_rate_limited_total`.
    pub max_beat_rate: Option<u32>,
    /// Optional path for a heartbeat file. When set, the observer
    /// writes a timestamp + loop-counter line on every poll iteration,
    /// allowing external watchdogs to detect observer stalls.
    pub heartbeat_file: Option<PathBuf>,
    /// If `Some`, a background watchdog thread is spawned that calls
    /// `process::abort()` if the poll loop has not ticked for longer than
    /// this duration.  Catches hung poll loops that signal-based supervisors
    /// cannot detect.  Set by `--self-watchdog-secs`.
    pub self_watchdog: Option<Duration>,
    /// If `Some`, the path to a hardware watchdog device (e.g.
    /// `/dev/watchdog`) that is opened at startup and kicked once per poll
    /// iteration.  On clean shutdown the magic-close byte `'V'` is written to
    /// disarm the watchdog.  Set by `--hw-watchdog`.
    pub hw_watchdog: Option<PathBuf>,
    /// Per-source-IP refill rate (connections per second) for the
    /// Prometheus `/metrics` endpoint.  Defaults to
    /// [`DEFAULT_PROM_RATE_LIMIT_PER_SEC`].
    pub prom_rate_limit_per_sec: u32,
    /// Per-source-IP burst (token-bucket capacity) for the Prometheus
    /// `/metrics` endpoint.  Defaults to [`DEFAULT_PROM_RATE_LIMIT_BURST`].
    pub prom_rate_limit_burst: u32,
    /// Operator opt-in required to bind a plaintext UDP listener.  When
    /// `--udp-port` is set and no AEAD keys are configured, startup
    /// refuses to proceed unless this is `true`.  The build must also
    /// include `--features unsafe-plaintext-udp` for the plaintext path
    /// to exist at all.  Set by `--i-accept-plaintext-udp`.
    pub i_accept_plaintext_udp: bool,
    /// Operator opt-in required to run shell-mode recovery (`--recovery-cmd`
    /// or `--recovery-cmd-file`).  Shell mode spawns `/bin/sh -c <template>`
    /// with root-equivalent process authority — a single template-injection
    /// vector can terminate any process the observer can reach.  For
    /// production deployments use `--recovery-exec` (no shell, no injection
    /// surface).  Set by `--i-accept-shell-risk`.
    pub i_accept_shell_risk: bool,
    /// Operator opt-in required to combine a UDP listener with a recovery
    /// command.  UDP transports (plain and secure) lack kernel attestation
    /// of the sending process, so a `frame.pid` field on the wire is not
    /// tied back to a verified sender — any holder of a shared PSK (or a
    /// per-agent key derived from a leaked master key) can forge a beat
    /// claiming any pid, then stop sending to trigger a recovery command
    /// targeting an arbitrary process.  Without this flag, startup refuses
    /// to proceed when both `--udp-port` and a recovery template are set.
    /// Even with this flag, the runtime origin gate (Recovery's
    /// `allow_unauthenticated_source`) still refuses UDP-origin stalls
    /// unless the operator additionally accepts that runtime risk.
    /// Set by `--i-accept-recovery-on-unauthenticated-transport`.
    pub i_accept_recovery_on_unauthenticated_transport: bool,
    /// Optional path the recovery audit TSV is appended to. When set, every
    /// recovery spawn and completion is recorded with wall-clock timestamp,
    /// agent pid, child pid, mode, outcome, exit code, and duration. See
    /// [`crate::audit::RecoveryAuditLog`] for the schema.
    pub recovery_audit_file: Option<PathBuf>,
    /// Optional byte cap for the recovery audit file. When exceeded, the
    /// file rotates through up to 5 generations (PATH → PATH.1 → … →
    /// PATH.5). Without a cap the file grows unbounded.
    pub recovery_audit_max_bytes: Option<u64>,
    /// Whether to capture child stdout/stderr non-blockingly for the audit
    /// record. Default off — pipes are inherited from the observer. Opt-in
    /// avoids deadlock risk for operators who alias chatty recovery
    /// commands (e.g. `journalctl -xeu agent.service`).
    pub recovery_capture_stdio: bool,
    /// Total byte cap (stdout + stderr combined, per child) when
    /// `recovery_capture_stdio` is enabled. Defaults to
    /// [`DEFAULT_RECOVERY_CAPTURE_BYTES`]. Values larger than
    /// [`MAX_RECOVERY_CAPTURE_BYTES`] are rejected at parse time.
    pub recovery_capture_bytes: u32,
    /// Soft per-iteration budget for the observer poll loop.  Iterations
    /// exceeding this increment
    /// `varta_observer_iteration_budget_exceeded_total` and are visible in
    /// the `varta_observer_iteration_seconds` histogram.  Advisory only —
    /// hard wedges are caught by `--self-watchdog-secs`.  Set by
    /// `--iteration-budget-ms`; defaults to
    /// [`crate::exporter::DEFAULT_ITERATION_BUDGET`].
    pub iteration_budget: Duration,
    /// Soft per-call budget for `PromExporter::serve_pending`.  Calls
    /// exceeding this increment
    /// `varta_observer_scrape_budget_exceeded_total` and are visible in
    /// the `varta_observer_serve_pending_seconds` histogram.  Lets
    /// operators alert on scrape-storm pressure separately from beat-path
    /// slowness.  Set by `--scrape-budget-ms`; defaults to
    /// [`crate::exporter::DEFAULT_SCRAPE_BUDGET`].
    pub scrape_budget: Duration,
    /// [test-hooks only] Sleep for this many milliseconds on the first poll
    /// iteration, simulating a wedged loop.  Used by the self-watchdog
    /// integration test (`tests/self_watchdog.rs`) to exercise the abort path
    /// without relying on SIGSTOP (which freezes the watchdog thread too).
    /// Present only when compiled with `--features test-hooks`.
    #[cfg(feature = "test-hooks")]
    pub inject_wedge_ms: Option<u64>,
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
    /// A value for a string-enum flag was not one of the accepted choices.
    BadValue {
        /// The flag whose value was rejected.
        flag: &'static str,
        /// The raw string that was provided.
        raw: String,
    },
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
    /// A flag that has been removed for security reasons was passed.  The
    /// `replacement` field carries an inline migration hint so operators
    /// see the fix in the same line as the error.
    RemovedFlag {
        /// The removed flag token (e.g. `"--key-env"`).
        flag: &'static str,
        /// Human-readable migration hint (e.g.
        /// `"--key-file (mode 0600, owned by the observer UID)"`).
        replacement: &'static str,
    },
    /// `--prom-addr` was set but `--prom-token-file` was not.  /metrics
    /// has no anonymous access; the observer refuses to start rather than
    /// expose agent topology to anyone who can reach the bound port.
    PromAddrRequiresToken,
    /// `--recovery-capture-bytes` was set above
    /// [`MAX_RECOVERY_CAPTURE_BYTES`]. Capturing more output than that
    /// risks holding too much child stdout/stderr in observer memory.
    RecoveryCaptureBytesTooLarge {
        /// The value that was provided.
        value: u32,
        /// The maximum allowed value.
        max: u32,
    },
    /// `--recovery-capture-stdio` was passed without any recovery command
    /// configured (`--recovery-cmd` / `--recovery-cmd-file` /
    /// `--recovery-exec` / `--recovery-exec-file`). Capture is meaningless
    /// without something to capture from.
    RecoveryCaptureRequiresRecovery,
    /// `--shutdown-grace-ms` was below [`MIN_SHUTDOWN_GRACE_MS`].
    ShutdownGraceTooLow {
        /// The value provided on the CLI.
        value: u64,
        /// The minimum allowed value.
        min: u64,
    },
    /// Shell-mode recovery flags were passed but this binary was compiled
    /// without the `unsafe-shell-recovery` Cargo feature.  Rebuild with
    /// `--features unsafe-shell-recovery` or use `--recovery-exec` instead.
    ShellRecoveryNotCompiledIn,
    /// A recovery command (`--recovery-cmd` / `--recovery-cmd-file` /
    /// `--recovery-exec` / `--recovery-exec-file`) was configured at the
    /// same time as a UDP listener (`--udp-port`), without the operator's
    /// explicit acknowledgement.  UDP transports cannot attest the sending
    /// process — an attacker holding the AEAD key (or a derived per-agent
    /// key) can forge a beat claiming any pid, then stop sending to
    /// trigger the recovery command against the chosen pid.  Pass
    /// `--i-accept-recovery-on-unauthenticated-transport` to proceed.
    RecoveryRequiresAuthenticatedTransport {
        /// The `IP:PORT` of the UDP listener that would have been bound.
        udp_addr: String,
    },
    /// `--iteration-budget-ms` was outside the accepted range
    /// (`[MIN_ITERATION_BUDGET_MS, MAX_ITERATION_BUDGET_MS]`).
    IterationBudgetOutOfRange {
        /// The value provided.
        value: u64,
        /// The minimum allowed value.
        min: u64,
        /// The maximum allowed value.
        max: u64,
    },
    /// `--scrape-budget-ms` was outside the accepted range
    /// (`[MIN_SCRAPE_BUDGET_MS, MAX_SCRAPE_BUDGET_MS]`).
    ScrapeBudgetOutOfRange {
        /// The value provided.
        value: u64,
        /// The minimum allowed value.
        min: u64,
        /// The maximum allowed value.
        max: u64,
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
            ConfigError::BadValue { flag, raw } => {
                write!(f, "{flag}: invalid value {raw:?}",)
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
            ConfigError::RemovedFlag { flag, replacement } => write!(
                f,
                "{flag} has been removed for security reasons; use {replacement}"
            ),
            ConfigError::PromAddrRequiresToken => f.write_str(
                "--prom-addr requires --prom-token-file. /metrics has no anonymous access; \
                 generate a token with `openssl rand -hex 32 > /etc/varta/prom.token && \
                 chmod 600 /etc/varta/prom.token`.",
            ),
            ConfigError::ShutdownGraceTooLow { value, min } => write!(
                f,
                "--shutdown-grace-ms: {value} is below the minimum allowed value ({min} ms)"
            ),
            ConfigError::RecoveryCaptureBytesTooLarge { value, max } => write!(
                f,
                "--recovery-capture-bytes: {value} exceeds the maximum allowed value ({max} bytes)"
            ),
            ConfigError::RecoveryCaptureRequiresRecovery => f.write_str(
                "--recovery-capture-stdio requires --recovery-cmd, --recovery-cmd-file, \
                 --recovery-exec, or --recovery-exec-file",
            ),
            ConfigError::ShellRecoveryNotCompiledIn => f.write_str(
                "shell-mode recovery (--recovery-cmd / --recovery-cmd-file) is not available \
                 in this build; rebuild with --features unsafe-shell-recovery, or use \
                 --recovery-exec instead",
            ),
            ConfigError::RecoveryRequiresAuthenticatedTransport { udp_addr } => write!(
                f,
                "recovery command is configured alongside a UDP listener on {udp_addr}. \
                 UDP transports cannot attest the sending process — a holder of the AEAD key \
                 (or a per-agent key derived from a leaked master key) can forge a beat \
                 claiming any pid, then stop sending to trigger recovery against the chosen pid. \
                 Either remove the recovery command, switch to a UDS-only deployment, or \
                 pass --i-accept-recovery-on-unauthenticated-transport to explicitly accept \
                 this risk."
            ),
            ConfigError::IterationBudgetOutOfRange { value, min, max } => write!(
                f,
                "--iteration-budget-ms: {value} is outside the accepted range [{min}, {max}] ms"
            ),
            ConfigError::ScrapeBudgetOutOfRange { value, min, max } => write!(
                f,
                "--scrape-budget-ms: {value} is outside the accepted range [{min}, {max}] ms"
            ),
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
                                     via the system shell with the stalled
                                     pid passed as $1. SECURITY: the
                                     template body is under full operator
                                     control; never accept it from an
                                     untrusted source. Requires --features
                                     unsafe-shell-recovery at build time.
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
                                     Requires --features
                                     unsafe-shell-recovery at build time.
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
                                    GET /metrics on this address.  Requires
                                    --prom-token-file; /metrics has no
                                    anonymous access.
    --prom-token-file <PATH>       Path to a file containing the 64-hex-char
                                     bearer token enforced on every /metrics
                                     scrape.  File must be mode 0600 or
                                     stricter, owned by the observer UID,
                                     not a symlink.  Required when
                                     --prom-addr is set.  Scrapers must send
                                     'Authorization: Bearer <hex>' to
                                     receive 200; missing/wrong tokens
                                     return 401 and bump
                                     varta_prom_auth_failures_total.
    --shutdown-grace-ms <MS>       Maximum time the daemon spends in
                                     Recovery::drop waiting for outstanding
                                     recovery children to exit after SIGKILL
                                     during shutdown.  Default 5000.  Minimum
                                     100.  systemd unit's TimeoutStopSec
                                     must be at least this value plus ~2
                                     seconds of reap margin.
    --recovery-timeout-ms <MS>     Kill-after deadline for recovery children;
                                     if a child runs longer than this it is
                                     killed via kill(2) (default: none —
                                     child runs until completion).
    --read-timeout-ms <MS>         UDS read timeout per poll call
                                     (default 100).  Bounded so a stalled peer
                                     cannot hold the observer loop indefinitely.
    --tracker-capacity <N>          Maximum number of distinct agent pids
                                      tracked concurrently (default 256).
                                      Beats for new pids beyond this limit are
                                      dropped.
    --tracker-eviction-policy <P>   Eviction policy when tracker is full:
                                      strict (default) evicts only confirmed-
                                      stalled agents; balanced falls back to
                                      evicting the oldest active slot to
                                      prevent capacity-exhaustion attacks.
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
    --max-beat-rate <N>            Per-pid maximum beat rate in beats/sec.
                                     Beats arriving faster than this rate
                                     from the same pid are dropped.
                                     Default: unlimited.
    --heartbeat-file <PATH>        Write a timestamp + loop-counter line to
                                     this file on every poll iteration.
                                     External watchdogs can monitor the file
                                     mtime to detect observer stalls.
    --self-watchdog-secs <SECS>    Spawn a background thread that calls
                                     process::abort() if the poll loop has
                                     not ticked for longer than SECS seconds.
                                     Catches hung poll loops. Triggers
                                     systemd Restart=on-abort. Minimum 1.
    --hw-watchdog <PATH>           Open a hardware watchdog device (e.g.
                                     /dev/watchdog) and kick it once per
                                     poll iteration. On clean shutdown the
                                     magic-close byte 'V' is written to
                                     disarm the watchdog.
    --prom-rate-limit-per-sec <N>  Per-source-IP refill rate for the
                                     /metrics endpoint token bucket
                                     (default 5).  Scrapes from any single
                                     IP arriving faster than this rate are
                                     accepted and immediately closed
                                     without serving.  Counted as
                                     varta_prom_connections_dropped_total
                                     {reason=\"rate_limit\"}.
    --prom-rate-limit-burst <N>    Maximum burst (and bucket capacity) for
                                     the per-source-IP token bucket
                                     (default 10).  Tune higher only if
                                     legitimate scrapers cluster requests.
    --i-accept-plaintext-udp       UNSAFE: explicitly accept the security
                                     risk of binding an unauthenticated
                                     plaintext UDP listener.  Required
                                     when --udp-port is set and no
                                     --key-file / --master-key-file is
                                     configured.  Build must also include
                                     --features unsafe-plaintext-udp.  NOT
                                     for production / safety-critical use;
                                     any device with network reach to the
                                     bound port can inject heartbeats.
    --i-accept-shell-risk          UNSAFE: explicitly accept the security
                                     risk of shell-mode recovery
                                     (--recovery-cmd / --recovery-cmd-file).
                                     Required to use shell-mode at all;
                                     without this flag, only --recovery-exec
                                     / --recovery-exec-file are permitted.
                                     Shell mode spawns the system shell
                                     with root-equivalent process authority
                                     — prefer --recovery-exec for any
                                     production deployment. Build must also
                                     include --features unsafe-shell-recovery.
    --i-accept-recovery-on-unauthenticated-transport
                                   UNSAFE: explicitly accept the security
                                     risk of running a recovery command
                                     while a UDP listener is bound.  UDP
                                     transports (plain or secure) have no
                                     kernel attestation of the sending
                                     process — a holder of the AEAD key
                                     (or a per-agent key derived from a
                                     leaked master key) can forge a beat
                                     claiming any pid, then stop sending
                                     to trigger recovery against that pid.
                                     Without this flag, --udp-port plus
                                     any recovery-command flag is rejected
                                     at startup.  The runtime origin gate
                                     still refuses UDP-origin recoveries
                                     by default; see
                                     docs/architecture/peer-authentication.md.
    --recovery-audit-file <PATH>   Append a tab-separated audit record for
                                     every recovery spawn and completion.
                                     Records carry wall-clock + observer
                                     timestamps, agent pid, child pid,
                                     mode, outcome, exit code, signal,
                                     duration, and captured stdio
                                     lengths. The file is created mode
                                     0600.
    --recovery-audit-max-bytes <N> Rotate the audit file after every write
                                     that pushes it above N bytes. Up to
                                     5 generations kept.
    --recovery-capture-stdio       Capture child stdout/stderr non-
                                     blockingly so its length and
                                     truncation status appear in the audit
                                     record. Off by default — opt in only
                                     when you have a recovery command whose
                                     output is bounded.
    --recovery-capture-bytes <N>   Total combined byte cap (stdout +
                                     stderr) per child when capture is
                                     enabled. Default 4096; max 1048576.
    --iteration-budget-ms <MS>     Soft per-iteration budget for the
                                     observer poll loop. Iterations that
                                     exceed this increment
                                     varta_observer_iteration_budget_exceeded_total
                                     and are visible in the
                                     varta_observer_iteration_seconds
                                     histogram. Advisory only — hard
                                     wedges are caught by
                                     --self-watchdog-secs.  Default 250.
                                     Range [50, 60000].  See
                                     docs/architecture/observer-liveness.md
                                     for the worst-case derivation.
    --scrape-budget-ms <MS>        Soft per-call budget for serve_pending
                                     (the /metrics serving phase of one
                                     poll iteration). Overruns increment
                                     varta_observer_scrape_budget_exceeded_total
                                     and are visible in
                                     varta_observer_serve_pending_seconds.
                                     Separates scrape-storm alarms from
                                     beat-path slowness. Default 250.
                                     Range [50, 60000].

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
        let mut prom_token_file: Option<PathBuf> = None;
        let mut shutdown_after_secs: Option<u64> = None;
        let mut recovery_timeout_ms: Option<u64> = None;
        let mut shutdown_grace_ms: Option<u64> = None;
        let mut socket_mode: Option<u32> = None;
        let mut read_timeout_ms: Option<u64> = None;
        let mut tracker_capacity: Option<usize> = None;
        let mut tracker_eviction_policy: Option<EvictionPolicy> = None;
        let mut udp_port: Option<u16> = None;
        let mut udp_bind_addr: Option<std::net::IpAddr> = None;
        let mut secure_key_file: Option<PathBuf> = None;
        let mut accepted_key_file: Option<PathBuf> = None;
        let mut master_key_file: Option<PathBuf> = None;
        let mut max_beat_rate: Option<u32> = None;
        let mut heartbeat_file: Option<PathBuf> = None;
        let mut self_watchdog: Option<Duration> = None;
        let mut hw_watchdog: Option<PathBuf> = None;
        let mut prom_rate_limit_per_sec: Option<u32> = None;
        let mut prom_rate_limit_burst: Option<u32> = None;
        let mut i_accept_plaintext_udp = false;
        let mut i_accept_shell_risk = false;
        let mut i_accept_recovery_on_unauthenticated_transport = false;
        let mut recovery_audit_file: Option<PathBuf> = None;
        let mut recovery_audit_max_bytes: Option<u64> = None;
        let mut recovery_capture_stdio = false;
        let mut recovery_capture_bytes: Option<u32> = None;
        let mut iteration_budget_ms: Option<u64> = None;
        let mut scrape_budget_ms: Option<u64> = None;
        #[cfg(feature = "test-hooks")]
        let mut inject_wedge_ms: Option<u64> = None;

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
                    recovery_timeout_ms = Some(parse_u64("--recovery-timeout-ms", &v)?);
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
                    // docs/architecture/peer-authentication.md.
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
                "--i-accept-shell-risk" => {
                    i_accept_shell_risk = true;
                }
                "--i-accept-recovery-on-unauthenticated-transport" => {
                    i_accept_recovery_on_unauthenticated_transport = true;
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
                    recovery_audit_max_bytes = Some(parse_u64("--recovery-audit-max-bytes", &v)?);
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
        if recovery_capture_bytes_resolved > MAX_RECOVERY_CAPTURE_BYTES {
            return Err(ConfigError::RecoveryCaptureBytesTooLarge {
                value: recovery_capture_bytes_resolved,
                max: MAX_RECOVERY_CAPTURE_BYTES,
            });
        }

        // Capture is meaningless without a recovery command. Reject the flag
        // at parse time so a misconfiguration surfaces at startup rather than
        // hiding silently in a runbook.
        if recovery_capture_stdio
            && recovery_cmd.is_none()
            && recovery_exec_cmd.is_none()
            && recovery_cmd_file.is_none()
            && recovery_exec_file.is_none()
        {
            return Err(ConfigError::RecoveryCaptureRequiresRecovery);
        }

        // H2 mitigation — recovery commands are operator-controlled actions
        // (`kill -9 {pid}`, `systemctl restart agent@{pid}.service`).  UDP
        // transports (plain *and* secure) cannot attest the sending process;
        // any holder of the AEAD key (or a per-agent key derived from a
        // leaked master key) can forge a beat claiming any pid, then stop
        // sending to trigger the recovery command against that pid.  Refuse
        // to start when both are configured unless the operator passes
        // `--i-accept-recovery-on-unauthenticated-transport`.  Per
        // docs/architecture/peer-authentication.md, even with the flag the
        // runtime gate in Recovery still refuses UDP-origin stalls unless
        // wired to explicitly allow them.
        let any_recovery_configured = recovery_cmd.is_some()
            || recovery_exec_cmd.is_some()
            || recovery_cmd_file.is_some()
            || recovery_exec_file.is_some();
        if any_recovery_configured && !i_accept_recovery_on_unauthenticated_transport {
            if let Some(port) = udp_port {
                let bind_ip =
                    udp_bind_addr.unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                let udp_addr = format!("{bind_ip}:{port}");
                return Err(ConfigError::RecoveryRequiresAuthenticatedTransport { udp_addr });
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
            prom_token_file,
            shutdown_after: shutdown_after_secs.map(Duration::from_secs),
            recovery_timeout: recovery_timeout_ms.map(Duration::from_millis),
            shutdown_grace: Duration::from_millis(shutdown_grace_ms),
            socket_mode: socket_mode.unwrap_or(DEFAULT_SOCKET_MODE),
            read_timeout: Duration::from_millis(read_timeout_ms.unwrap_or(DEFAULT_READ_TIMEOUT_MS)),
            tracker_capacity: tracker_capacity.unwrap_or(DEFAULT_CAPACITY),
            tracker_eviction_policy: tracker_eviction_policy.unwrap_or(EvictionPolicy::Strict),
            udp_port,
            udp_bind_addr,
            secure_key_file,
            accepted_key_file,
            master_key_file,
            max_beat_rate,
            heartbeat_file,
            self_watchdog,
            hw_watchdog,
            prom_rate_limit_per_sec: prom_rate_limit_per_sec
                .unwrap_or(DEFAULT_PROM_RATE_LIMIT_PER_SEC),
            prom_rate_limit_burst: prom_rate_limit_burst.unwrap_or(DEFAULT_PROM_RATE_LIMIT_BURST),
            i_accept_plaintext_udp,
            i_accept_shell_risk,
            i_accept_recovery_on_unauthenticated_transport,
            recovery_audit_file,
            recovery_audit_max_bytes,
            recovery_capture_stdio,
            recovery_capture_bytes: recovery_capture_bytes_resolved,
            iteration_budget,
            scrape_budget,
            #[cfg(feature = "test-hooks")]
            inject_wedge_ms,
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

        // Shell mode — inline OR file-based — spawns the system shell with
        // root-equivalent process authority.  A template-injection vector
        // can terminate any process the observer can reach.  Refuse to
        // proceed unless the operator has explicitly acknowledged the
        // risk; recommend the safer --recovery-exec path.  The check sits
        // before mutual-exclusion enforcement so the more actionable
        // diagnostic wins when both forms of misconfiguration are present.
        // Only compiled in when the feature is present; without it the
        // cfg(not) branch below fires first.
        #[cfg(feature = "unsafe-shell-recovery")]
        if shell_any && !self.i_accept_shell_risk {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "shell-mode recovery (--recovery-cmd / --recovery-cmd-file) runs \
                 the system shell with root-equivalent process authority. For production, \
                 use --recovery-exec (no shell, no injection surface). To proceed \
                 with shell mode anyway, pass --i-accept-shell-risk.",
            ));
        }

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

        // Shell mode — only reachable when the feature is compiled in.
        // Without the feature, the variant doesn't exist; error here so
        // the operator gets a clear message pointing to --recovery-exec.
        #[cfg(feature = "unsafe-shell-recovery")]
        {
            if let Some(ref tpl) = self.recovery_cmd {
                return Ok(Some(RecoveryMode::Shell(tpl.clone())));
            }
            if let Some(ref path) = self.recovery_cmd_file {
                let template = validate_recovery_file(path)?;
                return Ok(Some(RecoveryMode::Shell(template)));
            }
        }
        #[cfg(not(feature = "unsafe-shell-recovery"))]
        if shell_any {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                ConfigError::ShellRecoveryNotCompiledIn,
            ));
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
    /// `--key-file` is the sole source for secure-UDP keys: it is the only
    /// path that goes through [`validate_secret_file`], guaranteeing mode
    /// 0600 ownership and an `O_NOFOLLOW` open. Environment-variable keys
    /// were removed (see `ConfigError::RemovedFlag`) because they leak
    /// through `/proc/<pid>/environ` and `docker inspect`.
    ///
    /// Returns `Ok(None)` when `--key-file` is not set (UDP without AEAD).
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

        let Some(ref path) = self.secure_key_file else {
            return Ok(None);
        };

        let content = read_secret_file(path)?;
        let mut primary: Option<Key> = None;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if primary.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{}: multiple primary keys found (expected exactly one)",
                        path.display()
                    ),
                ));
            }
            primary = Some(Key::from_hex(line).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            })?);
        }

        let primary = match primary {
            Some(k) => k,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: no key found in file", path.display()),
                ))
            }
        };

        // Load accepted (rotation) keys
        let mut accepted = Vec::new();
        if let Some(ref path) = self.accepted_key_file {
            let content = read_secret_file(path)?;
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
    /// Returns an `io::Error` if the file cannot be read, the file does not
    /// meet [`validate_secret_file`]'s hardened requirements, or the key
    /// cannot be parsed as a 64-character hex string.
    #[cfg(feature = "secure-udp")]
    pub fn load_master_key(&self) -> std::io::Result<Option<varta_vlp::crypto::Key>> {
        use varta_vlp::crypto::Key;

        let Some(ref path) = self.master_key_file else {
            return Ok(None);
        };
        let hex = read_secret_file(path)?;
        Key::from_hex(hex.trim()).map(Some).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })
    }

    /// Load the Prometheus `/metrics` bearer token from
    /// [`Self::prom_token_file`].
    ///
    /// Returns `Ok(None)` when `--prom-token-file` is not set.  The file is
    /// validated through [`validate_secret_file`] (regular file, owned by
    /// the observer UID, mode `0o600` or stricter, `O_NOFOLLOW` open) and
    /// the contents must be exactly 64 hex characters (the same encoding
    /// used by [`varta_vlp::crypto::Key`], so operators can reuse
    /// `openssl rand -hex 32`).
    ///
    /// # Errors
    ///
    /// Returns an `io::Error` if the file fails validation or the contents
    /// cannot be decoded as 64 hex characters.
    pub fn load_prom_token(&self) -> std::io::Result<Option<[u8; 32]>> {
        use std::io;
        let Some(ref path) = self.prom_token_file else {
            return Ok(None);
        };
        let raw = validate_secret_file(path)?;
        let trimmed = raw.trim();
        let bytes = varta_vlp::decode_hex_32(trimmed.as_bytes()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {e}", path.display()),
            )
        })?;
        Ok(Some(bytes))
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

/// Validate that a secret file (recovery command, key, or token) meets the
/// hardened requirements: regular file, owned by the observer's UID, mode
/// `0o600` or stricter, no symlinks (`O_NOFOLLOW` open).
///
/// The open-and-validate flow is collapsed into a single file descriptor to
/// eliminate the TOCTOU window between metadata check and file read. The
/// sequence is:
///
/// 1. `open(path, O_RDONLY | O_NOFOLLOW)` — atomically rejects a symlink at
///    the leaf component. The kernel returns `ELOOP` if the path resolves
///    to a symlink, so no separate `symlink_metadata` probe is needed.
/// 2. `fstat(fd)` (via `File::metadata`) — operates on the open inode, not
///    the path. An attacker who renames or replaces the file in the parent
///    directory after the open has no effect: the fd still refers to the
///    inode we just authenticated.
/// 3. Mode / UID / file-type checks on the fstat result.
/// 4. `read_to_string` from the same fd.
///
/// Returns the raw file contents on success.
pub(crate) fn validate_secret_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    // Platform-specific O_NOFOLLOW values (hard-coded for zero-dependency).
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    const O_NOFOLLOW: i32 = 0x0100;

    #[cfg(target_os = "linux")]
    const O_NOFOLLOW: i32 = 0x20000;

    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_os = "linux",
    )))]
    compile_error!("O_NOFOLLOW value is unknown for this target — add it to the cfg gates above");

    // ELOOP is raw 40 on Linux and 62 on the BSD family. On platforms outside
    // both lists we fall through with the raw error message.
    #[cfg(target_os = "linux")]
    const ELOOP: i32 = 40;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    const ELOOP: i32 = 62;

    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            if e.raw_os_error() == Some(ELOOP) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{}: must not be a symlink", path.display()),
                ));
            }
            return Err(e);
        }
    };

    // fstat(fd) — operates on the open inode, immune to path-level races.
    let meta = file.metadata()?;

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

    let my_uid = crate::peer_cred::observer_uid();
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

    let mut content = String::new();
    file.read_to_string(&mut content)?;
    Ok(content)
}

/// Recovery-command-file wrapper around [`validate_secret_file`] that also
/// trims surrounding whitespace from the contents (recovery templates do not
/// want a trailing newline appended to the command line).
fn validate_recovery_file(path: &Path) -> std::io::Result<String> {
    let content = validate_secret_file(path)?;
    Ok(content.trim().to_string())
}

/// Validate and read a secret file (key, accepted-key, master-key, or
/// Prometheus token). Returns the raw bytes; callers are responsible for
/// trimming or splitting line-by-line.
#[cfg(feature = "secure-udp")]
pub(crate) fn read_secret_file(path: &Path) -> std::io::Result<String> {
    validate_secret_file(path)
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
        // --prom-addr now requires --prom-token-file; the file does not
        // need to exist at parse time (it's only validated when load_prom_token
        // is actually called by main()).
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--recovery-cmd",
            "echo $1",
            "--i-accept-shell-risk",
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
        assert_eq!(cfg.recovery_cmd.as_deref(), Some("echo $1"));
        assert!(cfg.i_accept_shell_risk);
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
            "--export-file-max-bytes",
            "--prom-addr",
            "--prom-token-file",
            "--shutdown-grace-ms",
            "--socket-mode",
            "--shutdown-after-secs",
            "--udp-port",
            "--udp-bind-addr",
            "--key-file",
            "--accepted-key-file",
            "--master-key-file",
            "--max-beat-rate",
            "--heartbeat-file",
            "--prom-rate-limit-per-sec",
            "--prom-rate-limit-burst",
            "--i-accept-plaintext-udp",
            "--i-accept-shell-risk",
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
        let cfg =
            Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
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
        #[allow(unreachable_patterns)]
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
            "--i-accept-shell-risk",
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
            "--i-accept-shell-risk",
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

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn resolve_shell_mode_from_cmd_flag() {
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--recovery-cmd",
            "echo $1",
            "--i-accept-shell-risk",
        ]))
        .expect("parse");
        let mode = cfg.resolve_recovery_mode().expect("resolve").expect("some");
        match mode {
            crate::recovery::RecoveryMode::Shell(tpl) => assert_eq!(tpl, "echo $1"),
            other => panic!("expected Shell mode, got {other:?}"),
        }
    }

    #[cfg(not(feature = "unsafe-shell-recovery"))]
    #[test]
    fn shell_recovery_not_compiled_in_is_rejected() {
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--recovery-cmd",
            "echo $1",
            "--i-accept-shell-risk",
        ]))
        .expect("parse");
        let err = cfg.resolve_recovery_mode().expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("unsafe-shell-recovery"),
            "error must name the feature, got: {msg}"
        );
        assert!(
            msg.contains("--recovery-exec"),
            "error must recommend --recovery-exec, got: {msg}"
        );
    }

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn shell_mode_inline_without_accept_flag_is_rejected() {
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--recovery-cmd",
            "echo $1",
        ]))
        .expect("parse");
        let err = cfg.resolve_recovery_mode().expect_err("must reject");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(
            msg.contains("--i-accept-shell-risk"),
            "expected error to name the accept flag, got: {msg}"
        );
        assert!(
            msg.contains("--recovery-exec"),
            "expected error to recommend --recovery-exec, got: {msg}"
        );
    }

    #[cfg(feature = "unsafe-shell-recovery")]
    #[test]
    fn shell_mode_file_without_accept_flag_is_rejected() {
        // The file does not need to exist — the accept-flag check runs
        // before the file-permission validation, so we never read it.
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--recovery-cmd-file",
            "/nonexistent",
        ]))
        .expect("parse");
        let err = cfg.resolve_recovery_mode().expect_err("must reject");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("--i-accept-shell-risk"));
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
        let cfg =
            Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
        assert!(!cfg.i_accept_plaintext_udp);
    }

    #[test]
    fn parses_i_accept_recovery_on_unauthenticated_transport_flag() {
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--i-accept-recovery-on-unauthenticated-transport",
        ]))
        .expect("parse");
        assert!(cfg.i_accept_recovery_on_unauthenticated_transport);
    }

    #[test]
    fn i_accept_recovery_on_unauthenticated_transport_defaults_to_false() {
        let cfg =
            Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
        assert!(!cfg.i_accept_recovery_on_unauthenticated_transport);
    }

    #[test]
    fn recovery_plus_udp_port_without_accept_flag_is_rejected() {
        // H2 mitigation: combining a recovery command with a UDP listener
        // is structurally unsafe (UDP cannot attest the sending process).
        // Without --i-accept-recovery-on-unauthenticated-transport, startup
        // must hard-error.
        let err = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--udp-port",
            "9000",
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
            .contains("--i-accept-recovery-on-unauthenticated-transport"));
    }

    #[test]
    fn recovery_plus_udp_port_with_accept_flag_succeeds() {
        let cfg = Config::from_args(args(&[
            "--socket",
            "/s",
            "--threshold-ms",
            "100",
            "--udp-port",
            "9000",
            "--recovery-exec",
            "/bin/true",
            "--i-accept-recovery-on-unauthenticated-transport",
        ]))
        .expect("parse");
        assert!(cfg.i_accept_recovery_on_unauthenticated_transport);
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
        assert!(!cfg.i_accept_recovery_on_unauthenticated_transport);
        assert!(cfg.udp_port.is_none());
    }

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
        let cfg =
            Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
        assert_eq!(cfg.prom_rate_limit_per_sec, DEFAULT_PROM_RATE_LIMIT_PER_SEC);
        assert_eq!(cfg.prom_rate_limit_burst, DEFAULT_PROM_RATE_LIMIT_BURST);
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
        let cfg =
            Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
        assert!(cfg.recovery_env.is_empty());
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
        let cfg =
            Config::from_args(args(&["--socket", "/s", "--threshold-ms", "100"])).expect("parse");
        assert!(cfg.heartbeat_file.is_none());
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
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .expect("chmod tempdir");
        dir
    }

    fn write_mode(path: &Path, content: &[u8], mode: u32) {
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
}
