use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::clock::ClockSource;
use crate::signal_install::SignalHandlerMode;
use crate::tracker::EvictionPolicy;

/// Default per-pid debounce window applied when `--recovery-exec` is set
/// without an explicit `--recovery-debounce-ms`.
pub const DEFAULT_RECOVERY_DEBOUNCE_MS: u64 = 1000;

/// Default UDS file permissions applied after bind (octal 0600 — owner-only
/// read and write). Tightens the blast radius so only the owning UID can
/// speak to the observer socket.
pub const DEFAULT_SOCKET_MODE: u32 = 0o600;

/// Default UDS read timeout in milliseconds. Capped so a stalled peer
/// cannot hold the observer poll loop indefinitely.
pub const DEFAULT_READ_TIMEOUT_MS: u64 = 100;

/// Hard self-watchdog abort threshold for the `Poll` iteration stage, in
/// milliseconds. `STAGE_ABORT_NS[IterStage::Poll]` in `main.rs` references
/// this constant so the two cannot drift.
pub const POLL_STAGE_ABORT_MS: u64 = 2_000;

/// Upper bound for `--read-timeout-ms`. The idle `Poll` stage spends ≈ one
/// blocking UDS `recv(2)` of `--read-timeout-ms` (see
/// `observer-liveness.md`), so the read timeout MUST stay safely below
/// [`POLL_STAGE_ABORT_MS`]; otherwise a perfectly healthy, idle observer
/// trips the self-watchdog and `process::abort()`s — a host reboot under
/// `--hw-watchdog`. Half the abort threshold leaves headroom for the rest of
/// the poll cycle plus the watchdog's tick granularity.
pub const MAX_READ_TIMEOUT_MS: u64 = POLL_STAGE_ABORT_MS / 2;

const _: () = assert!(
    MAX_READ_TIMEOUT_MS < POLL_STAGE_ABORT_MS,
    "read-timeout ceiling must stay below the Poll-stage self-watchdog abort",
);

/// Hard self-watchdog abort threshold for the `Maintenance` iteration stage,
/// in milliseconds. `STAGE_ABORT_NS[IterStage::Maintenance]` in `main.rs`
/// references this constant so the two cannot drift (mirrors how
/// [`POLL_STAGE_ABORT_MS`] feeds `STAGE_ABORT_NS[IterStage::Poll]`).
pub const MAINTENANCE_STAGE_ABORT_MS: u64 = 500;

/// Upper bound for `--audit-rotation-budget-ms`. `drive_audit_rotation` runs
/// inside the `Maintenance` stage and is *designed* to spend up to its full
/// per-tick budget before yielding (see `audit/rotation.rs`), so the budget
/// MUST stay safely below [`MAINTENANCE_STAGE_ABORT_MS`]; otherwise a healthy
/// observer rotating its audit log on a slow disk trips the per-stage
/// self-watchdog and `process::abort()`s — a host reboot under `--hw-watchdog`.
/// Half the abort threshold leaves headroom for the co-resident Maintenance
/// work (eviction drains, the 10 ms `flush_audit_pending`) plus the watchdog's
/// tick granularity, exactly as [`MAX_READ_TIMEOUT_MS`] does for the Poll
/// stage. 250 ms is also far below the *default*-build full-iteration deadline
/// (`--self-watchdog-secs`, min 1 s), so the bound protects both feature
/// profiles (the per-stage abort itself is `prometheus-exporter`-gated).
pub const MAX_AUDIT_ROTATION_BUDGET_MS: u32 = (MAINTENANCE_STAGE_ABORT_MS / 2) as u32;

const _: () = assert!(
    (MAX_AUDIT_ROTATION_BUDGET_MS as u64) < MAINTENANCE_STAGE_ABORT_MS,
    "audit-rotation budget ceiling must stay below the Maintenance-stage self-watchdog abort",
);

/// Minimum allowed value for `--threshold-ms`. A threshold of 0 ms would
/// cause every agent to be perpetually stalled, triggering recovery commands
/// on every poll cycle.
pub const MIN_THRESHOLD_MS: u64 = 10;

/// Minimum allowed value for `--self-watchdog-secs`. A deadline of `0`
/// makes the self-watchdog fire on the very first tick after startup —
/// once the poll loop has ticked, `now - last_tick > 0` is true forever —
/// and `process::abort()`s a perfectly healthy observer (a host reboot
/// under `--hw-watchdog`). `0` is the "disable" idiom for the sibling rate
/// flags (`--max-beat-rate 0`, `--global-beat-rate 0`, …), so an operator
/// reaching for it to *disable* the watchdog would instead arm a guaranteed
/// self-abort; reject it loudly. To run without a watchdog, omit the flag.
pub const MIN_SELF_WATCHDOG_SECS: u64 = 1;

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

/// Default per-pid maximum beat rate in beats per second.
/// Enabled by default to provide a baseline DoS ceiling.
/// Set `--max-beat-rate 0` to disable.
#[cfg(not(feature = "compile-time-config"))]
pub const DEFAULT_MAX_BEAT_RATE: u32 = 100;

/// Default global beat rate cap across all senders combined, in beats per
/// second.  Provides a hard ceiling that defeats per-pid rotation attacks.
/// Set `--global-beat-rate 0` to disable.  Sized for 50 concurrent agents
/// × 100 bps.
#[cfg(not(feature = "compile-time-config"))]
pub const DEFAULT_GLOBAL_BEAT_RATE: u32 = 5_000;

/// Default global burst capacity (token-bucket capacity).  2× the refill
/// rate so 50 agents can co-restart within a 1 s window.
#[cfg(not(feature = "compile-time-config"))]
pub const DEFAULT_GLOBAL_BEAT_BURST: u32 = 10_000;

/// Default receive-buffer size requested via `SO_RCVBUF` on the observer
/// UDS.  1 MiB ≈ 32 768 × 32 B frames ≈ 6 s of full-burst headroom at the
/// default global rate.  Linux doubles the value then clamps to
/// `net.core.rmem_max` (~208 KiB stock); the gauge surfaces the actual
/// granted value.  Set `--uds-rcvbuf-bytes 0` to leave the kernel default.
#[cfg(not(feature = "compile-time-config"))]
pub const DEFAULT_UDS_RCVBUF_BYTES: u32 = 1_048_576;

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

/// Default value for `--audit-fsync-budget-ms`.  If a single
/// `fdatasync(2)` on the audit file exceeds this, the remaining records
/// in the current drain are written-to-BufWriter only and the sync is
/// deferred to the next maintenance tick.  Bounds the worst-case poll
/// stall on a slow disk to one fsync per tick.
///
/// Referenced only by the argv parser; the compile-time-config build
/// reads its default directly from `build.rs`.
#[cfg(not(feature = "compile-time-config"))]
pub const DEFAULT_AUDIT_FSYNC_BUDGET_MS: u32 = 50;

/// Default value for `--audit-sync-interval-ms`.  `0` disables the
/// time-based cadence; durability falls back to the record-count cadence
/// set by `--recovery-audit-sync-every` alone — the IEC 62304 Class C
/// default semantics.  Operators who relax the record cadence pin a
/// worst-case sync interval here.
#[cfg(not(feature = "compile-time-config"))]
pub const DEFAULT_AUDIT_SYNC_INTERVAL_MS: u32 = 0;

/// Default value for `--audit-rotation-budget-ms`.  Rotation
/// (rename × 5 + reopen + header + boot record + fsync) executes as a
/// state machine; if a single tick exceeds this budget the state is
/// preserved and resumed on the next tick.  Keeps a wedged filesystem
/// from blocking the poll loop during rotation.
#[cfg(not(feature = "compile-time-config"))]
pub const DEFAULT_AUDIT_ROTATION_BUDGET_MS: u32 = 50;

/// Parsed daemon configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Filesystem path the observer's UDS will be bound at.
    pub socket: PathBuf,
    /// Per-pid silence window before the observer surfaces `Event::Stall`.
    pub threshold: Duration,
    /// Optional exec command line invoked on each unique stall. `{pid}` in
    /// any argument is replaced with the numeric PID. No shell is spawned.
    pub recovery_exec_cmd: Option<String>,
    /// Optional path to a file containing the `--recovery-exec` command line.
    /// The file must be owned by the observer's UID and have mode 0600 or
    /// stricter. Mutually exclusive with `recovery_exec_cmd`.
    pub recovery_exec_file: Option<PathBuf>,
    /// Per-pid debounce window for recovery invocations.
    pub recovery_debounce: Duration,
    /// Environment variables passed to recovery child processes. Each entry
    /// is in `KEY=VALUE` format. Applied on top of the base env chosen by
    /// [`Self::recovery_inherit_env`]: default-secure (cleared,
    /// `PATH=/usr/bin:/bin` only) → these become an explicit allowlist;
    /// inherit-mode → these override the inherited values for the named keys.
    pub recovery_env: Vec<String>,
    /// Opt in to inheriting the observer's full environment for recovery
    /// child processes. Default `false` (secure) — child env is cleared to
    /// `PATH=/usr/bin:/bin` plus any explicit `recovery_env` entries.
    /// Set via `--recovery-inherit-env`. See
    /// `book/src/architecture/recovery.md` for the rationale and migration
    /// guide.
    pub recovery_inherit_env: bool,
    /// Optional path the file exporter appends one event-line per record to.
    pub file_export: Option<PathBuf>,
    /// Optional byte limit for the file export. When exceeded, the current
    /// file is rotated (up to 5 generations) and a new one is opened.
    pub export_file_max_bytes: Option<u64>,
    /// Records between forced `fdatasync(2)` calls on the file exporter.
    /// `0` (default) preserves the v0.1 behavior — flush only on clean
    /// shutdown and during rotation. Non-zero values trade IO for
    /// crash-time durability; `1` matches the recovery audit log's
    /// per-record durability guarantee. Set via
    /// `--export-file-sync-every <N>`.
    pub export_file_sync_every: u32,
    /// Optional listening address for the Prometheus exporter.
    pub prom_addr: Option<SocketAddr>,
    /// Path to a file containing the 32-byte (64-hex-character) bearer token
    /// for the Prometheus `/metrics` endpoint.  Required whenever
    /// [`Self::prom_addr`] is set: `/metrics` has no anonymous access.  The
    /// file must be a regular file (no symlinks), owned by the observer's
    /// UID, mode `0o600` or stricter — see [`super::validate::validate_secret_file`].
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
    /// Maximum slots scanned per eviction attempt.
    /// Defaults to [`DEFAULT_EVICTION_SCAN_WINDOW`].
    pub eviction_scan_window: usize,
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
    /// `None` disables per-pid limiting (pass `--max-beat-rate 0`).
    /// Defaults to `Some(DEFAULT_MAX_BEAT_RATE)` — beats arriving faster
    /// than this rate from the same pid are dropped and counted via
    /// `varta_rate_limited_total{reason="per_pid"}`.
    pub max_beat_rate: Option<u32>,
    /// Global beat rate cap across all senders combined, in beats per
    /// second.  Provides a ceiling that defeats per-pid rotation attacks.
    /// `0` disables (`--global-beat-rate 0`).  Defaults to
    /// [`DEFAULT_GLOBAL_BEAT_RATE`].
    pub global_beat_rate: u32,
    /// Global token-bucket burst capacity.  Defaults to
    /// [`DEFAULT_GLOBAL_BEAT_BURST`].  `0` along with `global_beat_rate`
    /// effectively disables the global bucket.
    pub global_beat_burst: u32,
    /// Requested `SO_RCVBUF` size in bytes for the observer UDS.  `0`
    /// leaves the kernel default unchanged.  Defaults to
    /// [`DEFAULT_UDS_RCVBUF_BYTES`].  The actual granted size (which Linux
    /// clamps to `net.core.rmem_max`) is surfaced as
    /// `varta_observer_uds_rcvbuf_bytes`.
    pub uds_rcvbuf_bytes: u32,
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
    /// [`DEFAULT_PROM_RATE_LIMIT_PER_SEC`].  `0` disables per-IP rate
    /// limiting (same as a `0` burst); a zero refill cannot meaningfully
    /// limit — it would only lock out a steady scraper after the burst.
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
    /// Operator opt-in to combine the **secure-UDP** listener with a recovery
    /// command.  Secure UDP authenticates wire bytes but cannot attest the
    /// sending process — a holder of a shared PSK or a derived per-agent key
    /// can forge a beat for any pid.  Without this flag, startup refuses to
    /// proceed when both `--udp-port` (with key files) and a recovery template
    /// are set.  With this flag the runtime origin gate stamps beats from this
    /// listener [`BeatOrigin::OperatorAttestedTransport`] so recovery fires.
    /// Set by `--secure-udp-i-accept-recovery-on-unauthenticated-transport`.
    pub i_accept_recovery_on_secure_udp: bool,
    /// Operator opt-in to combine the **plaintext-UDP** listener with a
    /// recovery command.  Plaintext UDP has no authentication whatsoever —
    /// any host that can reach the observer port can forge any frame.  Without
    /// this flag, startup refuses to proceed when both `--udp-port` (without
    /// key files) and a recovery template are set.  With this flag the runtime
    /// origin gate stamps beats from this listener
    /// [`BeatOrigin::OperatorAttestedTransport`] so recovery fires.
    /// Set by `--plaintext-udp-i-accept-recovery-on-unauthenticated-transport`.
    pub i_accept_recovery_on_plaintext_udp: bool,
    /// Operator opt-in to bind the **secure-UDP** listener to a non-loopback
    /// address (H4). The per-sender replay protection retains state for up
    /// to 1024 authenticated PIDs and fails closed for unknown senders when
    /// the table is full. Loopback is the safe default; any reachable network
    /// can still turn authenticated high-cardinality traffic into admission
    /// pressure for new agents and must be explicitly acknowledged. Without
    /// this flag, startup refuses to proceed when `--udp-bind-addr` resolves
    /// to a non-loopback address and secure-UDP keys are configured. Set by
    /// `--i-accept-secure-udp-non-loopback`.
    pub i_accept_secure_udp_non_loopback: bool,
    /// Permit beats — and, by extension, recovery commands — for agents
    /// whose kernel-attested PID namespace differs from the observer's.
    /// Use only when agents intentionally share the host namespace
    /// (`--pid=host` containers) or an out-of-band translator is in place.
    /// Set by `--allow-cross-namespace-agents`. Default `false` — beats from
    /// cross-namespace agents are dropped at receive (counted via
    /// `varta_frame_namespace_mismatch_total`), and any stalls that did
    /// progress before opt-in refuse recovery (counted via
    /// `varta_recovery_refused_total{reason="cross_namespace_agent"}`).
    pub allow_cross_namespace_agents: bool,
    /// Treat a cross-namespace agent as a fatal startup error instead of the
    /// default refuse-recovery behaviour. Set by `--strict-namespace-check`.
    /// Useful in environments where the operator wants the daemon to fail
    /// loudly rather than silently log audit refusals. Default `false`.
    pub strict_namespace_check: bool,
    /// Optional path the recovery audit TSV is appended to. When set, every
    /// recovery spawn and completion is recorded with wall-clock timestamp,
    /// agent pid, child pid, mode, outcome, exit code, and duration. See
    /// [`crate::audit::RecoveryAuditLog`] for the schema.
    pub recovery_audit_file: Option<PathBuf>,
    /// Optional byte cap for the recovery audit file. When exceeded, the
    /// file rotates through up to 5 generations (PATH → PATH.1 → … →
    /// PATH.5). Without a cap the file grows unbounded.
    pub recovery_audit_max_bytes: Option<u64>,
    /// How many records to write between forced `fdatasync(2)` calls on
    /// the audit file. Default `1` (sync every record) — the only
    /// IEC 62304 Class C-conforming value. Higher values trade a small
    /// risk of losing up to N-1 records on power cut for a lower per-
    /// record cost. Values >1 trigger a startup warning. `0` is rejected
    /// at parse time.
    pub recovery_audit_sync_every: u32,
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
    /// Soft per-call budget for a single `fdatasync(2)` on the audit
    /// log.  If one fsync exceeds this, the remaining records in the
    /// current drain are written-to-BufWriter only and the fsync is
    /// deferred to the next maintenance tick — bounds the worst-case
    /// poll stall on a slow disk to one fsync per tick.  Increments
    /// `varta_audit_fsync_budget_exceeded_total` on overrun.  Set by
    /// `--audit-fsync-budget-ms`; defaults to
    /// [`DEFAULT_AUDIT_FSYNC_BUDGET_MS`].  `0` is rejected.
    pub audit_fsync_budget_ms: u32,
    /// Time-based fdatasync cadence in addition to the record-count
    /// cadence from `--recovery-audit-sync-every`.  `0` (default)
    /// disables the time-based cadence; with a non-zero value, the
    /// drain force-syncs after this many ms have elapsed since the
    /// last sync even when the per-record threshold has not yet
    /// been crossed.  Operators on safety-critical profiles keep
    /// `--recovery-audit-sync-every=1` and ignore this flag; deployments
    /// that relax the record cadence pin a worst-case sync interval
    /// here.  Set by `--audit-sync-interval-ms`; defaults to
    /// [`DEFAULT_AUDIT_SYNC_INTERVAL_MS`].
    pub audit_sync_interval_ms: u32,
    /// Per-tick wall-clock budget for the audit-log rotation state
    /// machine.  Rotation (rename × 5 + reopen + header + boot record +
    /// fsync) advances incrementally; if a tick exceeds this budget the
    /// state is preserved and the next tick resumes.  Increments
    /// `varta_audit_rotation_budget_exceeded_total` on overrun.  Set by
    /// `--audit-rotation-budget-ms`; defaults to
    /// [`DEFAULT_AUDIT_ROTATION_BUDGET_MS`].  Accepted range
    /// `1..=`[`MAX_AUDIT_ROTATION_BUDGET_MS`]: `0` perpetually defers rotation
    /// and a value at/above the Maintenance-stage self-watchdog abort
    /// `process::abort()`s a healthy observer.
    pub audit_rotation_budget_ms: u32,
    /// [test-hooks only] Sleep for this many milliseconds on the first poll
    /// iteration, simulating a wedged loop.  Used by the self-watchdog
    /// integration test (`tests/self_watchdog.rs`) to exercise the abort path
    /// without relying on SIGSTOP (which freezes the watchdog thread too).
    /// Present only when compiled with `--features test-hooks`.
    #[cfg(feature = "test-hooks")]
    pub inject_wedge_ms: Option<u64>,
    /// Kernel clock that backs stall-threshold accounting (H7).
    ///
    /// - `Monotonic` (default): `CLOCK_MONOTONIC` — pauses on system
    ///   suspend. Correct for SRE / cloud deployments.
    /// - `Boottime` (Linux only): `CLOCK_BOOTTIME` — advances during
    ///   suspend. Correct for embedded clinical devices that aggressively
    ///   sleep (insulin pumps, holter monitors).
    ///
    /// See `book/src/architecture/safety-profiles.md` for the deployment
    /// matrix. Set by `--clock-source <monotonic|boottime>`.
    pub clock_source: ClockSource,
    /// Signal-handler installation path on Linux.
    ///
    /// - `Direct` (default): direct `rt_sigaction(2)` syscall — owns the
    ///   kernel ABI end-to-end, including the x86_64 signal-return trampoline.
    ///   A readback + live SIGUSR1 smoke test run at startup.
    /// - `Libc`: libc `sigaction(3)` wrapper — libc's `__restore_rt` is used.
    ///   Opt-in for kernels not yet certified against the direct path.
    ///
    /// On macOS, FreeBSD, and other Unix, the mode is noted in startup
    /// logs but has no operational effect (libc / POSIX is the only option).
    /// Set by `--signal-handler-mode <direct|libc>`.
    pub signal_handler_mode: SignalHandlerMode,
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
    /// `--self-watchdog-secs` value is below [`MIN_SELF_WATCHDOG_SECS`]. A
    /// deadline of `0` self-aborts a healthy observer on the first watchdog
    /// tick; the watchdog is disabled by omitting the flag, never by `0`.
    SelfWatchdogTooLow {
        /// The value that was provided, in seconds.
        value: u64,
        /// The minimum allowed value, in seconds.
        min: u64,
    },
    /// Two or more mutually exclusive recovery flags were specified.
    MutuallyExclusive {
        /// The pair of conflicting flags (e.g. `("--recovery-exec", "--recovery-exec-file")`).
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
    /// configured (`--recovery-exec` / `--recovery-exec-file`). Capture is
    /// meaningless without something to capture from.
    RecoveryCaptureRequiresRecovery,
    /// `--shutdown-grace-ms` was below [`MIN_SHUTDOWN_GRACE_MS`].
    ShutdownGraceTooLow {
        /// The value provided on the CLI.
        value: u64,
        /// The minimum allowed value.
        min: u64,
    },
    /// Shell-mode recovery flags were passed (removed feature).  Use
    /// `--recovery-exec` instead.
    ShellRecoveryNotCompiledIn,
    /// A recovery command (`--recovery-exec` / `--recovery-exec-file`) was
    /// configured at the
    /// same time as a UDP listener (`--udp-port`), without the matching
    /// per-listener operator acknowledgement.  UDP transports cannot attest
    /// the sending process — an attacker holding the AEAD key (or a derived
    /// per-agent key) can forge a beat claiming any pid, then stop sending to
    /// trigger the recovery command against the chosen pid.  Pass
    /// `--secure-udp-i-accept-recovery-on-unauthenticated-transport` (for
    /// secure UDP) or
    /// `--plaintext-udp-i-accept-recovery-on-unauthenticated-transport` (for
    /// plaintext UDP) to proceed.
    RecoveryRequiresAuthenticatedTransport {
        /// The `IP:PORT` of the UDP listener that would have been bound.
        udp_addr: String,
    },
    /// A secure-UDP listener was configured with a non-loopback
    /// `--udp-bind-addr`, but `--i-accept-secure-udp-non-loopback` was not
    /// passed (H4). The replay-state table is bounded and fail-closed, so a
    /// reachable network can still deny admission for new agents by filling it
    /// with authenticated high-cardinality traffic.
    SecureUdpRequiresLoopbackBind {
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
    /// `--eviction-scan-window` was outside the accepted range
    /// (`[MIN_EVICTION_SCAN_WINDOW, MAX_EVICTION_SCAN_WINDOW]`).
    EvictionScanWindowOutOfRange {
        /// The value provided.
        value: usize,
        /// The minimum allowed value.
        min: usize,
        /// The maximum allowed value.
        max: usize,
    },
    /// `--tracker-capacity` was outside the accepted range
    /// (`[1, crate::tracker::MAX_CAPACITY]`).
    TrackerCapacityOutOfRange {
        /// The value provided.
        value: usize,
        /// The minimum allowed value.
        min: usize,
        /// The maximum allowed value.
        max: usize,
    },
    /// `--read-timeout-ms` exceeded [`MAX_READ_TIMEOUT_MS`]. A read timeout at
    /// or above the `Poll`-stage self-watchdog abort would let a healthy, idle
    /// observer trip the watchdog and `process::abort()`.
    ReadTimeoutTooLarge {
        /// The value provided, in milliseconds.
        value: u64,
        /// The maximum allowed value, in milliseconds.
        max: u64,
    },
    /// `--audit-rotation-budget-ms` exceeded [`MAX_AUDIT_ROTATION_BUDGET_MS`].
    /// `drive_audit_rotation` is spent inside the `Maintenance` stage and runs
    /// up to its full budget per tick, so a budget at/above the Maintenance
    /// self-watchdog abort lets a normal rotation `process::abort()` a healthy
    /// observer.
    AuditRotationBudgetTooLarge {
        /// The value provided, in milliseconds.
        value: u64,
        /// The maximum allowed value, in milliseconds.
        max: u64,
    },
    /// `--clock-source boottime` was requested but the host kernel has no
    /// equivalent of Linux's `CLOCK_BOOTTIME`. Currently fires on every
    /// non-Linux target (macOS, *BSD).
    ClockSourceUnsupported {
        /// The source the operator requested.
        source: ClockSource,
        /// `std::env::consts::OS` for the build target.
        platform: &'static str,
    },
    /// The binary was built with `--features compile-time-config` but the
    /// operator supplied one or more argv tokens.  Class-A safety-critical
    /// builds intentionally accept zero argv; the configuration is baked
    /// into the binary by `build.rs` at compile time.
    CompileTimeArgvForbidden,
    /// `Config::compile_time()` produced a value that fails cross-field
    /// validation at startup (e.g. recovery requires kernel-attested
    /// transport but the compile-time blob enabled both UDP and recovery
    /// without the acknowledgement flag).  Carries the same diagnostic
    /// text the corresponding `from_args` error would produce.
    CompileTimeConfigInvalid {
        /// Static description of which invariant was violated.
        reason: &'static str,
    },
}

// The `ConfigError` Display impl has two cfg-gated personalities:
//
// 1. Default (SRE) builds: rich messages that name the flag the operator
//    must supply or correct.  These strings carry literal flag names like
//    `--socket` and `--prom-addr` and are linked unconditionally.
//
// 2. Class-A (`compile-time-config`) builds: terse, neutral phrasings that
//    never mention argv flag names.  Most variants are dead code anyway —
//    they are produced only by `Config::from_args`, which is excluded from
//    compilation when the feature is on — but the Display impl must still
//    cover every variant, and any literal flag string in the impl ends up
//    in the binary (cerebrum 2026-05-12: `pub const &str` is always linked
//    regardless of `#[cfg]` on the code paths that consume it).
//
// The Class-A wording uses `config key` instead of `--flag-name` and refers
// the operator to `book/src/architecture/compile-time-config.md` for any
// remediation.  The two impls are mutually exclusive at the `#[cfg]` layer.

#[cfg(not(feature = "compile-time-config"))]
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
            ConfigError::SelfWatchdogTooLow { value, min } => write!(
                f,
                "--self-watchdog-secs: {value} is below the minimum {min} \
                 (0 self-aborts a healthy observer on the first watchdog tick; \
                 omit the flag to run without a watchdog)"
            ),
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
                "--recovery-capture-stdio requires --recovery-exec or --recovery-exec-file",
            ),
            ConfigError::ShellRecoveryNotCompiledIn => f.write_str(
                "shell-mode recovery has been permanently removed; use --recovery-exec instead",
            ),
            ConfigError::RecoveryRequiresAuthenticatedTransport { udp_addr } => write!(
                f,
                "recovery command is configured alongside a UDP listener on {udp_addr}. \
                 UDP transports cannot attest the sending process — a holder of the AEAD key \
                 (or a per-agent key derived from a leaked master key) can forge a beat \
                 claiming any pid, then stop sending to trigger recovery against the chosen pid. \
                 Either remove the recovery command, switch to a UDS-only deployment, or pass \
                 --secure-udp-i-accept-recovery-on-unauthenticated-transport (for secure UDP) \
                 or --plaintext-udp-i-accept-recovery-on-unauthenticated-transport (for plaintext \
                 UDP) to explicitly accept this risk on a per-listener basis."
            ),
            ConfigError::SecureUdpRequiresLoopbackBind { udp_addr } => write!(
                f,
                "secure-UDP listener configured with non-loopback --udp-bind-addr ({udp_addr}). \
                 The per-sender replay-state table is bounded to 1024 senders and fails \
                 closed for new senders at capacity. A reachable network can still deny \
                 new agents by exhausting that table with authenticated traffic. \
                 Either bind to a loopback address (default 127.0.0.1) or pass \
                 --i-accept-secure-udp-non-loopback to explicitly accept this risk. \
                 See book/src/architecture/vlp-transports.md for the threat-boundary derivation."
            ),
            ConfigError::IterationBudgetOutOfRange { value, min, max } => write!(
                f,
                "--iteration-budget-ms: {value} is outside the accepted range [{min}, {max}] ms"
            ),
            ConfigError::ScrapeBudgetOutOfRange { value, min, max } => write!(
                f,
                "--scrape-budget-ms: {value} is outside the accepted range [{min}, {max}] ms"
            ),
            ConfigError::EvictionScanWindowOutOfRange { value, min, max } => write!(
                f,
                "--eviction-scan-window: {value} is outside the accepted range [{min}, {max}]"
            ),
            ConfigError::TrackerCapacityOutOfRange { value, min, max } => write!(
                f,
                "--tracker-capacity: {value} is outside the accepted range [{min}, {max}]"
            ),
            ConfigError::ReadTimeoutTooLarge { value, max } => write!(
                f,
                "--read-timeout-ms: {value} ms exceeds the maximum {max} ms \
                 (must stay below the {POLL_STAGE_ABORT_MS} ms Poll-stage self-watchdog abort)"
            ),
            ConfigError::AuditRotationBudgetTooLarge { value, max } => write!(
                f,
                "--audit-rotation-budget-ms: {value} ms exceeds the maximum {max} ms \
                 (must stay below the {MAINTENANCE_STAGE_ABORT_MS} ms Maintenance-stage \
                 self-watchdog abort)"
            ),
            ConfigError::ClockSourceUnsupported { source, platform } => {
                let hint = match source {
                    crate::clock::ClockSource::Boottime => {
                        "`boottime` semantics (advance through suspend) require Linux's \
                         CLOCK_BOOTTIME. On macOS / iOS use `--clock-source monotonic-raw` \
                         (mach_continuous_time) for the same semantics; BSD has no equivalent \
                         kernel clock."
                    }
                    crate::clock::ClockSource::MonotonicRaw => {
                        "`monotonic-raw` is macOS / iOS only (CLOCK_MONOTONIC_RAW = \
                         mach_continuous_time). On Linux use `--clock-source boottime` \
                         (CLOCK_BOOTTIME) for advance-through-suspend semantics; BSD \
                         has no equivalent kernel clock."
                    }
                    crate::clock::ClockSource::Monotonic => "",
                };
                write!(
                    f,
                    "--clock-source {source} is not supported on `{platform}`. {hint} \
                     Otherwise use `--clock-source monotonic` (the default)."
                )
            }
            ConfigError::CompileTimeArgvForbidden => f.write_str(
                "this binary was configured at compile time \
                 (--features compile-time-config); refusing to accept argv. \
                 See book/src/architecture/compile-time-config.md for the \
                 supported configuration mechanism.",
            ),
            ConfigError::CompileTimeConfigInvalid { reason } => write!(
                f,
                "compile-time config violates a cross-field invariant: {reason}"
            ),
        }
    }
}

#[cfg(feature = "compile-time-config")]
impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Generic remediation pointer for every flag-relevant variant.
        // Argv-only variants are unreachable in Class-A builds (their
        // producer, `Config::from_args`, is excluded from compilation),
        // but the Display impl must still cover them.  Neutral wording
        // keeps argv flag names out of the binary's `strings` output.
        const REF: &str = "see book/src/architecture/compile-time-config.md";
        match self {
            ConfigError::MissingValue(_)
            | ConfigError::MissingRequired(_)
            | ConfigError::UnknownFlag(_)
            | ConfigError::BadInteger { .. }
            | ConfigError::BadSocketMode(_)
            | ConfigError::BadAddr(_)
            | ConfigError::BadValue { .. }
            | ConfigError::HelpRequested
            | ConfigError::MutuallyExclusive { .. }
            | ConfigError::RemovedFlag { .. }
            | ConfigError::PromAddrRequiresToken
            | ConfigError::ShutdownGraceTooLow { .. }
            | ConfigError::RecoveryCaptureBytesTooLarge { .. }
            | ConfigError::RecoveryCaptureRequiresRecovery
            | ConfigError::RecoveryRequiresAuthenticatedTransport { .. }
            | ConfigError::SecureUdpRequiresLoopbackBind { .. }
            | ConfigError::IterationBudgetOutOfRange { .. }
            | ConfigError::ScrapeBudgetOutOfRange { .. }
            | ConfigError::EvictionScanWindowOutOfRange { .. } => {
                write!(f, "configuration error (argv path unreachable; {REF})")
            }
            ConfigError::TrackerCapacityOutOfRange { value, min, max } => write!(
                f,
                "tracker capacity out of range: {value} not in [{min}, {max}] ({REF})"
            ),
            ConfigError::ReadTimeoutTooLarge { value, max } => write!(
                f,
                "read timeout out of range: {value} ms exceeds {max} ms ({REF})"
            ),
            ConfigError::AuditRotationBudgetTooLarge { value, max } => write!(
                f,
                "audit rotation budget out of range: {value} ms exceeds {max} ms ({REF})"
            ),
            ConfigError::ThresholdTooLow { value, min } => {
                write!(f, "threshold below minimum: {value} ms < {min} ms ({REF})")
            }
            ConfigError::SelfWatchdogTooLow { value, min } => {
                write!(
                    f,
                    "self-watchdog deadline below minimum: {value} < {min} ({REF})"
                )
            }
            ConfigError::ShellRecoveryNotCompiledIn => write!(
                f,
                "shell-mode recovery has been permanently removed ({REF})"
            ),
            ConfigError::ClockSourceUnsupported { platform, .. } => write!(
                f,
                "configured clock source is not supported on `{platform}`; \
                 only the monotonic source is available off Linux ({REF})"
            ),
            ConfigError::CompileTimeArgvForbidden => f.write_str(
                "this binary was configured at compile time; \
                 refusing to accept command-line arguments",
            ),
            ConfigError::CompileTimeConfigInvalid { reason } => write!(
                f,
                "compile-time config violates a cross-field invariant: {reason}"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}
