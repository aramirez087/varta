#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]
// SAFETY: unsafe_code is required for the signal_install::install() call in
// run() and for the inline test that calls it. The workspace-level deny
// forces explicit opt-in.
#![allow(unsafe_code)]

//! Varta observer binary entry point.
//!
//! Parses argv into a [`Config`], binds an [`Observer`], optionally
//! installs a [`Recovery`] runner and the file / Prometheus exporters,
//! then drives [`Observer::poll`] in a single thread until either a
//! `--shutdown-after-secs` deadline elapses or a signal (SIGINT /
//! SIGTERM) flips the [`SHUTDOWN`] latch.
//!
//! This binary uses `varta_watch::varta_*` logging macros.  Diagnostics
//! go to stderr — either plain `eprintln!` format (default) or JSON lines
//! when the `json-log` feature is enabled.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "prometheus-exporter")]
use varta_watch::exporter::IterStage;
use varta_watch::log_ratelimit::LogKind;
#[cfg(feature = "prometheus-exporter")]
use varta_watch::PromExporter;
use varta_watch::{
    varta_error, varta_error_err, varta_error_pid, varta_error_rl, varta_info_pid_child,
    varta_warn, varta_warn_child, varta_warn_rl, Config, ConfigError, Event, Exporter,
    FileExporter, Observer, Recovery, RecoveryOutcome,
};

/// Shutdown latch flipped by [`handle_shutdown`] on SIGINT/SIGTERM
/// and by the `--shutdown-after-secs` deadline path. The poll loop exits
/// when this becomes non-zero.
///
/// # Async-signal-safety
///
/// The signal handler writes `1` with `Ordering::Release` to this
/// `AtomicI32`.  `AtomicI32` is an integer atomic — the same primitive
/// as POSIX `volatile sig_atomic_t` (`int` on every conformant platform).
/// The `const _` assertion below proves at compile time that the type is
/// always lock-free, guaranteeing the store compiles to a single aligned
/// atomic instruction (e.g. `lock or $1,mem` on x86_64; `stlr` on
/// aarch64) and cannot be interrupted mid-store.
/// `SA_RESTART` is set so the observer's `recvmsg(2)` never returns `EINTR`.
/// On Linux the handler is installed via a direct `rt_sigaction(2)` syscall
/// (not the libc wrapper, which would strip our `sa_restorer`); on x86_64
/// the kernel returns through our own [`varta_signal_restorer`] trampoline.
/// On aarch64 the kernel-side `<asm-generic/signal.h>` struct has no
/// `sa_restorer` field, and signal-return goes through the vDSO.
static SHUTDOWN: AtomicI32 = AtomicI32::new(0);

/// Compile-time proof that [`SHUTDOWN`] lowers to a single uninterruptible
/// instruction: `AtomicI32` is only available when `target_has_atomic = "32"`,
/// i.e. when 32-bit atomic ops are lock-free on the target — the structural
/// requirement for async-signal-safety per POSIX (equivalent to
/// `volatile sig_atomic_t`).
#[cfg(not(target_has_atomic = "32"))]
compile_error!(
    "varta-watch requires lock-free 32-bit atomics (target_has_atomic = \"32\") \
     for the async-signal-safe SHUTDOWN latch"
);

/// Nanosecond timestamp of the most recent poll loop iteration, written by
/// the main thread each tick and read by the self-watchdog thread.
/// Initialised to 0; the watchdog ignores the zero value to avoid spurious
/// aborts before the first tick.
///
/// Synchronisation: store-Release / load-Acquire forms the publication
/// edge from the main thread to the self-watchdog. `Relaxed` gives no
/// upper bound on cross-thread visibility, which on weakly-ordered
/// targets could in theory let a healthy main thread look wedged.
static LAST_TICK_NS: AtomicU64 = AtomicU64::new(0);

/// Per-stage entry timestamps written by the main thread at the START of each
/// poll-loop phase.  The self-watchdog thread reads these to detect a wedge
/// inside a single stage (e.g. a hung `serve_pending`) without waiting for
/// the full [`LAST_TICK_NS`] deadline.  Indexed by [`IterStage as usize`].
///
/// Initialised to 0; the watchdog treats 0 as "stage not yet entered".
#[cfg(feature = "prometheus-exporter")]
static LAST_STAGE_ENTRY_NS: [AtomicU64; 6] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Index of the stage the main thread is currently executing, or `u8::MAX`
/// when the loop is idle (between iterations or in the throttle sleep).
/// Written by the main thread, read by the self-watchdog thread.
#[cfg(feature = "prometheus-exporter")]
static CURRENT_STAGE: AtomicU8 = AtomicU8::new(u8::MAX);

/// Per-stage hard abort threshold in nanoseconds.  If the main thread stays
/// in the same stage for longer than this value, the watchdog calls
/// `process::abort()`.  Each threshold is ≥ 5× the stage's soft budget so
/// transient overruns under scrape load do not trigger a false positive.
///
/// Indexed by [`IterStage as usize`] — must stay in sync with the enum.
#[cfg(feature = "prometheus-exporter")]
const STAGE_ABORT_NS: [u64; 6] = [
    2_000 * 1_000_000, // DrainPending: 2 s (5× 20 ms soft budget)
    2_000 * 1_000_000, // Poll:         2 s (≈18× read_timeout default)
    500 * 1_000_000,   // Maintenance:  500 ms (50× 10 ms)
    1_000 * 1_000_000, // RecoveryReap: 1 s (50× 20 ms)
    2_000 * 1_000_000, // ServePending: 2 s (10× 200 ms structural cap)
    1_000 * 1_000_000, // Housekeeping: 1 s (100× 10 ms)
];

/// Kernel clock source for `observer_now_ns()`.  Set exactly once in
/// `run()` before the self-watchdog thread spawns, so both threads agree
/// on the meaning of `LAST_TICK_NS` and on whether the clock advances
/// during host suspend.  H7 — see `crates/varta-watch/src/clock.rs`.
///
/// Encoding: `ClockSource::as_u8()` / `ClockSource::from_u8()`.
static CLOCK_SOURCE: AtomicU8 = AtomicU8::new(0);

// Signal-handler installation is delegated to the `signal_install` module
// (see `crates/varta-watch/src/signal_install/`). The handler below sets the
// `SHUTDOWN` latch; `run()` passes it to `signal_install::install`.
// Architecture support is gated in `signal_install/linux/mod.rs`.

/// Shutdown handler — flips [`SHUTDOWN`] on SIGINT / SIGTERM delivery.
///
/// Async-signal-safe by POSIX construction: `AtomicI32` is the integer
/// primitive equivalent to `volatile sig_atomic_t`, proven lock-free at
/// compile time (see the `const _` assertion after [`SHUTDOWN`]).
extern "C" fn handle_shutdown(_sig: i32) {
    SHUTDOWN.store(1, Ordering::Release);
}

/// Write `contents` to `path` atomically via a same-directory tempfile + rename.
///
/// `rename(2)` is atomic on POSIX-compliant filesystems; a reader of `path`
/// will observe either the previous complete file or the new complete file,
/// never a partial write.  A `.<pid>.tmp` suffix keeps concurrent observers
/// (misconfigured onto the same path) from clobbering each other's tempfile.
/// If the rename fails the tempfile is removed before returning the error.
/// Monotonic nanosecond clock for the self-watchdog thread.  Reads the
/// kernel clock selected by `--clock-source` via the `CLOCK_SOURCE`
/// atomic — `Monotonic` (CLOCK_MONOTONIC) or `Boottime`
/// (CLOCK_BOOTTIME, Linux only).
///
/// Replaces an earlier `SystemTime::now()` (wall-clock) implementation
/// which had the foot-gun of going backwards on NTP step.  The new
/// implementation aligns the watchdog's deadline arithmetic with what
/// the observer's `now_ns()` perceives — same clock, same semantics —
/// so a configured medical-device deployment gets watchdog ticks that
/// also advance during host suspend.
fn observer_now_ns() -> u64 {
    let src = varta_watch::clock::ClockSource::from_u8(CLOCK_SOURCE.load(Ordering::Acquire));
    let clk_id = match src.clk_id() {
        Some(id) => id,
        // Unreachable: the CLI parser rejects unsupported sources before
        // this static is written.  Defensive 0 keeps watchdog_expired's
        // `last == 0` skip-before-first-tick semantics from misfiring.
        None => return 0,
    };
    varta_watch::clock::clock_gettime_raw(clk_id).unwrap_or(0)
}

/// Returns `true` when the poll loop has not ticked for longer than
/// `deadline_ns` nanoseconds.  `last == 0` means "not yet started"; skip
/// until the first real tick to avoid false aborts at startup.
fn watchdog_expired(now_ns: u64, last_ns: u64, deadline_ns: u64) -> bool {
    last_ns != 0 && now_ns.saturating_sub(last_ns) > deadline_ns
}

fn write_heartbeat_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let pid = std::process::id();
    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(format!(".{pid}.tmp"));
    let tmp_path = PathBuf::from(tmp_os);

    let result = (|| -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(contents)?;
        drop(f);
        std::fs::rename(&tmp_path, path)
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

fn main() -> ExitCode {
    // Branch the configuration source on the `compile-time-config` feature.
    // Default builds parse argv (SRE profile); Class-A builds reject any argv
    // and read the baked-in constant produced by build.rs from
    // $VARTA_CONFIG_FILE at compile time.
    #[cfg(not(feature = "compile-time-config"))]
    let cfg_result: Result<Config, ConfigError> = {
        let args: Vec<String> = std::env::args().skip(1).collect();
        Config::from_args(args)
    };
    #[cfg(feature = "compile-time-config")]
    let cfg_result: Result<Config, ConfigError> = {
        if std::env::args().nth(1).is_some() {
            Err(ConfigError::CompileTimeArgvForbidden)
        } else {
            Config::compile_time()
        }
    };

    match cfg_result {
        Ok(cfg) => match run(cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                varta_error!("{e}");
                ExitCode::from(1)
            }
        },
        Err(ConfigError::HelpRequested) => {
            let _ = std::io::stdout().lock().write_all(Config::HELP.as_bytes());
            ExitCode::SUCCESS
        }
        Err(e) => {
            varta_error!("{e}");
            let _ = std::io::stderr().lock().write_all(Config::HELP.as_bytes());
            ExitCode::from(2)
        }
    }
}

fn run(cfg: Config) -> std::io::Result<()> {
    // SAFETY: sole entry point of a single-threaded binary with no competing
    // SIGINT/SIGTERM installers; called before any thread is spawned.
    unsafe {
        varta_watch::signal_install::install(cfg.signal_handler_mode, handle_shutdown)?;
    }
    // On Class-A builds (no prometheus-exporter) the mode is logged so the
    // startup audit can confirm the certified path is active.
    #[cfg(not(feature = "prometheus-exporter"))]
    varta_watch::varta_info!("signal_handler_mode={}", cfg.signal_handler_mode.as_str());

    // Publish the configured kernel clock source to `CLOCK_SOURCE` BEFORE
    // any thread is spawned. The self-watchdog thread reads this atomic on
    // every tick to decide which `clock_gettime(2)` clk_id to call.
    // Release ordering pairs with the watchdog's Acquire load in
    // `observer_now_ns()`.
    CLOCK_SOURCE.store(cfg.clock_source.as_u8(), Ordering::Release);

    let mut observer = Observer::bind(
        &cfg.socket,
        cfg.threshold,
        cfg.socket_mode,
        cfg.read_timeout,
        cfg.uds_rcvbuf_bytes,
        cfg.tracker_capacity,
        cfg.tracker_eviction_policy,
        cfg.eviction_scan_window,
        cfg.max_beat_rate,
        cfg.global_beat_rate,
        cfg.global_beat_burst,
        cfg.clock_source,
    )?
    .with_allow_cross_namespace(cfg.allow_cross_namespace_agents);

    // On platforms lacking kernel-level per-datagram credential passing
    // (OpenBSD, AIX, HP-UX, and other exotic Unixen) the observer relies
    // solely on --socket-mode (default 0600) as the trust boundary. Beats
    // are tagged BeatOrigin::SocketModeOnly; recovery commands are refused.
    //
    // Linux, macOS, FreeBSD, DragonFly, NetBSD, illumos, and Solaris all
    // have per-datagram credential mechanisms — the observer enforces them
    // automatically.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris",
    )))]
    varta_warn!(
        "running on {} — per-datagram PID verification is unavailable. \
         Beats are tagged socket-mode-only; recovery commands will be refused. \
         The only trust boundary is --socket-mode (default 0600): any process \
         under the same UID can forge frame.pid.",
        std::env::consts::OS,
    );

    #[cfg(feature = "secure-udp")]
    let secure_udp_keys = cfg.load_secure_keys()?;

    #[cfg(feature = "secure-udp")]
    let master_key = cfg.load_master_key()?;

    #[cfg(feature = "udp-core")]
    if let Some(port) = cfg.udp_port {
        // H4: secure-UDP defaults to loopback (127.0.0.1).  Replay protection
        // tolerates ≤1024 source addresses; on any reachable network an
        // attacker who can spoof UDP source ports rotates the eviction
        // shadow and replays captured frames.  Operators who genuinely need
        // a non-loopback secure-UDP bind must pass --udp-bind-addr explicitly
        // AND --i-accept-secure-udp-non-loopback (enforced by Config).
        // Plaintext UDP retains the historical 0.0.0.0 default — it is
        // already gated by --i-accept-plaintext-udp.
        #[cfg(feature = "secure-udp")]
        let secure_keys_configured = cfg.secure_key_file.is_some()
            || cfg.accepted_key_file.is_some()
            || cfg.master_key_file.is_some();
        #[cfg(not(feature = "secure-udp"))]
        let secure_keys_configured = false;

        let bind_addr = cfg.udp_bind_addr.unwrap_or(if secure_keys_configured {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        });
        let addr = std::net::SocketAddr::new(bind_addr, port);

        // High-visibility warning when the operator has opted out of the
        // loopback default for secure UDP.  Mirrors the prom-addr non-
        // loopback warning above.  Skipped for the default (loopback) and
        // for plaintext UDP (warned elsewhere).
        if secure_keys_configured && !bind_addr.is_loopback() {
            #[cfg(not(feature = "compile-time-config"))]
            varta_warn!(
                "secure-UDP is bound to non-loopback {addr} \
                 (--i-accept-secure-udp-non-loopback). The 1-deep replay shadow \
                 after capacity-forced eviction is inadequate for any reachable \
                 network; restrict reach via firewall / private VLAN. See \
                 book/src/architecture/vlp-transports.md for the threat-boundary \
                 derivation."
            );
            #[cfg(feature = "compile-time-config")]
            varta_warn!(
                "secure-UDP is bound to non-loopback {addr}. The 1-deep replay \
                 shadow after capacity-forced eviction is inadequate for any \
                 reachable network; restrict reach via firewall / private VLAN."
            );
        }

        // Listener selection — strict priority:
        //   1. secure-udp feature + keys loaded → SecureUdpListener
        //   2. unsafe-plaintext-udp feature + --i-accept-plaintext-udp
        //      → UdpListener with a high-visibility warning
        //   3. otherwise → hard error (no warn-and-continue path)
        #[allow(unused_mut, unused_assignments)]
        let mut secure_bound = false;

        #[cfg(feature = "secure-udp")]
        {
            let has_shared_keys = secure_udp_keys.is_some();
            let has_master = master_key.is_some();

            if has_shared_keys || has_master {
                let mut all_keys: Vec<varta_vlp::crypto::Key> = Vec::new();
                if let Some((primary, accepted)) = secure_udp_keys {
                    all_keys.push(primary);
                    all_keys.extend(accepted);
                }

                let secure = if let Some(mk) = master_key {
                    varta_watch::SecureUdpListener::bind_with_master(addr, all_keys, mk).map_err(
                        |e| {
                            std::io::Error::new(
                                e.kind(),
                                format!("secure UDP bind (master key) {}: {e}", addr),
                            )
                        },
                    )?
                } else {
                    varta_watch::SecureUdpListener::bind(addr, all_keys).map_err(|e| {
                        std::io::Error::new(e.kind(), format!("secure UDP bind {}: {e}", addr))
                    })?
                };
                let trust = if cfg.i_accept_recovery_on_secure_udp {
                    varta_watch::TransportTrust::Operator
                } else {
                    varta_watch::TransportTrust::Untrusted
                };
                let secure = secure.with_recovery_trust(trust);
                observer.add_listener(Box::new(secure));
                secure_bound = true;
            }
        }

        if !secure_bound {
            // No authenticated listener was bound — only the plaintext path
            // remains.  Refuse to fall back unless the operator has
            // explicitly opted in at runtime, and the plaintext path was
            // compiled in.
            if !cfg.i_accept_plaintext_udp {
                #[cfg(not(feature = "compile-time-config"))]
                varta_error!(
                    "--udp-port {addr} cannot bind: no AEAD keys are configured \
                     and --i-accept-plaintext-udp was not passed. Provide \
                     --key-file (or --master-key-file) for authenticated transport, \
                     or pass --i-accept-plaintext-udp to explicitly accept the \
                     security risk of an unauthenticated UDP listener (test/dev only)."
                );
                #[cfg(feature = "compile-time-config")]
                varta_error!(
                    "UDP listener at {addr} cannot bind: no AEAD keys are configured \
                     and plaintext-UDP acknowledgement is not set."
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "plaintext UDP requires the plaintext-UDP acknowledgement (and no keys are configured)",
                ));
            }

            #[cfg(feature = "unsafe-plaintext-udp")]
            {
                let trust = if cfg.i_accept_recovery_on_plaintext_udp {
                    varta_watch::TransportTrust::Operator
                } else {
                    varta_watch::TransportTrust::Untrusted
                };
                let udp = varta_watch::UdpListener::bind(addr)
                    .map_err(|e| std::io::Error::new(e.kind(), format!("UDP bind {}: {e}", addr)))?
                    .with_recovery_trust(trust);
                observer.add_listener(Box::new(udp));
                #[cfg(not(feature = "compile-time-config"))]
                varta_warn!(
                    "UDP on {addr} is running WITHOUT authentication \
                     (--i-accept-plaintext-udp). Any device with network reach to \
                     this port can inject heartbeats, suppress stall detection, or \
                     trigger false recovery commands. NOT for production / \
                     safety-critical use."
                );
                #[cfg(feature = "compile-time-config")]
                varta_warn!(
                    "UDP on {addr} is running WITHOUT authentication. \
                     Any device with network reach to this port can inject \
                     heartbeats. NOT for production / safety-critical use."
                );
            }

            #[cfg(not(feature = "unsafe-plaintext-udp"))]
            {
                #[cfg(not(feature = "compile-time-config"))]
                varta_error!(
                    "--udp-port {addr} cannot bind: this build does not include \
                     --features unsafe-plaintext-udp, and no AEAD keys are \
                     configured. Rebuild with --features secure-udp and provide \
                     --key-file / --master-key-file."
                );
                #[cfg(feature = "compile-time-config")]
                varta_error!(
                    "UDP listener at {addr} cannot bind: plaintext UDP is not \
                     compiled in and no AEAD keys are configured."
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "plaintext UDP not compiled in; no keys configured",
                ));
            }
        }
    }

    #[cfg(not(feature = "udp-core"))]
    if cfg.udp_port.is_some() {
        #[cfg(not(feature = "compile-time-config"))]
        varta_error!(
            "--udp-port requires UDP support (rebuild with --features secure-udp \
             for authenticated transport, or --features unsafe-plaintext-udp for \
             a development/testing plaintext listener)"
        );
        #[cfg(feature = "compile-time-config")]
        varta_error!("UDP port configured but UDP support is not compiled in");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "UDP support not compiled in",
        ));
    }

    #[cfg(not(feature = "secure-udp"))]
    if cfg.secure_key_file.is_some()
        || cfg.accepted_key_file.is_some()
        || cfg.master_key_file.is_some()
    {
        #[cfg(not(feature = "compile-time-config"))]
        varta_error!(
            "--key-file / --accepted-key-file / --master-key-file require secure \
             UDP support (rebuild with --features secure-udp)"
        );
        #[cfg(feature = "compile-time-config")]
        varta_error!(
            "secure-UDP key files are configured but the secure-UDP transport \
             is not compiled into this build"
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "secure UDP support not compiled in",
        ));
    }

    let recovery_mode = cfg.resolve_recovery_mode()?;

    // Audit-trail warning when the operator explicitly opts into shell-mode
    // recovery.  resolve_recovery_mode() already hard-errors when shell mode
    // is configured without the flag, so reaching here with the flag set
    // means the choice was deliberate — log it once so it appears in any
    // SIEM / syslog ingest alongside the other startup banners.
    #[cfg(feature = "unsafe-shell-recovery")]
    if cfg.i_accept_shell_risk && (cfg.recovery_cmd.is_some() || cfg.recovery_cmd_file.is_some()) {
        varta_warn!(
            "shell-mode recovery is active (--i-accept-shell-risk). The system shell \
             will be spawned with root-equivalent process authority on each unique \
             stall. NOT for production / safety-critical use — prefer --recovery-exec."
        );
    }

    // Audit-trail warning when the operator opts into legacy env inheritance
    // for recovery child processes.  The default is to clear the child env
    // (see `Recovery::apply_env`); the opt-in flag pulls in the observer's
    // full env, which may contain secrets (`AWS_*`, OAuth bearers, database
    // URLs, etc.).  Surfacing this once at startup ensures the choice is
    // visible in any SIEM / syslog ingest alongside the other safety banners.
    if cfg.recovery_inherit_env && recovery_mode.is_some() {
        #[cfg(not(feature = "compile-time-config"))]
        varta_warn!(
            "--recovery-inherit-env is set: recovery child processes will inherit \
             the observer's full environment. Audit the observer env for secrets \
             (AWS_*, *_TOKEN, OAuth bearers, database URLs) before production. \
             Prefer --recovery-env KEY=VALUE for explicit allowlisting."
        );
        // Class-A: the argv parser is excluded, but compile-time config can
        // still enable inheritance.  Use neutral wording with no flag-name
        // literals (cerebrum 2026-05-13 strings-audit discipline).
        #[cfg(feature = "compile-time-config")]
        varta_warn!(
            "recovery child env inheritance is enabled (compile-time config); \
             recovery subprocesses inherit the observer's environment. Audit \
             observer env for secrets before deployment."
        );
    }

    // Optional audit log — opened once at startup. The same hardened
    // permission check (mode 0600, owned by observer UID) used for key/
    // token files protects the audit path: never publish recovery
    // activity world-readable.
    let recovery_audit_sink = match cfg.recovery_audit_file.as_ref() {
        Some(path) => {
            let audit_cfg = varta_watch::audit::AuditConfig {
                max_bytes: cfg.recovery_audit_max_bytes,
                sync_every: cfg.recovery_audit_sync_every,
                daemon_pid: std::process::id(),
                fsync_budget: std::time::Duration::from_millis(cfg.audit_fsync_budget_ms as u64),
                sync_interval: if cfg.audit_sync_interval_ms == 0 {
                    None
                } else {
                    Some(std::time::Duration::from_millis(
                        cfg.audit_sync_interval_ms as u64,
                    ))
                },
                rotation_budget: std::time::Duration::from_millis(
                    cfg.audit_rotation_budget_ms as u64,
                ),
            };
            let (sink, warnings) = varta_watch::audit::RecoveryAuditLog::create(path, audit_cfg)?;
            // Surface the warnings the audit sink raised at construction
            // time. Each is a structural risk an auditor should know about
            // before the daemon emits its first recovery record.
            if warnings.chain_disabled {
                #[cfg(not(feature = "compile-time-config"))]
                varta_warn!(
                    "recovery audit chain is DISABLED (build is missing the `audit-chain` \
                     feature). v2 records will carry a literal `-` in the chain column and \
                     this build is NOT IEC 62304 Class C-conforming. Rebuild with \
                     --features audit-chain for tamper-evident audit records."
                );
                #[cfg(feature = "compile-time-config")]
                varta_warn!(
                    "recovery audit chain is DISABLED; records will carry `-` in the \
                     chain column and this build is NOT IEC 62304 Class C-conforming."
                );
            }
            if warnings.sync_relaxed {
                #[cfg(not(feature = "compile-time-config"))]
                varta_warn!(
                    "recovery audit fdatasync cadence is relaxed (--recovery-audit-sync-every \
                     > 1). A power cut can lose up to N-1 records. The Class C-conforming \
                     value is 1 (every record)."
                );
                #[cfg(feature = "compile-time-config")]
                varta_warn!(
                    "recovery audit fdatasync cadence is relaxed (> 1). A power cut can \
                     lose up to N-1 records. The Class C-conforming value is 1."
                );
            }
            if warnings.legacy_v1 {
                varta_warn!(
                    "recovery audit file contains a legacy v1 prefix; v2 section begins now \
                     with a `legacy_v1` boot record."
                );
            }
            if warnings.corrupt_tail {
                varta_warn!(
                    "recovery audit file had a torn tail from a prior unclean shutdown; \
                     truncated to the last newline before resuming."
                );
            }
            if warnings.schema_drift {
                varta_warn!(
                    "recovery audit file header does not match v1 or v2; appending a fresh \
                     v2 section with a `schema_drift` boot record."
                );
            }
            Some(sink)
        }
        None => None,
    };
    let recovery_source = if let Some(p) = cfg.recovery_cmd_file.as_ref() {
        p.display().to_string()
    } else if let Some(p) = cfg.recovery_exec_file.as_ref() {
        p.display().to_string()
    } else {
        "inline".to_string()
    };

    // High-visibility audit-trail when the operator has accepted recovery on
    // a UDP listener. Config-level validation already rejects the combination
    // without the per-listener flag, so reaching this branch is deliberate.
    if recovery_mode.is_some() {
        if cfg.i_accept_recovery_on_secure_udp {
            #[cfg(not(feature = "compile-time-config"))]
            varta_warn!(
                "recovery on secure-UDP listener is enabled \
                 (--secure-udp-i-accept-recovery-on-unauthenticated-transport). \
                 NOT for safety-critical use."
            );
            #[cfg(feature = "compile-time-config")]
            varta_warn!(
                "recovery on secure-UDP listener is enabled. \
                 NOT for safety-critical use."
            );
        }
        if cfg.i_accept_recovery_on_plaintext_udp {
            #[cfg(not(feature = "compile-time-config"))]
            varta_warn!(
                "recovery on plaintext-UDP listener is enabled \
                 (--plaintext-udp-i-accept-recovery-on-unauthenticated-transport). \
                 NOT for safety-critical use."
            );
            #[cfg(feature = "compile-time-config")]
            varta_warn!(
                "recovery on plaintext-UDP listener is enabled. \
                 NOT for safety-critical use."
            );
        }
    }

    let mut recovery = recovery_mode.map(|mode| {
        let capture_cap = if cfg.recovery_capture_stdio {
            cfg.recovery_capture_bytes
        } else {
            0
        };
        // `NetworkUnverified` beats are always refused by the runtime gate.
        // `OperatorAttestedTransport` beats (stamped by per-listener trust)
        // fire just like `KernelAttested` ones — trust is structural.
        Recovery::with_timeout(mode, cfg.recovery_debounce, cfg.recovery_timeout)
            .with_recovery_env(cfg.recovery_env.clone())
            .with_recovery_inherit_env(cfg.recovery_inherit_env)
            .with_shutdown_grace(cfg.shutdown_grace)
            .with_capture(capture_cap)
            .with_source(recovery_source.clone())
            .with_audit_sink(recovery_audit_sink)
            .with_allow_cross_namespace(cfg.allow_cross_namespace_agents)
            .with_reap_scratch_capacity(cfg.tracker_capacity)
            .with_outstanding_capacity(cfg.tracker_capacity)
    });
    let mut file_export: Option<FileExporter> = match cfg.file_export.as_ref() {
        Some(path) => Some(FileExporter::create(
            path,
            cfg.export_file_max_bytes,
            cfg.export_file_sync_every,
        )?),
        None => None,
    };
    #[cfg(feature = "prometheus-exporter")]
    let mut prom_export: Option<PromExporter> = match cfg.prom_addr {
        Some(addr) => {
            if !addr.ip().is_loopback() {
                varta_warn!(
                    "/metrics is bound to a non-loopback address ({addr}); any host \
                     that can reach this port can attempt a scrape. The bearer token \
                     in --prom-token-file is enforced on every connection, but \
                     binding to 127.0.0.1 / ::1 behind a reverse proxy or \
                     firewall-restricted interface remains the recommended \
                     defense-in-depth posture."
                );
            }
            // The token is mandatory whenever --prom-addr is set; the
            // Config layer rejects the combination of `--prom-addr` without
            // `--prom-token-file` before we get here, so `load_prom_token`
            // either returns Some(_) or surfaces a hard error from the
            // validator (mode 0600, ownership, no symlinks).
            let token = cfg.load_prom_token()?.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "internal: --prom-addr without --prom-token-file slipped past Config validation",
                )
            })?;
            let mut pe = PromExporter::bind_with_rate_limit(
                addr,
                token,
                cfg.prom_rate_limit_per_sec,
                cfg.prom_rate_limit_burst,
            )?
            .with_iteration_budget(cfg.iteration_budget)
            .with_scrape_budget(cfg.scrape_budget);
            pe.set_tracker_config(cfg.tracker_capacity, cfg.eviction_scan_window);
            pe.set_signal_handler_mode(cfg.signal_handler_mode.as_str());
            pe.set_uds_rcvbuf_bytes(observer.uds_rcvbuf_bytes());
            if let Ok(bound_addr) = pe.local_addr() {
                let line = format!("{bound_addr}\n");
                let _ = std::io::stdout().lock().write_all(line.as_bytes());
            }
            Some(pe)
        }
        None => None,
    };

    // --- sd_notify: signal READY=1 to the service manager. -----------------
    let mut sd_notify = varta_watch::notify::SdNotify::from_env();
    sd_notify.ready();

    // --- Self-watchdog thread (optional) ------------------------------------
    // The ONLY background thread in the binary.  It exists to (a) detect a
    // hung poll loop and `process::abort()`, AND (b) emit systemd
    // `WATCHDOG=1\n` notifications on its own cadence.  The latter is the H5
    // closure: with emission moved off the main loop, a silently-dead
    // watchdog thread stops WATCHDOG=1 and systemd's `WatchdogSec=` fires,
    // even when the main loop is still ticking.  The beat path and observer
    // loop remain single-threaded; the watchdog reads two atomics and writes
    // to its own dup-ed socket fd only.
    //
    // Enabled when EITHER `--self-watchdog-secs` is passed OR systemd
    // provided `$WATCHDOG_USEC`.  The latter is the "auto-enable" path: an
    // operator running under a `Type=notify` unit with `WatchdogSec=`
    // automatically gets in-process abort + watchdog emission without
    // touching the command line.
    //
    // `AUTO_DEADLINE_SECS` is the conservative default deadline applied in
    // the auto-enable case (operator passed no explicit `--self-watchdog-secs`).
    // 4 s mirrors the documented L1 example in
    // `book/src/architecture/observer-liveness.md`.  Operators with tighter
    // `WatchdogSec=` should pass `--self-watchdog-secs` to override.
    const AUTO_DEADLINE_SECS: u64 = 4;
    let wdt_notifier = sd_notify.take_watchdog_notifier();
    let wdt_deadline: Option<Duration> = match (cfg.self_watchdog, wdt_notifier.is_some()) {
        (Some(d), _) => Some(d),
        (None, true) => Some(Duration::from_secs(AUTO_DEADLINE_SECS)),
        (None, false) => None,
    };

    if let Some(deadline) = wdt_deadline {
        let deadline_ns = deadline.as_nanos() as u64;
        let secs = deadline.as_secs();
        // Sleep period for the watchdog thread.  Bounded above by 500 ms
        // (the historical cadence) and below by half_interval/2 when systemd
        // is supervising — a tight WatchdogSec (e.g. 500 ms) demands faster
        // ticks than a fixed 500 ms could deliver.
        // Sleep floor reduced to 25 ms to improve stage-wedge detection
        // resolution.  This costs one extra relaxed-load wake-up per 25 ms —
        // negligible CPU for a single background thread.
        let tick_sleep = match wdt_notifier.as_ref() {
            Some(n) => (n.half_interval() / 2)
                .min(Duration::from_millis(500))
                .max(Duration::from_millis(25)),
            None => Duration::from_millis(500),
        };
        let mut wdt_notifier = wdt_notifier;
        std::thread::Builder::new()
            .name("varta-watchdog".into())
            .spawn(move || loop {
                std::thread::sleep(tick_sleep);
                if SHUTDOWN.load(Ordering::Acquire) != 0 {
                    return;
                }
                let now = observer_now_ns();

                // Check 1: full-iteration deadline (existing).  Fires when the
                // poll loop has not completed a full tick in `deadline` seconds.
                // Acquire pairs with the Release store on the main thread.
                let last = LAST_TICK_NS.load(Ordering::Acquire);
                if watchdog_expired(now, last, deadline_ns) {
                    eprintln!("varta-watch poll loop wedged for >{secs}s; aborting");
                    std::process::abort();
                }

                // Check 2: per-stage deadline.  If the main thread is stuck
                // inside one phase for longer than STAGE_ABORT_NS[stage], abort
                // even if the full-iteration deadline has not yet expired.  This
                // catches e.g. a hung serve_pending that takes 1.9 s — visible
                // via the stage histogram immediately but not caught by the 4 s
                // iteration deadline until two full cycles later.
                //
                // Gated on `prometheus-exporter` because LAST_STAGE_ENTRY_NS and
                // CURRENT_STAGE are only compiled under that feature.
                #[cfg(feature = "prometheus-exporter")]
                {
                    // Acquire pairs with the Release store on CURRENT_STAGE in
                    // the main thread. The matching LAST_STAGE_ENTRY_NS write
                    // happens-before that Release, so a Relaxed load below
                    // observes the timestamp belonging to *this* stage entry,
                    // not a stale one from a prior visit.
                    let stage_idx = CURRENT_STAGE.load(Ordering::Acquire);
                    if stage_idx != u8::MAX {
                        let stage_idx = stage_idx as usize;
                        if let (Some(abort_ns), Some(entry_atom)) = (
                            STAGE_ABORT_NS.get(stage_idx),
                            LAST_STAGE_ENTRY_NS.get(stage_idx),
                        ) {
                            let entry_ns = entry_atom.load(Ordering::Relaxed);
                            if entry_ns != 0 && now.saturating_sub(entry_ns) > *abort_ns {
                                let stage_label = varta_watch::exporter::STAGE_LABELS
                                    .get(stage_idx)
                                    .copied()
                                    .unwrap_or("unknown");
                                eprintln!(
                                    "varta-watch stage '{stage_label}' wedged for >{abort_ns}ns; aborting"
                                );
                                std::process::abort();
                            }
                        }
                    }
                }

                // Main loop is still ticking — emit WATCHDOG=1 to keep
                // systemd informed of *our* liveness (not just the main
                // thread's).  No-op when WATCHDOG_USEC is unset.
                if let Some(n) = wdt_notifier.as_mut() {
                    n.tick();
                }
            })?;
    } else if sd_notify.watchdog_half_interval().is_some() {
        // Defensive: should be unreachable because `take_watchdog_notifier`
        // returns Some when the interval is set AND the socket is open.
        // Keep the branch so a future regression that mismatches the two
        // conditions surfaces a startup warning rather than a silent
        // watchdog drop.
        varta_warn!(
            "$WATCHDOG_USEC is set but no self-watchdog could be started \
             (notify socket open failed). systemd watchdog integration is disabled."
        );
    }

    // --- Hardware watchdog (optional) --------------------------------------
    let mut hw_wdt = if let Some(ref path) = cfg.hw_watchdog {
        match varta_watch::hw_watchdog::HwWatchdog::open(path) {
            Ok(w) => Some(w),
            Err(e) => {
                #[cfg(not(feature = "compile-time-config"))]
                let msg = format!("--hw-watchdog {}: {e}", path.display());
                #[cfg(feature = "compile-time-config")]
                let msg = format!("hw_watchdog {}: {e}", path.display());
                return Err(io::Error::new(e.kind(), msg));
            }
        }
    } else {
        None
    };

    let started = Instant::now();
    let mut loop_count: u64 = 0;
    // [test-hooks] One-shot wedge flag extracted from cfg before the loop.
    #[cfg(feature = "test-hooks")]
    let mut wedge_once = cfg.inject_wedge_ms;
    loop {
        if SHUTDOWN.load(Ordering::Acquire) != 0 {
            break;
        }
        if let Some(deadline) = cfg.shutdown_after {
            if started.elapsed() >= deadline {
                break;
            }
        }

        // H5: timestamp the start of the work portion of this iteration so
        // we can record per-iteration wall time. Captures everything except
        // the optional idle sleep (step 4) and the test-hooks wedge — those
        // are throttling primitives / fault injection, not real work, and
        // including them would pollute the histogram. The heartbeat write,
        // sd_notify, and HW watchdog kick ARE included because a slow disk
        // or wedged sd_notify socket would be a real budget event.
        #[cfg(feature = "prometheus-exporter")]
        let iter_start = Instant::now();
        // Per-stage timer reused across phases; reset before each phase.
        // DrainPending starts at iter_start (no separate Instant needed).
        #[cfg(feature = "prometheus-exporter")]
        let mut stage_start = iter_start;
        // Signal to the watchdog that DrainPending is now active.
        // Publish the entry timestamp FIRST (Relaxed) then the stage index
        // (Release): the Release on CURRENT_STAGE forms the happens-before
        // edge that makes the matching ENTRY_NS write visible to the
        // watchdog's Acquire load on CURRENT_STAGE.
        #[cfg(feature = "prometheus-exporter")]
        {
            if let Some(a) = LAST_STAGE_ENTRY_NS.get(IterStage::DrainPending as usize) {
                a.store(observer_now_ns(), Ordering::Relaxed);
            }
            CURRENT_STAGE.store(IterStage::DrainPending as u8, Ordering::Release);
        }

        // ------ 1. Drain queued stall events before I/O or maintenance ------
        // Surface every pending stall immediately; this prevents a batch of
        // N simultaneous stalls from taking N full poll cycles (each of which
        // includes Prometheus serving / file I/O / reaping).
        while let Some(ev) = observer.poll_pending() {
            if let Some(fe) = file_export.as_mut() {
                if let Err(e) = fe.record(&ev) {
                    varta_error_rl!(LogKind::FileExportIo, "file export error: {e}");
                }
            }
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                let _ = pe.record(&ev);
            }
            if let Event::Stall {
                pid,
                origin,
                pid_ns_inode,
                ..
            } = &ev
            {
                if let Some(rec) = recovery.as_mut() {
                    // Cross-namespace agent: the slot's pinned PID-namespace
                    // inode differs from the observer's. Linux-only signal;
                    // on non-Linux both inodes are None and this is always
                    // false.
                    let observer_ns_inode = observer.observer_pid_namespace_inode();
                    let cross_namespace_agent = matches!(
                        (observer_ns_inode, *pid_ns_inode),
                        (Some(a), Some(b)) if a != b
                    );
                    let outcome = rec.on_stall(*pid, *origin, cross_namespace_agent);
                    #[cfg(feature = "prometheus-exporter")]
                    if let Some(pe) = prom_export.as_mut() {
                        pe.record_recovery_outcome(&outcome, None);
                    }
                    match outcome {
                        RecoveryOutcome::Spawned { child_pid } => {
                            varta_info_pid_child!(
                                *pid,
                                child_pid,
                                "recovery for pid {pid} spawned (child {child_pid})"
                            );
                        }
                        RecoveryOutcome::Debounced => {}
                        RecoveryOutcome::SpawnFailed(e) => {
                            varta_error_pid!(
                                *pid,
                                e,
                                "recovery for pid {pid} failed to spawn: {e}"
                            );
                        }
                        RecoveryOutcome::RefusedUnauthenticatedSource { pid } => {
                            // Class-A builds (`compile-time-config`) must
                            // not carry argv flag names in static strings;
                            // SRE builds emit a remediation pointer.
                            #[cfg(not(feature = "compile-time-config"))]
                            varta_warn!(
                                "recovery for pid {pid} REFUSED: stalled beat lifetime \
                                 includes a non-kernel-attested transport (UDP). Pass \
                                 --i-accept-recovery-on-unauthenticated-transport AND \
                                 enable Recovery's allow_unauthenticated_source to \
                                 override at your own risk."
                            );
                            #[cfg(feature = "compile-time-config")]
                            varta_warn!(
                                "recovery for pid {pid} REFUSED: stalled beat lifetime \
                                 includes a non-kernel-attested transport (UDP)."
                            );
                        }
                        RecoveryOutcome::RefusedCrossNamespace { pid } => {
                            #[cfg(not(feature = "compile-time-config"))]
                            varta_warn!(
                                "recovery for pid {pid} REFUSED: agent's PID namespace \
                                 differs from observer's. kill(2) against this pid \
                                 in the observer's namespace would target the wrong \
                                 process. Pass --allow-cross-namespace-agents only when \
                                 agents are run with --pid=host or an out-of-band PID \
                                 translator is in place."
                            );
                            #[cfg(feature = "compile-time-config")]
                            varta_warn!(
                                "recovery for pid {pid} REFUSED: agent's PID namespace \
                                 differs from observer's."
                            );
                        }
                        RecoveryOutcome::RefusedDebounceCapacity { pid } => {
                            // Class-A builds must not carry remediation
                            // pointers that name CLI flags; SRE builds
                            // surface enough context to tune capacity.
                            #[cfg(not(feature = "compile-time-config"))]
                            varta_warn!(
                                "recovery for pid {pid} REFUSED: debounce ledger at \
                                 capacity and no slot's debounce window has elapsed. \
                                 This is the M8 fail-closed guard against stall-burst \
                                 attacks. Alert on \
                                 rate(varta_recovery_refused_total{{reason=\"debounce_capacity\"}}[5m]) > 0; \
                                 see book/src/architecture/observer-liveness.md."
                            );
                            #[cfg(feature = "compile-time-config")]
                            varta_warn!(
                                "recovery for pid {pid} REFUSED: debounce ledger \
                                 at capacity (M8 fail-closed guard)."
                            );
                        }
                        RecoveryOutcome::RefusedOutstandingCapacity { pid } => {
                            #[cfg(not(feature = "compile-time-config"))]
                            varta_warn!(
                                "recovery for pid {pid} REFUSED: outstanding-child \
                                 table at capacity (tracker_capacity worth of \
                                 recoveries already in flight). Alert on \
                                 rate(varta_recovery_refused_total{{reason=\"outstanding_capacity\"}}[5m]) > 0."
                            );
                            #[cfg(feature = "compile-time-config")]
                            varta_warn!(
                                "recovery for pid {pid} REFUSED: outstanding-child \
                                 table at capacity."
                            );
                        }
                        RecoveryOutcome::RefusedSocketModeOnly { pid } => {
                            varta_warn!(
                                "recovery for pid {pid} REFUSED: observer is running \
                                 on a platform without per-datagram kernel credential \
                                 passing (socket-mode-only). frame.pid cannot be \
                                 verified — spawning a recovery command against it is \
                                 unsafe."
                            );
                        }
                        RecoveryOutcome::Reaped { .. }
                        | RecoveryOutcome::Killed { .. }
                        | RecoveryOutcome::ReapFailed(_) => {
                            unreachable!("on_stall returned a reap-only recovery outcome")
                        }
                    }
                }
            }
        }

        // Record drain_pending stage, then reset timer for the poll phase.
        #[cfg(feature = "prometheus-exporter")]
        if let Some(pe) = prom_export.as_mut() {
            pe.record_stage_duration(IterStage::DrainPending, stage_start.elapsed());
            stage_start = Instant::now();
            if let Some(a) = LAST_STAGE_ENTRY_NS.get(IterStage::Poll as usize) {
                a.store(observer_now_ns(), Ordering::Relaxed);
            }
            CURRENT_STAGE.store(IterStage::Poll as u8, Ordering::Release);
        }

        // ----- 2. One non-blocking I/O poll for new beats / decode / auth ------
        // poll() never returns stalls — those are surfaced exclusively via
        // poll_pending() above.
        let had_io = if let Some(ev) = observer.poll() {
            if let Some(fe) = file_export.as_mut() {
                if let Err(e) = fe.record(&ev) {
                    varta_error_rl!(LogKind::FileExportIo, "file export error: {e}");
                }
            }
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                let _ = pe.record(&ev);
            }
            // Strict namespace mode: a cross-namespace agent is a fatal
            // startup error. The default behaviour is to drop the beat and
            // refuse recovery (already enforced inside `Observer`); strict
            // mode escalates to daemon exit so the operator notices.
            if cfg.strict_namespace_check && !cfg.allow_cross_namespace_agents {
                if let Event::NamespaceConflict { claimed_pid, .. } = &ev {
                    #[cfg(not(feature = "compile-time-config"))]
                    varta_error!(
                        "FATAL --strict-namespace-check: cross-namespace agent \
                         detected for claimed pid {claimed_pid}; refusing to \
                         continue. Re-run with --allow-cross-namespace-agents \
                         only if PID translation is correctly configured."
                    );
                    #[cfg(feature = "compile-time-config")]
                    varta_error!(
                        "FATAL strict namespace check: cross-namespace agent \
                         detected for claimed pid {claimed_pid}; refusing to \
                         continue."
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "cross-namespace agent detected under strict namespace check",
                    ));
                }
            }
            true
        } else {
            false
        };

        // Record poll stage, then reset timer for the maintenance phase.
        #[cfg(feature = "prometheus-exporter")]
        if let Some(pe) = prom_export.as_mut() {
            pe.record_stage_duration(IterStage::Poll, stage_start.elapsed());
            stage_start = Instant::now();
            if let Some(a) = LAST_STAGE_ENTRY_NS.get(IterStage::Maintenance as usize) {
                a.store(observer_now_ns(), Ordering::Relaxed);
            }
            CURRENT_STAGE.store(IterStage::Maintenance as u8, Ordering::Release);
        }

        // ------ 3. Maintenance (evictions, capacity, reaping, /metrics) ------
        let evicted = observer.drain_evictions();
        if evicted > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_eviction(evicted);
            }
        }

        if let Some(evicted_pid) = observer.drain_evicted_pid() {
            if let Some(fe) = file_export.as_mut() {
                fe.record_eviction_pid(evicted_pid, observer.now_ns());
            }
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_evicted_pid(evicted_pid);
            }
        }

        let capacity_exceeded = observer.drain_capacity_exceeded();
        if capacity_exceeded > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_capacity_exceeded(capacity_exceeded);
            }
        }

        let bind_dir_fsync_failed = Observer::drain_bind_dir_fsync_failures();
        if bind_dir_fsync_failed > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_bind_dir_fsync_failed(bind_dir_fsync_failed);
            }
        }

        let decrypt_failures = observer.drain_decrypt_failures();
        if decrypt_failures > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_decrypt_failures(decrypt_failures);
            }
        }

        let truncated = observer.drain_truncated();
        if truncated > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_truncated(truncated);
            }
        }

        let sender_state_full = observer.drain_sender_state_full();
        if sender_state_full > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_sender_state_full(sender_state_full);
            }
        }

        let aead_attempts = observer.drain_aead_attempts();
        if aead_attempts > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_secure_aead_attempts(aead_attempts);
            }
        }

        let per_pid_rate_limited = observer.drain_per_pid_rate_limited();
        if per_pid_rate_limited > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_per_pid_rate_limited(per_pid_rate_limited);
            }
        }

        let global_rate_limited = observer.drain_global_rate_limited();
        if global_rate_limited > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_global_rate_limited(global_rate_limited);
            }
        }

        let clock_regressions = observer.drain_clock_regressions();
        if clock_regressions > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_clock_regressions(clock_regressions);
            }
        }

        let nonce_wraps = observer.drain_nonce_wraps();
        if nonce_wraps > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_nonce_wraps(nonce_wraps);
            }
        }

        let eviction_scan_truncated = observer.drain_eviction_scan_truncated();
        if eviction_scan_truncated > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_eviction_scan_truncated(eviction_scan_truncated);
            }
        }

        let origin_conflicts = observer.drain_origin_conflicts();
        if origin_conflicts > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_origin_conflicts(origin_conflicts);
            }
        }

        // Cross-namespace frame drops at receive (Linux-only signal; 0 on
        // other platforms or when --allow-cross-namespace-agents is set).
        let frame_ns_mismatches = observer.drain_cross_namespace_drops();
        if frame_ns_mismatches > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_frame_namespace_mismatches(frame_ns_mismatches);
            }
        }

        // PID-above-max frame drops at receive (Linux-only signal; 0 on
        // other platforms where `pid_max == u32::MAX`).
        let pid_above_max = observer.drain_pid_above_max_drops();
        if pid_above_max > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_pid_above_max_drops(pid_above_max);
            }
            #[cfg(not(feature = "prometheus-exporter"))]
            let _ = pid_above_max;
        }

        // Tracker namespace conflicts (rebind with a different inode).
        let tracker_ns_conflicts = observer.drain_namespace_conflicts();
        if tracker_ns_conflicts > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_tracker_namespace_conflicts(tracker_ns_conflicts);
            }
        }

        let tracker_invariants = observer.drain_invariant_violations();
        if tracker_invariants > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_tracker_invariant_violations(tracker_invariants);
            }
        }

        let probe_exhausted = observer.drain_pid_index_probe_exhausted();
        if probe_exhausted > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_tracker_pid_index_probe_exhausted(probe_exhausted);
            }
        }

        // Drain LastFiredTable counters once per tick.  Evictions are
        // debounce-respecting churn; invariant_violations should stay
        // at 0 in correct operation.  See M8 in
        // `book/src/architecture/observer-liveness.md`.
        if let Some(rec) = recovery.as_mut() {
            let evictions = rec.take_last_fired_evictions();
            let invariants = rec.take_last_fired_invariant_violations();
            let outstanding_probe_exhausted = rec.take_outstanding_probe_exhausted();
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                if evictions > 0 {
                    pe.record_recovery_last_fired_evictions(evictions);
                }
                if invariants > 0 {
                    pe.record_recovery_invariant_violations(invariants);
                }
                if outstanding_probe_exhausted > 0 {
                    pe.record_recovery_outstanding_probe_exhausted(outstanding_probe_exhausted);
                }
            }
            #[cfg(not(feature = "prometheus-exporter"))]
            {
                // Silence unused-value lints when the exporter is gated
                // out (Class-A builds).  The counters still drain so
                // `LastFiredTable`'s internal accumulators stay bounded.
                let _ = evictions;
                let _ = invariants;
                let _ = outstanding_probe_exhausted;
            }
        }

        // Flush buffered audit lines to disk (bounded by 10 ms). This
        // decouples fdatasync from the hot path: record_spawn / record_complete
        // enqueue into the ring, and this call drains up to 10 ms worth per
        // tick. Lines that cannot be written within budget stay in the ring
        // and are retried next tick.
        if let Some(rec) = recovery.as_mut() {
            rec.flush_audit_pending(std::time::Duration::from_millis(10));
            // Drive rotation incrementally — bounded by --audit-rotation-budget-ms.
            // The state machine resumes from where the last tick left off when
            // the budget was exceeded; a wedged filesystem can therefore never
            // pin the poll loop for more than one rotation budget per tick.
            if rec.audit_rotation_pending() || rec.audit_rotation_due() {
                let _ = rec.drive_audit_rotation(std::time::Duration::from_millis(
                    cfg.audit_rotation_budget_ms as u64,
                ));
            }
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                let dropped = rec.take_audit_dropped();
                if dropped > 0 {
                    pe.record_audit_dropped(dropped);
                }
                let budget_exceeded = rec.take_audit_flush_budget_exceeded();
                if budget_exceeded > 0 {
                    pe.record_audit_flush_budget_exceeded(budget_exceeded);
                }
                // New: per-fsync histogram + budget overrun counters.
                for d in rec.take_audit_fsync_durations() {
                    pe.record_audit_fsync_duration(d);
                }
                let fsync_overrun = rec.take_audit_fsync_budget_exceeded();
                if fsync_overrun > 0 {
                    pe.record_audit_fsync_budget_exceeded(fsync_overrun);
                }
                let rot_overrun = rec.take_audit_rotation_budget_exceeded();
                if rot_overrun > 0 {
                    pe.record_audit_rotation_budget_exceeded(rot_overrun);
                }
                let warn_cross = rec.take_audit_ring_watermark_warn();
                if warn_cross > 0 {
                    pe.record_audit_ring_watermark("warn", warn_cross);
                }
                let crit_cross = rec.take_audit_ring_watermark_critical();
                if crit_cross > 0 {
                    pe.record_audit_ring_watermark("critical", crit_cross);
                }
            }
            #[cfg(not(feature = "prometheus-exporter"))]
            {
                // Drain new counters even without the exporter so they
                // do not accumulate unbounded; the values are simply
                // dropped on the floor.
                let _ = rec.take_audit_fsync_durations();
                let _ = rec.take_audit_fsync_budget_exceeded();
                let _ = rec.take_audit_rotation_budget_exceeded();
                let _ = rec.take_audit_ring_watermark_warn();
                let _ = rec.take_audit_ring_watermark_critical();
            }
        }

        // Drain any latched audit-sink IO error. The audit log latches
        // failed writes / rotations / fsyncs internally so the recovery
        // hot path never blocks on disk I/O — but silently dropping audit
        // failures would itself be an IEC 62304 Class C violation, so we
        // surface them once per tick.
        if let Some(rec) = recovery.as_mut() {
            if let Some(err) = rec.drain_audit_err() {
                varta_warn_rl!(LogKind::AuditIo, "recovery audit IO error: {err}");
            }
        }

        // Record maintenance stage, then reset timer for the recovery_reap phase.
        #[cfg(feature = "prometheus-exporter")]
        if let Some(pe) = prom_export.as_mut() {
            pe.record_stage_duration(IterStage::Maintenance, stage_start.elapsed());
            stage_start = Instant::now();
            if let Some(a) = LAST_STAGE_ENTRY_NS.get(IterStage::RecoveryReap as usize) {
                a.store(observer_now_ns(), Ordering::Relaxed);
            }
            CURRENT_STAGE.store(IterStage::RecoveryReap as u8, Ordering::Release);
        }

        // Reap completed or timeout-exceeded children each tick.
        if let Some(rec) = recovery.as_mut() {
            for outcome in rec.try_reap() {
                #[cfg(feature = "prometheus-exporter")]
                if let Some(pe) = prom_export.as_mut() {
                    // Duration is only meaningful for terminal outcomes; the
                    // audit sink already carries the exact ns, but the
                    // Prometheus sum/count tracks aggregate runtime trends.
                    // We pass `None` here and rely on the audit log for
                    // per-recovery duration history.
                    pe.record_recovery_outcome(&outcome, None);
                }
                match outcome {
                    RecoveryOutcome::Reaped { child_pid, status } if !status.success() => {
                        varta_warn_child!(
                            child_pid,
                            "recovery child {child_pid} exited non-zero: {status}"
                        );
                    }
                    RecoveryOutcome::Killed { child_pid } => {
                        varta_warn_child!(
                            child_pid,
                            "recovery child {child_pid} killed after timeout"
                        );
                    }
                    RecoveryOutcome::ReapFailed(e) => {
                        varta_error_err!(e, "recovery reap failed: {e}");
                    }
                    _ => {}
                }
            }
            // Drain the per-tick truncation counter separately so the
            // outcomes loop above doesn't need to borrow rec again.
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                let truncated = rec.take_reap_truncated();
                if truncated > 0 {
                    pe.record_recovery_reap_truncated(truncated);
                }
            }
            #[cfg(not(feature = "prometheus-exporter"))]
            {
                let _ = rec.take_reap_truncated();
            }
        }

        #[cfg(feature = "prometheus-exporter")]
        if let Some(pe) = prom_export.as_mut() {
            // Record recovery_reap stage before entering serve_pending.
            pe.record_stage_duration(IterStage::RecoveryReap, stage_start.elapsed());
            if let Some(a) = LAST_STAGE_ENTRY_NS.get(IterStage::ServePending as usize) {
                a.store(observer_now_ns(), Ordering::Relaxed);
            }
            CURRENT_STAGE.store(IterStage::ServePending as u8, Ordering::Release);

            // Bracket serve_pending so its wall time is observable
            // independently of beat-path latency.  See
            // `book/src/architecture/observer-liveness.md` ("Why /metrics is on
            // the poll thread") — keeping it on the main thread is a
            // load-bearing invariant, and the separate histogram is the
            // observability primitive that lets scrape-storm alarms fire
            // without polluting beat-path alarms.
            let serve_start = Instant::now();
            if let Err(e) = pe.serve_pending() {
                varta_error_rl!(LogKind::PromServe, "/metrics serve error: {e}");
            }
            pe.record_loop_tick();
            let serve_elapsed = serve_start.elapsed();
            pe.record_serve_pending_duration(serve_elapsed);
            pe.record_stage_duration(IterStage::ServePending, serve_elapsed);
            stage_start = Instant::now(); // housekeeping starts after serve_pending
            if let Some(a) = LAST_STAGE_ENTRY_NS.get(IterStage::Housekeeping as usize) {
                a.store(observer_now_ns(), Ordering::Relaxed);
            }
            CURRENT_STAGE.store(IterStage::Housekeeping as u8, Ordering::Release);
        }

        // ----- 4. Heartbeat file, self-watchdog tick, and HW watchdog kick ------
        // These run before the iteration histogram capture so a slow disk
        // (atomic heartbeat write) or a wedged sd_notify socket counts as
        // a real budget event.
        loop_count = loop_count.wrapping_add(1);
        if let Some(ref hb_path) = cfg.heartbeat_file {
            let ts = observer.now_ns();
            let line = format!("{loop_count} {ts}\n");
            if let Err(e) = write_heartbeat_atomic(hb_path, line.as_bytes()) {
                varta_error_rl!(LogKind::HeartbeatIo, "heartbeat file write error: {e}");
            }
        }
        // Update the self-watchdog liveness timestamp.  Uses wall-clock so the
        // watchdog thread (which cannot access the observer) reads the same
        // epoch.  Store after the poll work so a hung hw-watchdog kick would
        // also be caught.
        //
        // H5: systemd `WATCHDOG=1` notifications are emitted from the
        // self-watchdog thread, NOT here.  This is the load-bearing closure
        // — if the watchdog thread dies but the main loop survives, the
        // emission stream stops and `WatchdogSec=` fires.  Calling
        // `sd_notify.watchdog_tick()` on the main thread would re-open that
        // gap, so it is deliberately omitted.
        // Release pairs with the Acquire load in the self-watchdog thread.
        LAST_TICK_NS.store(observer_now_ns(), Ordering::Release);
        if let Some(ref mut hw) = hw_wdt {
            hw.kick();
        }

        // ----- 5. Record per-stage and per-iteration wall time ------
        // H5: capture the duration of the work portion of this iteration
        // (everything from `iter_start` at the top of the loop body through
        // the watchdog kicks).  Excludes the idle sleep below and the
        // test-hooks wedge — those are throttling / fault injection, not
        // real work.  See `book/src/architecture/observer-liveness.md`.
        #[cfg(feature = "prometheus-exporter")]
        if let Some(pe) = prom_export.as_mut() {
            pe.record_stage_duration(IterStage::Housekeeping, stage_start.elapsed());
            pe.record_iteration_duration(iter_start.elapsed());
        }
        // Mark the loop as idle — the watchdog should not enforce a stage
        // deadline between iterations (the throttle sleep is not work).
        // Release matches every other CURRENT_STAGE store so the watchdog's
        // single Acquire load always sees a consistent stage transition.
        #[cfg(feature = "prometheus-exporter")]
        CURRENT_STAGE.store(u8::MAX, Ordering::Release);

        // ----- 6. Throttle: sleep only when truly idle ------
        // Avoid busy-waiting when there are no I/O events and no queued
        // stalls.  If poll() populated new stalls via drain_stalls() the
        // check below catches them and the next iteration drains them
        // without a sleep penalty.
        if !had_io && !observer.has_pending_stalls() {
            std::thread::sleep(Duration::from_millis(10));
        }

        // [test-hooks] One-shot artificial stall of the poll loop.  Fires on
        // the first iteration only (take() zeroes the option); the watchdog
        // thread sees LAST_TICK_NS stop advancing and calls process::abort().
        // Only compiled when --features test-hooks; absent in production.
        #[cfg(feature = "test-hooks")]
        if let Some(ms) = wedge_once.take() {
            std::thread::sleep(Duration::from_millis(ms));
        }
    }

    // Clean shutdown — disarm hardware watchdog and notify service manager.
    if let Some(ref hw) = hw_wdt {
        hw.arm_disarm_on_drop();
    }
    sd_notify.stopping();

    if let Some(fe) = file_export.as_mut() {
        let _ = fe.flush();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use varta_watch::signal_install::SignalHandlerMode;

    /// Serializes tests that install global signal handlers or read/write
    /// the `SHUTDOWN` static. Cargo runs tests in parallel by default; two
    /// SIGINT-touching tests racing on the same process-wide handler would
    /// be flaky. Zero-dep alternative to the `serial_test` crate.
    #[cfg(unix)]
    static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn watchdog_expired_returns_false_before_first_tick() {
        // last == 0 means no tick yet — must never fire.
        assert!(!watchdog_expired(u64::MAX, 0, 1));
    }

    #[test]
    fn watchdog_expired_returns_false_within_deadline() {
        let now = 1_000_000_000u64; // 1 s
        let last = 999_000_000u64; // 1 ms ago
        let deadline = 5_000_000_000u64; // 5 s
        assert!(!watchdog_expired(now, last, deadline));
    }

    #[test]
    fn watchdog_expired_returns_true_past_deadline() {
        let now = 10_000_000_000u64; // 10 s
        let last = 1_000_000u64; // very old
        let deadline = 5_000_000_000u64; // 5 s
        assert!(watchdog_expired(now, last, deadline));
    }

    fn mk_tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("varta_hb_{}_{}", tag, std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        // Ensure the directory is accessible regardless of process umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        }
        dir
    }

    #[test]
    fn heartbeat_write_overwrites_existing() {
        let dir = mk_tmpdir("overwrite");
        let path = dir.join("hb.txt");
        write_heartbeat_atomic(&path, b"1 100\n").unwrap();
        write_heartbeat_atomic(&path, b"2 200\n").unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "2 200\n");
    }

    #[test]
    fn heartbeat_write_is_atomic_under_reader_contention() {
        let dir = mk_tmpdir("atomic");
        let path = dir.join("hb.txt");
        // Seed the file so the reader doesn't race a missing file.
        write_heartbeat_atomic(&path, b"0 0\n").unwrap();

        let bad_reads: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let bad_reads_r = bad_reads.clone();
        let path_r = path.clone();

        let reader = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_millis(300);
            while std::time::Instant::now() < deadline {
                let mut buf = String::new();
                if let Ok(mut f) = fs::File::open(&path_r) {
                    let _ = f.read_to_string(&mut buf);
                    // Every successful read must be "<u64> <u64>\n" — two tokens.
                    if !buf.is_empty() {
                        let parts: Vec<&str> = buf.split_whitespace().collect();
                        if parts.len() != 2
                            || parts[0].parse::<u64>().is_err()
                            || parts[1].parse::<u64>().is_err()
                        {
                            bad_reads_r.lock().unwrap().push(buf.clone());
                        }
                    }
                }
                std::hint::spin_loop();
            }
        });

        let deadline = std::time::Instant::now() + Duration::from_millis(300);
        let mut n: u64 = 1;
        while std::time::Instant::now() < deadline {
            let line = format!("{n} {}\n", n * 1000);
            write_heartbeat_atomic(&path, line.as_bytes()).unwrap();
            n += 1;
        }

        reader.join().unwrap();
        let bad = bad_reads.lock().unwrap();
        assert!(
            bad.is_empty(),
            "saw {} truncated/malformed heartbeat read(s): {:?}",
            bad.len(),
            &*bad
        );
    }

    #[cfg(unix)]
    #[test]
    fn signal_handler_returns_ok_under_normal_conditions() {
        let _guard = SIGNAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Verifies the error-propagation path doesn't misclassify success.
        // SAFETY: single-threaded test process; no other signal handlers active.
        let result = unsafe {
            varta_watch::signal_install::install(SignalHandlerMode::Direct, handle_shutdown)
        };
        assert!(result.is_ok(), "signal install failed: {:?}", result);
    }

    #[cfg(unix)]
    #[test]
    fn signal_handler_real_sigint_flips_shutdown() {
        let _guard = SIGNAL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        SHUTDOWN.store(0, Ordering::Release);

        // SAFETY: single-threaded test process; handler does one atomic store.
        unsafe { varta_watch::signal_install::install(SignalHandlerMode::Direct, handle_shutdown) }
            .expect("install signal handlers");

        // Confirm the handler hasn't already fired from some stray signal.
        assert!(
            SHUTDOWN.load(Ordering::Acquire) == 0,
            "SHUTDOWN was already non-zero before signal delivery"
        );

        // Deliver SIGINT to ourselves via raw FFI — no `libc` crate dep.
        // The signal is delivered to one (unspecified) thread of this
        // process; the handler is the same regardless of which thread.
        extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
            fn getpid() -> i32;
        }
        const SIGINT: i32 = 2;
        // SAFETY: `kill(2)` and `getpid(2)` are POSIX, with no preconditions
        // on the caller beyond the right to signal our own pid.
        let rc = unsafe { kill(getpid(), SIGINT) };
        assert_eq!(
            rc,
            0,
            "kill(getpid(), SIGINT) failed: {:?}",
            io::Error::last_os_error()
        );

        // Signal delivery is asynchronous — spin briefly while yielding.
        // 50 ms is several orders of magnitude longer than typical kernel
        // signal delivery latency (single-digit microseconds).
        let deadline = std::time::Instant::now() + Duration::from_millis(50);
        while std::time::Instant::now() < deadline && SHUTDOWN.load(Ordering::Acquire) == 0 {
            std::thread::yield_now();
        }

        let fired = SHUTDOWN.load(Ordering::Acquire) != 0;

        // Reset so subsequent tests in this binary see a clean slate.
        SHUTDOWN.store(0, Ordering::Release);

        assert!(
            fired,
            "SHUTDOWN was not set within 50ms of SIGINT delivery — handler did not fire"
        );
    }

    #[test]
    fn heartbeat_tempfile_cleaned_on_rename_failure() {
        let dir = mk_tmpdir("cleanup");
        // Point the target path at a directory that doesn't exist so the
        // rename will fail (the parent dir is missing).
        let target = dir.join("nonexistent_subdir").join("hb.txt");
        let result = write_heartbeat_atomic(&target, b"1 100\n");
        assert!(result.is_err());
        // The tempfile should have been removed.
        let pid = std::process::id();
        let tmp = PathBuf::from(format!("{}.{pid}.tmp", target.display()));
        assert!(
            !tmp.exists(),
            "stale tempfile left behind: {}",
            tmp.display()
        );
    }
}
