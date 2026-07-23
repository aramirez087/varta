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
use std::sync::atomic::AtomicU8;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use varta_watch::exporter::{IterStage, STAGE_LABELS};
use varta_watch::log_ratelimit::LogKind;
#[cfg(feature = "prometheus-exporter")]
use varta_watch::PromExporter;
use varta_watch::{
    varta_error, varta_error_err, varta_error_pid, varta_error_rl, varta_info_pid,
    varta_info_pid_child, varta_warn, varta_warn_child, varta_warn_rl, Config, ConfigError, Event,
    Exporter, FileExporter, Observer, Recovery, RecoveryOutcome, StallFreshness,
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

/// Forward-only high-water mark for [`watchdog_now_ns`].
///
/// `CLOCK_MONOTONIC` can still *appear* to step backward on virtualized hosts
/// (TSC drift across cores, live-migration pause/resume) — the same hazard
/// `observer::Observer::apply_raw_clock` already clamps on the stall-detection
/// path.  The self-watchdog left its clock unclamped: a backward excursion
/// drove [`watchdog_expired`]'s `saturating_sub` to `0`, so a genuinely wedged
/// poll loop was neither `process::abort()`ed nor stopped from petting the
/// systemd watchdog (`WATCHDOG=1`, emitted at the foot of the watchdog loop)
/// until the clock climbed back — silently defeating BOTH liveness layers for
/// the width of the regression.  A backward-dipped *stamp* is the mirror
/// failure: it inflates a later `now - last` into a spurious abort of a
/// healthy observer.  Clamping every reading forward through one shared
/// high-water mark removes both, and keeps the watchdog thread's `now` and the
/// main thread's stamps on a single monotonic timeline.
static WATCHDOG_LAST_NS: AtomicU64 = AtomicU64::new(0);

/// Per-stage entry timestamps written by the main thread at the START of each
/// poll-loop phase.  The self-watchdog thread reads these to detect a wedge
/// inside a single stage (e.g. a hung `serve_pending`) without waiting for
/// the full [`LAST_TICK_NS`] deadline.  Indexed by [`IterStage as usize`].
///
/// Initialised to 0; the watchdog treats 0 as "stage not yet entered".
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
static CURRENT_STAGE: AtomicU8 = AtomicU8::new(u8::MAX);

/// Sentinel value stored in [`CURRENT_STAGE`] while the loop is idle.
const STAGE_IDLE: u8 = u8::MAX;

/// Per-stage hard abort threshold in nanoseconds.  If the main thread stays
/// in the same stage for longer than this value, the watchdog calls
/// `process::abort()`.  Each threshold is ≥ 5× the stage's soft budget so
/// transient overruns under scrape load do not trigger a false positive.
///
/// Indexed by [`IterStage as usize`] — must stay in sync with the enum.
const STAGE_ABORT_NS: [u64; 6] = [
    2_000 * 1_000_000, // DrainPending: 2 s (5× 20 ms soft budget)
    varta_watch::config::POLL_STAGE_ABORT_MS * 1_000_000, // Poll: capped vs MAX_READ_TIMEOUT_MS
    varta_watch::config::MAINTENANCE_STAGE_ABORT_MS * 1_000_000, // Maintenance: capped vs MAX_AUDIT_ROTATION_BUDGET_MS
    1_000 * 1_000_000,                                           // RecoveryReap: 1 s (50× 20 ms)
    2_000 * 1_000_000, // ServePending: 2 s (10× 200 ms structural cap)
    1_000 * 1_000_000, // Housekeeping: 1 s (100× 10 ms)
];

/// Maximum tracker-removal cleanup records drained per maintenance tick.
///
/// A generation-recycle sweep can retire many stale slots in one poll call.
/// Draining cleanup through a fixed cap keeps file-export I/O bounded while
/// still clearing Prometheus/file rows over subsequent ticks.
const REMOVED_PID_DRAIN_MAX_PER_TICK: usize = 64;

/// Unique suffix source for heartbeat tempfiles.
///
/// The sequence prevents a stale tempfile left by a crashed process or a
/// recycled PID from permanently blocking future atomic heartbeat writes.
static HEARTBEAT_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Maximum exclusive-create attempts for one heartbeat publication.
///
/// The loop is bounded because this code runs on the observer's single poll
/// thread. Normal operation succeeds on the first attempt; retries only cover
/// stale tempfiles or deliberate name collisions.
const HEARTBEAT_TEMP_CREATE_ATTEMPTS: usize = 16;

/// The self-watchdog's clock is **hardwired** to the suspend-paused
/// monotonic clock (`CLOCK_MONOTONIC`), never the operator-selected
/// `--clock-source`.  The watchdog measures on-CPU wedge time of the main
/// loop; an advance-through-suspend source (`boottime` / `monotonic-raw`)
/// would make a host suspend look like a wedge and `process::abort()` a
/// healthy observer on wake.  Pinned by
/// `tests::self_watchdog_clock_is_suspend_paused_not_configured_source`.
const WATCHDOG_CLOCK: varta_watch::clock::ClockSource = varta_watch::clock::ClockSource::Monotonic;

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

/// Suspend-paused monotonic nanosecond clock for the self-watchdog thread.
///
/// The watchdog measures how long the main poll loop has gone without
/// completing a tick — i.e. *on-CPU wedge time* — so it ALWAYS reads
/// `CLOCK_MONOTONIC`, which pauses while the host is suspended, independent
/// of the operator's `--clock-source`.
///
/// `--clock-source boottime` / `monotonic-raw` deliberately *advance through
/// suspend* so the STALL detector counts a 4-hour sleep as 4 hours of agent
/// silence (see `clock.rs`).  Feeding that advance-through-suspend clock into
/// the watchdog was a foot-gun: a suspend longer than the deadline looked
/// identical to a wedged loop, so a healthy observer `process::abort()`ed on
/// every wake — a reboot loop under `--hw-watchdog` on precisely the
/// aggressively-suspending clinical devices those sources target.  Wedge time
/// must be measured against time the CPU actually ran the (frozen-on-suspend)
/// main loop, never against suspended wall/boot time.
fn watchdog_now_ns() -> u64 {
    // `Monotonic.clk_id()` is `Some(CLOCK_MONOTONIC)` on every supported
    // platform; the `None` arm is unreachable and its defensive 0 keeps
    // `watchdog_expired`'s `last == 0` skip-before-first-tick semantics from
    // misfiring (before the first tick the high-water is also 0, so the clamp
    // is a no-op).
    let raw = match WATCHDOG_CLOCK.clk_id() {
        Some(clk_id) => varta_watch::clock::clock_gettime_raw(clk_id).unwrap_or(0),
        None => 0,
    };
    watchdog_clamp_forward(raw, &WATCHDOG_LAST_NS)
}

/// Clamp `raw` forward against a shared high-water mark, returning a value that
/// never decreases across calls.  Structural mirror of `observer`'s
/// `apply_raw_clock`; see [`WATCHDOG_LAST_NS`] for why the watchdog needs it.
/// `fetch_max` keeps it correct when the main thread (stamping [`LAST_TICK_NS`]
/// and the stage-entry timestamps) and the watchdog thread (reading `now`)
/// share the same high-water mark; `Relaxed` is sufficient because this only
/// orders the time source against itself — the cross-thread publication edges
/// on `LAST_TICK_NS` / `CURRENT_STAGE` carry the happens-before for the values.
fn watchdog_clamp_forward(raw: u64, high_water: &AtomicU64) -> u64 {
    let prior = high_water.fetch_max(raw, Ordering::Relaxed);
    raw.max(prior)
}

/// Returns `true` when the poll loop has not ticked for longer than
/// `deadline_ns` nanoseconds.  `last == 0` means "not yet started"; skip
/// until the first real tick to avoid false aborts at startup.
fn watchdog_expired(now_ns: u64, last_ns: u64, deadline_ns: u64) -> bool {
    last_ns != 0 && now_ns.saturating_sub(last_ns) > deadline_ns
}

/// Returns `true` when the watchdog thread may emit `WATCHDOG=1` to systemd.
///
/// The pet must reflect *main-loop* liveness, not merely the watchdog thread's
/// own liveness. `last_ns == 0` means the poll loop has not completed a single
/// iteration yet (it stamps [`LAST_TICK_NS`] only at the foot of the loop), so
/// petting systemd here would feed its `WatchdogSec` timer while the loop is
/// wedged in its very first pass — e.g. a hung fsync or an NFS audit dir that
/// blocks the first maintenance write before any tick. Withholding the pet
/// until the first real tick preserves the systemd backstop while the
/// in-process stage guard is still converging on the first published stage.
/// Once the loop has ticked at least once the pet resumes and still detects
/// watchdog-thread death (no pet → systemd trips).
fn watchdog_should_pet_systemd(last_ns: u64) -> bool {
    last_ns != 0
}

struct StageWedge {
    label: &'static str,
    abort_ns: u64,
}

/// Publish the stage currently executing in the poll loop.
///
/// When the self-watchdog is disabled, this is a no-op so builds that do not
/// request watchdog supervision do not pay extra monotonic-clock reads.
/// Otherwise the entry timestamp is published first, then the stage index is
/// stored with Release ordering. The watchdog thread's Acquire load of
/// [`CURRENT_STAGE`] observes the matching timestamp.
fn publish_stage(enabled: bool, stage: IterStage) {
    if !enabled {
        return;
    }
    let stage_idx = stage as usize;
    if let Some(a) = LAST_STAGE_ENTRY_NS.get(stage_idx) {
        a.store(watchdog_now_ns(), Ordering::Relaxed);
    }
    CURRENT_STAGE.store(stage as u8, Ordering::Release);
}

/// Mark the loop as idle between iterations.
fn publish_idle_stage(enabled: bool) {
    if enabled {
        CURRENT_STAGE.store(STAGE_IDLE, Ordering::Release);
    }
}

/// Return the wedged stage, if the current stage has exceeded its hard abort
/// threshold.
fn current_stage_wedge(now_ns: u64) -> Option<StageWedge> {
    // Acquire pairs with the Release store in `publish_stage`. The matching
    // LAST_STAGE_ENTRY_NS write happens-before that Release, so the Relaxed
    // load below observes the timestamp belonging to this stage entry.
    let stage_idx = CURRENT_STAGE.load(Ordering::Acquire);
    if stage_idx == STAGE_IDLE {
        return None;
    }
    let stage_idx = stage_idx as usize;
    let abort_ns = *STAGE_ABORT_NS.get(stage_idx)?;
    let entry_ns = LAST_STAGE_ENTRY_NS.get(stage_idx)?.load(Ordering::Relaxed);
    if entry_ns != 0 && now_ns.saturating_sub(entry_ns) > abort_ns {
        let label = STAGE_LABELS.get(stage_idx).copied().unwrap_or("unknown");
        Some(StageWedge { label, abort_ns })
    } else {
        None
    }
}

struct HeartbeatTempPath {
    path: PathBuf,
    armed: bool,
}

impl HeartbeatTempPath {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for HeartbeatTempPath {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn create_heartbeat_temp(path: &Path) -> io::Result<(std::fs::File, HeartbeatTempPath)> {
    use std::os::unix::fs::OpenOptionsExt;

    let pid = std::process::id();
    for _ in 0..HEARTBEAT_TEMP_CREATE_ATTEMPTS {
        let sequence = HEARTBEAT_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut tmp_os = path.as_os_str().to_owned();
        tmp_os.push(format!(".{pid}.{sequence}.tmp"));
        let tmp_path = PathBuf::from(tmp_os);

        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        match options.open(&tmp_path) {
            Ok(file) => return Ok((file, HeartbeatTempPath::new(tmp_path))),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "heartbeat tempfile create attempts exhausted",
    ))
}

/// Write `contents` to `path` atomically via a same-directory tempfile + rename.
///
/// `rename(2)` is atomic on POSIX-compliant filesystems; a reader of `path`
/// will observe either the previous complete file or the new complete file,
/// never a partial write. Each tempfile is created exclusively with mode
/// `0600`; pre-existing files and symlinks are never opened or truncated.
/// A per-process sequence prevents stale PID-reuse tempfiles from wedging the
/// writer. If writing or renaming fails, the owned tempfile is removed by its
/// RAII guard before the error returns.
fn write_heartbeat_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let (mut file, mut temp) = create_heartbeat_temp(path)?;
    file.write_all(contents)?;
    drop(file);
    std::fs::rename(&temp.path, path)?;
    temp.disarm();
    Ok(())
}

fn main() -> ExitCode {
    #[cfg(feature = "json-log")]
    varta_watch::log::init_session_id();

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

/// Record one ingress [`Event`] into the configured exporters and enforce
/// strict-namespace fatality. Shared by the Poll step and the DrainPending
/// ingress pre-drain so a beat consumed early in the tick is exported
/// identically to one consumed by the regular poll step.
fn record_ingress_event(
    ev: &Event,
    file_export: &mut Option<FileExporter>,
    #[cfg(feature = "prometheus-exporter")] prom_export: &mut Option<PromExporter>,
    cfg: &Config,
) -> std::io::Result<()> {
    if let Some(fe) = file_export.as_mut() {
        if let Err(e) = fe.record(ev) {
            varta_error_rl!(LogKind::FileExportIo, "file export error: {e}");
        }
    }
    #[cfg(feature = "prometheus-exporter")]
    if let Some(pe) = prom_export.as_mut() {
        let _ = pe.record(ev);
    }
    // Strict namespace mode: a cross-namespace agent is a fatal
    // startup error. The default behaviour is to drop the beat and
    // refuse recovery (already enforced inside `Observer`); strict
    // mode escalates to daemon exit so the operator notices.
    if cfg.strict_namespace_check {
        if let Event::NamespaceConflict { claimed_pid, .. } = ev {
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
    Ok(())
}

fn run(cfg: Config) -> std::io::Result<()> {
    // Attest single-threadedness before the first umask(2) call in
    // UdsListener::bind.  The token is constructed here — the first
    // executable statement in run() — before signal handlers, before the
    // observer bind, and before the self-watchdog thread spawn.
    let pre_thread = varta_watch::listener::PreThreadAttestation::new()?;

    // SAFETY: sole entry point of a single-threaded binary with no competing
    // SIGINT/SIGTERM installers; called before any thread is spawned.
    unsafe {
        varta_watch::signal_install::install(cfg.signal_handler_mode, handle_shutdown)?;
    }
    // On Class-A builds (no prometheus-exporter) the mode is logged so the
    // startup audit can confirm the certified path is active.
    #[cfg(not(feature = "prometheus-exporter"))]
    varta_watch::varta_info!("signal_handler_mode={}", cfg.signal_handler_mode.as_str());

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
        &pre_thread,
    )?
    .with_allow_cross_namespace(cfg.allow_cross_namespace_agents);

    // On platforms lacking kernel-level per-datagram credential passing for
    // pathname UDS datagrams (macOS, OpenBSD, AIX, HP-UX, and other Unixen)
    // the observer relies solely on --socket-mode (default 0600) as the trust
    // boundary. Beats are tagged BeatOrigin::SocketModeOnly; recovery commands
    // are refused.
    // Linux, FreeBSD, DragonFly, NetBSD, illumos, and Solaris have
    // per-datagram credential mechanisms for this socket shape — the observer
    // enforces them automatically.
    #[cfg(all(
        not(feature = "compile-time-config"),
        not(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "illumos",
            target_os = "solaris",
        ))
    ))]
    varta_warn!(
        "running on {} — per-datagram PID verification is unavailable. \
         Beats are tagged socket-mode-only; recovery commands will be refused. \
         The only trust boundary is --socket-mode (default 0600): any process \
         under the same UID can forge frame.pid.",
        std::env::consts::OS,
    );
    #[cfg(all(
        feature = "compile-time-config",
        not(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "netbsd",
            target_os = "illumos",
            target_os = "solaris",
        ))
    ))]
    varta_warn!(
        "running on {} — per-datagram PID verification is unavailable. \
         Beats are tagged socket-mode-only; recovery commands will be refused. \
         The only trust boundary is the configured socket file mode: any process \
         under the same UID can forge frame.pid.",
        std::env::consts::OS,
    );

    #[cfg(feature = "secure-udp")]
    let secure_udp_keys = cfg.load_secure_keys()?;

    #[cfg(feature = "secure-udp")]
    let master_key = cfg.load_master_key()?;

    #[cfg(feature = "udp-core")]
    if let Some(port) = cfg.udp_port {
        // H4: secure-UDP defaults to loopback (127.0.0.1). The replay-state
        // table is bounded and fails closed for new senders at capacity; on
        // any reachable network that still creates an availability boundary
        // operators must accept explicitly. Non-loopback secure-UDP binds
        // require --udp-bind-addr AND --i-accept-secure-udp-non-loopback
        // (enforced by Config).
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
                 (--i-accept-secure-udp-non-loopback). Replay protection now \
                 fails closed when the bounded sender-state table is full, so \
                 a reachable network can still deny new senders by exhausting \
                 that table; restrict reach via firewall / private VLAN. See \
                 book/src/architecture/vlp-transports.md for the threat-boundary \
                 derivation."
            );
            #[cfg(feature = "compile-time-config")]
            varta_warn!(
                "secure-UDP is bound to non-loopback {addr}. Replay protection \
                 fails closed when the bounded sender-state table is full, so a \
                 reachable network can deny new senders by exhausting that \
                 table; restrict reach via firewall / private VLAN."
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
                let all_keys: Vec<varta_vlp::crypto::Key> = secure_udp_keys.unwrap_or_default();

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
                // Align the listener's session-restart gate with the tracker's
                // recycle reset (both gate on the configured stall threshold)
                // so a recycled-PID agent's resume beats are admitted before
                // the dead predecessor's slot can stall and fire recovery.
                let secure = secure
                    .with_recovery_trust(trust)
                    .with_session_restart_gap(cfg.threshold);
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
    let recovery_source = if let Some(p) = cfg.recovery_exec_file.as_ref() {
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
    let mut recovery_reap_outcomes = if recovery.is_some() {
        Vec::with_capacity(varta_watch::recovery::RECOVERY_REAP_OUTCOME_MAX_PER_TICK)
    } else {
        Vec::new()
    };
    let mut audit_fsync_durations = if recovery.is_some() {
        Vec::with_capacity(varta_watch::audit::AUDIT_FSYNC_HISTORY_CAP)
    } else {
        Vec::new()
    };
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
            pe.set_pid_max_current(observer.pid_max());
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
    // loop remain single-threaded; the watchdog reads a small fixed set of
    // atomics and writes to its own dup-ed socket fd only.
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
    let stage_watchdog_enabled = wdt_deadline.is_some();
    // Captured so we can join the watchdog thread before emitting STOPPING=1
    // on clean shutdown — otherwise a tick scheduled before the join can
    // append a stray WATCHDOG=1 after STOPPING=1 (race seen on macOS CI).
    let mut wdt_handle: Option<std::thread::JoinHandle<()>> = None;

    if let Some(deadline) = wdt_deadline {
        // Saturate at u64::MAX ns: a large `--self-watchdog-secs` (operator intent
        // = lenient deadline) whose nanos exceed u64::MAX must NOT wrap a bare
        // `as u64` cast to a tiny value and self-abort a healthy observer.
        // Matches the saturating-cast pattern at log.rs / reaper.rs.
        let deadline_ns = deadline.as_nanos().min(u64::MAX as u128) as u64;
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
        let handle = std::thread::Builder::new()
            .name("varta-watchdog".into())
            .spawn(move || loop {
                std::thread::sleep(tick_sleep);
                if SHUTDOWN.load(Ordering::Acquire) != 0 {
                    return;
                }
                let now = watchdog_now_ns();

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
                // even if the full-iteration deadline has not yet expired.
                if let Some(wedge) = current_stage_wedge(now) {
                    let stage_label = wedge.label;
                    let abort_ns = wedge.abort_ns;
                    eprintln!(
                        "varta-watch stage '{stage_label}' wedged for >{abort_ns}ns; aborting"
                    );
                    std::process::abort();
                }

                // Emit WATCHDOG=1 to keep systemd informed of *our* liveness
                // (not just the main thread's) — but only once the main loop
                // has completed at least one iteration. Before the first tick
                // (`last == 0`) the loop may be wedged in its very first pass;
                // petting here would mask that wedge from systemd's WatchdogSec
                // backstop just as Check 1's `last == 0` skip masks it from the
                // in-process abort. After the first tick the pet resumes and
                // still detects watchdog-thread death. No-op when WATCHDOG_USEC
                // is unset.
                if watchdog_should_pet_systemd(last) {
                    if let Some(n) = wdt_notifier.as_mut() {
                        n.tick();
                    }
                }
            })?;
        wdt_handle = Some(handle);
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
        publish_stage(stage_watchdog_enabled, IterStage::DrainPending);

        // ------ 1a. Ingress pre-drain before deferred stalls may fire ------
        // A queued stall is only as fresh as the tracker state behind it, and
        // the tracker only learns that an agent resumed when poll() consumes
        // the agent's beat. Step 2 consumes at most one returnable beat per
        // tick, while the loop below fires up to RECOVERY_SPAWN_MAX_PER_TICK
        // recoveries per tick — under a mass stall whose agents have since
        // resumed (a transient system-wide pause: cgroup freeze, hypervisor
        // pause, suspend/resume on a suspend-advancing --clock-source),
        // deferred kills would outrun the resume-beats that prove them wrong
        // ~16:1 and the stall_freshness gate would read stale `stall_emitted`
        // state, killing most of a healthy, already-recovered fleet. Drain
        // ingress until the sockets are empty so the gate judges every queued
        // stall against all evidence already received. Genuinely stalled
        // agents are silent and contribute nothing here; a hostile flood is
        // bounded by RECOVERY_PREDRAIN_INGRESS_MAX_PER_TICK (each item is one
        // recv+decode+record, microseconds — far inside the 2 s DrainPending
        // stage ceiling).
        if recovery.is_some() && observer.has_pending_stalls() {
            let mut predrained = 0usize;
            while predrained < varta_watch::recovery::RECOVERY_PREDRAIN_INGRESS_MAX_PER_TICK {
                predrained += 1;
                let ev = observer.poll();
                let consumed = observer.last_poll_consumed();
                if let Some(ev) = ev {
                    record_ingress_event(
                        &ev,
                        &mut file_export,
                        #[cfg(feature = "prometheus-exporter")]
                        &mut prom_export,
                        &cfg,
                    )?;
                }
                if !consumed {
                    break;
                }
            }
        }

        // ------ 1. Drain queued stall events before I/O or maintenance ------
        // Surface every pending stall immediately; this prevents a batch of
        // N simultaneous stalls from taking N full poll cycles (each of which
        // includes Prometheus serving / file I/O / reaping).
        // Per-tick recovery spawn budget: a mass simultaneous stall must not
        // fork+exec the whole fleet in one DrainPending stage (head-of-line
        // block + 2 s self-watchdog abort). Count only actual spawn attempts;
        // cheap Debounced/Refused outcomes never consume this budget. The
        // remainder stays queued (the stall_queue cursor resumes next tick).
        let mut spawns_this_tick = 0usize;
        // Set only when a real scheduler budget leaves queued stalls for a
        // later tick. The normal first-pass queue is not a deferral boundary:
        // its enqueue path already performed the safe generation check, and
        // treating it as deferred would suppress recovery forever on
        // credential-attested platforms without Linux start-time tokens.
        let mut recovery_budget_deferred_stalls = false;
        // Per-tick stall *evaluation* budget: even a non-spawning outcome costs
        // an O(tracker_capacity) debounce-ledger scan in on_stall plus a
        // /proc/<pid>/stat freshness read, so a mass non-spawning batch (a
        // flapping fleet whose stalls all Debounce) could otherwise drain the
        // whole tracker_capacity-deep queue in one stage — the last unbounded
        // per-tick poll-loop walk. The loop condition itself bounds the walk so
        // the cheap `continue` (AgentResumed/PidRecycled) paths are capped too;
        // the cursor defers the remainder to the next tick, exactly like the
        // spawn budget. See recovery::RECOVERY_STALL_EVAL_MAX_PER_TICK.
        let mut evals_this_tick = 0usize;
        while evals_this_tick < varta_watch::recovery::RECOVERY_STALL_EVAL_MAX_PER_TICK {
            let Some((ev, requires_freshness_check)) = observer.poll_pending_for_recovery() else {
                break;
            };
            evals_this_tick += 1;
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
                generation,
                observer_ns,
                ..
            } = &ev
            {
                if let Some(rec) = recovery.as_mut() {
                    // Only stalls actually held back by the scheduler's
                    // per-tick budget need the fire-time check. The initial
                    // pass was validated at enqueue time; on platforms that
                    // attest PID but expose no start-time generation, applying
                    // this to that pass would withhold every recovery rather
                    // than only the recycle-risking deferred ones.
                    if requires_freshness_check {
                        match observer.stall_freshness(*pid, *generation) {
                            StallFreshness::Warranted => {}
                            StallFreshness::AgentResumed => {
                                let outcome = RecoveryOutcome::SkippedAgentResumed { pid: *pid };
                                rec.record_deferred_skip_audit(&outcome, *observer_ns);
                                #[cfg(feature = "prometheus-exporter")]
                                if let Some(pe) = prom_export.as_mut() {
                                    pe.record_recovery_outcome(&outcome, None);
                                }
                                varta_info_pid!(
                                    *pid,
                                    "recovery for pid {pid} SKIPPED: agent resumed \
                                 beating before its deferred stall fired"
                                );
                                continue;
                            }
                            StallFreshness::PidRecycled => {
                                let outcome = RecoveryOutcome::SkippedPidRecycled { pid: *pid };
                                rec.record_deferred_skip_audit(&outcome, *observer_ns);
                                #[cfg(feature = "prometheus-exporter")]
                                if let Some(pe) = prom_export.as_mut() {
                                    pe.record_recovery_outcome(&outcome, None);
                                }
                                varta_info_pid!(
                                    *pid,
                                    "recovery for pid {pid} SKIPPED: PID recycled to a \
                                 different process before its deferred stall fired"
                                );
                                continue;
                            }
                            StallFreshness::UnverifiableGeneration => {
                                let outcome =
                                    RecoveryOutcome::SkippedStallUnverifiable { pid: *pid };
                                rec.record_deferred_skip_audit(&outcome, *observer_ns);
                                #[cfg(feature = "prometheus-exporter")]
                                if let Some(pe) = prom_export.as_mut() {
                                    pe.record_recovery_outcome(&outcome, None);
                                }
                                varta_info_pid!(
                                    *pid,
                                    "recovery for pid {pid} SKIPPED: kernel-attested stall \
                                 cannot prove start-time generation at fire time, so a PID \
                                 recycle in the deferral window cannot be ruled out; \
                                 refusing recovery to avoid targeting a recycled bystander"
                                );
                                continue;
                            }
                        }
                    }
                    // Cross-namespace agent: the slot's pinned PID-namespace
                    // inode differs from the observer's. Linux-only signal;
                    // on non-Linux both inodes are None and this is always
                    // false.
                    let observer_ns_inode = observer.observer_pid_namespace_inode();
                    let cross_namespace_agent = matches!(
                        (observer_ns_inode, *pid_ns_inode),
                        (Some(a), Some(b)) if a != b
                    );
                    let outcome = rec.on_stall(
                        *pid,
                        *origin,
                        cross_namespace_agent,
                        *generation,
                        *observer_ns,
                    );
                    // Computed before the match below moves `outcome`.
                    let did_spawn = matches!(
                        outcome,
                        RecoveryOutcome::Spawned { .. } | RecoveryOutcome::SpawnFailed(_)
                    );
                    #[cfg(feature = "prometheus-exporter")]
                    if let Some(pe) = prom_export.as_mut() {
                        pe.record_recovery_outcome(&outcome, outcome.duration_ns());
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
                                 includes a non-kernel-attested transport (UDP). To allow \
                                 recovery for this listener, restart with \
                                 --secure-udp-i-accept-recovery-on-unauthenticated-transport \
                                 (secure UDP) or \
                                 --plaintext-udp-i-accept-recovery-on-unauthenticated-transport \
                                 (plaintext UDP), which stamps its beats operator-attested."
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
                        RecoveryOutcome::RefusedStaleChildKillFailed { pid, error } => {
                            varta_error_pid!(
                                pid,
                                error,
                                "recovery for pid {pid} REFUSED: PID recycled while a \
                                 previous recovery child was still running, and that \
                                 stale child could not be killed: {error}"
                            );
                        }
                        RecoveryOutcome::Reaped { .. }
                        | RecoveryOutcome::Killed { .. }
                        | RecoveryOutcome::ReapFailed(_) => {
                            unreachable!("on_stall returned a reap-only recovery outcome")
                        }
                        RecoveryOutcome::SkippedAgentResumed { .. }
                        | RecoveryOutcome::SkippedPidRecycled { .. }
                        | RecoveryOutcome::SkippedStallUnverifiable { .. } => {
                            // Synthesized only by the freshness re-check above,
                            // which `continue`s before reaching this match;
                            // on_stall never returns them.
                            unreachable!("on_stall returned a deferred-skip outcome")
                        }
                    }

                    if did_spawn {
                        spawns_this_tick += 1;
                        if spawns_this_tick >= varta_watch::recovery::RECOVERY_SPAWN_MAX_PER_TICK {
                            // Budget reached: leave the remaining queued stalls
                            // for the next tick (the stall_queue cursor resumes)
                            // so a mass stall can't fork the whole fleet in one
                            // DrainPending stage and trip the self-watchdog.
                            #[cfg(feature = "prometheus-exporter")]
                            if let Some(pe) = prom_export.as_mut() {
                                pe.record_recovery_spawn_budget_exceeded(1);
                            }
                            recovery_budget_deferred_stalls = true;
                            break;
                        }
                    }
                }
            }
        }

        // The spawn-cap branch above breaks directly; the evaluation cap exits
        // via the loop condition. Either way, only the still-queued tail has
        // crossed a real deferral boundary and must receive the fire-time
        // PID-freshness check on a later tick.
        if recovery.is_some()
            && observer.has_pending_stalls()
            && (recovery_budget_deferred_stalls
                || evals_this_tick >= varta_watch::recovery::RECOVERY_STALL_EVAL_MAX_PER_TICK)
        {
            observer.defer_remaining_stalls_for_recovery();
        }

        // Record drain_pending stage, then reset timer for the poll phase.
        // Only the histogram needs a live exporter; stage publication feeds
        // the self-watchdog even in default/Class-A builds.
        #[cfg(feature = "prometheus-exporter")]
        {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_stage_duration(IterStage::DrainPending, stage_start.elapsed());
            }
            stage_start = Instant::now();
        }
        publish_stage(stage_watchdog_enabled, IterStage::Poll);

        // ----- 2. One non-blocking I/O poll for new beats / decode / auth ------
        // poll() never returns stalls — those are surfaced exclusively via
        // poll_pending() above.
        // poll() pulls at most one datagram per listener and returns the
        // first returnable Event (if any). Whether the socket still holds
        // queued beats is reported separately via `last_poll_consumed()` —
        // a dropped datagram yields no Event but is still I/O, and must not
        // be mistaken for an idle tick by the throttle below.
        if let Some(ev) = observer.poll() {
            record_ingress_event(
                &ev,
                &mut file_export,
                #[cfg(feature = "prometheus-exporter")]
                &mut prom_export,
                &cfg,
            )?;
        }

        // Record poll stage, then reset timer for the maintenance phase.
        #[cfg(feature = "prometheus-exporter")]
        {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_stage_duration(IterStage::Poll, stage_start.elapsed());
            }
            stage_start = Instant::now();
        }
        publish_stage(stage_watchdog_enabled, IterStage::Maintenance);

        // ------ 3. Maintenance (evictions, capacity, reaping, /metrics) ------
        let evicted = observer.drain_evictions();
        if evicted > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_eviction(evicted);
            }
        }

        for _ in 0..REMOVED_PID_DRAIN_MAX_PER_TICK {
            let Some(evicted_pid) = observer.drain_evicted_pid() else {
                break;
            };
            // bug-459: a queued removal can be stale by the time it is drained.
            // Under a >REMOVED_PID_DRAIN_MAX_PER_TICK eviction burst (or a
            // same-tick evict-then-rebeat) the pid may have been re-tracked —
            // by the SAME process (a spurious eviction) or by a RECYCLED one —
            // before its entry is popped. Per-pid exporter rows are keyed by
            // bare PID, so whichever identity now holds the pid owns the single
            // shared row and its counters are LIVE; removing it would reset the
            // agent's beats_total / stalls_total and drop any stall that lands
            // before its next beat. The only safe question is membership, NOT
            // generation: the earlier generation-equality gate (the bug-458
            // fix) reaped the row of a pid recycled to a *different* generation,
            // reopening the same clobber for the recycle case. A pid that is
            // genuinely gone (no live slot) still has its stale row removed.
            if observer.is_tracked(evicted_pid) {
                continue;
            }
            if let Some(fe) = file_export.as_mut() {
                if let Err(e) = fe.record_eviction_pid(evicted_pid, observer.now_ns()) {
                    varta_error_rl!(LogKind::FileExportIo, "file export error: {e}");
                }
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

        let replay_refused = observer.drain_replay_refused();
        if replay_refused > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_replay_refused(replay_refused);
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

        let clock_jumps_forward = observer.drain_clock_jumps_forward();
        if clock_jumps_forward > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_clock_jumps_forward(clock_jumps_forward);
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

        // Periodically re-read /proc/sys/kernel/pid_max so a sysctl-driven
        // runtime change (e.g. `sysctl -w kernel.pid_max=...`) is picked up
        // within one PID_MAX_REFRESH_INTERVAL_NS without daemon restart.
        // The call is gated internally by elapsed time; ~1 /proc read per
        // minute, off the hot path. Updates the Prometheus gauge whether
        // or not the value changed, so dashboards always reflect the
        // current cached ceiling.
        if observer.maybe_refresh_pid_max() {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.set_pid_max_current(observer.pid_max());
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

        // Tracker PID recycles (slot reset after a start-time mismatch).
        let tracker_pid_recycles = observer.drain_pid_recycles();
        if tracker_pid_recycles > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_tracker_pid_recycles(tracker_pid_recycles);
            }
            #[cfg(not(feature = "prometheus-exporter"))]
            let _ = tracker_pid_recycles;
        }

        let tracker_invariants = observer.drain_invariant_violations();
        if tracker_invariants > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_tracker_invariant_violations(tracker_invariants);
            }
        }

        // Drained every tick (resets the tracker counter) so a sustained
        // eviction burst that outruns the removed-pid drain is surfaced as
        // `varta_tracker_removed_pid_drops_total` rather than lost silently.
        let tracker_removed_pid_drops = observer.drain_removed_pid_drops();
        if tracker_removed_pid_drops > 0 {
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                pe.record_tracker_removed_pid_drops(tracker_removed_pid_drops);
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
            let recycle_resets = rec.take_last_fired_recycle_resets();
            let outstanding_recycle_resets = rec.take_outstanding_recycle_resets();
            let invariants = rec.take_last_fired_invariant_violations();
            let outstanding_probe_exhausted = rec.take_outstanding_probe_exhausted();
            #[cfg(feature = "prometheus-exporter")]
            if let Some(pe) = prom_export.as_mut() {
                if evictions > 0 {
                    pe.record_recovery_last_fired_evictions(evictions);
                }
                if recycle_resets > 0 {
                    pe.record_recovery_debounce_recycle_resets(recycle_resets);
                }
                if outstanding_recycle_resets > 0 {
                    pe.record_recovery_outstanding_recycle_resets(outstanding_recycle_resets);
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
                let _ = recycle_resets;
                let _ = outstanding_recycle_resets;
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
                // Per-fsync histogram + budget overrun counters.
                rec.take_audit_fsync_durations_into(&mut audit_fsync_durations);
                for d in audit_fsync_durations.drain(..) {
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
                rec.take_audit_fsync_durations_into(&mut audit_fsync_durations);
                audit_fsync_durations.clear();
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
        {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_stage_duration(IterStage::Maintenance, stage_start.elapsed());
            }
            stage_start = Instant::now();
        }
        publish_stage(stage_watchdog_enabled, IterStage::RecoveryReap);

        // Reap completed or timeout-exceeded children each tick.
        if let Some(rec) = recovery.as_mut() {
            rec.try_reap_into(observer.now_ns(), &mut recovery_reap_outcomes);
            for outcome in recovery_reap_outcomes.drain(..) {
                #[cfg(feature = "prometheus-exporter")]
                if let Some(pe) = prom_export.as_mut() {
                    pe.record_recovery_outcome(&outcome, outcome.duration_ns());
                }
                match outcome {
                    RecoveryOutcome::Reaped {
                        child_pid, status, ..
                    } if !status.success() => {
                        varta_warn_child!(
                            child_pid,
                            "recovery child {child_pid} exited non-zero: {status}"
                        );
                    }
                    RecoveryOutcome::Killed { child_pid } => {
                        varta_warn_child!(child_pid, "recovery child {child_pid} killed");
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

        // Publish the recovery_reap → serve_pending → housekeeping transitions;
        // only the serve_pending work and its histograms need the live exporter.
        #[cfg(feature = "prometheus-exporter")]
        {
            // Record recovery_reap stage before entering serve_pending.
            if let Some(pe) = prom_export.as_mut() {
                pe.record_stage_duration(IterStage::RecoveryReap, stage_start.elapsed());
            }
            publish_stage(stage_watchdog_enabled, IterStage::ServePending);

            if let Some(pe) = prom_export.as_mut() {
                // Bracket serve_pending so its wall time is observable
                // independently of beat-path latency.  See
                // `book/src/architecture/observer-liveness.md` ("Why /metrics is
                // on the poll thread") — keeping it on the main thread is a
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
            }
            stage_start = Instant::now(); // housekeeping starts after serve_pending
        }
        publish_stage(stage_watchdog_enabled, IterStage::Housekeeping);

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
        // Update the self-watchdog liveness timestamp.  Uses the suspend-paused
        // monotonic clock (`watchdog_now_ns`) so the watchdog thread — which
        // cannot reach the observer's own `Clock` — reads the same epoch, and a
        // host suspend is never mistaken for a wedged loop.  Store after the
        // poll work so a hung hw-watchdog kick would also be caught.
        //
        // H5: systemd `WATCHDOG=1` notifications are emitted from the
        // self-watchdog thread, NOT here.  This is the load-bearing closure
        // — if the watchdog thread dies but the main loop survives, the
        // emission stream stops and `WatchdogSec=` fires.  Calling
        // `sd_notify.watchdog_tick()` on the main thread would re-open that
        // gap, so it is deliberately omitted.
        // Release pairs with the Acquire load in the self-watchdog thread.
        LAST_TICK_NS.store(watchdog_now_ns(), Ordering::Release);
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
        publish_idle_stage(stage_watchdog_enabled);

        // ----- 6. Throttle: sleep only when truly idle ------
        // Avoid busy-waiting when there is no I/O and no queued stalls.
        // "Truly idle" means poll() pulled nothing off any socket this
        // iteration — `last_poll_consumed()` is false. A consumed-but-dropped
        // datagram (rate-limited / short / cross-namespace) yields no Event
        // but IS I/O: sleeping after it would cap drain at ~100 datagrams/s
        // and head-of-line-block real beats behind dropped traffic, causing
        // false stalls and spurious recovery. If poll() populated new stalls
        // via drain_stalls() the next iteration drains them without a sleep.
        if !observer.last_poll_consumed() && !observer.has_pending_stalls() {
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
    // Stop the self-watchdog thread BEFORE STOPPING=1 so a scheduled tick
    // cannot append a stray WATCHDOG=1 after STOPPING=1.  The break above
    // can fire from the `shutdown_after` deadline path which never sets
    // SHUTDOWN, so latch it here unconditionally.
    SHUTDOWN.store(1, Ordering::Release);
    if let Some(h) = wdt_handle.take() {
        let _ = h.join();
    }
    sd_notify.stopping();

    // Drain any remaining stall events so they are written to disk before the
    // file exporter is flushed — stalls queued during the last `poll()` call
    // would otherwise be lost on clean shutdown.
    while let Some(ev) = observer.poll_pending() {
        if let Some(fe) = file_export.as_mut() {
            let _ = fe.record(&ev);
        }
    }

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

    static STAGE_TEST_LOCK: Mutex<()> = Mutex::new(());

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

    #[test]
    fn watchdog_does_not_pet_systemd_before_first_tick() {
        // last == 0: the poll loop has not completed an iteration, so the
        // watchdog thread must NOT emit WATCHDOG=1. A first-iteration wedge then
        // lets systemd's WatchdogSec timer fire instead of being silently
        // masked — the symmetric companion to `watchdog_expired`'s last==0 skip.
        assert!(!watchdog_should_pet_systemd(0));
    }

    #[test]
    fn watchdog_pets_systemd_after_first_tick() {
        // Any non-zero LAST_TICK_NS means the loop has ticked at least once;
        // the pet resumes (and still detects watchdog-thread death via the
        // absence of a tick).
        assert!(watchdog_should_pet_systemd(1));
        assert!(watchdog_should_pet_systemd(u64::MAX));
    }

    #[test]
    fn stage_watchdog_detects_wedged_stage_without_prometheus_exporter() {
        let _guard = STAGE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for entry in &LAST_STAGE_ENTRY_NS {
            entry.store(0, Ordering::Relaxed);
        }
        CURRENT_STAGE.store(STAGE_IDLE, Ordering::Release);

        let stage = IterStage::Maintenance;
        let stage_idx = stage as usize;
        let entry_ns = 1_000_000_000u64;
        LAST_STAGE_ENTRY_NS[stage_idx].store(entry_ns, Ordering::Relaxed);
        CURRENT_STAGE.store(stage as u8, Ordering::Release);

        assert!(
            current_stage_wedge(entry_ns + STAGE_ABORT_NS[stage_idx]).is_none(),
            "the abort threshold is strict: equal-to-threshold is still tolerated"
        );

        let wedge = current_stage_wedge(entry_ns + STAGE_ABORT_NS[stage_idx] + 1)
            .expect("stage overrun must be detected");
        assert_eq!(wedge.label, STAGE_LABELS[stage_idx]);
        assert_eq!(wedge.abort_ns, STAGE_ABORT_NS[stage_idx]);

        publish_idle_stage(true);
        assert!(
            current_stage_wedge(u64::MAX).is_none(),
            "idle loop time must not be judged against the last active stage"
        );
    }

    #[test]
    fn stage_publication_is_noop_when_watchdog_disabled() {
        let _guard = STAGE_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for entry in &LAST_STAGE_ENTRY_NS {
            entry.store(0, Ordering::Relaxed);
        }
        CURRENT_STAGE.store(STAGE_IDLE, Ordering::Release);

        publish_stage(false, IterStage::Poll);

        assert_eq!(CURRENT_STAGE.load(Ordering::Acquire), STAGE_IDLE);
        assert!(LAST_STAGE_ENTRY_NS
            .iter()
            .all(|entry| entry.load(Ordering::Relaxed) == 0));
    }

    #[test]
    fn self_watchdog_clock_is_suspend_paused_not_configured_source() {
        use varta_watch::clock::ClockSource;
        // The watchdog measures on-CPU wedge time, so its clock is hardwired
        // to the suspend-paused monotonic clock — NEVER the operator's
        // advance-through-suspend `--clock-source`.  If a future change rewires
        // `--clock-source` back into the watchdog, this assertion fails.
        assert_eq!(WATCHDOG_CLOCK, ClockSource::Monotonic);
        // `Monotonic` resolves to a real `clk_id` on every supported platform,
        // so `watchdog_now_ns()` never falls into its defensive `0` arm.
        assert!(WATCHDOG_CLOCK.clk_id().is_some());
        assert!(watchdog_now_ns() > 0);
    }

    #[test]
    fn host_suspend_does_not_trip_watchdog_when_stall_clock_advances() {
        // Model the bug class: operator runs `--clock-source boottime` on an
        // aggressively-suspending clinical device; the host suspends for an
        // hour while the deadline is the systemd auto-enable default (4 s).
        let deadline_ns = 4 * 1_000_000_000; // AUTO_DEADLINE_SECS
        let suspend_ns = 3_600 * 1_000_000_000u64; // 1 h
        let last_tick_ns = 10 * 1_000_000_000u64; // pre-suspend baseline

        // FIXED behaviour: the watchdog stamps and reads `watchdog_now_ns`
        // (CLOCK_MONOTONIC), which PAUSES during suspend, so on resume
        // `now - last` is only the real on-CPU delta (a few ms) — no abort.
        let now_monotonic = last_tick_ns + 5_000_000; // 5 ms real elapsed
        assert!(
            !watchdog_expired(now_monotonic, last_tick_ns, deadline_ns),
            "suspend-paused watchdog clock must not abort a healthy observer on resume"
        );

        // Regression guard: the old code fed the advance-through-suspend
        // (boottime) clock, which jumped by the entire suspend — that single
        // forward jump was the spurious `process::abort()` this fix removes.
        let now_boottime = last_tick_ns + suspend_ns;
        assert!(
            watchdog_expired(now_boottime, last_tick_ns, deadline_ns),
            "sanity: a suspend-inclusive clock would have tripped — the defect this fix removes"
        );
    }

    #[test]
    fn watchdog_clock_clamps_backward_excursion_forward() {
        // CLOCK_MONOTONIC can appear to step backward on VMs (TSC drift,
        // live-migration resume). The watchdog clamps every reading forward
        // through a shared high-water mark so a backward dip can neither
        // suppress wedge detection nor manufacture a spurious abort.
        let hw = AtomicU64::new(0);

        // Normal forward progress passes through unchanged.
        assert_eq!(watchdog_clamp_forward(1_000, &hw), 1_000);
        assert_eq!(watchdog_clamp_forward(2_000, &hw), 2_000);

        // A backward excursion is pinned to the high-water mark, NOT returned
        // raw — otherwise `watchdog_expired`'s saturating_sub would read 0.
        assert_eq!(watchdog_clamp_forward(500, &hw), 2_000);
        assert_eq!(watchdog_clamp_forward(1_999, &hw), 2_000);

        // Recovery above the high-water resumes true progress.
        assert_eq!(watchdog_clamp_forward(3_000, &hw), 3_000);
    }

    #[test]
    fn watchdog_wedge_still_detected_when_monotonic_clock_dips() {
        // Model a wedged poll loop whose last successful tick stamped `last`,
        // then the monotonic clock dips backward before the watchdog samples.
        let deadline_ns = 4 * 1_000_000_000u64; // AUTO_DEADLINE_SECS
        let hw = AtomicU64::new(0);

        // Main thread stamps its last tick at t = 100 s (clamped path).
        let last = watchdog_clamp_forward(100 * 1_000_000_000, &hw);

        // The loop wedges; the raw clock then dips to 95 s before the watchdog
        // samples. UNCLAMPED, `95 s - 100 s` saturates to 0 and the wedge is
        // silently masked (the bug). Clamped, `now` is pinned to the 100 s
        // high-water and can never precede the last stamp.
        let raw_dipped = 95 * 1_000_000_000u64;
        let now = watchdog_clamp_forward(raw_dipped, &hw);
        assert!(now >= last, "clamped now must never precede the last stamp");

        // Direct proof of the pre-fix defect: feeding the raw dip straight into
        // watchdog_expired suppresses detection entirely.
        assert!(
            !watchdog_expired(raw_dipped, last, deadline_ns),
            "sanity: the unclamped backward dip is exactly what masked the wedge"
        );

        // Once the clock recovers past `last + deadline`, the wedge fires; the
        // clamp guarantees the dip cannot indefinitely mask a real wedge.
        let now_recovered = watchdog_clamp_forward(105 * 1_000_000_000, &hw);
        assert!(
            watchdog_expired(now_recovered, last, deadline_ns),
            "a wedge longer than the deadline must still abort after a clock dip"
        );
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

    #[test]
    fn heartbeat_write_does_not_follow_preplanted_temp_symlink() {
        use std::os::unix::fs::symlink;

        let dir = mk_tmpdir("temp-symlink");
        let path = dir.join("hb.txt");
        let victim = dir.join("victim.txt");
        fs::write(&victim, b"do not touch\n").expect("seed victim");

        let pid = std::process::id();
        let legacy_tmp = PathBuf::from(format!("{}.{pid}.tmp", path.display()));
        symlink(&victim, &legacy_tmp).expect("plant legacy tempfile symlink");

        write_heartbeat_atomic(&path, b"1 100\n").expect("write hardened heartbeat");

        assert_eq!(
            fs::read(&victim).expect("read victim"),
            b"do not touch\n",
            "heartbeat tempfile handling must never follow a pre-planted symlink"
        );
        assert!(
            fs::symlink_metadata(&path)
                .expect("heartbeat metadata")
                .file_type()
                .is_file(),
            "published heartbeat must be a regular file"
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
        // Renaming a regular tempfile over a non-empty directory fails after
        // the tempfile has been created, exercising the RAII cleanup path.
        let target = dir.join("hb.txt");
        fs::create_dir(&target).expect("create conflicting target directory");
        fs::write(target.join("keep"), b"x").expect("make target non-empty");

        let result = write_heartbeat_atomic(&target, b"1 100\n");
        assert!(result.is_err());

        let prefix = format!("hb.txt.{}.", std::process::id());
        let stale_temp = fs::read_dir(&dir)
            .expect("read temp directory")
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .any(|name| {
                let name = name.to_string_lossy();
                name.starts_with(&prefix) && name.ends_with(".tmp")
            });
        assert!(
            !stale_temp,
            "stale heartbeat tempfile left behind after rename failure"
        );
    }
}
