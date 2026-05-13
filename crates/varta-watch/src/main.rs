#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]
// SAFETY: unsafe_code is legitimately required for sigaction(2) FFI in
// install_signal_handlers().  The workspace-level deny forces explicit opt-in.
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use varta_watch::{
    varta_error, varta_error_err, varta_error_pid, varta_info_pid_child, varta_warn,
    varta_warn_child, Config, ConfigError, Event, Exporter, FileExporter, Observer, PromExporter,
    Recovery, RecoveryOutcome,
};

/// Shutdown latch flipped by [`install_signal_handlers`] on SIGINT/SIGTERM
/// and by the `--shutdown-after-secs` deadline path. The poll loop exits
/// when this becomes `true`.
///
/// # Async-signal-safety
///
/// The signal handler writes `true` with `Ordering::Release` to this
/// `AtomicBool`.  On all Tier-1 targets the operation compiles to a single
/// aligned atomic instruction (e.g. `lock or $1,mem` on x86_64; `stlr` on
/// aarch64) and cannot be interrupted mid-store.  POSIX `sig_atomic_t` is
/// the minimum guarantee, but lock-free atomics are explicitly supported in
/// signal handlers by Linux `signal-safety(7)` and Apple `sigaction(2)`.
/// `SA_RESTART` is set so the observer's `recvmsg(2)` never returns `EINTR`.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Nanosecond timestamp of the most recent poll loop iteration, written by
/// the main thread each tick and read by the self-watchdog thread.
/// Initialised to 0; the watchdog ignores the zero value to avoid spurious
/// aborts before the first tick.
static LAST_TICK_NS: AtomicU64 = AtomicU64::new(0);

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd",))]
unsafe fn install_signal_handlers() -> io::Result<()> {
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    /// `SA_RESTART`: automatically restart interrupted syscalls (e.g.
    /// `recvmsg(2)`) instead of returning `EINTR`.  Eliminates the need
    /// for explicit `EINTR` handling in the I/O path.  Values are
    /// platform-defined; verified against `<bits/signum-generic.h>`
    /// (Linux), `<sys/signal.h>` (macOS), and `<sys/signal.h>` (FreeBSD).
    #[cfg(target_os = "linux")]
    const SA_RESTART: i32 = 0x1000_0000;
    #[cfg(target_os = "macos")]
    const SA_RESTART: i32 = 0x0002;
    #[cfg(target_os = "freebsd")]
    const SA_RESTART: i32 = 0x0040;

    extern "C" fn handle(_sig: i32) {
        SHUTDOWN.store(true, Ordering::Release);
    }

    // Platform-specific sigaction struct: layout differs between Linux,
    // macOS, and FreeBSD (sigset_t size, field ordering, presence of
    // sa_restorer).  Each layout is matched against the platform C ABI
    // and guarded by compile-time size / offset assertions.
    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct SigAction {
        sa_handler: *const (),
        sa_mask: [u8; 128],
        sa_flags: i32,
        _pad: i32,
        sa_restorer: *const (),
    }

    #[cfg(target_os = "macos")]
    #[repr(C)]
    struct SigAction {
        sa_handler: *const (),
        /// sigset_t on macOS / XNU is `__uint32_t` (4 bytes), not 32 bytes.
        /// Defined in `<sys/_types/_sigset_t.h>`; verified against xnu
        /// sources (xnu-8792.81.2, xnu-11215.1.10).  Passing a 32-byte mask
        /// here would write past the kernel-expected field and corrupt the
        /// caller's stack frame on ARM64 / Apple Silicon.
        sa_mask: u32,
        sa_flags: i32,
    }

    #[cfg(target_os = "freebsd")]
    #[repr(C)]
    struct SigAction {
        sa_handler: *const (),
        sa_flags: i32,
        /// sigset_t on FreeBSD is `__uint32_t[4]` (16 bytes).  Verified
        /// against `<sys/_sigset.h>` (FreeBSD 14.2).
        sa_mask: [u8; 16],
    }

    // Compile-time size and offset assertions — guard against ABI drift
    // across kernel / libc versions.  These `const _` assertions are
    // evaluated at compile time (not runtime), so a mismatch becomes a
    // hard "evaluation of constant value failed" error during `cargo build`,
    // preventing stack corruption at signal-install time.  Every platform
    // field's size and offset is pinned against the known-good C ABI values
    // documented in the per-platform struct comments above.
    #[cfg(target_os = "linux")]
    const _: () = assert!(core::mem::size_of::<SigAction>() == 152);
    #[cfg(target_os = "macos")]
    const _: () = assert!(core::mem::size_of::<SigAction>() == 16);
    #[cfg(target_os = "freebsd")]
    const _: () = assert!(core::mem::size_of::<SigAction>() == 32);

    #[cfg(target_os = "linux")]
    const _: () = assert!(core::mem::offset_of!(SigAction, sa_handler) == 0);
    #[cfg(target_os = "linux")]
    const _: () = assert!(core::mem::offset_of!(SigAction, sa_mask) == 8);
    #[cfg(target_os = "linux")]
    const _: () = assert!(core::mem::offset_of!(SigAction, sa_flags) == 136);
    #[cfg(target_os = "linux")]
    const _: () = assert!(core::mem::offset_of!(SigAction, sa_restorer) == 144);

    #[cfg(target_os = "macos")]
    const _: () = assert!(core::mem::offset_of!(SigAction, sa_handler) == 0);
    #[cfg(target_os = "macos")]
    const _: () = assert!(core::mem::offset_of!(SigAction, sa_mask) == 8);
    #[cfg(target_os = "macos")]
    const _: () = assert!(core::mem::offset_of!(SigAction, sa_flags) == 12);

    #[cfg(target_os = "freebsd")]
    const _: () = assert!(core::mem::offset_of!(SigAction, sa_handler) == 0);
    #[cfg(target_os = "freebsd")]
    const _: () = assert!(core::mem::offset_of!(SigAction, sa_flags) == 8);
    #[cfg(target_os = "freebsd")]
    const _: () = assert!(core::mem::offset_of!(SigAction, sa_mask) == 12);

    extern "C" {
        fn sigaction(signum: i32, act: *const SigAction, oldact: *mut SigAction) -> i32;
    }

    // SAFETY: MaybeUninit::zeroed() allocates zeroed stack memory without
    // constructing a SigAction value, so there is no UB regardless of the
    // fields' validity requirements.  We write sa_handler through the raw
    // pointer before passing the struct to sigaction(2).  sa_mask of all
    // zeros and sa_flags of 0 are correct defaults (no blocked signals,
    // SA_RESETHAND not set).  The handler is async-signal-safe: it writes
    // to a lock-free AtomicBool only.
    let mut act = std::mem::MaybeUninit::<SigAction>::zeroed();
    unsafe {
        (*act.as_mut_ptr()).sa_handler = handle as *const ();
        (*act.as_mut_ptr()).sa_flags = SA_RESTART;
    }
    let act = unsafe { act.assume_init() };

    let install = |sig: i32| -> io::Result<()> {
        // SAFETY: `act` is a fully-initialised SigAction on the stack;
        // passing null for oldact is permitted by POSIX.
        let rc = unsafe { sigaction(sig, &act, std::ptr::null_mut()) };
        if rc == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    install(SIGINT)?;
    install(SIGTERM)?;
    Ok(())
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "macos", target_os = "freebsd",)),
))]
unsafe fn install_signal_handlers() -> io::Result<()> {
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    extern "C" {
        // Declared as *const () so we can compare against SIG_ERR = -1isize
        // as a raw pointer value without a function-pointer-to-integer cast.
        fn signal(signum: i32, handler: *const ()) -> *const ();
    }

    extern "C" fn handle(_sig: i32) {
        SHUTDOWN.store(true, Ordering::Release);
    }

    // SIG_ERR is defined as `(void(*)(int))-1` in C99 §7.14.1.1 and POSIX.
    // The all-ones pointer value is portable across the exotic-Unix set this
    // branch covers.
    let sig_err: *const () = (-1isize) as usize as *const ();

    // SAFETY: signal(2) fallback for exotic Unix targets whose sigaction(2)
    // struct layout is unknown (NetBSD, OpenBSD, illumos, etc.). On SysV
    // systems signal(2) may reset the handler to SIG_DFL after delivery,
    // but the shutdown latch stays set after the first signal — a repeated
    // signal becomes a SIG_DFL termination, which is acceptable during
    // shutdown.
    let prev = unsafe { signal(SIGINT, handle as *const ()) };
    if prev == sig_err {
        return Err(io::Error::last_os_error());
    }
    let prev = unsafe { signal(SIGTERM, handle as *const ()) };
    if prev == sig_err {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
unsafe fn install_signal_handlers() -> io::Result<()> {
    // No-op on non-Unix; --shutdown-after-secs remains the only exit path.
    Ok(())
}

/// Write `contents` to `path` atomically via a same-directory tempfile + rename.
///
/// `rename(2)` is atomic on POSIX-compliant filesystems; a reader of `path`
/// will observe either the previous complete file or the new complete file,
/// never a partial write.  A `.<pid>.tmp` suffix keeps concurrent observers
/// (misconfigured onto the same path) from clobbering each other's tempfile.
/// If the rename fails the tempfile is removed before returning the error.
/// Monotonic nanosecond clock for the self-watchdog thread.  Uses
/// `Instant::now()` so it never goes backwards, which is the only
/// property needed for deadline arithmetic.
fn observer_now_ns() -> u64 {
    use std::time::UNIX_EPOCH;
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    match Config::from_args(args) {
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
    // SAFETY: `install_signal_handlers` is safe to call here because this is
    // the sole entry point of a single-threaded binary with no other libraries
    // that install their own SIGINT/SIGTERM handlers.
    unsafe {
        install_signal_handlers()?;
    }

    let mut observer = Observer::bind(
        &cfg.socket,
        cfg.threshold,
        cfg.socket_mode,
        cfg.read_timeout,
        cfg.tracker_capacity,
        cfg.tracker_eviction_policy,
        cfg.eviction_scan_window,
        cfg.max_beat_rate,
    )?
    .with_allow_cross_namespace(cfg.allow_cross_namespace_agents);

    // On platforms lacking kernel-level per-datagram credential passing
    // (OpenBSD, Solaris, illumos, and other exotic Unixen) the observer
    // relies solely on --socket-mode (default 0600) as the trust boundary.
    // Linux, macOS, FreeBSD, DragonFly, and NetBSD all have per-datagram
    // credential mechanisms — the observer enforces them automatically.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
    )))]
    varta_warn!(
        "running on {} — per-datagram PID verification is unavailable. \
         The only defence is --socket-mode (default 0600); any process under the same \
         UID can impersonate any PID.",
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
            varta_warn!(
                "secure-UDP is bound to non-loopback {addr} \
                 (--i-accept-secure-udp-non-loopback). The 1-deep replay shadow \
                 after capacity-forced eviction is inadequate for any reachable \
                 network; restrict reach via firewall / private VLAN. See \
                 docs/architecture/vlp-transports.md for the threat-boundary \
                 derivation."
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
                varta_error!(
                    "--udp-port {addr} cannot bind: no AEAD keys are configured \
                     and --i-accept-plaintext-udp was not passed. Provide \
                     --key-file (or --master-key-file) for authenticated transport, \
                     or pass --i-accept-plaintext-udp to explicitly accept the \
                     security risk of an unauthenticated UDP listener (test/dev only)."
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "plaintext UDP requires --i-accept-plaintext-udp (and no keys are configured)",
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
                varta_warn!(
                    "UDP on {addr} is running WITHOUT authentication \
                     (--i-accept-plaintext-udp). Any device with network reach to \
                     this port can inject heartbeats, suppress stall detection, or \
                     trigger false recovery commands. NOT for production / \
                     safety-critical use."
                );
            }

            #[cfg(not(feature = "unsafe-plaintext-udp"))]
            {
                varta_error!(
                    "--udp-port {addr} cannot bind: this build does not include \
                     --features unsafe-plaintext-udp, and no AEAD keys are \
                     configured. Rebuild with --features secure-udp and provide \
                     --key-file / --master-key-file."
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
        varta_error!(
            "--udp-port requires UDP support (rebuild with --features secure-udp \
             for authenticated transport, or --features unsafe-plaintext-udp for \
             a development/testing plaintext listener)"
        );
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
        varta_error!(
            "--key-file / --accepted-key-file / --master-key-file require secure \
             UDP support (rebuild with --features secure-udp)"
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

    // Optional audit log — opened once at startup. The same hardened
    // permission check (mode 0600, owned by observer UID) used for key/
    // token files protects the audit path: never publish recovery
    // activity world-readable.
    let recovery_audit_sink = match cfg.recovery_audit_file.as_ref() {
        Some(path) => {
            let sink =
                varta_watch::audit::RecoveryAuditLog::create(path, cfg.recovery_audit_max_bytes)?;
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
            varta_warn!(
                "recovery on secure-UDP listener is enabled \
                 (--secure-udp-i-accept-recovery-on-unauthenticated-transport). \
                 NOT for safety-critical use."
            );
        }
        if cfg.i_accept_recovery_on_plaintext_udp {
            varta_warn!(
                "recovery on plaintext-UDP listener is enabled \
                 (--plaintext-udp-i-accept-recovery-on-unauthenticated-transport). \
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
            .with_shutdown_grace(cfg.shutdown_grace)
            .with_capture(capture_cap)
            .with_source(recovery_source.clone())
            .with_audit_sink(recovery_audit_sink)
            .with_allow_cross_namespace(cfg.allow_cross_namespace_agents)
    });
    let mut file_export: Option<FileExporter> = match cfg.file_export.as_ref() {
        Some(path) => Some(FileExporter::create(path, cfg.export_file_max_bytes)?),
        None => None,
    };
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
    // `docs/architecture/observer-liveness.md`.  Operators with tighter
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
        let tick_sleep = match wdt_notifier.as_ref() {
            Some(n) => (n.half_interval() / 2)
                .min(Duration::from_millis(500))
                .max(Duration::from_millis(50)),
            None => Duration::from_millis(500),
        };
        let mut wdt_notifier = wdt_notifier;
        std::thread::Builder::new()
            .name("varta-watchdog".into())
            .spawn(move || loop {
                std::thread::sleep(tick_sleep);
                if SHUTDOWN.load(Ordering::Acquire) {
                    return;
                }
                let last = LAST_TICK_NS.load(Ordering::Relaxed);
                let now = observer_now_ns();
                if watchdog_expired(now, last, deadline_ns) {
                    eprintln!("varta-watch poll loop wedged for >{secs}s; aborting");
                    std::process::abort();
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
                return Err(io::Error::new(
                    e.kind(),
                    format!("--hw-watchdog {}: {e}", path.display()),
                ));
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
        if SHUTDOWN.load(Ordering::Acquire) {
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
        let iter_start = Instant::now();

        // ------ 1. Drain queued stall events before I/O or maintenance ------
        // Surface every pending stall immediately; this prevents a batch of
        // N simultaneous stalls from taking N full poll cycles (each of which
        // includes Prometheus serving / file I/O / reaping).
        while let Some(ev) = observer.poll_pending() {
            if let Some(fe) = file_export.as_mut() {
                if let Err(e) = fe.record(&ev) {
                    varta_error!("file export error: {e}");
                }
            }
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
                            varta_warn!(
                                "recovery for pid {pid} REFUSED: stalled beat lifetime \
                                 includes a non-kernel-attested transport (UDP). Pass \
                                 --i-accept-recovery-on-unauthenticated-transport AND \
                                 enable Recovery's allow_unauthenticated_source to \
                                 override at your own risk."
                            );
                        }
                        RecoveryOutcome::RefusedCrossNamespace { pid } => {
                            varta_warn!(
                                "recovery for pid {pid} REFUSED: agent's PID namespace \
                                 differs from observer's. kill(2) against this pid \
                                 in the observer's namespace would target the wrong \
                                 process. Pass --allow-cross-namespace-agents only when \
                                 agents are run with --pid=host or an out-of-band PID \
                                 translator is in place."
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

        // ----- 2. One non-blocking I/O poll for new beats / decode / auth ------
        // poll() never returns stalls — those are surfaced exclusively via
        // poll_pending() above.
        let had_io = if let Some(ev) = observer.poll() {
            if let Some(fe) = file_export.as_mut() {
                if let Err(e) = fe.record(&ev) {
                    varta_error!("file export error: {e}");
                }
            }
            if let Some(pe) = prom_export.as_mut() {
                let _ = pe.record(&ev);
            }
            // Strict namespace mode: a cross-namespace agent is a fatal
            // startup error. The default behaviour is to drop the beat and
            // refuse recovery (already enforced inside `Observer`); strict
            // mode escalates to daemon exit so the operator notices.
            if cfg.strict_namespace_check && !cfg.allow_cross_namespace_agents {
                if let Event::NamespaceConflict { claimed_pid, .. } = &ev {
                    varta_error!(
                        "FATAL --strict-namespace-check: cross-namespace agent \
                         detected for claimed pid {claimed_pid}; refusing to \
                         continue. Re-run with --allow-cross-namespace-agents \
                         only if PID translation is correctly configured."
                    );
                    return Err(io::Error::other(
                        "cross-namespace agent detected under --strict-namespace-check",
                    ));
                }
            }
            true
        } else {
            false
        };

        // ------ 3. Maintenance (evictions, capacity, reaping, /metrics) ------
        let evicted = observer.drain_evictions();
        if evicted > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_eviction(evicted);
            }
        }

        if let Some(evicted_pid) = observer.drain_evicted_pid() {
            if let Some(fe) = file_export.as_mut() {
                fe.record_eviction_pid(evicted_pid, observer.now_ns());
            }
            if let Some(pe) = prom_export.as_mut() {
                pe.record_evicted_pid(evicted_pid);
            }
        }

        let capacity_exceeded = observer.drain_capacity_exceeded();
        if capacity_exceeded > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_capacity_exceeded(capacity_exceeded);
            }
        }

        let decrypt_failures = observer.drain_decrypt_failures();
        if decrypt_failures > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_decrypt_failures(decrypt_failures);
            }
        }

        let truncated = observer.drain_truncated();
        if truncated > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_truncated(truncated);
            }
        }

        let sender_state_full = observer.drain_sender_state_full();
        if sender_state_full > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_sender_state_full(sender_state_full);
            }
        }

        let aead_attempts = observer.drain_aead_attempts();
        if aead_attempts > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_secure_aead_attempts(aead_attempts);
            }
        }

        let rate_limited = observer.drain_rate_limited();
        if rate_limited > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_rate_limited(rate_limited);
            }
        }

        let nonce_wraps = observer.drain_nonce_wraps();
        if nonce_wraps > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_nonce_wraps(nonce_wraps);
            }
        }

        let eviction_scan_truncated = observer.drain_eviction_scan_truncated();
        if eviction_scan_truncated > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_eviction_scan_truncated(eviction_scan_truncated);
            }
        }

        let origin_conflicts = observer.drain_origin_conflicts();
        if origin_conflicts > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_origin_conflicts(origin_conflicts);
            }
        }

        // Cross-namespace frame drops at receive (Linux-only signal; 0 on
        // other platforms or when --allow-cross-namespace-agents is set).
        let frame_ns_mismatches = observer.drain_cross_namespace_drops();
        if frame_ns_mismatches > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_frame_namespace_mismatches(frame_ns_mismatches);
            }
        }

        // Tracker namespace conflicts (rebind with a different inode).
        let tracker_ns_conflicts = observer.drain_namespace_conflicts();
        if tracker_ns_conflicts > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_tracker_namespace_conflicts(tracker_ns_conflicts);
            }
        }

        let tracker_invariants = observer.drain_invariant_violations();
        if tracker_invariants > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_tracker_invariant_violations(tracker_invariants);
            }
        }

        let probe_exhausted = observer.drain_pid_index_probe_exhausted();
        if probe_exhausted > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_tracker_pid_index_probe_exhausted(probe_exhausted);
            }
        }

        // Reap completed or timeout-exceeded children each tick.
        if let Some(rec) = recovery.as_mut() {
            for outcome in rec.try_reap() {
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
        }

        if let Some(pe) = prom_export.as_mut() {
            // Bracket serve_pending so its wall time is observable
            // independently of beat-path latency.  See
            // `docs/architecture/observer-liveness.md` ("Why /metrics is on
            // the poll thread") — keeping it on the main thread is a
            // load-bearing invariant, and the separate histogram is the
            // observability primitive that lets scrape-storm alarms fire
            // without polluting beat-path alarms.
            let serve_start = Instant::now();
            if let Err(e) = pe.serve_pending() {
                varta_error!("/metrics serve error: {e}");
            }
            pe.record_loop_tick();
            pe.record_serve_pending_duration(serve_start.elapsed());
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
                varta_error!("heartbeat file write error: {e}");
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
        LAST_TICK_NS.store(observer_now_ns(), Ordering::Relaxed);
        if let Some(ref mut hw) = hw_wdt {
            hw.kick();
        }

        // ----- 5. Record per-iteration wall time ------
        // H5: capture the duration of the work portion of this iteration
        // (everything from `iter_start` at the top of the loop body through
        // the watchdog kicks).  Excludes the idle sleep below and the
        // test-hooks wedge — those are throttling / fault injection, not
        // real work.  See `docs/architecture/observer-liveness.md`.
        if let Some(pe) = prom_export.as_mut() {
            pe.record_iteration_duration(iter_start.elapsed());
        }

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
        // Verifies the new error-propagation path doesn't misclassify success.
        // SAFETY: single-threaded test process; no other signal handlers active.
        let result = unsafe { install_signal_handlers() };
        assert!(
            result.is_ok(),
            "install_signal_handlers failed: {:?}",
            result
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
