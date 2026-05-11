#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]

//! Varta observer binary entry point.
//!
//! Parses argv into a [`Config`], binds an [`Observer`], optionally
//! installs a [`Recovery`] runner and the file / Prometheus exporters,
//! then drives [`Observer::poll`] in a single thread until either a
//! `--shutdown-after-secs` deadline elapses or a signal (SIGINT /
//! SIGTERM) flips the [`SHUTDOWN`] latch.
//!
//! This binary is the only place in the workspace where `eprintln!` is
//! permitted. Diagnostics (errors, recovery outcomes) go to stderr; the
//! `--help` text goes to stdout via `std::io::stdout`.

use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use varta_watch::{
    Config, ConfigError, Event, Exporter, FileExporter, Observer, PromExporter, Recovery,
    RecoveryOutcome,
};

/// Shutdown latch flipped by [`install_signal_handlers`] on SIGINT/SIGTERM
/// and by the `--shutdown-after-secs` deadline path. The poll loop exits
/// when this becomes `true`.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
unsafe fn install_signal_handlers() {
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;

    extern "C" {
        fn signal(signum: i32, handler: extern "C" fn(i32)) -> extern "C" fn(i32);
    }

    extern "C" fn handle(_sig: i32) {
        SHUTDOWN.store(true, Ordering::Release);
    }

    // SAFETY: We are the only caller of signal() in this binary; no other
    // library or thread installs competing handlers. The handler itself is
    // async-signal-safe: it writes to a lock-free AtomicBool and performs no
    // allocation, I/O, or non-reentrant calls.
    unsafe {
        let _ = signal(SIGINT, handle);
        let _ = signal(SIGTERM, handle);
    }
}

#[cfg(not(unix))]
unsafe fn install_signal_handlers() {
    // No-op on non-Unix; --shutdown-after-secs remains the only exit path.
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match Config::from_args(args) {
        Ok(cfg) => match run(cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("varta-watch: {e}");
                ExitCode::from(1)
            }
        },
        Err(ConfigError::HelpRequested) => {
            let _ = std::io::stdout().lock().write_all(Config::HELP.as_bytes());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("varta-watch: {e}");
            eprintln!();
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
        install_signal_handlers();
    }

    let mut observer = Observer::bind(
        &cfg.socket,
        cfg.threshold,
        cfg.socket_mode,
        cfg.read_timeout,
    )?;

    #[cfg(feature = "udp")]
    if let Some(port) = cfg.udp_port {
        let bind_addr = cfg
            .udp_bind_addr
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let addr = std::net::SocketAddr::new(bind_addr, port);
        let udp = varta_watch::UdpListener::bind(addr)
            .map_err(|e| std::io::Error::new(e.kind(), format!("UDP bind {}: {e}", addr)))?;
        observer.add_listener(Box::new(udp));
    }

    #[cfg(not(feature = "udp"))]
    if cfg.udp_port.is_some() {
        eprintln!("varta-watch: --udp-port requires UDP support (rebuild with --features udp)");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "UDP support not compiled in",
        ));
    }

    #[cfg(not(feature = "secure-udp"))]
    if cfg.secure_key_file.is_some()
        || cfg.accepted_key_file.is_some()
        || cfg.key_env != "VARTA_KEY"
    {
        eprintln!(
            "varta-watch: --key-file / --accepted-key-file / --key-env require secure UDP support \
             (rebuild with --features secure-udp)"
        );
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "secure UDP support not compiled in",
        ));
    }

    // --- secure UDP listener (AEAD) ---
    #[cfg(feature = "secure-udp")]
    if let Some((keys, accepted_keys)) = cfg.load_secure_keys()? {
        if let Some(port) = cfg.udp_port {
            let bind_addr = cfg
                .udp_bind_addr
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            let addr = std::net::SocketAddr::new(bind_addr, port);
            let mut all_keys = keys;
            all_keys.extend(accepted_keys);
            let secure = varta_watch::SecureUdpListener::bind(addr, all_keys).map_err(|e| {
                std::io::Error::new(e.kind(), format!("secure UDP bind {}: {e}", addr))
            })?;
            observer.add_listener(Box::new(secure));
        }
    }

    let mut recovery = cfg.recovery_cmd.as_ref().map(|tpl| {
        Recovery::with_timeout(tpl.clone(), cfg.recovery_debounce, cfg.recovery_timeout)
    });
    let mut file_export: Option<FileExporter> = match cfg.file_export.as_ref() {
        Some(path) => Some(FileExporter::create(path)?),
        None => None,
    };
    let mut prom_export: Option<PromExporter> = match cfg.prom_addr {
        Some(addr) => {
            let pe = PromExporter::bind(addr)?;
            if let Ok(bound_addr) = pe.local_addr() {
                let line = format!("{bound_addr}\n");
                let _ = std::io::stdout().lock().write_all(line.as_bytes());
            }
            Some(pe)
        }
        None => None,
    };

    let started = Instant::now();
    loop {
        if SHUTDOWN.load(Ordering::Relaxed) {
            break;
        }
        if let Some(deadline) = cfg.shutdown_after {
            if started.elapsed() >= deadline {
                break;
            }
        }

        // ------ 1. Drain queued stall events before I/O or maintenance ------
        // Surface every pending stall immediately; this prevents a batch of
        // N simultaneous stalls from taking N full poll cycles (each of which
        // includes Prometheus serving / file I/O / reaping).
        while let Some(ev) = observer.poll_pending() {
            if let Some(fe) = file_export.as_mut() {
                fe.record(&ev);
            }
            if let Some(pe) = prom_export.as_mut() {
                pe.record(&ev);
            }
            if let Event::Stall { pid, .. } = &ev {
                if let Some(rec) = recovery.as_mut() {
                    match rec.on_stall(*pid) {
                        RecoveryOutcome::Spawned { child_pid } => {
                            eprintln!(
                                "varta-watch: recovery for pid {pid} spawned (child {child_pid})"
                            );
                        }
                        RecoveryOutcome::Debounced => {}
                        RecoveryOutcome::SpawnFailed(e) => {
                            eprintln!("varta-watch: recovery for pid {pid} failed to spawn: {e}");
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
                fe.record(&ev);
            }
            if let Some(pe) = prom_export.as_mut() {
                pe.record(&ev);
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

        // Reap completed or timeout-exceeded children each tick.
        if let Some(rec) = recovery.as_mut() {
            for outcome in rec.try_reap() {
                match outcome {
                    RecoveryOutcome::Reaped { child_pid, status } if !status.success() => {
                        eprintln!(
                            "varta-watch: recovery child {child_pid} exited non-zero: {status}"
                        );
                    }
                    RecoveryOutcome::Killed { child_pid } => {
                        eprintln!("varta-watch: recovery child {child_pid} killed after timeout");
                    }
                    RecoveryOutcome::ReapFailed(e) => {
                        eprintln!("varta-watch: recovery reap failed: {e}");
                    }
                    _ => {}
                }
            }
        }

        if let Some(pe) = prom_export.as_mut() {
            if let Err(e) = pe.serve_pending() {
                eprintln!("varta-watch: /metrics serve error: {e}");
            }
        }

        // ----- 4. Throttle: sleep only when truly idle ------
        // Avoid busy-waiting when there are no I/O events and no queued
        // stalls.  If poll() populated new stalls via drain_stalls() the
        // check below catches them and the next iteration drains them
        // without a sleep penalty.
        if !had_io && !observer.has_pending_stalls() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    if let Some(fe) = file_export.as_mut() {
        let _ = fe.flush();
    }
    Ok(())
}
