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
use std::time::Instant;

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

    let mut observer = Observer::bind(&cfg.socket, cfg.threshold, cfg.socket_mode)?;
    let mut recovery = cfg.recovery_cmd.as_ref().map(|tpl| {
        Recovery::with_timeout(tpl.clone(), cfg.recovery_debounce, cfg.recovery_timeout)
    });
    let mut file_export: Option<FileExporter> = match cfg.file_export.as_ref() {
        Some(path) => Some(FileExporter::create(path)?),
        None => None,
    };
    let mut prom_export: Option<PromExporter> = match cfg.prom_addr {
        Some(addr) => Some(PromExporter::bind(addr)?),
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

        if let Some(ev) = observer.poll() {
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

        let evicted = observer.drain_evictions();
        if evicted > 0 {
            if let Some(pe) = prom_export.as_mut() {
                pe.record_eviction(evicted);
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
    }

    if let Some(fe) = file_export.as_mut() {
        let _ = fe.flush();
    }
    Ok(())
}
