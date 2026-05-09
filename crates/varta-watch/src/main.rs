#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]

//! Varta observer binary entry point.
//!
//! Parses argv into a [`Config`], binds an [`Observer`], optionally
//! installs a [`Recovery`] runner and the file / Prometheus exporters,
//! then drives [`Observer::poll`] in a single thread until either a
//! `--shutdown-after-secs` deadline elapses or the process is killed.
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

/// Shutdown latch. A future SIGINT hook flips this to `true`; v0.1.0 ships
/// without a signal handler (no `libc` dep is on the surface), so the
/// only way to flip it today is `--shutdown-after-secs`.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

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
    let mut observer = Observer::bind(&cfg.socket, cfg.threshold)?;
    let mut recovery = cfg
        .recovery_cmd
        .as_ref()
        .map(|tpl| Recovery::new(tpl.clone(), cfg.recovery_debounce));
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
                        RecoveryOutcome::Spawned(status) if status.success() => {}
                        RecoveryOutcome::Spawned(status) => {
                            eprintln!("varta-watch: recovery for pid {pid} exited {status}");
                        }
                        RecoveryOutcome::SpawnFailed(e) => {
                            eprintln!("varta-watch: recovery for pid {pid} failed to spawn: {e}");
                        }
                        RecoveryOutcome::Debounced => {}
                    }
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
