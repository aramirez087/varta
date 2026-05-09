---
session: 05
title: "varta-watch lifecycle (test-first): recovery + exporters + binary"
depends_on: [03]
touches:
  - "crates/varta-watch/src/recovery.rs"
  - "crates/varta-watch/src/exporter.rs"
  - "crates/varta-watch/src/config.rs"
  - "crates/varta-watch/src/lib.rs"
  - "crates/varta-watch/src/main.rs"
  - "crates/varta-watch/tests/**"
parallel_safe: true
produces:
  - "crates/varta-watch/src/recovery.rs"
  - "crates/varta-watch/src/exporter.rs"
  - "crates/varta-watch/src/config.rs"
  - "crates/varta-watch/src/main.rs"
  - "crates/varta-watch/tests/recovery_e2e.rs"
  - "crates/varta-watch/tests/exporter_endpoint.rs"
  - "crates/varta-watch/tests/cli_smoke.rs"
  - "docs/roadmap/varta-v0-1-0/session-05-handoff.md"
model: "opus"
---

# Session 05: recovery + exporter + watcher binary (test-first)

Paste this into a new Claude Code session:

```md
## Continuity
Continue from Session 03 artifacts. Read these BEFORE editing:
- `docs/acceptance/varta-v0-1-0.md` (Session 05 section — 6 tests across 3 files)
- `docs/roadmap/varta-v0-1-0/session-03-handoff.md` (Observer, Event, Tracker)
- `docs/claude-sessions/varta-v0-1-0/session-00-operator-rules.md` (TDD discipline)
- `crates/varta-watch/src/{observer.rs,tracker.rs,lib.rs}` (consume — DO NOT modify exports beyond appending new modules)

## Mission
Wire the observer's Event stream into actionable behavior — recovery_cmd execution, file + Prometheus exporters, and the runnable `varta-watch` binary — built test-first.

## Repository anchors
- `crates/varta-watch/tests/{recovery_e2e.rs,exporter_endpoint.rs,cli_smoke.rs}` (new) — contract tests S05
- `crates/varta-watch/src/{recovery.rs,exporter.rs,config.rs}` (new) — implementation modules
- `crates/varta-watch/src/lib.rs` (append `pub mod recovery; pub mod exporter; pub mod config;`)
- `crates/varta-watch/src/main.rs` (replace placeholder)

## Tasks
1. **Read contract.** Open `docs/acceptance/varta-v0-1-0.md`, copy the six S05 test names verbatim across the three test files.
2. **RED — write tests.**
   - `tests/recovery_e2e.rs`: `recovery_cmd_fires_once_per_stall_within_debounce` (configure `Recovery` with `recovery_cmd = "touch <marker>"`, debounce 1s; force two stalls within 500ms; assert marker exists exactly once); `recovery_cmd_template_substitutes_pid` (cmd = `"echo $$:{pid} >> <log>"`; assert log contains the right pid).
   - `tests/exporter_endpoint.rs`: `prom_exporter_reports_beats_total_per_pid`, `prom_exporter_reports_stalls_total_per_pid` (bind `PromExporter` on `127.0.0.1:0`, send beats, force a stall, GET `/metrics` over `TcpStream`, regex-assert `varta_beats_total{pid="..."} N` and `varta_stalls_total{pid="..."} M`); `file_exporter_appends_one_line_per_event` (record N events, read file, assert N lines + stable schema).
   - `tests/cli_smoke.rs`: `cli_help_lists_every_documented_flag` — spawn the compiled binary via `env!("CARGO_BIN_EXE_varta-watch")` with `--help`, assert stdout contains every flag string from `Config::from_args` help text.
3. **Capture RED.** Run `cargo test -p varta-watch 2>&1 | tail -30`. Expect compile errors. Save tail.
4. **GREEN — implement.**
   - `recovery.rs`: `pub struct Recovery { template: String, last_fired: HashMap<u32, Instant>, debounce: Duration }`; `pub fn on_stall(&mut self, pid: u32) -> RecoveryOutcome` substitutes `{pid}`, runs `Command::new("/bin/sh").arg("-c").arg(rendered).status()`. Outcome: `Spawned(ExitStatus) | Debounced | SpawnFailed(io::Error)`. HashMap is fine (cold path).
   - `exporter.rs`: `pub trait Exporter { fn record(&mut self, ev: &Event); fn flush(&mut self) -> io::Result<()>; }`. `FileExporter` appends one stable-schema line per Event. `PromExporter` binds `TcpListener::bind("127.0.0.1:port")`, `set_nonblocking(true)`; `pub fn serve_pending(&mut self) -> io::Result<()>` accepts ready connections and writes `HTTP/1.0 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n\r\n` + Prometheus body (`# HELP`, `# TYPE`, `varta_beats_total{pid="..."} N`, `varta_status{pid="..."} N`, `varta_stalls_total{pid="..."} N`). Maintain a `HashMap<u32, GaugeRow>`.
   - `config.rs`: `pub struct Config { socket: PathBuf, threshold: Duration, recovery_cmd: Option<String>, recovery_debounce: Duration, file_export: Option<PathBuf>, prom_addr: Option<SocketAddr>, shutdown_after: Option<Duration> }`. `pub fn from_args(args: impl Iterator<Item=String>) -> Result<Config, ConfigError>` parsing `--socket`, `--threshold-ms`, `--recovery-cmd`, `--recovery-debounce-ms`, `--export-file`, `--prom-addr`, `--shutdown-after-secs`, `--help`. Hand-rolled, no `clap`.
   - `main.rs`: parse argv → construct Observer + optional Recovery + exporters, run poll loop. On SIGINT use a static `AtomicBool` flag (no `signal_hook`); test fixtures use `--shutdown-after-secs`.
5. **Capture GREEN.** Re-run `cargo test -p varta-watch 2>&1 | tail -30`. All six S05 tests pass. Save tail.
6. **Refactor + gate.** `cargo fmt`, `cargo clippy -p varta-watch --all-targets -- -D warnings`. Re-run tests. Verify `cargo run -p varta-watch -- --help` exits 0 and lists every flag.

## Quality gates
- `cargo fmt --all -- --check`
- `cargo clippy -p varta-watch --all-targets -- -D warnings`
- `RUSTFLAGS="-D warnings" cargo test -p varta-watch`
- `cargo build -p varta-watch --release`
- Verify `[dependencies]` still empty in `crates/varta-watch/Cargo.toml`.

## Deliverables
- Files under `produces:` above.
- Handoff with TDD ledger (RED + GREEN tails), full CLI flag table, exporter wire format, debounce semantics, file paths Session 06 needs.

## Exit criteria
- All six S05 acceptance tests pass; debounce verified by counting marker creations.
- `/metrics` returns parseable Prometheus text (regex-asserted in tests).
- TDD ledger captures compile-error RED → all-pass GREEN.
```
