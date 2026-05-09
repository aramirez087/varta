# Session 05 — Handoff (Recovery, Exporters, Binary Surface)

## Done

- `crates/varta-watch/src/lib.rs` — appended `pub mod {config, exporter,
  recovery};` and re-exports for `Config`, `ConfigError`, `Exporter`,
  `FileExporter`, `PromExporter`, `Recovery`, `RecoveryOutcome`. Existing
  `Observer`/`Tracker`/etc. exports left untouched.
- `crates/varta-watch/src/config.rs` — hand-rolled GNU-style argv parser,
  `Config` struct, `ConfigError` enum, single-source-of-truth `Config::HELP`
  constant, six in-module unit tests.
- `crates/varta-watch/src/recovery.rs` — `Recovery` runner with per-pid
  `HashMap<u32, Instant>` debounce, `{pid}` template substitution,
  `/bin/sh -c` spawn via `Command::status()`, `RecoveryOutcome` enum,
  three in-module unit tests.
- `crates/varta-watch/src/exporter.rs` — `Exporter` trait, `FileExporter`
  (BufWriter, tab-separated stable schema), `PromExporter` (non-blocking
  TCP listener, poll-driven `serve_pending`, HTTP/1.0 + Prometheus text
  body, deterministic per-pid sort), two in-module unit tests.
- `crates/varta-watch/src/main.rs` — daemon entry point: parse argv →
  bind observer → install optional `Recovery` + `FileExporter` +
  `PromExporter` → run a single-threaded poll/dispatch loop honouring
  `--shutdown-after-secs` and a static `AtomicBool` (no signal hook —
  see Open issues).
- `crates/varta-watch/tests/recovery_e2e.rs` — two S05 contract tests
  verbatim per `docs/acceptance/varta-v0-1-0.md`.
- `crates/varta-watch/tests/exporter_endpoint.rs` — three S05 contract
  tests verbatim, with a synchronous `http_get` helper that drives
  `serve_pending` from the test thread.
- `crates/varta-watch/tests/cli_smoke.rs` — one S05 contract test
  spawning the compiled binary via `env!("CARGO_BIN_EXE_varta-watch")`.
- `docs/roadmap/varta-v0-1-0/session-05-handoff.md` — this file.

`crates/varta-watch/Cargo.toml` is intentionally unmodified; the only
inter-crate dep remains `varta-vlp = { path = "../varta-vlp" }`.

## Decisions

- **D1 — `Recovery` uses `HashMap<u32, Instant>` for per-pid debounce.**
  Recovery is the cold path; the hash-table allocation cost is
  acceptable per the operator rules (`HashMap is fine (cold path)`).
- **D2 — `Recovery::on_stall` returns `RecoveryOutcome` instead of
  `Result`.** `Debounced` and `SpawnFailed(_)` are both legitimate runtime
  outcomes; the daemon main loop logs each without treating either as
  fatal.
- **D3 — `{pid}` substitution is a literal `str::replace`.** The shell
  is `/bin/sh -c <rendered>`, so the user-supplied template owns
  quoting. Documenting `{pid}` as the only substitution token in
  `Config::HELP` prevents future feature creep into a templating
  language.
- **D4 — Exporters live as `Option<FileExporter>` / `Option<PromExporter>`
  in `main`, not behind `Box<dyn Exporter>`.** Avoids a startup heap
  allocation and lets `serve_pending()` (Prom-only) stay off the trait.
- **D5 — `PromExporter` is poll-driven, not threaded.** `serve_pending()`
  drains the listener's accept queue each main-loop tick. No background
  thread, no `Mutex`, single-threaded everywhere.
- **D6 — `PromExporter` reads the request until `\r\n\r\n` (4 KiB cap)
  then unconditionally responds 200 + metrics.** `/metrics` is the only
  endpoint; the path is not parsed.
- **D7 — Counter aggregation lives inside `PromExporter::record`.**
  `FileExporter::record` only writes a line. This separation matches the
  contract (file → "one line per event"; prom → "totals").
- **D8 — `Config::from_args` is hand-rolled, GNU long-flag style.** All
  eight flags listed in the CLI table below are parsed directly; no
  `clap`. `Config::HELP` is the single source of truth read by both
  `--help` and `cli_help_lists_every_documented_flag`.
- **D9 — No SIGINT handler in v0.1.0.** Std-only signal install is not
  feasible without `libc`/`signal-hook`; the static `SHUTDOWN: AtomicBool`
  is wired so a future signal hook can flip it. Tests use
  `--shutdown-after-secs` exclusively (see Open issues R10).
- **D10 — Prometheus tests bind on `127.0.0.1:0` and discover the
  kernel-assigned port via `local_addr()`.** No fixed-port collisions
  between parallel test runs.
- **D11 — Recovery tests mint per-test temp paths under
  `std::env::temp_dir()` with a process-pid + atomic-counter suffix and
  remove them via an RAII `TempPath` guard on drop.** Mirrors the
  Session 03 UDS helper.
- **D12 — `cli_smoke.rs` uses `env!("CARGO_BIN_EXE_varta-watch")`.**
  Cargo provides this env var to integration tests in the same crate as
  a binary, side-stepping `target/debug` path-mangling.
- **D13 — `FileExporter::record` is best-effort (write errors are
  swallowed) but `flush()` surfaces them.** Keeps the daemon poll loop
  off the panic path; transient IO errors get reported at flush time.
- **D14 — `PromExporter` body is `\n`-separated, headers are `\r\n`.**
  Prometheus text format expects `\n`; HTTP framing expects `\r\n`.
- **D15 — Per-pid order in the Prom body is numerically sorted.** Tests
  use `str::contains`, so order is not asserted; deterministic output
  simplifies debugging.
- **D16 — `--help` writes to stdout via `std::io::stdout().lock().write_all`
  rather than `println!`.** `#![forbid(clippy::print_stdout)]` lints the
  macros, not the `Write` trait, so this is the safe path.
- **D17 — Unit tests inside `config.rs`/`recovery.rs`/`exporter.rs` are
  in addition to the S05 contract.** They guard internal invariants
  (debounce per-pid, sort order, decode/io events not creating rows,
  full flag-surface parsing).
- **D18 — `Event::Decode`/`Event::Io` rows are `-`-padded in the file
  schema and are no-ops in the Prom counters.** Keeps the file schema
  rectangular and avoids polluting `varta_*_total{pid="..."}` rows with
  pid-less events.

## TDD ledger

### RED

```text
$ cargo test -p varta-watch 2>&1 | tail -30
  --> crates/varta-watch/src/lib.rs:11:1
   |
11 | pub mod config;
   | ^^^^^^^^^^^^^^^
   |
   = help: to create the module `config`, create file "crates/varta-watch/src/config.rs" or "crates/varta-watch/src/config/mod.rs"
   = note: if there is a `mod config` elsewhere in the crate already, import it with `use crate::...` instead

error[E0583]: file not found for module `exporter`
  --> crates/varta-watch/src/lib.rs:12:1
   |
12 | pub mod exporter;
   | ^^^^^^^^^^^^^^^^^
   |
   = help: to create the module `exporter`, create file "crates/varta-watch/src/exporter.rs" or "crates/varta-watch/src/exporter/mod.rs"
   = note: if there is a `mod exporter` elsewhere in the crate already, import it with `use crate::...` instead

error[E0583]: file not found for module `recovery`
  --> crates/varta-watch/src/lib.rs:14:1
   |
14 | pub mod recovery;
   | ^^^^^^^^^^^^^^^^^
   |
   = help: to create the module `recovery`, create file "crates/varta-watch/src/recovery.rs" or "crates/varta-watch/src/recovery/mod.rs"
   = note: if there is a `mod recovery` elsewhere in the crate already, import it with `use crate::...` instead

For more information about this error, try `rustc --explain E0583`.
error: could not compile `varta-watch` (lib) due to 3 previous errors
warning: build failed, waiting for other jobs to finish...
error: could not compile `varta-watch` (lib test) due to 3 previous errors
```

### GREEN

```text
$ cargo test -p varta-watch 2>&1 | tail -30
test observer_reports_decode_error_for_bad_magic ... ok
test observer_emits_stall_after_threshold_elapses ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.52s


running 1 test
test cli_help_lists_every_documented_flag ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.30s


running 3 tests
test file_exporter_appends_one_line_per_event ... ok
test prom_exporter_reports_beats_total_per_pid ... ok
test prom_exporter_reports_stalls_total_per_pid ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 2 tests
test recovery_cmd_template_substitutes_pid ... ok
test recovery_cmd_fires_once_per_stall_within_debounce ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Test totals (S05 only):
- `tests/recovery_e2e.rs` — 2 contract tests passing.
- `tests/exporter_endpoint.rs` — 3 contract tests passing.
- `tests/cli_smoke.rs` — 1 contract test passing.
- In-module unit tests — 11 (6 config + 3 recovery + 2 exporter) passing.

Workspace-wide sweep at end of session: all crates green
(`cargo test --workspace` → 0 failures across vlp, client, watch, tests,
bench).

## Wire formats (frozen this session)

### `FileExporter` line schema

One line per event, `\n`-terminated, tab-separated:

```text
<observer_ns>\t<kind>\t<pid>\t<nonce>\t<status>\t<payload>\n
```

- `kind ∈ {beat, stall, decode, io}`.
- For `decode`/`io` events the `pid`/`nonce`/`status`/`payload` columns
  are `-` so the column count stays rectangular.
- `status` is the lowercase debug name (`ok|degraded|critical|stall`).
- `observer_ns` is the elapsed nanoseconds since the `FileExporter` was
  created, snapshotted at `record()` time. The `Event` enum carries no
  per-event timestamp.

### `PromExporter` HTTP/Prometheus framing

Response bytes (single `write_all`):

```text
HTTP/1.0 200 OK\r\n
Content-Type: text/plain; version=0.0.4\r\n
Content-Length: <N>\r\n
Connection: close\r\n
\r\n
<body>
```

Body (lines `\n`-separated, pids sorted ascending):

```text
# HELP varta_beats_total Total accepted beats per agent pid.
# TYPE varta_beats_total counter
varta_beats_total{pid="<P>"} <N>
# HELP varta_stalls_total Total observer-detected stalls per agent pid.
# TYPE varta_stalls_total counter
varta_stalls_total{pid="<P>"} <M>
# HELP varta_status Last reported status code per agent pid (0=ok,1=degraded,2=critical,3=stall).
# TYPE varta_status gauge
varta_status{pid="<P>"} <S>
```

`varta_status` rows are emitted only for pids that have produced at
least one `Event::Beat` or `Event::Stall`.

## CLI flag table

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--socket <PATH>` | path | (required) | Bind the observer's UDS at this path. |
| `--threshold-ms <MS>` | u64 ms | (required) | Per-pid silence window before stall surfaces. |
| `--recovery-cmd <TEMPLATE>` | string | none | Shell fragment run on each unique stall (`{pid}` substituted). |
| `--recovery-debounce-ms <MS>` | u64 ms | `1000` | Per-pid debounce window for recovery invocations. |
| `--export-file <PATH>` | path | none | Append one event-line per record to this file. |
| `--prom-addr <IP:PORT>` | `SocketAddr` | none | Bind the Prometheus `/metrics` endpoint here. |
| `--shutdown-after-secs <SECS>` | u64 secs | none | Exit cleanly after the given uptime. |
| `-h`, `--help` | flag | — | Print help to stdout and exit 0. |

## Debounce semantics

- `Recovery` keys debounce state by pid (`HashMap<u32, Instant>`).
- The window starts on the previous `Spawned` *or* `SpawnFailed`
  outcome — both consume the per-pid slot. `Debounced` does not reset
  the clock.
- Distinct pids are independent; two pids may fire within a single
  window without suppressing one another.
- A `Debounced` outcome is not a failure — the daemon does not log it
  to stderr.
- When a pid recovers (a fresh `Event::Beat` arrives, the tracker
  clears `stall_emitted`, and the next stall fires a new event), the
  `Recovery` runner sees an entirely separate `on_stall(pid)` call;
  the prior `last_fired` entry remains and the next call is debounced
  iff it falls inside the still-active window.

## Open issues

- **R1 — "Empty `[dependencies]`" rule (carried from Session 03).**
  `crates/varta-watch/Cargo.toml:8` violates the literal reading of the
  operator mandate by carrying `varta-vlp = { path = "../varta-vlp" }`.
  Session 01's handoff and Session 03's handoff both adopted the
  interpretation "no registry deps", and Session 08's CI gate must
  encode that explicitly.
- **R10 — No SIGINT handler.** Std-only signal install is not feasible
  without `libc`/`signal-hook`. The daemon shuts down only on
  `--shutdown-after-secs`. The static `SHUTDOWN: AtomicBool` lives at
  `crates/varta-watch/src/main.rs:30` and is wired into the loop check;
  a future hook can flip it without touching the loop. v0.2 work.
- **`Recovery::on_stall` blocks the poll loop while `/bin/sh -c` runs.**
  Cold path by construction (`crates/varta-watch/src/recovery.rs:62`),
  but a runaway recovery script will stall stall detection. Documented
  on the public API; v0.2 may move to spawn+wait-async.
- **`Event` carries no timestamp**, so `FileExporter` synthesises one
  per-record. Cross-exporter timestamp comparison is meaningless. If
  Session 06's e2e harness wants a single observer clock, surface
  `last_ns` more consistently in the `Event` variants.

## Quality gate results

- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p varta-watch --all-targets -- -D warnings` — clean.
- `RUSTFLAGS="-D warnings" cargo test -p varta-watch` — 22 passed,
  0 failed (4 S03 acceptance + 6 S05 acceptance + 11 unit + 1 doctest).
- `cargo build -p varta-watch --release` — clean.
- `cargo run -p varta-watch -- --help` — exit 0, prints all flags.
- `cargo test --workspace` — all crates green, 0 failures.
- `crates/varta-watch/Cargo.toml [dependencies]` — unchanged; only
  `varta-vlp` path-dep present.

## Next-session inputs

Session 06 (end-to-end + bench harness) MUST read:

- `docs/acceptance/varta-v0-1-0.md` (Session 06 section — five tests).
- `docs/claude-sessions/varta-v0-1-0/session-00-operator-rules.md`.
- `docs/roadmap/varta-v0-1-0/session-05-handoff.md` (this file).
- `crates/varta-watch/src/lib.rs` (current re-exports — `Config`,
  `Recovery`, `RecoveryOutcome`, `FileExporter`, `PromExporter`,
  `Exporter`).
- `crates/varta-watch/src/config.rs` (`Config::from_args`,
  `Config::HELP`, all flag names).
- `crates/varta-watch/src/recovery.rs` (`Recovery::new`,
  `Recovery::on_stall`, `RecoveryOutcome` variants).
- `crates/varta-watch/src/exporter.rs` (`Exporter` trait,
  `FileExporter::create`, `PromExporter::bind`,
  `PromExporter::local_addr`, `PromExporter::serve_pending`).
- `crates/varta-watch/src/main.rs` (daemon entry point — argv layout,
  shutdown semantics).
- `crates/varta-watch/tests/exporter_endpoint.rs` (synchronous
  `http_get` helper pattern — Session 06 will need similar plumbing).
- The compiled binary path: `env!("CARGO_BIN_EXE_varta-watch")` from
  any integration test in a crate that names `varta-watch` as a binary
  dep, or `cargo run -p varta-watch --` from a parent process spawn.
- `crates/varta-client/src/{lib.rs,client.rs}` (the client API the e2e
  harness drives against the observer).
