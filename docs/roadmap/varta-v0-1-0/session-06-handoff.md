# Session 06 — Handoff (integration + bench)

## Done

- `crates/varta-tests/Cargo.toml` — added path-based `[dev-dependencies]`
  on `varta-vlp`, `varta-client` (with `panic-handler` feature), and
  `varta-watch`; declared the `end_to_end` test target with
  `harness = false`.
- `crates/varta-tests/tests/end_to_end.rs` — hand-rolled test runner
  (no libtest harness) that dispatches `VARTA_E2E_PANIC_CHILD` env-var
  re-entry for the panic-hook child path, then runs the two S06
  contract tests sequentially.
- `crates/varta-bench/Cargo.toml` — added path-based `[dependencies]` on
  `varta-vlp` and `varta-client`.
- `crates/varta-bench/src/main.rs` — three subcommands (`latency`,
  `cpu-50-agents`, `binary-size`) each computing one measurement and
  asserting it against the contract threshold. Single `extern "C" {}`
  block declaring `getrusage(2)` with two `// SAFETY:` comments naming
  the invariants upheld.
- `docs/benchmarks/results.md` — host info, per-metric measurements,
  PASS/WARN/FAIL status, exact reproduction commands.
- `docs/roadmap/varta-v0-1-0/session-06-handoff.md` — this file.

No production crate (`varta-vlp`, `varta-client`, `varta-watch`) was
modified. The `awk` zero-dep gate continues to report empty
`[dependencies]` on `varta-vlp` and `varta-client`; `varta-watch`
retains its single path-dep on `varta-vlp` from prior sessions.

## Decisions

- **D1 — `harness = false` for `end_to_end`.** The contract specifies
  `Command::new(std::env::current_exe()).env("VARTA_E2E_PANIC_CHILD",
  ...)` re-entry. With libtest, there is no place to intercept the
  env-var dispatch before the runner enumerates `#[test]` functions.
  Hand-rolled `fn main()` keeps the contract honoured. Test names appear
  as `fn <name>` declarations so the S08 grep gate recognises them.
- **D2 — Probe-port pattern for `--prom-addr`.** `varta-watch` does
  **not** print the bound Prometheus port to stdout in v0.1.0 (deviation
  from the operator plan's "parse port from banner" note). Per the
  no-production-edits rule we work around it: bind a `TcpListener` on
  `127.0.0.1:0`, capture `local_addr().port()`, drop the listener, and
  pass that port to `--prom-addr`. Tiny TOCTOU window on a non-hostile
  test host — see Open Issues #1.
- **D3 — Treat `BeatOutcome::Failed(_)` (ENOBUFS) as drop-equivalent.**
  On macOS, line-rate `send(2)` on a non-blocking UDS surfaces ENOBUFS
  ("No buffer space available", os error 55) once the kernel's small
  per-socket recv buffer fills. The client maps that into
  `BeatOutcome::Failed`, not `Dropped`. The full-loop test must observe
  exactly 100 beats in `/metrics`; we retry on `Failed(_)` and
  `Dropped` alike with a 500 µs back-off, capping at 5 000 retries.
  The retry budget is test-only — see Open Issues #2.
- **D4 — Latency drainer thread.** A background `UnixDatagram` listener
  recv-discards in a loop so the agent's `send(2)` returns `Ok(32)`
  rather than fighting kernel back-pressure. The drainer runs at
  identical priority to the agent thread, but the timing loop is
  process-local and does not include the drainer's CPU.
- **D5 — Latency harness scaffolding.** A single `Vec<u64>` is
  pre-allocated outside the timing loop and `push`-ed to inside it. The
  contract permits this scaffolding allocation (it is not part of the
  steady-state `beat()` path under measurement) and is documented
  inline.
- **D6 — `getrusage(RUSAGE_CHILDREN)` with `MaybeUninit::zeroed`.**
  Single justified `extern "C"` block, two `// SAFETY:` comments naming
  the invariants. The `Rusage` struct's leading two fields
  (`ru_utime`, `ru_stime`) are ABI-stable on Linux and macOS; the
  trailing `[u8; 144]` padding sizes the struct to cover the larger of
  the two ABIs and is explicitly zero-initialised so the
  `assume_init` path can never read uninitialised memory regardless of
  kernel behaviour.
- **D7 — `cpu-50-agents` waits for daemon termination.**
  `RUSAGE_CHILDREN` accounts for **terminated** children only. We bound
  the daemon at `--shutdown-after-secs 35` (slightly past the agents'
  30-second emit window), `Child::wait()` to reap, then snapshot.
- **D8 — `binary-size` fixture isolation.** Two ad-hoc cargo crates
  (`fix-empty`, `fix-client`) live under a session-private tempdir.
  Each gets `[workspace]` set to detach from the parent workspace, a
  per-fixture `CARGO_TARGET_DIR`, and a fixed release profile
  (`lto = false`, `codegen-units = 1`, `opt-level = 3`,
  `strip = false`) so the size comparison is reproducible.
  `strip` is invoked on the resulting binaries before measuring;
  `strip -x` is tried first (macOS) with a fallback to plain `strip`.
- **D9 — Panic-child sends one warmup beat.** The Critical frame
  emitted by the hook races process exit; the warmup `agent.beat(Ok)`
  guarantees the child's pid label exists in `/metrics` even if the
  Critical datagram is lost. The canonical assertion remains the
  Critical-status gauge (`varta_status{pid="<P>"} 2`) — the warmup is
  defence in depth.
- **D10 — Cross-crate binary lookup via `current_exe`.**
  `env!("CARGO_BIN_EXE_varta-watch")` is only set for tests in the same
  crate as the binary, so we resolve `target/<profile>/varta-watch`
  relative to `std::env::current_exe()` at runtime. Tests panic with a
  clear message if the binary is missing — `cargo test --workspace`
  builds it as part of the same invocation, so the lookup succeeds.

## TDD ledger

### RED — `cargo test -p varta-tests`

```text
$ cargo test -p varta-tests 2>&1 | tail -30
   Compiling varta-vlp v0.1.0 (.../crates/varta-vlp)
   Compiling varta-tests v0.1.0 (.../crates/varta-tests)
   Compiling varta-client v0.1.0 (.../crates/varta-client)
   Compiling varta-watch v0.1.0 (.../crates/varta-watch)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.30s
     Running unittests src/lib.rs (target/debug/deps/varta_tests-...)
     Running tests/end_to_end.rs (target/debug/deps/end_to_end-...)
running 2 tests
test client_to_observer_to_recovery_full_loop ... starting

thread 'main' (...) panicked at crates/varta-tests/tests/end_to_end.rs:107:5:
client_to_observer_to_recovery_full_loop unimplemented
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test client_to_observer_to_recovery_full_loop ... FAILED
test panic_handler_critical_beat_visible_in_metrics ... starting

thread 'main' (...) panicked at crates/varta-tests/tests/end_to_end.rs:114:5:
panic_handler_critical_beat_visible_in_metrics unimplemented
test panic_handler_critical_beat_visible_in_metrics ... FAILED

test result: FAILED. 0 passed; 2 failed; 0 ignored
error: test failed, to rerun pass `-p varta-tests --test end_to_end`
```

### RED — `cargo run -p varta-bench --release -- latency`

```text
$ cargo run -p varta-bench --release -- latency 2>&1 | tail -10
   Compiling varta-vlp v0.1.0 (.../crates/varta-vlp)
   Compiling varta-client v0.1.0 (.../crates/varta-client)
   Compiling varta-bench v0.1.0 (.../crates/varta-bench)
    Finished `release` profile [optimized] target(s) in 0.15s
     Running `target/release/varta-bench latency`
varta-bench: latency subcommand unimplemented
```

(Process exited with code 1.)

### GREEN — `cargo test -p varta-tests`

```text
$ cargo test -p varta-tests 2>&1 | tail -20
     Running unittests src/lib.rs (target/debug/deps/varta_tests-...)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/end_to_end.rs (target/debug/deps/end_to_end-...)
running 2 tests
test client_to_observer_to_recovery_full_loop ... starting
test client_to_observer_to_recovery_full_loop ... ok
test panic_handler_critical_beat_visible_in_metrics ... starting
test panic_handler_critical_beat_visible_in_metrics ... ok

test result: ok. 2 passed; 0 failed; 0 ignored
   Doc-tests varta_tests

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### GREEN — bench harness (all three subcommands)

```text
$ cargo run -p varta-bench --release -- latency 2>&1 | tail -10
    Finished `release` profile [optimized] target(s) in 0.00s
     Running `target/release/varta-bench latency`
latency: iters=1000000 p50=584ns p99=916ns p99.9=1042ns threshold=1000ns
bench_latency_p99_under_one_microsecond: PASS (p99=916ns)

$ cargo run -p varta-bench --release -- binary-size 2>&1 | tail -10
     Running `target/release/varta-bench binary-size`
   Compiling fix-empty v0.0.1 (/var/folders/.../fix-empty)
    Finished `release` profile [optimized] target(s) in 0.08s
     Locking 2 packages to latest compatible versions
   Compiling varta-vlp v0.1.0 (.../crates/varta-vlp)
   Compiling varta-client v0.1.0 (.../crates/varta-client)
   Compiling fix-client v0.0.1 (/var/folders/.../fix-client)
    Finished `release` profile [optimized] target(s) in 0.15s
binary-size: empty=361848B with-client=365720B delta=3872B threshold=20480B stripped=true
bench_binary_size_delta_under_twenty_kilobytes: PASS (delta=3KB)

$ cargo run -p varta-bench --release -- cpu-50-agents 2>&1 | tail -10
    Finished `release` profile [optimized] target(s) in 0.00s
     Running `target/release/varta-bench cpu-50-agents`
cpu-50-agents: daemon_cpu_ns=19367000 wall_ns=35090686083 cpu_pct=0.0552 threshold=0.1000%
bench_observer_cpu_under_zero_point_one_percent: PASS (0.0552%)
```

## Bench invocation cheat-sheet

```bash
# Build the workspace once so target/release/varta-watch exists.
cargo build --workspace --release

# Three contract assertions (in order of wall cost):
cargo run -p varta-bench --release -- latency        # ~1 s wall
cargo run -p varta-bench --release -- binary-size    # ~5 s wall (rebuilds two fixtures)
cargo run -p varta-bench --release -- cpu-50-agents  # ~35 s wall (50 agents × 30 × 1 Hz)
```

The harness assert thresholds are encoded as `const` values at the top
of `crates/varta-bench/src/main.rs`:

- `LATENCY_P99_NS_THRESHOLD = 1_000`
- `CPU_THRESHOLD_PCT = 0.1`
- `BINARY_DELTA_BYTES_THRESHOLD = 20 * 1024`

Failure prints the measured value to stderr and exits non-zero.

## Quality gate results

- `cargo fmt --all -- --check` → clean.
- `cargo clippy -p varta-tests -p varta-bench --all-targets -- -D warnings` → clean.
- `RUSTFLAGS="-D warnings" cargo test -p varta-tests` → 2 / 2 pass.
- `cargo run -p varta-bench --release -- latency` → exit 0.
- `cargo run -p varta-bench --release -- cpu-50-agents` → exit 0 (~35 s).
- `cargo run -p varta-bench --release -- binary-size` → exit 0.
- `cargo test --workspace` → 0 failures across all crates.
- `awk` zero-dep check: `varta-vlp` and `varta-client` `[dependencies]`
  empty; `varta-watch` retains the single path-dep on `varta-vlp`
  carried from prior sessions.

## Open issues

1. **D-S05-banner — `varta-watch` does not print the bound Prom port.**
   The original Session 06 plan assumed
   `crates/varta-watch/src/main.rs` would print a `bound 127.0.0.1:<P>`
   banner to stdout that the e2e tests could parse. The existing daemon
   (Session 05) does not print one (`crates/varta-watch/src/main.rs:30`,
   right where a future banner would live). The e2e tests work around
   this with the probe-port pattern (D2). A future v0.1.x session
   should print the banner so consumers don't need TOCTOU port-probing.
2. **D-ENOBUFS-not-classified-as-Dropped.** The `varta-client::beat()`
   classifier in `crates/varta-client/src/client.rs:103-110` does not
   include `io::ErrorKind::Other` (which is what ENOBUFS becomes on
   macOS). For the contract's exact-100 count assertion we retry on
   `Failed(_)` in the test, but a future v0.1.x session may want to
   widen the classifier so production agents do not surface this kernel
   transient as `Failed`. The fix is one line at
   `crates/varta-client/src/client.rs:104`.
3. **No production code edits in S06.** Per operator rules, all
   workarounds for the two issues above live in `varta-tests`. No
   `varta-vlp`, `varta-client`, or `varta-watch` files were touched.

## Next-session inputs

Session 07 (docs polish + examples) MUST read:

- `docs/acceptance/varta-v0-1-0.md` (Session 07 section).
- `docs/roadmap/varta-v0-1-0/session-06-handoff.md` (this file).
- `docs/benchmarks/results.md` (per-metric numbers to reference in
  README).
- `crates/varta-client/src/lib.rs` (public facade — what to document
  on the client side).
- `crates/varta-watch/src/lib.rs` (re-exports).
- `crates/varta-bench/src/main.rs` (subcommand invocation surface to
  document in README).
- `crates/varta-tests/tests/end_to_end.rs` (the canonical example of
  how to drive the full stack — useful for example code).

Session 08 (CI gate) MUST read:

- This handoff for the TDD ledger pattern (RED + GREEN tails) it must
  grep-validate.
- All five `[ ]/[ ]` files under `crates/varta-{tests,bench}/` for the
  contract test names (`fn <name>`) it must locate.
