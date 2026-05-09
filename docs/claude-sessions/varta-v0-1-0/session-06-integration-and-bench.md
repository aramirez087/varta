---
session: 06
title: "End-to-end tests + benchmark assertions (test-first)"
depends_on: [04, 05]
touches:
  - "crates/varta-tests/**"
  - "crates/varta-bench/**"
  - "docs/benchmarks/**"
parallel_safe: true
produces:
  - "crates/varta-tests/Cargo.toml"
  - "crates/varta-tests/tests/end_to_end.rs"
  - "crates/varta-bench/Cargo.toml"
  - "crates/varta-bench/src/main.rs"
  - "docs/benchmarks/results.md"
  - "docs/roadmap/varta-v0-1-0/session-06-handoff.md"
model: "opus"
---

# Session 06: e2e + benchmark harness (test-first)

Paste this into a new Claude Code session:

```md
## Continuity
Continue from Sessions 04, 05 artifacts. Read these BEFORE editing:
- `docs/acceptance/varta-v0-1-0.md` (Session 06 section — 2 e2e tests + 3 bench assertions)
- `docs/roadmap/varta-v0-1-0/session-04-handoff.md`, `session-05-handoff.md`
- `docs/claude-sessions/varta-v0-1-0/session-00-operator-rules.md` (TDD discipline)
- `crates/varta-client/src/{client.rs,panic.rs}`, `crates/varta-watch/src/{config.rs,main.rs,exporter.rs}`

## Mission
Drive the full client → observer → stall → recovery loop end-to-end, and prove the three success metrics with a dependency-free benchmark harness. Both built test-first.

## Repository anchors
- `crates/varta-tests/Cargo.toml` (path deps on varta-client w/ panic-handler, varta-watch, varta-vlp)
- `crates/varta-tests/tests/end_to_end.rs` (new) — 2 contract tests
- `crates/varta-bench/Cargo.toml` (path deps on varta-client, varta-vlp)
- `crates/varta-bench/src/main.rs` (replace placeholder — three subcommands with hard-coded thresholds that fail when missed)
- `docs/benchmarks/results.md` (new)

## Tasks
1. **Read contract.** Open `docs/acceptance/varta-v0-1-0.md`, copy the two S06 e2e test names + the three bench assertion names verbatim.
2. **RED — write tests + bench assertions.**
   - `tests/end_to_end.rs`: `client_to_observer_to_recovery_full_loop` spawns `env!("CARGO_BIN_EXE_varta-watch")` with `--socket <tmp>.sock --threshold-ms 200 --recovery-cmd "touch <marker>" --recovery-debounce-ms 1000 --prom-addr 127.0.0.1:0 --shutdown-after-secs 5`, parses bound port from stdout banner (verify Session 05 prints it; if not, document the deviation), connects a `Varta`, beats 100×, sleeps 400ms, asserts marker appears within 2s, GETs `/metrics`, regex-asserts `varta_beats_total{pid="<n>"} 100`. `panic_handler_critical_beat_visible_in_metrics` spawns a child process via `Command::new(std::env::current_exe()).env("VARTA_E2E_PANIC_CHILD", path).spawn()`; the test binary's `main` detects that env var and runs the panic-child code path; parent asserts `/metrics` shows the Critical beat.
   - `bench/main.rs`: argv subcommands `latency`, `cpu-50-agents`, `binary-size`. Each computes a measurement and asserts it against the contract's threshold (`p99 < 1µs`, `cpu < 0.1%`, `delta < 20KB`). Failure → non-zero exit + stderr explaining the gap. `latency` uses one preallocated `Vec<u64>` (allocation outside the timing loop is documented harness scaffolding). `cpu-50-agents` uses `getrusage` via a single justified `extern "C"` block (`// SAFETY:` describes pointer + lifetime invariants). `binary-size` writes two fixture crates to a tempdir, builds both with `cargo build --release`, strips, diffs.
3. **Capture RED.** Run `cargo test -p varta-tests 2>&1 | tail -30` AND `cargo run -p varta-bench --release -- latency 2>&1 | tail -10`. Expect compile errors / threshold failures. Save both tails.
4. **GREEN — fill in.** Implement `crates/varta-tests/tests/end_to_end.rs` against the existing binaries (no production code changes — if a behavior is missing, escalate via handoff, do not add it here). Implement `crates/varta-bench/src/main.rs` subcommands. Tune the harness (warmup iterations, release mode, isolated tempdir) until the asserted thresholds hold on the host running the session.
5. **Capture GREEN.** Re-run all four invocations: `cargo test -p varta-tests`, `cargo run -p varta-bench --release -- latency`, `... cpu-50-agents`, `... binary-size`. Save tails. If any bench misses its threshold and the cause is host noise (not a code defect), document the measured number, tag the threshold with a `// HOST-DEPENDENT:` comment, and write `STATUS: WARN` in `docs/benchmarks/results.md` for that metric — do NOT relax the threshold silently.
6. **Refactor + gate.** `cargo fmt`, `cargo clippy -p varta-tests -p varta-bench --all-targets -- -D warnings`. Re-verify production crates `[dependencies]` still empty.

## Quality gates
- `cargo fmt --all -- --check`
- `cargo clippy -p varta-tests -p varta-bench --all-targets -- -D warnings`
- `RUSTFLAGS="-D warnings" cargo test -p varta-tests`
- `cargo run -p varta-bench --release -- latency` (exit 0 OR warn-documented)
- `cargo run -p varta-bench --release -- cpu-50-agents` (≤60s wall)
- `cargo run -p varta-bench --release -- binary-size`
- `awk` zero-dep check still passes for vlp/client/watch.

## Deliverables
- Files under `produces:` above.
- `docs/benchmarks/results.md`: per-metric measured value, threshold, PASS/WARN/FAIL, host info, exact commands.
- Handoff with TDD ledger (RED + GREEN tails for `cargo test -p varta-tests` AND for the bench harness), bench invocation cheat-sheet, any documented WARNs with root-cause analysis.

## Exit criteria
- Both e2e contract tests pass deterministically (bounded retries, no raw sleeps).
- Three bench assertions report PASS or WARN (with documented justification).
- TDD ledger captures RED → GREEN for both test and bench paths.
```
