---
session: 08
title: "CI gate: full workspace verification + release readiness report"
depends_on: [01, 02, 03, 04, 05, 06, 07]
touches:
  - ".github/workflows/**"
  - "docs/release/**"
parallel_safe: false
produces:
  - ".github/workflows/ci.yml"
  - "docs/release/v0.1.0-readiness.md"
  - "docs/roadmap/varta-v0-1-0/session-08-handoff.md"
model: "opus"
---

# Session 08: CI gate + release readiness

Paste this into a new Claude Code session:

```md
## Continuity
Continue from Sessions 01-07. Read these BEFORE acting:
- `docs/roadmap/varta-v0-1-0/session-01-handoff.md` … `session-07-handoff.md` (every prior outcome)
- `docs/claude-sessions/varta-v0-1-0/session-00-operator-rules.md` (constraints to enforce)
- `docs/benchmarks/results.md` (measured success metrics)

## Mission
Run the full workspace verification suite, fix any defect that surfaces, codify the gate as a GitHub Actions workflow, and write a go/no-go release readiness report for v0.1.0.

## Repository anchors
- `.github/workflows/ci.yml` (new) — runs every gate below on push/PR
- `docs/release/v0.1.0-readiness.md` (new) — go/no-go report
- Source files across `crates/**` may be touched ONLY to fix gate failures; record every fix in the handoff with rationale.

## Tasks
1. Execute the full gate locally and capture every output. If any command fails, fix the underlying defect (do not relax the gate). Re-run until green.
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   - `cargo clippy --workspace --all-targets --no-default-features -- -D warnings`
   - `RUSTFLAGS="-D warnings" cargo test --workspace --all-features`
   - `cargo test --doc --workspace --all-features`
   - `cargo build --workspace --release`
   - `cargo build --workspace --examples --all-features`
   - Zero-dep proof for production crates: for each of `varta-vlp`, `varta-client`, `varta-watch` run `awk '/^\[dependencies\]$/{f=1;next} /^\[/{f=0} f && NF{print "FAIL " FILENAME ": " $0; exit 1}' crates/<name>/Cargo.toml`.
   - Re-run `cargo run -p varta-bench --release -- latency`, `cpu-50-agents`, `binary-size`. Compare against `docs/benchmarks/results.md`. If a metric regressed >10% from session 06's recorded number, treat it as a gate failure.
   - **TDD ledger audit:** for each of `docs/roadmap/varta-v0-1-0/session-{01..06}-handoff.md`, grep that the file contains both a fenced `RED` block and a fenced `GREEN` block. Sessions 07 must contain the literal `n/a — docs-only session` ledger note. Failure → gate failure.
   - **Acceptance contract audit:** for every test name listed in `docs/acceptance/varta-v0-1-0.md`, grep that a `#[test] fn <name>` exists in the listed file. Missing tests → gate failure.
   - **Ignore audit:** `git grep -nE '^\s*#\[ignore' -- 'crates/**/tests/*.rs'` — every match must have an adjacent `// JUSTIFY:` comment within 2 lines, else gate failure.
2. `.github/workflows/ci.yml`: `name: ci`, triggers on push + pull_request, ubuntu-latest runner, steps: checkout, `dtolnay/rust-toolchain@stable` (with rustfmt + clippy), then each of the gate commands above as separate `run:` steps so failures localize. Add a final step `cargo run -p varta-bench --release -- latency` to keep perf visibility (but DO NOT fail CI on perf — record only; perf is verified locally per session 06).
3. `docs/release/v0.1.0-readiness.md`:
   - **Status:** GO / NO-GO with one-sentence justification.
   - **Gate matrix:** every command above with PASS/FAIL and timing.
   - **Success metrics:** measured vs target table (binary delta, beat() latency p50/p95/p99, observer CPU at 50 agents).
   - **Acceptance contract coverage:** N/N tests present and passing per session.
   - **TDD ledger audit:** confirmation that every implementation session shipped RED + GREEN blocks.
   - **Defects fixed in this session:** file:line + one-line root cause for each.
   - **Known limitations:** roadmap items deliberately deferred (no_std, visual CLI, eBPF) explicitly listed as "v0.1.0 NOT included".
   - **Sign-off checklist:** every item from Session 00's "definition of done" satisfied across the workspace.

## Quality gates
- Every command listed in Task 1 exits 0.
- `act -j ci` (if installed) or visual review of `.github/workflows/ci.yml` confirms all gate commands appear and ordering matches local execution.
- `docs/release/v0.1.0-readiness.md` contains GO and zero unchecked items in the sign-off checklist (else NO-GO with explicit reasons).

## Deliverables
- Files under `produces:` above.
- `docs/roadmap/varta-v0-1-0/session-08-handoff.md`: gate-by-gate summary, list of defects fixed (with diffs referenced by file:line), final go/no-go decision, hand-off to whoever cuts the v0.1.0 tag.

## Exit criteria
- All gates green from a clean clone (`cargo clean && <every gate>`).
- CI workflow file is syntactically valid YAML and references stable toolchain.
- Release readiness report is GO. If NO-GO, the report must enumerate every blocker with a clear owner and proposed next session.
```
