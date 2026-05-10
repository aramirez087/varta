---
session: 05
title: "CI gate — full workspace verification"
depends_on: [1, 2, 3, 4]
touches:
  - "docs/roadmap/recovery-async-spawn/**"
  - "crates/**"
  - "docs/**"
  - "README.md"
parallel_safe: false
produces:
  - "docs/roadmap/recovery-async-spawn/session-05-handoff.md"
skip_deliverables_check: true
model: "opus"
---

# Session 05 — CI gate

```md
Continue from Session 01, 02, 03, 04 artifacts in
docs/roadmap/recovery-async-spawn/.

Mission: prove the epic is shippable. Run the full CI checklist and iterate
until every command exits clean. Fix forward; do not paper over failures.

Repository anchors:
- crates/varta-watch/src/recovery.rs
- crates/varta-watch/src/config.rs
- crates/varta-watch/src/main.rs
- crates/varta-watch/tests/recovery_e2e.rs
- crates/varta-watch/tests/cli_smoke.rs
- crates/varta-tests/tests/end_to_end.rs
- .github/workflows/ci.yml (mirror its commands locally)

Tasks:
1. Run, in order, and resolve every failure:
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo build --workspace`
   - `cargo build --workspace --release`
   - `cargo test --workspace --lib`
   - `cargo test -p varta-vlp`
   - `cargo test -p varta-client`
   - `cargo test -p varta-watch`
   - `cargo test -p varta-tests --test end_to_end`
   - `cargo run -p varta-bench --release -- latency` (smoke; check it
     completes — do not commit numbers).
2. If a fix is required, contain it to the minimum viable change and log
   the bug to `.wolf/buglog.json`.
3. Verify the blocker is actually fixed end-to-end: run varta-watch with
   `--recovery-cmd 'sleep 3' --recovery-timeout-ms 500 --threshold-ms 100
   --shutdown-after-secs 4 --prom-addr 127.0.0.1:0` against a manual
   beat-then-stall scenario; confirm `/metrics` (or its tracker logs) keep
   serving while the recovery child sleeps, and that the child is killed
   after 500ms. Document the procedure in the handoff.
4. Spot-check that the existing acceptance contract names from
   docs/acceptance/varta-v0-1-0.md (Sessions 02–07) are still present in
   the test files — the CI workflow greps them.

Deliverables:
- docs/roadmap/recovery-async-spawn/session-05-handoff.md containing:
  - copy of every command + a single-line PASS/FAIL per command,
  - go / no-go verdict for merging into trunk,
  - any follow-up issues queued for a future epic (do NOT fix scope creep
    here; record and move on).

Quality gates (the session itself):
- All commands listed in Task 1 must exit 0.
- No new dependencies appear in any production Cargo.toml.

Exit criteria: every gate is green and the handoff records the verdict.
```
