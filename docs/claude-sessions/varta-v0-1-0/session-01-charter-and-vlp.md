---
session: 01
title: "Charter: workspace, acceptance contract, complete VLP (test-first)"
depends_on: []
touches:
  - "Cargo.toml"
  - "rust-toolchain.toml"
  - "crates/**"
  - "docs/architecture/**"
  - "docs/acceptance/**"
  - "docs/roadmap/varta-v0-1-0/**"
parallel_safe: false
produces:
  - "Cargo.toml"
  - "rust-toolchain.toml"
  - "crates/varta-vlp/Cargo.toml"
  - "crates/varta-vlp/src/lib.rs"
  - "crates/varta-vlp/tests/frame.rs"
  - "crates/varta-client/Cargo.toml"
  - "crates/varta-client/src/lib.rs"
  - "crates/varta-watch/Cargo.toml"
  - "crates/varta-watch/src/lib.rs"
  - "crates/varta-watch/src/main.rs"
  - "crates/varta-tests/Cargo.toml"
  - "crates/varta-tests/src/lib.rs"
  - "crates/varta-bench/Cargo.toml"
  - "crates/varta-bench/src/main.rs"
  - "docs/architecture/vlp-frame.md"
  - "docs/acceptance/varta-v0-1-0.md"
  - "docs/roadmap/varta-v0-1-0/session-01-handoff.md"
model: "opus"
---

# Session 01: Charter — workspace + acceptance contract + test-first VLP

Paste this into a new Claude Code session:

```md
## Mission
Bootstrap the Varta workspace, publish the authoritative acceptance contract before any production code, and ship the `varta-vlp` protocol crate built test-first (RED → GREEN → Refactor).

## Repository anchors
- `Cargo.toml`, `rust-toolchain.toml` (new)
- `crates/varta-vlp/{Cargo.toml,src/lib.rs,tests/frame.rs}` (new, COMPLETE)
- `crates/varta-{client,watch,tests,bench}/...` (new, skeletons only)
- `docs/architecture/vlp-frame.md`, `docs/acceptance/varta-v0-1-0.md` (new)
- Read `docs/claude-sessions/varta-v0-1-0/session-00-operator-rules.md` first (constraints + TDD discipline).

## Tasks
1. Workspace `Cargo.toml` (`resolver = "2"`, members: vlp/client/watch/tests/bench), `rust-toolchain.toml` (channel = "stable", components = rustfmt + clippy).
2. **Acceptance contract.** Author `docs/acceptance/varta-v0-1-0.md`. Read every sibling session prompt under `docs/claude-sessions/varta-v0-1-0/session-{02..06}-*.md`. For each, extract the headline behaviors and produce one `##` section per session containing a markdown table `| Test name | File | Behavior |`. Aim 3-6 tests per session. Required test names per session (use these exact identifiers — downstream sessions match them):
   - **S02:** `connect_succeeds_when_observer_socket_exists`, `beat_emits_canonical_32_byte_frame`, `beat_increments_nonce_monotonically`, `beat_returns_dropped_when_observer_absent` (in `crates/varta-client/tests/acceptance.rs`); `beat_makes_zero_heap_allocations_after_init` (in `crates/varta-client/tests/zero_alloc.rs`).
   - **S03:** `observer_emits_beat_per_received_frame`, `observer_emits_stall_after_threshold_elapses`, `observer_reports_decode_error_for_bad_magic`, `tracker_capacity_bounded_to_64_pids` (in `crates/varta-watch/tests/acceptance.rs`).
   - **S04:** `panic_handler_emits_critical_beat_before_unwind`, `panic_handler_preserves_original_panic_outcome`, `panic_module_excluded_without_feature` (in `crates/varta-client/tests/panic_feature.rs`).
   - **S05:** `recovery_cmd_fires_once_per_stall_within_debounce`, `recovery_cmd_template_substitutes_pid` (in `crates/varta-watch/tests/recovery_e2e.rs`); `prom_exporter_reports_beats_total_per_pid`, `prom_exporter_reports_stalls_total_per_pid`, `file_exporter_appends_one_line_per_event` (in `crates/varta-watch/tests/exporter_endpoint.rs`); `cli_help_lists_every_documented_flag` (in `crates/varta-watch/tests/cli_smoke.rs`).
   - **S06:** `client_to_observer_to_recovery_full_loop`, `panic_handler_critical_beat_visible_in_metrics` (in `crates/varta-tests/tests/end_to_end.rs`); plus three bench assertions documented as `bench_latency_p99_under_one_microsecond`, `bench_observer_cpu_under_zero_point_one_percent`, `bench_binary_size_delta_under_twenty_kilobytes`.
3. **Skeletons.** Create `crates/varta-vlp/Cargo.toml` (literal empty `[dependencies]`) plus minimal `src/lib.rs` containing only crate-root attrs (per Session 00) — NO `Frame`, NO `Status` yet. Same for `varta-client`, `varta-watch` (re-exports point at vlp items that don't exist yet — that's fine, they'll resolve in step 6). `varta-watch/src/main.rs`: `fn main() { eprintln!("varta-watch v0.1.0 — implemented in session 05"); }`. `varta-tests/src/lib.rs`, `varta-bench/src/main.rs` placeholders.
4. **RED.** Author `crates/varta-vlp/tests/frame.rs` with all VLP tests: golden-byte round-trip (assert exact 32 bytes for a known Frame), bad-magic + bad-version + bad-status rejection, every Status variant, payload preservation across `u64::MAX`, runtime size + alignment assertions. Run `cargo test -p varta-vlp 2>&1 | tail -30`. Confirm compile failure (Frame/Status missing). Save tail for handoff ledger as `RED`.
5. **GREEN.** Implement `crates/varta-vlp/src/lib.rs` per spec: `#[repr(C, align(8))] struct Frame { magic:[u8;2], version:u8, status:u8, pid:u32, timestamp:u64, nonce:u64, payload:u64 }`, `const _: () = assert!(size_of::<Frame>()==32 && align_of::<Frame>()==8);`, layout LE, `MAGIC = [0x56,0x41]`, `VERSION = 0x01`, `#[repr(u8)] enum Status { Ok=0, Degraded=1, Critical=2, Stall=3 }` + `try_from_u8`, `Frame::encode(&self,&mut [u8;32])`, `Frame::decode(&[u8;32]) -> Result<Frame, DecodeError>` validating magic/version/status, `enum DecodeError { BadMagic, BadVersion, BadStatus(u8) }` with `Display` + `core::error::Error`. Every public item rustdoc'd; every `unsafe` carries `// SAFETY:`. Re-run the same `cargo test` command. Save tail as `GREEN`.
6. **Refactor.** Run `cargo fmt`, `cargo clippy -p varta-vlp -- -D warnings`. Re-run tests. Then write `docs/architecture/vlp-frame.md`: ASCII byte-map, why `repr(C, align(8))`, why little-endian, why zero-dep.

## Quality gates
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `RUSTFLAGS="-D warnings" cargo test --workspace`
- `cargo build --workspace`
- For each of vlp/client/watch: `awk '/^\[dependencies\]$/{f=1;next} /^\[/{f=0} f && NF{print "EXTRA DEP:" $0; exit 1}' crates/<name>/Cargo.toml`

## Deliverables
- All paths under `produces:` above. The contract doc lists ≥21 acceptance tests.
- Handoff with TDD ledger (RED + GREEN tails for `cargo test -p varta-vlp`), file list, decisions, next-session inputs (paths to `Frame`, `Status`, contract).

## Exit criteria
- Contract doc exists; downstream sessions can grep their test names from it.
- VLP RED (compile error) and GREEN (all tests pass) outputs are both captured in the ledger.
- Three production crates have provably empty `[dependencies]`.
```
