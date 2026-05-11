# Session 08 Handoff — Nits Cleanup Final CI Gate

## What landed

All 11 nits (n1–n11) addressed across sessions 02–07. Zero production deps introduced. Zero heap allocation on beat path preserved.

## Nit-by-nit verification matrix

| Nit | Status | Verification |
|-----|--------|-------------|
| n1 | PASS | Zero `.expect(` calls in Frame::decode (`crates/varta-vlp/src/lib.rs`) |
| n2 | PASS | `used: bool` field present on Slot (`crates/varta-watch/src/tracker.rs:37`) |
| n3 | PASS | `status_code` function deleted from `crates/varta-watch/src/exporter.rs` |
| n4 | PASS | `--read-timeout-ms` flag in Config HELP, from_args, tests (`crates/varta-watch/src/config.rs`) |
| n5 | PASS | `# Thread safety` section on Varta + `assert_send` static assertion (`crates/varta-client/src/client.rs:107`) |
| n6 | PASS | `405 Method Not Allowed` guard in `serve_one` + unit test (`crates/varta-watch/src/exporter.rs:270,530`) |
| n7 | PASS | "operates entirely on the stack" removed from panic.rs; reworded (`crates/varta-client/src/panic.rs:28-31`) |
| n8 | PASS | `fuzz/Cargo.toml` + `fuzz/fuzz_targets/frame_decode.rs` exist; workspace excludes fuzz |
| n9 | PASS | `macos-latest` in CI strategy matrix (`ci.yml:13`) |
| n10 | PASS | `tools/acceptance-contract.tsv` has 23 entries; audit reads from TSV (not inline heredoc) |
| n11 | PASS | `crates/varta-tests/src/` deleted; `cargo check -p varta-tests --tests` succeeds |

## Quality gates

| Gate | Result |
|------|--------|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | PASS |
| `cargo clippy --workspace --all-targets --no-default-features -- -D warnings` | PASS |
| `RUSTFLAGS="-D warnings" cargo test --workspace --all-features` | PASS (all 84 test functions) |
| `cargo test --doc --workspace --all-features` | PASS |
| `cargo build --workspace --release` | PASS |
| `cargo build --workspace --examples --all-features` | PASS |
| zero-dep audit (varta-vlp, client, watch) | PASS (empty [dependencies]) |
| acceptance contract audit (23 entries from TSV) | PASS |
| `cd fuzz && cargo +stable check` | PASS |

## Files changed

| File | Change |
|------|--------|
| `docs/architecture/nits-cleanup-decisions.md` | Created: 11 nit design decisions locked |
| `tools/acceptance-contract.tsv` | Created: 23-entry acceptance contract manifest |
| `docs/roadmap/nits-cleanup/session-01-handoff.md` | Created |
| `crates/varta-vlp/src/lib.rs` | n1: `.expect("len N")` → `.unwrap()` in Frame::decode |
| `fuzz/Cargo.toml` | Created: cargo-fuzz scaffold |
| `fuzz/fuzz_targets/frame_decode.rs` | Created: Frame::decode fuzz harness |
| `Cargo.toml` (root) | `exclude = ["fuzz"]` added |
| `.gitignore` | fuzz artifact paths added |
| `crates/varta-watch/src/tracker.rs` | n2: `used: bool` field on Slot; all scan loops gated |
| `crates/varta-watch/src/exporter.rs` | n3: `status_code` deleted, `s as u8` inline. n6: 405 method guard + test |
| `crates/varta-watch/src/config.rs` | n4: `--read-timeout-ms` flag, `read_timeout` field, HELP, tests |
| `crates/varta-watch/src/observer.rs` | n4: `read_timeout` parameter on `Observer::bind` |
| `crates/varta-watch/src/main.rs` | n4: wire `cfg.read_timeout` through |
| `crates/varta-watch/tests/acceptance.rs` | n4: pass `Duration::from_millis(100)` to all Observer::bind calls |
| `crates/varta-watch/tests/observer_lifecycle.rs` | n4: pass `Duration::from_millis(100)` to all Observer::bind calls |
| `crates/varta-client/src/client.rs` | n5: `# Thread safety` docs + `assert_send` static assertion |
| `crates/varta-client/src/panic.rs` | n7: rewrote allocation doc claim |
| `.github/workflows/ci.yml` | n9: macOS matrix; n10: acceptance audit reads from TSV |
| `crates/varta-tests/src/lib.rs` | n11: deleted |
| `crates/varta-tests/src/` | n11: deleted |

## Deviations from decisions doc

- n10 entry count: decisions doc says 22, actual count is 23. The original ci.yml inline contract also had 23 entries; the session text used an approximate count.