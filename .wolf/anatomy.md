# anatomy.md

> Auto-maintained by OpenWolf. Last scanned: 2026-05-09T19:20:32.424Z
> Files: 57 tracked | Anatomy hits: 0 | Misses: 0

## ./

- `.gitignore` — Git ignore rules (~183 tok)
- `Cargo.toml` — Rust package manifest (~49 tok)
- `CLAUDE.md` — OpenWolf (~898 tok)
- `LICENSE` — Project license (~290 tok)
- `README.md` — Project documentation (~803 tok)
- `rust-toolchain.toml` (~25 tok)
- `skills-lock.json` (~70 tok)

## .agents/skills/rust-best-practices/

- `SKILL.md` — Rust Best Practices (~1085 tok)

## .agents/skills/rust-best-practices/references/

- `chapter_01.md` — Chapter 1 - Coding Styles and Idioms (~4315 tok)
- `chapter_02.md` — Chapter 2 - Clippy and Linting Discipline (~1363 tok)
- `chapter_03.md` — Chapter 3 - Performance Mindset (~2192 tok)
- `chapter_04.md` — Chapter 4 - Errors Handling (~1769 tok)
- `chapter_05.md` — Chapter 5 - Automated Testing (~3506 tok)
- `chapter_06.md` — Chapter 6 - Generics, Dynamic Dispatch and Static Dispatch (~1691 tok)
- `chapter_07.md` — Chapter 7 - Type State Pattern (~2055 tok)
- `chapter_08.md` — Chapter 8 - Comments vs Documentation (~2517 tok)
- `chapter_09.md` — Chapter 9 - Understanding Pointers (~2388 tok)

## .claude/

- `settings.json` (~441 tok)

## .claude/rules/

- `openwolf.md` (~313 tok)

## .github/workflows/

- `ci.yml` — /tests/*.rs' || true) (~1746 tok)

## crates/varta-bench/

- `Cargo.toml` — Rust package manifest (~89 tok)

## crates/varta-bench/src/

- `main.rs` — Varta performance harness. (~5680 tok)

## crates/varta-client/

- `Cargo.toml` — Rust package manifest (~122 tok)
- `README.md` — Project documentation (~848 tok)

## crates/varta-client/examples/

- `basic.rs` — Minimal Varta beat loop — connect once, emit `Status::Ok` every 500 ms. (~136 tok)
- `with_panic_handler.rs` — Demonstrates the opt-in panic handler. (~225 tok)
- `with_payload.rs` — Beat loop that packs queue depth and last error code into the 64-bit payload. (~277 tok)

## crates/varta-client/src/

- `client.rs` — Agent surface — `Varta` connects to the observer's UDS and `beat()` emits (~1166 tok)
- `lib.rs` — Varta agent API — `Varta::connect` opens a Unix Domain Socket to the (~217 tok)
- `panic.rs` — Opt-in panic hook that emits a [`varta_vlp::Status::Critical`] VLP frame to (~756 tok)

## crates/varta-client/tests/

- `acceptance.rs` — Session 02 acceptance tests for `varta-client`. (~896 tok)
- `panic_feature.rs` — Session 04 acceptance tests for the `panic-handler` feature. (~996 tok)
- `zero_alloc.rs` — Session 02 zero-allocation guard for `Varta::beat`. (~898 tok)

## crates/varta-tests/

- `Cargo.toml` — Rust package manifest (~123 tok)

## crates/varta-tests/src/

- `lib.rs` — Varta end-to-end test harness — Session 06 will land integration fixtures (~90 tok)

## crates/varta-tests/tests/

- `end_to_end.rs` — Session 06 end-to-end contract tests. (~4026 tok)

## crates/varta-vlp/

- `Cargo.toml` — Rust package manifest (~54 tok)
- `README.md` — Project documentation (~720 tok)

## crates/varta-vlp/src/

- `lib.rs` — Varta Lifeline Protocol — 32-byte fixed-layout health frame. (~1926 tok)

## crates/varta-vlp/tests/

- `frame.rs` — Integration tests for the Varta Lifeline Protocol frame. (~1190 tok)

## crates/varta-watch/

- `Cargo.toml` — Rust package manifest (~90 tok)
- `README.md` — Project documentation (~981 tok)

## crates/varta-watch/src/

- `config.rs` — Hand-rolled GNU-style argv parser for the `varta-watch` binary. (~3122 tok)
- `exporter.rs` — Exporters for [`crate::observer::Event`] streams. (~3172 tok)
- `lib.rs` — Varta observer library — UDS receive loop, per-pid tracker, stall surface. (~228 tok)
- `main.rs` — Varta observer binary entry point. (~1137 tok)
- `observer.rs` — Single-threaded observer: bind a Unix datagram socket, decode incoming (~1790 tok)
- `recovery.rs` — Per-pid debounced recovery command runner. (~1193 tok)
- `tracker.rs` — Per-pid liveness tracker backed by a fixed `[Slot; 64]` array. (~1695 tok)

## crates/varta-watch/tests/

- `acceptance.rs` — Session 03 acceptance contract tests for `varta-watch`. (~1976 tok)
- `cli_smoke.rs` — Session 05 acceptance contract test for the `varta-watch` binary surface. (~310 tok)
- `exporter_endpoint.rs` — Session 05 acceptance contract tests for `varta-watch::exporter`. (~1383 tok)
- `recovery_e2e.rs` — Session 05 acceptance contract tests for `varta-watch::Recovery`. (~754 tok)

## docs/acceptance/

- `varta-v0-1-0.md` — Varta v0.1.0 — Acceptance Contract (~1390 tok)

## docs/architecture/

- `vlp-frame.md` — VLP Frame — Wire Layout (v0.1.0) (~980 tok)

## docs/benchmarks/

- `results.md` — Varta v0.1.0 — Bench Harness Results (~785 tok)

## docs/release/

- `v0.1.0-readiness.md` — Varta v0.1.0 — Release Readiness (~2675 tok)
