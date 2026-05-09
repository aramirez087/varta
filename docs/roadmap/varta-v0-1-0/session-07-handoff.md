# Session 07 — Handoff (Docs & Examples)

## Done

- `README.md` — replaced the `# Varta` stub with the full project README:
  tagline, "Why Varta" four-bullet section, install snippet (path dep),
  30-line quickstart, crate link table, performance link, constraints callout.
- `crates/varta-vlp/README.md` — new. Protocol description, byte-map table
  (verbatim from `docs/architecture/vlp-frame.md`), Status variant table,
  version policy, usage code block, constraints callout.
- `crates/varta-client/README.md` — new. `Varta::connect`/`beat` API table,
  `BeatOutcome` semantics table, `Status` variant table, payload encoding
  example, `panic-handler` feature flag usage, constraints callout, cross-links.
- `crates/varta-watch/README.md` — new. CLI invocation example, full 8-flag
  table, `/metrics` Prometheus schema, file export schema, `recovery_cmd`
  template syntax and debounce semantics, constraints callout, cross-links.
- `crates/varta-client/examples/basic.rs` — new. Minimal beat loop; connects
  to `/tmp/varta.sock`, emits `Status::Ok` every 500 ms with `payload = 0`.
- `crates/varta-client/examples/with_payload.rs` — new. Beat loop that packs
  queue depth (high 32 bits) and last error code (low 32 bits) into the
  64-bit payload using atomics.
- `crates/varta-client/examples/with_panic_handler.rs` — new. Calls
  `install_panic_handler` before `Varta::connect`, then beats 10 times.
  Requires `--features panic-handler`.
- `crates/varta-client/Cargo.toml` — added three `[[example]]` sections;
  `with_panic_handler` carries `required-features = ["panic-handler"]`.
- `docs/benchmarks/results.md` — new stub. Root README links here; content
  will be populated by `varta-bench` before the v0.1.0 release.
- `docs/roadmap/varta-v0-1-0/session-07-handoff.md` — this file.

## Decisions

- **README code blocks are prose-verified, not cargo-tested.** Markdown fences
  in `.md` files are never compiled by `cargo test --doc`. All compile-verified
  runnable code lives in `crates/varta-client/examples/*.rs`. README blocks
  use `no_run` annotation where shown in rustdoc style; they are kept accurate
  by reading the actual public API before writing.
- **`docs/benchmarks/results.md` stub created by Session 07.** The root README
  must link here and the link must not be a 404. Session 06 (bench harness) is
  not a DAG parent of Session 07, so the file did not exist.
- **`[[example]]` sections added for all three examples.** Cargo only respects
  `required-features` on examples declared explicitly; without the section
  `cargo build --example with_panic_handler` would build without the feature
  and produce a compile error on `install_panic_handler`.
- **`basic.rs` uses `let _ =` to discard `BeatOutcome`.** `BeatOutcome` is not
  `#[must_use]` (confirmed by reading `client.rs:17`); discarding the return is
  correct for the minimal demo.
- **`with_panic_handler.rs` does not trigger a panic.** The example
  demonstrates setup and normal operation; actually panicking would make `cargo
  run` exit non-zero and confuse first-time users.
- **Cross-link topology is asymmetric.** Per-crate READMEs link back to the
  workspace root and sideways to `varta-vlp`; the root links forward to each
  per-crate README and to the benchmark stub. This matches how readers arrive
  (crates.io / GitHub directory) and navigate.

## Cross-link map

```
README.md
  └─→ crates/varta-vlp/README.md    ─→ docs/architecture/vlp-frame.md
  └─→ crates/varta-client/README.md ─→ crates/varta-vlp/README.md
                                     ─→ docs/architecture/vlp-frame.md
  └─→ crates/varta-watch/README.md  ─→ crates/varta-vlp/README.md
                                     ─→ docs/architecture/vlp-frame.md
  └─→ docs/benchmarks/results.md

Each per-crate README also carries:
  └─→ ../../README.md  (workspace root back-link)
```

## TDD ledger

`n/a — docs-only session. Proxy quality signals: cargo build --workspace --examples and cargo test --doc --workspace.`

## Open issues

- **`docs/benchmarks/results.md` is a stub.** Numbers will be populated when
  `varta-bench` (Session 06 deliverable) is run against a release build on a
  reference machine.
- **No rustdoc gaps observed in source.** Every public item in `varta-client`
  and `varta-watch` carries a rustdoc paragraph as required by
  `#![deny(missing_docs)]`. The CI gate (`cargo build --workspace`) enforces
  this; no source changes were made in this session.

## Next-session inputs

Session 08 (CI gate) MUST read:

- `docs/roadmap/varta-v0-1-0/session-07-handoff.md` (this file).
- `docs/roadmap/varta-v0-1-0/session-04-handoff.md` (TDD ledger format reference).
- `docs/roadmap/varta-v0-1-0/session-05-handoff.md` (TDD ledger format reference).
- `crates/varta-client/Cargo.toml` (example declarations, `required-features` gate).
- `crates/varta-client/examples/*.rs` (three examples to verify build).
- `README.md`, `crates/*/README.md` (markdown to validate for no TODO/TBD/XXX).
- `docs/acceptance/varta-v0-1-0.md` (acceptance test names to grep-validate in source).
