---
session: 07
title: "Docs polish: top-level README, per-crate READMEs, examples"
depends_on: [04, 05]
touches:
  - "README.md"
  - "crates/varta-vlp/README.md"
  - "crates/varta-client/README.md"
  - "crates/varta-watch/README.md"
  - "crates/varta-client/examples/**"
parallel_safe: true
produces:
  - "README.md"
  - "crates/varta-vlp/README.md"
  - "crates/varta-client/README.md"
  - "crates/varta-watch/README.md"
  - "crates/varta-client/examples/basic.rs"
  - "crates/varta-client/examples/with_payload.rs"
  - "crates/varta-client/examples/with_panic_handler.rs"
  - "docs/roadmap/varta-v0-1-0/session-07-handoff.md"
model: "sonnet"
---

# Session 07: docs polish (READMEs + runnable examples)

Paste this into a new Claude Code session:

```md
## Continuity
Continue from Sessions 04, 05 artifacts. Read these BEFORE editing:
- `docs/roadmap/varta-v0-1-0/session-04-handoff.md` (panic-handler API)
- `docs/roadmap/varta-v0-1-0/session-05-handoff.md` (varta-watch CLI flags)
- `docs/architecture/vlp-frame.md` (byte-map authoritative source)
- `crates/varta-client/src/{client.rs,panic.rs,lib.rs}` (public surface)
- `crates/varta-watch/src/{config.rs,exporter.rs,recovery.rs}` (CLI + exporter)
- `crates/varta-vlp/src/lib.rs` (Frame, Status)
- DO NOT modify any `src/*.rs` files in this session — they are owned by feature sessions. Only README.md files and `crates/varta-client/examples/*.rs`.

## Mission
Replace the stub root `README.md`, write tight per-crate READMEs that mirror rustdoc, and ship three runnable examples that demonstrate the full developer experience.

## TDD note
This session is docs-only and does not author production behavior. The handoff's TDD ledger entry is `n/a — docs-only session`. The proxy quality signal is `cargo build --workspace --examples` and `cargo test --doc --workspace` — examples and rustdoc snippets must compile against the real public API.

## Repository anchors
- `README.md` (replace stub) — project tagline, install, 30-line quickstart, link to per-crate docs, performance summary (link to `docs/benchmarks/results.md`).
- `crates/varta-vlp/README.md` (new) — protocol description, byte-map (copy from architecture doc), version policy.
- `crates/varta-client/README.md` (new) — `Varta::connect`/`beat` summary, `BeatOutcome` semantics, `panic-handler` feature flag usage.
- `crates/varta-watch/README.md` (new) — CLI invocation, every flag, `/metrics` schema, recovery_cmd template syntax.
- `crates/varta-client/examples/basic.rs` — minimal beat loop matching the PRD's snippet.
- `crates/varta-client/examples/with_payload.rs` — encoding queue depth + last-error code into the 64-bit payload.
- `crates/varta-client/examples/with_panic_handler.rs` — `#![cfg(feature = "panic-handler")]` not needed (Cargo gates examples via `required-features`); add `[[example]] name = "with_panic_handler" required-features = ["panic-handler"]` to `crates/varta-client/Cargo.toml` ONLY IF Session 04 didn't already. If it did, just author the .rs file.

## Tasks
1. Author the four README files. Each must:
   - Open with one sentence stating what the crate does.
   - Show a code block that compiles against the current API (verify by reading the source).
   - End with a "Constraints" callout naming the zero-dep / zero-alloc / sub-µs guarantees.
2. Author the three examples. Each must compile with `cargo build --example <name>` (and `--features panic-handler` for the third). Use only public API.
3. Top-level `README.md`: include
   - Tagline: "Zero-overhead health protocol for distributed local agents."
   - Install snippet (`[dependencies] varta-client = { path = "..." }` for now; mention crates.io publish is post-v0.1.0).
   - The PRD-style usage snippet (must compile against the real `Varta`).
   - "Why Varta" with the four core principles bulleted.
   - Link to `docs/benchmarks/results.md` for measured numbers.
   - Link to each per-crate README.
4. Cross-link READMEs (workspace root → per-crate; per-crate → architecture doc).

## Quality gates
- `cargo fmt --all -- --check`
- `cargo build --workspace --examples`
- `cargo build --example with_panic_handler -p varta-client --features panic-handler`
- `cargo test --doc --workspace` (rustdoc examples in source must still compile — Session 07 does not edit source, but the doctest gate proves nothing regressed in the workspace build path)
- Markdown sanity: `grep -l 'TODO\|TBD\|XXX' README.md crates/*/README.md` MUST return nothing.

## Deliverables
- Files under `produces:` above.
- `docs/roadmap/varta-v0-1-0/session-07-handoff.md`: list of READMEs and examples shipped, the cross-link map, any rustdoc gaps observed in source (file:line) for the CI gate to flag.

## Exit criteria
- All three examples build; the panic-handler example builds only with the feature flag.
- READMEs collectively cover every public item in `varta-client` and `varta-watch`.
- No `TODO`/`TBD` in shipped markdown.
```
