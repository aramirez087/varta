---
session: 04
title: "varta-client panic-handler feature (test-first)"
depends_on: [02]
touches:
  - "crates/varta-client/src/panic.rs"
  - "crates/varta-client/src/lib.rs"
  - "crates/varta-client/Cargo.toml"
  - "crates/varta-client/tests/panic_feature.rs"
parallel_safe: true
produces:
  - "crates/varta-client/src/panic.rs"
  - "crates/varta-client/src/lib.rs"
  - "crates/varta-client/Cargo.toml"
  - "crates/varta-client/tests/panic_feature.rs"
  - "docs/roadmap/varta-v0-1-0/session-04-handoff.md"
model: "sonnet"
---

# Session 04: panic-handler feature (test-first)

Paste this into a new Claude Code session:

```md
## Continuity
Continue from Session 02 artifacts. Read these BEFORE editing:
- `docs/acceptance/varta-v0-1-0.md` (Session 04 section)
- `docs/roadmap/varta-v0-1-0/session-02-handoff.md` (client API surface)
- `docs/claude-sessions/varta-v0-1-0/session-00-operator-rules.md` (TDD discipline)
- `crates/varta-client/src/{client.rs,lib.rs}`

## Mission
Add an opt-in `panic-handler` Cargo feature that installs a `std::panic::set_hook` firing a `Status::Critical` beat over a one-shot UDS connection, built test-first.

## Repository anchors
- `crates/varta-client/Cargo.toml` (add `[features] default = []  panic-handler = []`)
- `crates/varta-client/tests/panic_feature.rs` (new, gated `#![cfg(feature = "panic-handler")]`)
- `crates/varta-client/src/panic.rs` (new, gated `#[cfg(feature = "panic-handler")]`)
- `crates/varta-client/src/lib.rs` (add gated module + re-export)

## Tasks
1. **Read contract.** Open `docs/acceptance/varta-v0-1-0.md`, copy the three S04 test names verbatim.
2. **RED — write tests.** Author `tests/panic_feature.rs` with the three contract tests:
   - `panic_handler_emits_critical_beat_before_unwind`: bind `UnixDatagram` server in test thread; in `thread::spawn`, call `install_panic_handler(path)` then `panic!("boom")`; join asserts `Err`. Test thread `recv`s a 32-byte frame within 500ms (use `set_read_timeout`); decode and assert `status == Status::Critical && nonce == u64::MAX`.
   - `panic_handler_preserves_original_panic_outcome`: install hook, panic in spawned thread, assert thread `JoinHandle::join()` still returns `Err` with the original payload.
   - `panic_module_excluded_without_feature`: a `#[cfg(not(feature = "panic-handler"))] #[test] fn _excluded()` smoke compile guard — separate test file at `tests/no_feature_smoke.rs` is overkill; instead, this lives as a doc-asserted negative compile in `panic_feature.rs` via `#[cfg(feature = "panic-handler")]` on the file header (the file simply doesn't compile without the feature, satisfying the contract). Note this in the handoff.
3. **Capture RED.** Run `cargo test -p varta-client --features panic-handler 2>&1 | tail -30`. Expect compile errors (`install_panic_handler` missing). Save tail.
4. **GREEN — implement.**
   - `Cargo.toml`: add `[features]` table with `default = []` and `panic-handler = []`. No new deps.
   - `panic.rs`: `pub fn install(socket_path: impl Into<PathBuf>)` — capture owned `PathBuf`, `pid = std::process::id()`, `start = Instant::now()`. `let prev = std::panic::take_hook(); std::panic::set_hook(Box::new(move |info| { ... ; prev(info); }))`. The `Box` is the only allocation (init path). Inside the hook: `UnixDatagram::unbound()`, `connect(&path)`, build `Frame { magic: MAGIC, version: VERSION, status: Status::Critical as u8, pid, timestamp: start.elapsed().as_nanos() as u64, nonce: u64::MAX, payload: 0 }`, encode to stack `[u8; 32]`, `send(&buf).ok()`. Swallow every error (panic-in-panic = abort). `// SAFETY:` notes on re-entrancy.
   - `lib.rs`: `#[cfg(feature = "panic-handler")] pub mod panic;` and `#[cfg(feature = "panic-handler")] pub use panic::install as install_panic_handler;`.
5. **Capture GREEN.** Re-run `cargo test -p varta-client --features panic-handler 2>&1 | tail -30`. Then `cargo test -p varta-client 2>&1 | tail -10` (default features still pass). Save both tails (label the second `GREEN-no-feature`).
6. **Refactor + gate.** `cargo fmt`, `cargo clippy -p varta-client --all-targets --all-features -- -D warnings`, `cargo clippy -p varta-client --all-targets --no-default-features -- -D warnings`. Re-run both test invocations.

## Quality gates
- `cargo fmt --all -- --check`
- `cargo clippy -p varta-client --all-targets --all-features -- -D warnings`
- `cargo clippy -p varta-client --all-targets --no-default-features -- -D warnings`
- `RUSTFLAGS="-D warnings" cargo test -p varta-client --features panic-handler`
- `cargo test -p varta-client` (default features)
- `cargo build -p varta-client --no-default-features` (deps still empty)

## Deliverables
- Files under `produces:` above.
- Handoff with TDD ledger (RED + GREEN tails for both feature-on and feature-off `cargo test`), feature flag semantics, install signature, integration-test pattern.

## Exit criteria
- All three S04 acceptance tests pass with `--features panic-handler`.
- Default-features build excludes the panic module (compile fails if `install_panic_handler` is called without the feature — verify with a one-shot `cargo build`).
- TDD ledger captures both feature-on RED→GREEN and feature-off GREEN.
```
