---
session: 02
title: "varta-client core (test-first): connect, beat, zero-alloc"
depends_on: [01]
touches:
  - "crates/varta-client/src/**"
  - "crates/varta-client/tests/**"
parallel_safe: true
produces:
  - "crates/varta-client/src/client.rs"
  - "crates/varta-client/src/lib.rs"
  - "crates/varta-client/tests/acceptance.rs"
  - "crates/varta-client/tests/zero_alloc.rs"
  - "docs/roadmap/varta-v0-1-0/session-02-handoff.md"
model: "opus"
---

# Session 02: varta-client core (test-first)

Paste this into a new Claude Code session:

```md
## Continuity
Continue from Session 01 artifacts. Read these BEFORE editing:
- `docs/acceptance/varta-v0-1-0.md` (your authoritative test list — Session 02 section)
- `docs/roadmap/varta-v0-1-0/session-01-handoff.md`
- `docs/claude-sessions/varta-v0-1-0/session-00-operator-rules.md` (TDD discipline + constraints)
- `crates/varta-vlp/src/lib.rs` (Frame, Status, MAGIC, VERSION)
- `crates/varta-client/src/lib.rs` (skeleton to replace)

## Mission
Implement `Varta::connect` + `Varta::beat` + `BeatOutcome` test-first so the agent fires-and-forgets 32-byte VLP datagrams with zero post-init heap allocation.

## Repository anchors
- `crates/varta-client/tests/acceptance.rs` (new) — contract tests S02
- `crates/varta-client/tests/zero_alloc.rs` (new) — guard-allocator test S02
- `crates/varta-client/src/client.rs` (new) — implementation
- `crates/varta-client/src/lib.rs` (replace skeleton)

## Tasks
1. **Read contract.** Open `docs/acceptance/varta-v0-1-0.md` and copy the five S02 test names verbatim. Any deviation must be justified in the handoff.
2. **RED — write tests.** Author `tests/acceptance.rs` with the four contract tests, each spawning a `UnixDatagram::bind` server in a tempdir as fixture and asserting against the `Varta`/`BeatOutcome` API as if it exists. Author `tests/zero_alloc.rs` defining `#[global_allocator] static GUARD: GuardAlloc` (wrapping `System` with an `AtomicBool` "armed" flag that panics on alloc when armed); the `beat_makes_zero_heap_allocations_after_init` test connects, arms, beats 10_000 times, disarms, asserts receiver got > 0 datagrams and decoded the latest frame. RAII drop-guard unlinks the temp socket.
3. **Capture RED.** Run `cargo test -p varta-client 2>&1 | tail -30`. Expect compile errors (`Varta`, `BeatOutcome`, `connect`, `beat` missing). Save the tail for the handoff ledger.
4. **GREEN — implement.** In `client.rs`: `pub struct Varta { sock: UnixDatagram, buf: [u8; 32], pid: u32, start: Instant, nonce: u64 }`. `pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self>` — `unbound()`, `connect`, `set_nonblocking(true)`, capture pid/start, zero buf/nonce (only allocation point). `pub fn beat(&mut self, status: Status, payload: u64) -> BeatOutcome` — saturating `nonce += 1`, build `Frame` on stack, `Frame::encode(&mut self.buf)`, `self.sock.send(&self.buf)` mapped to `BeatOutcome::{Sent, Dropped, Failed(io::Error)}`. NO `String`/`Vec`/`Box`/`format!`/`vec!` on the steady-state path. `lib.rs`: `pub mod client; pub use client::{Varta, BeatOutcome}; pub use varta_vlp::{Frame, Status, DecodeError};`.
5. **Capture GREEN.** Re-run `cargo test -p varta-client 2>&1 | tail -30`. All five S02 tests must pass. Save the tail.
6. **Refactor + gate.** Run `cargo fmt`, `cargo clippy -p varta-client --all-targets -- -D warnings`. Then `grep -nE 'String::|Vec::|Box::|format!|vec!' crates/varta-client/src/client.rs` MUST return empty. Re-run tests to confirm green after any refactor.

## Quality gates
- `cargo fmt --all -- --check`
- `cargo clippy -p varta-client --all-targets -- -D warnings`
- `RUSTFLAGS="-D warnings" cargo test -p varta-client`
- `cargo build -p varta-client --release`
- `cargo test --doc -p varta-client`
- Verify production deps still empty: `awk '/^\[dependencies\]$/{f=1;next} /^\[/{f=0} f && NF{print; exit 1}' crates/varta-client/Cargo.toml`

## Deliverables
- Files under `produces:` above.
- Handoff `docs/roadmap/varta-v0-1-0/session-02-handoff.md` with: TDD ledger (RED + GREEN tails), API summary, list of `unsafe` blocks (if any) with safety arguments, next-session inputs (panic-handler entry point, integration-test fixture suggestions).

## Exit criteria
- All five S02 acceptance tests pass; guard allocator never trips after `arm()`.
- `beat()` source has zero `String`/`Vec`/`Box`/`format!`/`vec!` tokens.
- TDD ledger shows compile-error RED → all-pass GREEN for `cargo test -p varta-client`.
```
