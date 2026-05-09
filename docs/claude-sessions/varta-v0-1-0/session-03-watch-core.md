---
session: 03
title: "varta-watch core (test-first): recv loop, tracker, stall detection"
depends_on: [01]
touches:
  - "crates/varta-watch/src/lib.rs"
  - "crates/varta-watch/src/observer.rs"
  - "crates/varta-watch/src/tracker.rs"
  - "crates/varta-watch/tests/**"
parallel_safe: true
produces:
  - "crates/varta-watch/src/observer.rs"
  - "crates/varta-watch/src/tracker.rs"
  - "crates/varta-watch/src/lib.rs"
  - "crates/varta-watch/tests/acceptance.rs"
  - "docs/roadmap/varta-v0-1-0/session-03-handoff.md"
model: "opus"
---

# Session 03: varta-watch core (test-first)

Paste this into a new Claude Code session:

```md
## Continuity
Continue from Session 01 artifacts. Read these BEFORE editing:
- `docs/acceptance/varta-v0-1-0.md` (Session 03 section is your test list)
- `docs/roadmap/varta-v0-1-0/session-01-handoff.md`
- `docs/claude-sessions/varta-v0-1-0/session-00-operator-rules.md` (TDD discipline)
- `crates/varta-vlp/src/lib.rs` (Frame, Status, DecodeError)
- `crates/varta-watch/src/{lib.rs,main.rs}` (skeleton — DO NOT touch `main.rs`, owned by Session 05)

## Mission
Implement `Observer` + `Tracker` + `Event` test-first: bind a UDS server, drive a single-threaded recv loop, maintain bounded per-PID state, emit `Event::Stall` when a tracked agent goes silent past a threshold.

## Repository anchors
- `crates/varta-watch/tests/acceptance.rs` (new) — contract tests S03
- `crates/varta-watch/src/observer.rs` (new) — Observer + Event + poll loop
- `crates/varta-watch/src/tracker.rs` (new) — fixed-capacity per-PID slots
- `crates/varta-watch/src/lib.rs` (replace skeleton: module decls + re-exports)

## Tasks
1. **Read contract.** Open `docs/acceptance/varta-v0-1-0.md`, copy the four S03 test names verbatim.
2. **RED — write tests.** Author `tests/acceptance.rs` with the four contract tests:
   - `observer_emits_beat_per_received_frame`: bind observer, send 3 hand-built frames with increasing nonces from a client `UnixDatagram`, assert three `Event::Beat` in order.
   - `observer_emits_stall_after_threshold_elapses`: send one frame, stop, assert `Event::Stall` arrives after the configured threshold (use bounded retry loop, not raw sleep).
   - `observer_reports_decode_error_for_bad_magic`: send `[0xFF; 32]`, assert `Event::Decode(DecodeError::BadMagic)`.
   - `tracker_capacity_bounded_to_64_pids`: insert 65 distinct pids; assert 65th returns `Update::CapacityExceeded` and `tracker.len() == 64`.
3. **Capture RED.** Run `cargo test -p varta-watch 2>&1 | tail -30`. Expect compile errors. Save tail.
4. **GREEN — implement.**
   - `tracker.rs`: `pub struct Tracker { entries: [Slot; 64], len: usize }` with `Slot { pid: u32, last_nonce: u64, last_ns: u64, status: Status }`. Methods: `record(&mut self, &Frame, now_ns: u64) -> Update` (linear scan: existing pid → refresh, new pid → append if room, else `CapacityExceeded`; out-of-order nonce → `OutOfOrder`), `iter_stalled(&self, now_ns, threshold_ns) -> impl Iterator<Item = &Slot>`, `len(&self) -> usize`. `pub enum Update { Inserted, Refreshed, OutOfOrder, CapacityExceeded }`.
   - `observer.rs`: `pub struct Observer { sock: UnixDatagram, tracker: Tracker, threshold_ns: u64, start: Instant }`. `Observer::bind(path, threshold: Duration)` removes stale socket, binds, sets `set_read_timeout(Some(100ms))`. `pub enum Event { Beat { pid, status, payload, nonce }, Stall { pid, last_nonce, last_ns }, Decode(DecodeError), Io(io::Error) }`. `pub fn poll(&mut self) -> Option<Event>`: `recv` into stack `[u8; 32]`; on full read decode + `tracker.record`; on `WouldBlock`/`TimedOut` scan `iter_stalled` for new stalls; on other errors return `Io`.
   - `lib.rs`: `pub mod observer; pub mod tracker; pub use observer::{Observer, Event}; pub use tracker::{Tracker, Slot, Update};`.
5. **Capture GREEN.** Re-run `cargo test -p varta-watch 2>&1 | tail -30`. All four S03 tests pass. Save tail.
6. **Refactor + gate.** `cargo fmt`, `cargo clippy -p varta-watch --all-targets -- -D warnings`, re-run tests. Confirm `Tracker` size: `const _: () = assert!(size_of::<Tracker>() <= 64*40 + 16);` (rough — adjust based on Slot layout).

## Quality gates
- `cargo fmt --all -- --check`
- `cargo clippy -p varta-watch --all-targets -- -D warnings`
- `RUSTFLAGS="-D warnings" cargo test -p varta-watch`
- `cargo build -p varta-watch`
- Verify `[dependencies]` still empty in `crates/varta-watch/Cargo.toml`.

## Deliverables
- Files under `produces:` above.
- Handoff with TDD ledger (RED + GREEN tails for `cargo test -p varta-watch`), `Event` variants, polling cadence, file paths Session 05 needs.

## Exit criteria
- All four S03 acceptance tests pass deterministically (bounded retries replace raw sleeps).
- TDD ledger captures compile-error RED → all-pass GREEN.
- `Tracker` has fixed `[Slot; 64]` layout — never reallocates.
```
