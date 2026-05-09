# Session 03 — Handoff (Watch Core)

## Done

- `crates/varta-watch/Cargo.toml` — added the only allowed inter-crate dep:
  `varta-vlp = { path = "../varta-vlp" }`. No registry crates, no version
  specs, no dev-deps.
- `crates/varta-watch/src/lib.rs` — replaced skeleton with module decls and
  re-exports (`Observer`, `Event`, `Tracker`, `Slot`, `Update`).
- `crates/varta-watch/src/tracker.rs` — `Tracker` (fixed `[Slot; 64]`),
  `Slot`, `Update`, with `record`, `iter_stalled`, `len`, `is_empty`, and
  the crate-private `mark_stall_emitted` latch. Compile-time
  `assert!(size_of::<Tracker>() <= 64*40 + 16)`.
- `crates/varta-watch/src/observer.rs` — `Observer::bind`, `Observer::poll`,
  `Event::{Beat, Stall, Decode, Io}`. UDS bind with stale-file removal,
  100 ms read timeout, single-threaded recv loop.
- `crates/varta-watch/tests/acceptance.rs` — four S03 contract tests verbatim
  per `docs/acceptance/varta-v0-1-0.md`, plus small helpers for unique UDS
  paths and bounded poll-retry.
- `docs/roadmap/varta-v0-1-0/session-03-handoff.md` — this file.
- `crates/varta-watch/src/main.rs` — left untouched (Session 05 owns it).

## Decisions

- **`varta-vlp` path dep is the literal interpretation of "varta-watch
  depends on varta-vlp only".** The operator rule says production crates
  must keep `[dependencies]` empty *and* that all inter-crate deps go through
  `path = "../<crate>"` and that `varta-watch` depends on `varta-vlp`. Those
  are not literally compatible. Session 01's handoff anticipated this and
  recorded that "Sessions 02/03 add both the path dep and the re-export
  together." We adopt that interpretation: empty means "no registry deps",
  not "no path deps." Flagged for Session 08's CI gate.
- **`Slot` uses default Rust repr, not `#[repr(C)]`.** It is internal, never
  on the wire, and never crosses an FFI boundary, so the compiler may pick
  any field order it likes. Default repr is the smallest layout.
- **Stall-once-per-silence-run is implemented with a private
  `stall_emitted` latch on `Slot`.** `iter_stalled` keeps the prompt's
  read-only `&Slot` signature; `Observer::poll` flips the latch via the
  crate-private `mark_stall_emitted` after surfacing `Event::Stall`. The
  latch clears automatically inside `Tracker::record` when a fresh beat
  arrives.
- **`set_read_timeout(Some(100ms))`, not `set_nonblocking(true)`.** The
  observer is a single-threaded poll loop and parking the kernel-side recv
  for 100 ms is the cheapest way to keep CPU near zero while bounding stall
  latency. The non-blocking rule is a `varta-client` constraint, not an
  observer constraint.
- **Status reports OOO instead of panicking on bad bytes inside `record`.**
  `Frame::decode` already validates the status byte; `Tracker::record`
  re-validates as a defense-in-depth move and treats a violation as
  `OutOfOrder` rather than crashing the daemon. Should never fire in
  practice.
- **Truncated / oversized datagrams are silently dropped.** The wire format
  is a fixed 32 bytes; anything else is a client bug. Surfacing a fourth
  `Event` variant is a Session 05 conversation if exporters want a counter.
- **Test sockets live under `std::env::temp_dir()` with a per-process,
  per-test counter suffix.** A small `UdsPath` Drop guard removes the file
  on test exit so failed runs do not orphan sockets.
- **Bounded retry, not raw sleep.** Both real-time tests use a deadline
  loop with a 1 ms inter-poll yield. The stall test deadline is
  `threshold + 1 s` so we never assert on jitter.

## TDD ledger

### RED

```text
$ cargo test -p varta-watch 2>&1 | tail -30
   Compiling varta-vlp v0.1.0 (/Users/aramirez/Code/.epic-worktrees/Varta/epic--varta-v0-1-0--s03-watch-core/crates/varta-vlp)
   Compiling varta-watch v0.1.0 (/Users/aramirez/Code/.epic-worktrees/Varta/epic--varta-v0-1-0--s03-watch-core/crates/varta-watch)
error[E0432]: unresolved imports `varta_watch::Event`, `varta_watch::Observer`, `varta_watch::Tracker`, `varta_watch::Update`
  --> crates/varta-watch/tests/acceptance.rs:14:19
   |
14 | use varta_watch::{Event, Observer, Tracker, Update};
   |                   ^^^^^  ^^^^^^^^  ^^^^^^^  ^^^^^^ no `Update` in the root
   |                   |      |         |
   |                   |      |         no `Tracker` in the root
   |                   |      no `Observer` in the root
   |                   no `Event` in the root

warning: unreachable call
   --> crates/varta-watch/tests/acceptance.rs:185:33
    |
185 |         Event::Decode(other) => Err(panic!("wrong decode error variant: {other:?}")),
    |                                 ^^^ ----------------------------------------------- any code following this expression is unreachable
    |                                 |
    |                                 unreachable call
    |
    = note: `#[warn(unreachable_code)]` (part of `#[warn(unused)]`) on by default

For more information about this error, try `rustc --explain E0432`.
warning: `varta-watch` (test "acceptance") generated 1 warning
error: could not compile `varta-watch` (test "acceptance") due to 1 previous error; 1 warning emitted
warning: build failed, waiting for other jobs to finish...
```

### GREEN

```text
$ cargo test -p varta-watch 2>&1 | tail -30
running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 4 tests
test tracker_capacity_bounded_to_64_pids ... ok
test observer_reports_decode_error_for_bad_magic ... ok
test observer_emits_beat_per_received_frame ... ok
test observer_emits_stall_after_threshold_elapses ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.52s

   Doc-tests varta_watch

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Open issues

- **Truncated / oversized datagrams** are silently dropped in
  `crates/varta-watch/src/observer.rs:108`. If Session 05's exporter wants
  to count them, surface a fourth `Event` variant (`Event::Truncated { len }`
  or similar) and update the contract.
- **`Cargo.toml` "literal empty `[dependencies]`" gate** in
  `crates/varta-watch/Cargo.toml:8` is now violated by the path dep. The
  CI gate (Session 08) needs to permit `path = "../*"` deps explicitly,
  matching the operator rule's architecture mandate.

## Quality gate results

- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p varta-watch --all-targets -- -D warnings` — clean.
- `RUSTFLAGS="-D warnings" cargo test -p varta-watch` — 4 passed, 0 failed.
- `cargo build -p varta-watch` — clean.
- `cargo test --workspace` — 13 passed (9 vlp + 4 watch), 0 failed.

## Polling cadence + Event surface (for Session 05)

- `Observer::poll` blocks for at most 100 ms (`READ_TIMEOUT` in
  `observer.rs`). The daemon must call `poll` in a tight loop; each call
  returns `Option<Event>`.
- Variant set, fixed for v0.1.0:
  - `Event::Beat { pid, status, payload, nonce }`
  - `Event::Stall { pid, last_nonce, last_ns }` (fires once per silence run)
  - `Event::Decode(DecodeError)`
  - `Event::Io(io::Error)`
- `last_ns` is observer-local nanoseconds since `Observer::bind`. It is not
  a wall-clock value; it is suitable for relative latency in a single
  process, not for cross-process correlation.

## Next-session inputs

Session 05 (recovery + exporters + binary surface) MUST read:

- `docs/acceptance/varta-v0-1-0.md` (Session 05 section — six tests).
- `docs/claude-sessions/varta-v0-1-0/session-00-operator-rules.md` (TDD +
  dep mandate).
- `crates/varta-watch/src/lib.rs` (current re-exports).
- `crates/varta-watch/src/observer.rs` (`Observer`, `Event`, `poll`).
- `crates/varta-watch/src/tracker.rs` (`Tracker`, `Slot`, `Update`,
  `mark_stall_emitted` latch behavior).
- `crates/varta-watch/tests/acceptance.rs` (test style + UDS helpers).
- `crates/varta-watch/Cargo.toml` (current `[dependencies]` shape — path
  dep on `varta-vlp` only).
- `crates/varta-watch/src/main.rs` (skeleton entry point — Session 05
  rewrites this).
- This handoff: `docs/roadmap/varta-v0-1-0/session-03-handoff.md`.
