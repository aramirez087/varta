# Session 03 — Typed `Frame.status` + `Frame::new` Handoff

**Epic:** `client-protocol-hygiene`
**Session:** 03 — m1 (typed in-memory status) + m2 (`Frame::new` constructor)
in one atomic sweep.
**Date:** 2026-05-10.
**Branch:** `epic/client-protocol-hygiene--s03-typed-status-and-frame-new`.

---

## What changed

### `crates/varta-vlp/src/lib.rs`

1. **`Frame.status` retyped** from `pub status: u8` to `pub status: Status`.
   The doc-comment was rewritten to make the in-memory-vs-wire split
   explicit ("Health status reported by the agent. Encoded on the wire as a
   single byte at offset 3 — [`Status`] discriminants are `#[repr(u8)]`.").
2. **`Frame::encode`** now writes `out[3] = self.status as u8;` (was
   `self.status;`). Wire byte and offset are unchanged.
3. **`Frame::decode`** now binds typed: `let status = Status::try_from_u8(bytes[3])?;`,
   collapsing the prior two-step `let status = bytes[3]; Status::try_from_u8(status)?;`.
   The returned `Frame` literal uses the shorthand `status,` field — the
   bound value is now `Status`, not `u8`.
4. **`Frame::new` added** as a `pub const fn`, placed *above* `encode` so
   the public constructor reads first:
   ```rust
   pub const fn new(
       status: Status,
       pid: u32,
       timestamp: u64,
       nonce: u64,
       payload: u64,
   ) -> Frame
   ```
   It populates `magic: MAGIC` and `version: VERSION` automatically; all
   fields remain `pub` so the struct literal remains available where useful.
5. **Seven `offset_of!` compile-time asserts** were appended after the
   existing two const asserts (`size_of == 32`, `align_of == 8`):
   - `magic == 0`, `version == 2`, `status == 3`, `pid == 4`,
     `timestamp == 8`, `nonce == 16`, `payload == 24`.
   `core::mem::offset_of!` is stable since Rust 1.77; the pinned toolchain
   (1.93.1) is well clear of the MSRV requirement.

### `crates/varta-watch/src/observer.rs`

- `Update::Inserted | Update::Refreshed` arm no longer calls
  `Status::try_from_u8(frame.status).expect(...)`. The arm now builds
  `Event::Beat { status: frame.status, ... }` directly. The `.expect(...)`
  message is gone; the `Status` import remains because `Event::Beat::status: Status`
  still requires it.

### `crates/varta-watch/src/tracker.rs`

- `Tracker::record` no longer matches on `Status::try_from_u8(frame.status)`.
  The defensive `Err(_) => Update::OutOfOrder` arm is gone, replaced by a
  single `let status = frame.status;`. The three downstream uses of the
  binding (`slot.status = status;` and two `Slot { ... status, ... }`
  initialisers) are unchanged — minimises diff and preserves clarity.
- The `Status` import stays because `Slot.status: Status` and
  `Slot::EMPTY` reference `Status::Ok`.

### `crates/varta-client/src/client.rs`

- Import line shortened: `use varta_vlp::{Frame, Status, NONCE_TERMINAL};`
  (dropped `MAGIC, VERSION`).
- `Varta::beat` body's `Frame { ... }` literal collapsed to
  `let frame = Frame::new(status, self.pid, timestamp, self.nonce, payload);`.
- No `as u8` cast on `status` anymore; the parameter is already `Status`.

### `crates/varta-client/src/panic.rs`

- Import line shortened: `use varta_vlp::{Frame, Status, NONCE_TERMINAL};`
  (dropped `MAGIC, VERSION`).
- Panic-hook closure's `Frame { ... }` literal collapsed to
  `let frame = Frame::new(Status::Critical, pid, timestamp, NONCE_TERMINAL, 0);`.

### `crates/varta-vlp/tests/frame.rs`

- `fixture_frame()` literal — `status: Status::Ok as u8` → `status: Status::Ok`.
- `every_status_variant_round_trips` — the in-range loop body was
  rewritten per Session 01's plan: build with `Frame::new(expected, 7, 0, 1, 0)`,
  assert the encoded byte `buf[3] == byte`, then assert
  `decoded.status == expected` (typed against typed). The separate
  `decode_rejects_bad_status` test (raw byte mutation) is untouched.
- `payload_preserved_at_u64_max` — `status: Status::Critical as u8` →
  `status: Status::Critical`.
- The two optional fixture literals (`fixture_frame()` and
  `payload_preserved_at_u64_max`) intentionally remain struct literals,
  not `Frame::new` calls. Rationale: this test file documents the wire
  layout, and struct literals show field order — the new `offset_of!`
  asserts in `lib.rs` provide compile-time proof of that same fact, but
  the runtime literal stays as redundant local documentation.

### `crates/varta-client/tests/zero_alloc.rs`

- `assert_eq!(frame.status, Status::Ok as u8)` → `assert_eq!(frame.status, Status::Ok)`.

### `crates/varta-client/tests/acceptance.rs`

- `assert_eq!(frame.status, Status::Ok as u8)` → `assert_eq!(frame.status, Status::Ok)`.

### `crates/varta-client/tests/panic_feature.rs`

- `assert_eq!(frame.status, Status::Critical as u8, "...")` →
  `assert_eq!(frame.status, Status::Critical, "...")`. (rustfmt collapsed
  the macro to one line after the change.)

### `crates/varta-watch/tests/acceptance.rs`

- Import shortened: `use varta_vlp::{DecodeError, Frame, Status};`
  (dropped `MAGIC, VERSION`).
- `make_frame` body collapsed to `Frame::new(status, pid, nonce, nonce, payload)`
  (timestamp argument is `nonce` to match the prior literal's choice of
  `timestamp: nonce`).

### `crates/varta-bench/src/main.rs`

- The embedded Rust source string (the heredoc that spawns a transient
  cargo project for the binary-size benchmark) was updated:
  - Import line shortened: `use varta_vlp::Frame;` (dropped
    `MAGIC, VERSION` — they're not referenced inside the generated binary
    any more).
  - `Frame { ... }` literal collapsed to
    `let frame = Frame::new(Status::Ok, 0, 0, 1, 0);`.
- The benchmark spawn was verified end-to-end: `cargo run -p varta-bench
  --release -- binary-size` succeeds.

### `.wolf/` scaffold

This worktree did not have a `.wolf/` directory (session 02 created it on
its branch). The S03 worktree re-bootstraps:
- `OPENWOLF.md` — minimal context-management skeleton.
- `anatomy.md` — directory + file map.
- `cerebrum.md` — preferences, key-learnings (offset_of! 1.77+, typed
  in-memory vs. wire byte), do-not-repeat list.
- `memory.md` — ledger of S03 actions.
- `buglog.json` — `[]` (no bugs surfaced during the sweep).

---

## Files touched

Production:
- `crates/varta-vlp/src/lib.rs`
- `crates/varta-watch/src/observer.rs`
- `crates/varta-watch/src/tracker.rs`
- `crates/varta-client/src/client.rs`
- `crates/varta-client/src/panic.rs`
- `crates/varta-bench/src/main.rs`

Tests:
- `crates/varta-vlp/tests/frame.rs`
- `crates/varta-client/tests/zero_alloc.rs`
- `crates/varta-client/tests/acceptance.rs`
- `crates/varta-client/tests/panic_feature.rs`
- `crates/varta-watch/tests/acceptance.rs`

Docs / scaffold:
- `.wolf/OPENWOLF.md` (new)
- `.wolf/anatomy.md` (new)
- `.wolf/cerebrum.md` (new)
- `.wolf/memory.md` (new)
- `.wolf/buglog.json` (new)
- `docs/roadmap/client-protocol-hygiene/session-03-handoff.md` (this file)

---

## Decisions made

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | `Frame::new` is `pub const fn`; all fields stay `pub`. | Zero overhead; callers retain literal control. `const fn` enables compile-time use. |
| D2 | Argument order = `(status, pid, timestamp, nonce, payload)`. | Matches wire-byte order after the implicit `magic, version` prefix; matches Session 01 contract. |
| D3 | Drop `MAGIC`/`VERSION` imports from `client.rs`, `panic.rs`, `watch acceptance.rs`. | Unused after `Frame::new` adoption; `clippy -D warnings` would have flagged. |
| D4 | Keep `fixture_frame()` and `payload_preserved_at_u64_max` as struct literals. | They document field order; the new offset asserts give the same proof at compile time but the runtime literal is useful redundant documentation. |
| D5 | `tracker::record` keeps `let status = frame.status;` binding. | Minimises diff; preserves local-binding pattern used three times in the function body. |
| D6 | Updated doc-comment at `lib.rs:82` for `status` field. | The prior comment ("Status byte, one of the [`Status`] discriminants.") was misleading after the type change. |
| D7 | Added **seven** `offset_of!` asserts. | Full layout proof at compile time (magic, version, status, pid, timestamp, nonce, payload). |
| D8 | The exporter's `last_status: Option<u8>` is **not** changed. | Out of scope per audit; exporter consumes raw bytes by design. |
| D9 | `varta-vlp/README.md:47-50` example **not** updated. | Out of scope per session task list; README is not compiled. Captured as Open Issue (1). |
| D10 | `.wolf/` scaffold re-bootstrapped on this worktree. | Required by `.claude/rules/openwolf.md`. Will merge with session 02's scaffold at branch-integration time. |

---

## Test outputs (gate-by-gate)

```
cargo fmt --all -- --check          → clean (no output)
cargo clippy --workspace -- -D warnings → clean; Finished dev profile
cargo test -p varta-vlp             → 9 passed; 0 failed
cargo test -p varta-client          → 4 acceptance + 4 classifier + 1 zero_alloc + 1 doctest; all ok
cargo test -p varta-client --features panic-handler → adds 3 panic_feature tests; all ok
cargo test -p varta-watch           → 5 acceptance + 4 cli_smoke + 3 exporter_endpoint + 3 exporter_format + 6 recovery_runner; all ok
cargo test --workspace              → every crate's suite passes
cargo build --workspace --release   → Finished release profile [optimized]
cargo test -p varta-tests --test end_to_end → 2 passed; 0 failed
cargo run -p varta-bench --release -- binary-size → PASS (delta=4KB, threshold 20KB)
```

Spot-check signals:

```
$ grep -rn "status:.*as u8" crates --include="*.rs"
(empty)

$ grep -rn "Status::try_from_u8" crates --include="*.rs"
crates/varta-vlp/src/lib.rs:35:/// [`Status::try_from_u8`].
crates/varta-vlp/src/lib.rs:151:        let status = Status::try_from_u8(bytes[3])?;
crates/varta-vlp/src/lib.rs:170:/// Error returned by [`Frame::decode`] and [`Status::try_from_u8`].
crates/varta-vlp/tests/frame.rs:86:            Status::try_from_u8(byte).expect("known byte must decode"),
```

Only `Frame::decode` and the variant-mapping test still call
`Status::try_from_u8`. Everywhere else, `frame.status` is typed and
used directly.

---

## Open issues for Session 04+

1. **`crates/varta-vlp/README.md:47-50`** still shows a `Frame { ...
   status: Status::Ok as u8, ... }` example. The example is now a lie
   under m1 (the field is typed `Status`). README is not compiled, so
   this is non-blocking, but a docs sweep should update it to use
   `Frame::new(Status::Ok, ...)`.

2. **`.wolf/` scaffold collision** — both session 02 and session 03
   worktrees created `.wolf/OPENWOLF.md`, `.wolf/anatomy.md`,
   `.wolf/cerebrum.md`, `.wolf/memory.md`, `.wolf/buglog.json`. On merge,
   take the union of `memory.md` and `buglog.json` entries; one canonical
   copy of the other three files (they describe stable, shared workflow
   conventions).

3. **`varta-watch/src/exporter.rs:140`** `last_status: Option<u8>`
   remains as `u8`. Audited and consciously skipped per S01 plan; the
   Prometheus gauge consumes raw bytes by design. Optional symmetry
   refactor to `Option<Status>` is a separate future task.

4. **Pre-existing unused import** in
   `crates/varta-watch/tests/cli_smoke.rs:11` (`Path`) trips clippy
   under `--all-targets` but not under the plan's `cargo clippy
   --workspace -- -D warnings` command (which excludes integration test
   targets). Belongs to the unrelated `recovery-async-spawn` epic.

---

## Next session inputs

**Branch.** Continue from this branch's HEAD.

**Read.** This document and `session-01-handoff.md` (for the full contract).

**Next moves (if any remaining hygiene work surfaces).**
1. README docs sweep (Open Issue 1) when convenient.
2. If a symmetry refactor of `exporter.rs::last_status` is desired,
   convert `Option<u8>` → `Option<Status>` and keep `status_code(status)`
   as the byte-emitter at the Prometheus boundary.

**Forbidden moves (carry-over from S01/S02 plus S03 specifics).**
- Do not add any registry dependency to production crates.
- Do not change `Frame`'s 32-byte wire layout or offsets.
- Do not relax `#[repr(C, align(8))]` on `Frame` or `#[repr(u8)]` on
  `Status`.
- Do not introduce `String`, `Vec`, `Box`, or `format!` on the beat path.
- Do not call `set_nonblocking(false)`.
- Do not change `BeatOutcome`'s variants.

---

## Exit criteria — all met

- ✅ `Frame.status: Status` (typed) and `Frame::new(...)` exists as `pub const fn`.
- ✅ Seven `offset_of!` asserts present in `varta-vlp/src/lib.rs`.
- ✅ `observer.rs` and `tracker.rs` no longer call `Status::try_from_u8(frame.status)`.
- ✅ `grep -rn "status:.*as u8" crates --include="*.rs"` is empty.
- ✅ All quality gates green.
- ✅ `.wolf/` scaffold present and up to date.
- ✅ Handoff written.
