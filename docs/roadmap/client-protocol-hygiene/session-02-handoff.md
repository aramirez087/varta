# Session 02 — M6 ENOBUFS Classifier Handoff

**Epic:** `client-protocol-hygiene`
**Session:** 02 — ENOBUFS classifier implementation.
**Date:** 2026-05-10.
**Branch:** `epic/client-protocol-hygiene--s02-enobufs-classifier`.

---

## What changed

### `crates/varta-client/src/client.rs`

1. Added two `cfg`-gated `ENOBUFS` constants at module scope (before any `impl`
   block), one comment-cited to `<asm-generic/errno.h>` (Linux = 105) and one
   to `<sys/errno.h>` (Darwin/BSD = 55). Unlisted platforms refuse to compile —
   the compiler error is the signal to add a new `cfg` arm.

2. Extracted `pub fn classify_send_error(e: &io::Error) -> BeatOutcome`. Branch
   order:
   - **(a)** Raw-OS check: `e.raw_os_error() == Some(ENOBUFS)` → `Dropped`.
   - **(b)** Existing `ErrorKind` arms (`WouldBlock`, `ConnectionRefused`,
     `ConnectionReset`, `NotFound`, `NotConnected`, `BrokenPipe`) → `Dropped`.
   - **(c)** Belt-and-braces `OutOfMemory | StorageFull` → `Dropped`.
   - **(d)** Fall-through → `Failed(cloned)` where the clone uses
     `io::Error::from_raw_os_error(code)` (no heap) when a raw OS code is
     present, and `io::Error::from(e.kind())` (no heap) otherwise.

3. Simplified `send_frame()` to a one-line dispatch:
   ```rust
   fn send_frame(&mut self) -> BeatOutcome {
       match self.sock.send(&self.buf) {
           Ok(_) => BeatOutcome::Sent,
           Err(e) => classify_send_error(&e),
       }
   }
   ```

### `crates/varta-client/src/lib.rs`

Added `classify_send_error` to the public re-export list:
```rust
pub use client::{classify_send_error, BeatOutcome, Varta};
```

**Deviation from plan:** The session 01 contract specified `pub(crate)`, but
`pub(crate)` items cannot be re-exported as `pub` (E0364). Since integration
tests in `tests/classifier.rs` live in a separate crate and import via
`varta_client::classify_send_error`, the function must be `pub`. This is
recorded as a decision; the function is not part of the stable API contract
but is publicly visible for testing purposes.

### `crates/varta-client/tests/classifier.rs` (new)

Four integration tests for `classify_send_error`:

| Test | Outcome expected |
|------|-----------------|
| `enobufs_classifies_as_dropped` | `Dropped` (cfg-gated to supported OS list) |
| `wouldblock_classifies_as_dropped` | `Dropped` |
| `connection_refused_classifies_as_dropped` | `Dropped` |
| `permission_denied_classifies_as_failed` | `Failed(_)` |

The `ENOBUFS_FOR_THIS_OS` constant is duplicated in this file (same `cfg`
guards, same values) because the `ENOBUFS` constant in `client.rs` is
module-private. If the value ever changes, both sites must be updated.

### `crates/varta-tests/tests/end_to_end.rs`

Replaced the dual `Dropped | Failed(_)` transient arm with:
```rust
BeatOutcome::Sent => break,
BeatOutcome::Dropped => { tries += 1; /* back-off */ }
BeatOutcome::Failed(e) => panic!("unexpected hard failure: {e}"),
```
The old comment explaining the ENOBUFS mis-classification was replaced with
a comment confirming the fix. Any `Failed` outcome now panics, surfacing
genuine unexpected OS errors immediately in CI.

### `.wolf/` scaffold (new)

Bootstrapped `OPENWOLF.md`, `anatomy.md`, `cerebrum.md`, `memory.md`, and
`buglog.json` in this worktree (the session 01 charter branch had them but
they are not in this worktree).

---

## Decisions made

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | `classify_send_error` is `pub`, not `pub(crate)` | Integration tests in `tests/` are a separate crate; `pub(crate)` cannot be re-exported as `pub` (E0364). The function is documented as internal-only in its doc-comment. |
| D2 | `cfg`-gated numeric constants, no `libc` | Hard constraint 1: zero registry dependencies. Unlisted platforms fail to compile — that is the intended signal. |
| D3 | Raw-OS check before `ErrorKind` match | `ENOBUFS` maps to `ErrorKind::Other` on all stable toolchains today. Checking `raw_os_error()` first ensures correct classification even if a future toolchain adds a dedicated kind. |
| D4 | Heap-free `Failed` clone | Hard constraint 2: zero heap allocation on the beat path. `io::Error::from_raw_os_error` and `io::Error::from(kind)` construct inline reprs. `io::Error::new(kind, string)` is forbidden. |
| D5 | `Failed(_)` panics in the e2e retry loop | Post-fix, `Failed` signals a genuine unexpected OS error. Panicking immediately with the error message makes CI failures self-documenting. |

---

## Test outputs (all gates)

```
cargo fmt --all -- --check          → clean (no output)
cargo clippy --workspace -- -D warnings → clean; Finished dev profile
cargo test -p varta-client          → 4 classifier + 4 acceptance + 1 zero_alloc + 3 panic_feature; all ok
cargo test --workspace              → all crates; all ok; 2 e2e tests ok
cargo build --workspace --release   → Finished release profile
cargo test -p varta-tests --test end_to_end → 2 passed; 0 failed
```

Classifier test detail:
```
running 4 tests
test connection_refused_classifies_as_dropped ... ok
test enobufs_classifies_as_dropped ... ok
test permission_denied_classifies_as_failed ... ok
test wouldblock_classifies_as_dropped ... ok
test result: ok. 4 passed; 0 failed
```

---

## Files touched

- `crates/varta-client/src/client.rs` — ENOBUFS constants, `classify_send_error`, simplified `send_frame`.
- `crates/varta-client/src/lib.rs` — re-export `classify_send_error`.
- `crates/varta-client/tests/classifier.rs` — new; four classifier tests.
- `crates/varta-tests/tests/end_to_end.rs` — workaround removed; `Failed(_)` now panics.
- `.wolf/OPENWOLF.md` — new (scaffold).
- `.wolf/anatomy.md` — new (scaffold + new classifier.rs entry).
- `.wolf/cerebrum.md` — new (scaffold).
- `.wolf/memory.md` — new (scaffold + S02 entries).
- `.wolf/buglog.json` — new (B001: ENOBUFS misclassification).
- `docs/roadmap/client-protocol-hygiene/session-02-handoff.md` — this file.

---

## Open issues for Session 03

1. **`classify_send_error` is `pub`** — the plan said `pub(crate)`. The change
   is documented in D1. Session 03 may choose to wrap it in a `#[doc(hidden)]`
   attribute to signal it is not stable API, but this is cosmetic.

2. **MSRV note** — `io::ErrorKind::StorageFull` requires Rust ≥ 1.83.0. The
   pinned toolchain is 1.93.1. If the pin ever regresses below 1.83, the arm
   causes a compile error. Document in `rust-toolchain.toml` comments if desired.

3. **Unsupported OS** — illumos, Solaris, AIX, Windows have no `ENOBUFS`
   constant defined. Those platforms will fail to compile `varta-client`. The
   belt-and-braces `OutOfMemory | StorageFull` arms provide partial coverage
   but the compile failure is the explicit signal to add a `cfg` arm.

---

## Next session inputs (Session 03 — m1 + m2)

**Branch.** Continue from this branch's HEAD.

**Read.** `session-01-handoff.md` (full m1 + m2 contracts) and this document.

**Order of operations.**
1. Re-run `grep -rn "Frame {" crates --include="*.rs"` and diff against
   the session 01 inventory (10 sites). Investigate any new sites.
2. Edit `crates/varta-vlp/src/lib.rs` first: retype `status: u8` → `status: Status`,
   update `encode` (`self.status as u8`), update `decode` (typed binding),
   add six `offset_of!` compile-time asserts, add `Frame::new`.
3. Fix every downstream consumer until `cargo build --workspace` is green.
   Canonical sweep in session 01 handoff §"m1 contract".
4. Rewrite `crates/varta-vlp/tests/frame.rs:91-104` per the session 01 plan.
5. Run full gate set plus `cargo run -p varta-bench --release -- binary-size`.

**Forbidden moves.** Same as session 02 plus: do not move `status` off wire
offset 3, do not change encoded field widths, do not relax `repr(C, align(8))`
on `Frame`, do not break `GOLDEN_BYTES` at `crates/varta-vlp/tests/frame.rs:26`.
