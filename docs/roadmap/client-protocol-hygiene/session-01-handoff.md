# Session 01 — Charter & Audit Handoff

**Epic:** `client-protocol-hygiene`
**Session:** 01 — read-only audit, contracts, and handoff.
**Date:** 2026-05-10.
**Branch:** `epic/client-protocol-hygiene--s01-charter`.

## What this session did

This was a **read-only** audit session. No production code was edited.

1. Audited every `Frame { ... }` construction site and every `status:`
   reference across the workspace.
2. Locked the exact signatures, constants, and rewrite plans for the
   three coherent fixes shipping under this epic:
   - **M6** — broaden `varta-client::beat()`'s error classifier so
     ENOBUFS becomes `BeatOutcome::Dropped` instead of `Failed`.
   - **m1** — type `Frame.status` as the `Status` enum in memory; wire
     bytes unchanged.
   - **m2** — introduce `Frame::new(status, pid, timestamp, nonce,
     payload)` so callsites stop spelling out `magic` and `version`.
3. Stood up the OpenWolf scaffold (`.wolf/anatomy.md`,
   `.wolf/cerebrum.md`, `.wolf/memory.md`, `.wolf/buglog.json`,
   `.wolf/OPENWOLF.md`) for the project.
4. Confirmed the pinned toolchain supports every API the next two
   sessions need (`core::mem::offset_of!`, `io::Error::from_raw_os_error`).

## Toolchain

- `rust-toolchain.toml`: `channel = "stable"`, `components =
  ["rustfmt", "clippy"]`, `profile = "minimal"`.
- Local `rustc --version`: `rustc 1.93.1 (01f6ddf75 2026-02-11)`.
- `core::mem::offset_of!` was stabilised in **Rust 1.77.0 (2024-05)**
  and is therefore available unconditionally on the pinned channel.
- No nightly features required for any of M6 / m1 / m2.

## Files touched (this session)

- `.wolf/OPENWOLF.md` (new) — OpenWolf conventions.
- `.wolf/anatomy.md` (new) — file inventory.
- `.wolf/cerebrum.md` (new) — Preferences / Learnings / Do-Not-Repeat.
- `.wolf/memory.md` (new) — ledger of session activity.
- `.wolf/buglog.json` (new) — empty `[]`.
- `docs/roadmap/client-protocol-hygiene/session-01-handoff.md` (new)
  — this document.

No file under `crates/**` was edited.

---

## Frame literal inventory (canonical re-check command: `grep -rn "Frame {" crates --include="*.rs"`)

| # | File:line | Site | Action under m1 + m2 |
| --- | --- | --- | --- |
| 1 | `crates/varta-vlp/src/lib.rs:77` | `pub struct Frame { ... }` declaration | m1: change `pub status: u8` → `pub status: Status`. |
| 2 | `crates/varta-vlp/src/lib.rs:102` | `impl Frame { ... }` (header, not a literal) | m2: add `pub const fn Frame::new(..)` here. |
| 3 | `crates/varta-vlp/src/lib.rs:136` | `decode()` returns `Frame { ... }` | m1: assign typed `status: Status` instead of raw byte. |
| 4 | `crates/varta-client/src/client.rs:119-127` | `beat()` Frame literal | m1 + m2 (**mandatory**): replace with `Frame::new(status, self.pid, timestamp, self.nonce, payload)`. |
| 5 | `crates/varta-client/src/panic.rs:51-59` | panic-hook Frame literal | m1 + m2 (**mandatory**): replace with `Frame::new(Status::Critical, pid, timestamp, NONCE_TERMINAL, 0)`. |
| 6 | `crates/varta-watch/tests/acceptance.rs:46-54` | `make_frame()` helper body | m1 + m2 (**mandatory**): replace with `Frame::new(status, pid, nonce, nonce, payload)`. |
| 7 | `crates/varta-vlp/tests/frame.rs:14-22` | `fixture_frame()` | m1: typed `status: Status::Ok`. m2: optional — keep as struct literal if Session 03 wants the test to keep proving field order. |
| 8 | `crates/varta-vlp/tests/frame.rs:91-99` | in-range byte loop | **Rewrite required** — see §"Test-rewrite plan for `frame.rs:91-99`" below. |
| 9 | `crates/varta-vlp/tests/frame.rs:109-117` | `payload_preserved_at_u64_max` | m1: typed `status: Status::Critical`. m2: optional. |
| 10 | `crates/varta-bench/src/main.rs:534-545` | binary-size bench template string | m1 + m2 (**mandatory**): replace the in-heredoc literal with `Frame::new(Status::Ok, 0, 0, 1, 0)`. |

`grep -rn "Frame {"` matched 12 lines: 10 distinct sites above plus two
that the grep classifies as "Frame {" but are actually unrelated:
`crates/varta-watch/tests/acceptance.rs:45` is the `make_frame` function
signature (the body is at L46-54, row 6 above) and
`crates/varta-vlp/tests/frame.rs:13` is the `fixture_frame` signature
(the body is row 7 above). They are listed here for completeness.

## Status-byte read/write inventory (`grep -rn "status:" crates --include="*.rs"` and `grep -rn "frame.status" crates --include="*.rs"`)

| # | File:line | Site | m1 expected change |
| --- | --- | --- | --- |
| 1 | `crates/varta-vlp/src/lib.rs:83` | declaration `pub status: u8` | → `pub status: Status` |
| 2 | `crates/varta-vlp/src/lib.rs:109` | `out[3] = self.status` | → `out[3] = self.status as u8` |
| 3 | `crates/varta-vlp/src/lib.rs:128-129` | `let status = bytes[3]; Status::try_from_u8(status)?;` | → `let status = Status::try_from_u8(bytes[3])?;` (typed binding) |
| 4 | `crates/varta-vlp/src/lib.rs:139` | field assignment inside returned `Frame` | → keep field name; bound value is now `Status` |
| 5 | `crates/varta-watch/src/observer.rs:173-174` | `Status::try_from_u8(frame.status).expect(..)` | → `let status = frame.status;` (or use `frame.status` inline) |
| 6 | `crates/varta-watch/src/tracker.rs:106-111` | defensive `match Status::try_from_u8(frame.status)` with `Err(_) => Update::OutOfOrder` | → `let status = frame.status;`; **delete** the `Err(_)` arm — `Frame::decode` already validates. |
| 7 | `crates/varta-watch/src/exporter.rs:140, 148` | `last_status: Option<u8>` exporter state | **No change required for m1.** Exporter retains the wire byte as `u8` for its gauge; converting via `frame.status as u8` upstream is trivial. Session 03 may revisit but it is not required. |
| 8 | `crates/varta-client/src/client.rs:122` | `status: status as u8` inside `beat()` literal | → `status,` (subsumed by `Frame::new(..)` in row 4 above). |
| 9 | `crates/varta-client/src/panic.rs:54` | `status: Status::Critical as u8` | → `status: Status::Critical` (subsumed by `Frame::new(..)`). |
| 10 | `crates/varta-watch/tests/acceptance.rs:49` | `status: status as u8` | → `status,` (subsumed by `Frame::new(..)`). |
| 11 | `crates/varta-vlp/tests/frame.rs:17` | `status: Status::Ok as u8` (fixture) | → `status: Status::Ok` |
| 12 | `crates/varta-vlp/tests/frame.rs:94` | `status: byte` in in-range loop | **Rewrite required** — see §below. |
| 13 | `crates/varta-vlp/tests/frame.rs:103` | `assert_eq!(decoded.status, byte)` | → `assert_eq!(decoded.status, expected)` (typed compare) |
| 14 | `crates/varta-vlp/tests/frame.rs:112` | `status: Status::Critical as u8` | → `status: Status::Critical` |
| 15 | `crates/varta-client/tests/zero_alloc.rs:92` | `assert_eq!(frame.status, Status::Ok as u8)` | → `assert_eq!(frame.status, Status::Ok)` |
| 16 | `crates/varta-client/tests/acceptance.rs:63` | `assert_eq!(frame.status, Status::Ok as u8)` | → `assert_eq!(frame.status, Status::Ok)` |
| 17 | `crates/varta-client/tests/panic_feature.rs:63` | `assert_eq!(frame.status, ...)` over multi-line | → compare against `Status::Critical` (drop `as u8`) |
| 18 | `crates/varta-bench/src/main.rs:537` | template string `status: Status::Ok as u8` | subsumed by `Frame::new(..)` rewrite |

Other `status:` matches are sourced from already-typed sites (watch
event enum, recovery process exit status, exporter test fixtures using
`Status::Ok`) and require no change for m1. The full grep output (24
hits) is the authoritative source; the rows above are the only ones
that need an edit.

---

## M6 contract — `classify_send_error`

**Location.** `crates/varta-client/src/client.rs`. Lives alongside
`Varta` and `BeatOutcome` (already in scope). Add it as a private
free function (or `pub(crate)` if cross-module testing is desired).

**Constants.** Add near the top of the file, **before** any test
module:

```rust
/// Linux value of `ENOBUFS` from `<asm-generic/errno.h>`. Hard-coded
/// because production crates carry zero registry dependencies.
#[cfg(target_os = "linux")]
const ENOBUFS: i32 = 105;

/// Darwin / BSD value of `ENOBUFS`. Hard-coded for the same reason.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
))]
const ENOBUFS: i32 = 55;
```

Targets not listed here (illumos, Solaris, AIX, Windows, etc.) will
fail to compile because no `ENOBUFS` constant is defined. That is the
explicit signal to add a `cfg` arm for the new platform; Hard
Constraint 1 forbids pulling `libc`/`nix` to paper over it. For
short-term portability the belt-and-braces `ErrorKind::OutOfMemory` /
`ErrorKind::StorageFull` arms still cover the case if a different
`raw_os_error` value lands.

**Signature (exact).**

```rust
pub(crate) fn classify_send_error(e: &io::Error) -> BeatOutcome {
    // (a) Raw-OS path first — catches ENOBUFS even when libstd has
    //     not minted a dedicated ErrorKind for it on this toolchain.
    if let Some(code) = e.raw_os_error() {
        if code == ENOBUFS {
            return BeatOutcome::Dropped;
        }
    }

    // (b) Existing ErrorKind arms: peer not there / channel full.
    // (c) Plus belt-and-braces OutOfMemory/StorageFull, which cover
    //     toolchain combos that surface ENOBUFS as a kind, not a
    //     raw_os_error.
    match e.kind() {
        io::ErrorKind::WouldBlock
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::NotFound
        | io::ErrorKind::NotConnected
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::OutOfMemory
        | io::ErrorKind::StorageFull => BeatOutcome::Dropped,

        // (d) Default: Failed with a heap-free clone of the error.
        _ => {
            let cloned = match e.raw_os_error() {
                // Inline Repr::Os(i32) — no heap.
                Some(code) => io::Error::from_raw_os_error(code),
                // Inline Repr::Simple(kind) — no heap.
                None => io::Error::from(e.kind()),
            };
            BeatOutcome::Failed(cloned)
        }
    }
}
```

**Heap-free clone justification.** `io::Error` has four internal
representations: `Os(i32)`, `Simple(ErrorKind)`, `SimpleMessage(&'static
SimpleMessage)`, and `Custom { kind, error: Box<dyn Error + ...> }`.
The first two are inline. `from_raw_os_error` constructs `Os(i32)`;
`From<ErrorKind>` constructs `Simple(kind)`. Neither boxes. The
alternative `io::Error::new(kind, msg)` and `io::Error::other(msg)`
constructors *do* allocate and are therefore explicitly forbidden on
this path — they would break the `zero_alloc` guard-allocator test.

**Why borrowed, not owned.** Taking `&io::Error` keeps the call-site
unchanged in shape — the existing `Err(e)` binding stays — and allows
unit tests to build one `io::Error`, classify it, and re-inspect it.
The Failed branch synthesises a fresh `io::Error` only when the
classifier decides to escalate; that is by definition off the hot
path because `Sent`/`Dropped` paths return earlier without
constructing anything.

**Call-site change.** `crates/varta-client/src/client.rs:90-98`
collapses to:

```rust
fn send_frame(&mut self) -> BeatOutcome {
    match self.sock.send(&self.buf) {
        Ok(_) => BeatOutcome::Sent,
        Err(e) => classify_send_error(&e),
    }
}
```

`BeatOutcome` is **not** modified. No retry logic is added inside
`beat()`. M6 is a classification fix only.

**Unit tests (TDD red first).** Add a `#[cfg(test)] mod tests` block
inside `crates/varta-client/src/client.rs`. The classifier is
`pub(crate)` so the tests can reach it directly without a public
re-export. Suggested coverage:

- `enobufs_is_classified_as_dropped` — build
  `io::Error::from_raw_os_error(ENOBUFS)` and assert `Dropped`. This
  test is `#[cfg(any(target_os = "linux", target_os = "macos", ...))]`
  to match the constant's `cfg` arms.
- `each_existing_kind_is_dropped` — iterate
  `[WouldBlock, ConnectionRefused, ConnectionReset, NotFound,
  NotConnected, BrokenPipe]`, build
  `io::Error::from(kind)` and assert `Dropped`.
- `out_of_memory_kind_is_dropped` — assert `Dropped` for
  `io::ErrorKind::OutOfMemory`.
- `storage_full_kind_is_dropped` — assert `Dropped` for
  `io::ErrorKind::StorageFull`.
- `unrelated_kind_yields_failed_preserving_raw_os_error` — build
  `io::Error::from_raw_os_error(1)` (EPERM); assert `Failed(_)` whose
  inner `raw_os_error()` is `Some(1)`.
- `unrelated_kind_with_no_raw_os_error_yields_failed_preserving_kind`
  — build `io::Error::from(ErrorKind::Other)`; assert `Failed(_)`
  whose inner `kind()` is `ErrorKind::Other`.

**End-to-end clean-up.** Drop the `BeatOutcome::Failed(_)` arm and the
explanatory comment block at
`crates/varta-tests/tests/end_to_end.rs:120-145`. The loop becomes:

```rust
match agent.beat(Status::Ok, 0) {
    BeatOutcome::Sent => break,
    BeatOutcome::Dropped => {
        tries += 1;
        if tries > 5_000 {
            panic!("kernel never accepted a beat within 5000 retries");
        }
        std::thread::sleep(Duration::from_micros(500));
    }
    BeatOutcome::Failed(e) => panic!("unexpected Failed: {e}"),
}
```

`Failed(_)` now signals a genuine bug (e.g. an unhandled OS error) and
should fail the test loudly rather than silently retry.

---

## m1 contract — typed `Frame.status: Status`

**Field retype.** `crates/varta-vlp/src/lib.rs:83`:

```rust
// Was: pub status: u8,
pub status: Status,
```

`Status` already carries `#[repr(u8)]`, so the field's width and
alignment contribution remain one byte. The struct's `repr(C,
align(8))` guarantees field order is unchanged. The on-wire `[u8; 32]`
encoding (the `GOLDEN_BYTES` fixture at `crates/varta-vlp/tests/frame.rs:26`)
is byte-identical before and after this change.

**`encode` change.** `crates/varta-vlp/src/lib.rs:109`:

```rust
// Was: out[3] = self.status;
out[3] = self.status as u8;
```

**`decode` change.** `crates/varta-vlp/src/lib.rs:128-129` and the
returned struct at `:136-144`:

```rust
// Was: let status = bytes[3]; Status::try_from_u8(status)?;
let status = Status::try_from_u8(bytes[3])?;
// ... unchanged integer parses ...
Ok(Frame {
    magic,
    version,
    status,        // typed Status now
    pid,
    timestamp,
    nonce,
    payload,
})
```

**Compile-time asserts (additions).** Existing size/align asserts at
`crates/varta-vlp/src/lib.rs:99-100` stay. Add the following six
offset asserts immediately after them:

```rust
const _: () = assert!(core::mem::offset_of!(Frame, magic)     == 0);
const _: () = assert!(core::mem::offset_of!(Frame, version)   == 2);
const _: () = assert!(core::mem::offset_of!(Frame, status)    == 3);
const _: () = assert!(core::mem::offset_of!(Frame, pid)       == 4);
const _: () = assert!(core::mem::offset_of!(Frame, timestamp) == 8);
const _: () = assert!(core::mem::offset_of!(Frame, nonce)     == 16);
const _: () = assert!(core::mem::offset_of!(Frame, payload)   == 24);
```

`offset_of!` is stable since Rust 1.77.0 (May 2024); the pinned
toolchain is far newer.

**Read-side consumer changes (cascading).**

- `crates/varta-watch/src/observer.rs:171-181` — remove the
  `Status::try_from_u8(frame.status).expect("Frame::decode validated
  the status byte")` block. The `Event::Beat { ... status: frame.status,
  ... }` field can now be assigned directly.
- `crates/varta-watch/src/tracker.rs:105-111` — remove the
  defensive `match Status::try_from_u8(frame.status)` and its
  `Err(_) => Update::OutOfOrder` arm. Replace with
  `let status = frame.status;`. The invariant is now type-enforced:
  every `Frame` reaching `Tracker::record` originated from
  `Frame::decode` (in `observer.rs:171`), which already validates the
  status byte; and `Frame::new` (under m2) takes a typed `Status`
  parameter.
- `crates/varta-client/src/client.rs:122` — drop `as u8` cast (will be
  subsumed by `Frame::new(status, ...)` in m2).
- `crates/varta-client/src/panic.rs:54` — drop `as u8` cast (also
  subsumed by `Frame::new(Status::Critical, ...)`).
- `crates/varta-watch/tests/acceptance.rs:49` — drop `as u8` cast
  (subsumed by `Frame::new(..)`).
- `crates/varta-watch/tests/exporter_endpoint.rs` — no change. The
  `Event::Beat { status: Status::Ok, .. }` literals here already use
  typed `Status`. The file contains no `Frame { ... }` literal.
- `crates/varta-watch/src/exporter.rs` — no change for m1. The
  exporter retains its `last_status: Option<u8>` internal state for
  the Prometheus gauge; values come from `frame.status as u8` (one
  more cast at the boundary, which Session 03 will add inline where
  the gauge is set). This is intentionally not folded into m1.

**Test consumer changes (`as u8` → typed).**

- `crates/varta-client/tests/zero_alloc.rs:92` —
  `assert_eq!(frame.status, Status::Ok as u8)` →
  `assert_eq!(frame.status, Status::Ok)`.
- `crates/varta-client/tests/acceptance.rs:63` — same shape.
- `crates/varta-client/tests/panic_feature.rs:62-66` —
  `Status::Critical as u8` → `Status::Critical`.
- `crates/varta-vlp/tests/frame.rs:17` —
  `status: Status::Ok as u8` → `status: Status::Ok`.
- `crates/varta-vlp/tests/frame.rs:112` —
  `status: Status::Critical as u8` → `status: Status::Critical`.
- `crates/varta-vlp/tests/frame.rs:91-104` — rewrite, see next
  section.

---

## Test-rewrite plan for `crates/varta-vlp/tests/frame.rs:91-99`

The current loop body constructs a `Frame` literal with `status:
byte` where `byte: u8`. Under m1 this no longer compiles — the field
is now `Status`, not `u8`. The choice is between (a) feeding the
in-scope typed `expected: Status` into the literal, or (b) keeping
the literal raw and mutating the encoded byte after the fact.

**Chosen approach: option (a).** The loop only iterates the four
valid status bytes (`0..=3`), so `expected: Status` already carries
exactly the typed form of `byte`. The body becomes:

```rust
for (byte, expected) in [
    (0u8, Status::Ok),
    (1u8, Status::Degraded),
    (2u8, Status::Critical),
    (3u8, Status::Stall),
] {
    assert_eq!(
        Status::try_from_u8(byte).expect("known byte must decode"),
        expected,
        "byte {byte:#x} did not map to {expected:?}"
    );

    let frame = Frame::new(expected, 7, 0, 1, 0);
    let mut buf = [0u8; 32];
    frame.encode(&mut buf);
    let decoded = Frame::decode(&buf).expect("variant frame must decode");
    assert_eq!(decoded.status, expected);
}
```

Notes:
- The new body adopts `Frame::new` (m2) inline. This is *not*
  optional in this test — see "Rationale" below.
- The final `assert_eq!(decoded.status, byte)` becomes
  `assert_eq!(decoded.status, expected)` because the field is typed
  now; a `u8` comparison would not compile.
- The `byte` variable in the tuple destructure is retained so the
  call to `Status::try_from_u8(byte)` still proves the conversion
  function works for every valid byte.

**Bad-byte coverage.** `decode_rejects_bad_status` at
`crates/varta-vlp/tests/frame.rs:71-75` already constructs an invalid
status by mutating the encoded byte (`buf[3] = 0x09`) rather than
through a `Frame` literal. It needs **no** change for m1. This
mechanism — mutate the byte post-encode — is the canonical way to
build "invalid frames" under the typed-status field; tests that need
new bad-byte coverage in future should follow the same pattern.

**Rationale for adopting `Frame::new` inside the loop.** Two reasons.
First, `expected: Status` is the only natural value to put in the
`status` slot of a `Frame { ... }` literal under m1, and once every
field except `magic`/`version` is already supplied locally, the
literal is strictly longer than the equivalent `Frame::new(..)`
call. Second, this test is *the* showcase test for the new typed
field; demonstrating `Frame::new` here doubles as user-facing
documentation.

**Optional adoption sites.** `fixture_frame` (L13-23) and
`payload_preserved_at_u64_max` (L107-117) may stay as struct literals
under Session 03's discretion. Argument for keeping them: the test
file's entire role is to prove the wire layout, and struct literals
make field order obvious to a reader. Argument for converting: the
size/offset asserts (added under m1) carry the layout proof and
already-typed `status: Status::Ok` says exactly what we mean. Either
is acceptable; the choice is documented in the Session 03 handoff.

---

## m2 contract — `Frame::new`

**Signature (exact).**

```rust
impl Frame {
    /// Construct a new frame with the canonical `MAGIC` prefix and
    /// `VERSION` byte. All other fields are caller-supplied.
    pub const fn new(
        status: Status,
        pid: u32,
        timestamp: u64,
        nonce: u64,
        payload: u64,
    ) -> Frame {
        Frame {
            magic: MAGIC,
            version: VERSION,
            status,
            pid,
            timestamp,
            nonce,
            payload,
        }
    }
    // ... existing encode, decode ...
}
```

- `const fn` so the constructor is usable from `const` contexts.
  Nothing in the body precludes it (`MAGIC` and `VERSION` are `const`,
  field assignment of `Copy` types is `const`-eligible).
- Fields stay `pub`. Callers that want raw literal control still have
  it. `Frame::new` is opt-in sugar.

**Mandatory adoption sites.** These four sites lose the
`magic: MAGIC, version: VERSION` boilerplate and must adopt
`Frame::new`:

- `crates/varta-client/src/client.rs:119-127` (the `beat()` hot path).
- `crates/varta-client/src/panic.rs:51-59` (the panic-hook hot path).
- `crates/varta-watch/tests/acceptance.rs:46-54` (the `make_frame`
  helper).
- `crates/varta-bench/src/main.rs:534-545` (the binary-size bench
  template string — the heredoc content also needs `Frame::new(..)`
  so the generated bench binary actually compiles).
- `crates/varta-vlp/tests/frame.rs:91-104` (the in-range byte loop,
  per the rewrite plan above).

**Optional adoption sites.** `fixture_frame` (`frame.rs:13-23`) and
`payload_preserved_at_u64_max` (`frame.rs:107-117`). Session 03's
call.

---

## Risks recorded for Sessions 02 / 03

| # | Risk | Mitigation |
| --- | --- | --- |
| R1 | A new `Frame { ... }` literal lands between this audit and Session 03's edits, and it gets missed. | Session 03's step 1 is to re-run `grep -rn "Frame {" crates --include="*.rs"` and diff against the inventory above. |
| R2 | `io::Error::from_raw_os_error(code)` semantics change between toolchain versions. | Function is stable since 1.0; observable behaviour is fixed by stdlib API guarantees. The Failed-branch unit tests assert `raw_os_error()` round-trips identically. |
| R3 | An unlisted platform maps `ENOBUFS` to a different errno. | The constant is `cfg`-gated for the supported targets; unlisted platforms fail to compile rather than silently mis-classify. The belt-and-braces `ErrorKind::{OutOfMemory, StorageFull}` arms cover the case if a different `raw_os_error` value lands. |
| R4 | `offset_of!` asserts uncover a layout drift on some target (padding inserted between `version: u8` and `status: u8`). | Already implicitly checked by the size assert; the new asserts make the contract explicit. If a future field reshuffle breaks them, the build fails at compile time — that is the mitigation. |
| R5 | Typed `status` field changes `Frame`'s automatic `Debug` output. | `Status` already derives the same trait set as `Frame`. No consumer matches on the textual `Debug` output. |
| R6 | Removing the defensive `Status::try_from_u8` in `tracker.rs` exposes a path where an attacker bypasses validation. | All `Frame` instances reaching `Tracker::record` originate from `Frame::decode` (`observer.rs:171`). No public API exposes a `Frame` constructor that skips validation; `Frame::new` consumes a typed `Status`, so the invariant is type-enforced. |
| R7 | The bench template string in `varta-bench/src/main.rs:534-545` is double-escaped and easy to break. | Session 03 must run `cargo run -p varta-bench --release -- binary-size` end-to-end before declaring done. |

---

## Quality gates run this session

All four ran clean against the pre-existing source tree. No production
code was edited; the gates serve as a baseline for Sessions 02 / 03 to
diff against.

- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace -- -D warnings` — clean.
- `cargo build --workspace` — succeeds.
- `cargo test --workspace` — passes.

(Detailed runner output is in the commit message and the session's
shell history; not duplicated here.)

---

## Exit criteria — satisfied

- [x] Handoff lists every `Frame {` literal in the workspace by
      file:line.
- [x] Handoff specifies the exact `classify_send_error` signature and
      ENOBUFS constants per OS.
- [x] Handoff specifies the exact `Frame::new` signature and the
      rewrite plan for `frame.rs:91-99`.
- [x] Workspace still compiles and all existing tests still pass — no
      production code was edited this session.

---

## Next session inputs (Session 02 — M6)

**Branch.** Continue on `epic/client-protocol-hygiene--s01-charter` or
cut a fresh branch off it; the epic operator will route.

**Read.** This handoff (full).

**Files to edit (M6, exact paths):**

- `crates/varta-client/src/client.rs` — add `const ENOBUFS` (cfg-gated),
  add `pub(crate) fn classify_send_error`, simplify `send_frame`.
  Add `#[cfg(test)] mod tests` block (currently absent).
- `crates/varta-tests/tests/end_to_end.rs:120-145` — drop the
  `Failed(_)` arm and the workaround comment block; treat `Failed`
  as a test failure.

**Commands.**

```bash
cargo test -p varta-client                      # new unit tests
cargo test -p varta-tests --test end_to_end     # end-to-end contract
cargo build --workspace --release               # binary-size sanity
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace                          # full sweep
```

**Forbidden moves.** No new entries in `[dependencies]` for
`varta-client`, `varta-vlp`, or `varta-watch`. No retry logic inside
`beat()`. No change to `BeatOutcome` variants. No `set_nonblocking(false)`.

---

## Next session inputs (Session 03 — m1 + m2)

**Branch.** Continue from Session 02's head, or cut a fresh branch.

**Read.** This handoff (full), plus Session 02's handoff (which lands
ENOBUFS classification and the `classify_send_error` unit-test
scaffold that Session 03 must keep green).

**Order of operations.**

1. Re-run `grep -rn "Frame {" crates --include="*.rs"` and diff
   against the inventory in this handoff. Investigate any new sites.
2. Edit `crates/varta-vlp/src/lib.rs` first: retype the field, change
   `encode`/`decode`, add the offset asserts, add `Frame::new`. The
   compile errors that fan out are the to-do list for the rest of the
   session.
3. Fix every read-side consumer until `cargo build --workspace` is
   green. The list under "m1 contract — typed Frame.status: Status"
   is the canonical sweep.
4. Rewrite `crates/varta-vlp/tests/frame.rs:91-104` per the plan in
   this handoff.
5. Run the full gate set, plus `cargo run -p varta-bench --release
   -- binary-size` to exercise the bench template string.

**Forbidden moves.** Same as Session 02 plus: do not move the status
byte off offset 3. Do not change the encoded width of any field. Do
not relax the `repr(C, align(8))` attribute on `Frame`. Do not break
`GOLDEN_BYTES` at `crates/varta-vlp/tests/frame.rs:26`.

---

## Open issues

None blocking. The exporter's `last_status: Option<u8>` retention
(item 7 in the status-byte table) is a recorded non-change: Session
03 may revisit if it prefers a typed `Option<Status>` for symmetry,
but the wire-gauge semantics are preserved either way.
