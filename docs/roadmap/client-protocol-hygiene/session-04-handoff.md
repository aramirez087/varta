# Session 04 — CI Gate Go/No-Go

**Epic:** `client-protocol-hygiene`
**Session:** 04 — full quality-gate run + go/no-go report
**Date:** 2026-05-10
**Branch:** `epic/client-protocol-hygiene--s04-ci-gate`

---

## What changed

No production source files were modified this session. All gates passed on the
first attempt against the merged epic branch (sessions 01–03 delivered clean
code; no regression was introduced during integration). The only new files
are the `.wolf/` scaffold and this handoff document.

---

## Files touched

- `.wolf/OPENWOLF.md` — new (scaffold)
- `.wolf/anatomy.md` — new (file inventory for this worktree)
- `.wolf/cerebrum.md` — new (union of S01–S03 learnings + do-not-repeat list)
- `.wolf/memory.md` — new (ledger of S04 actions)
- `.wolf/buglog.json` — new (`[]`, no bugs surfaced)
- `docs/roadmap/client-protocol-hygiene/session-04-handoff.md` — this file

---

## Five verification greps

### 1. Zero-dependency invariant

```
$ grep -A20 "\[dependencies\]" \
    crates/varta-vlp/Cargo.toml \
    crates/varta-client/Cargo.toml \
    crates/varta-watch/Cargo.toml
```

```
crates/varta-vlp/Cargo.toml:[dependencies]
--
crates/varta-client/Cargo.toml:[dependencies]
crates/varta-client/Cargo.toml-
crates/varta-client/Cargo.toml-[dependencies.varta-vlp]
crates/varta-client/Cargo.toml-path = "../varta-vlp"
...
crates/varta-watch/Cargo.toml:[dependencies]
crates/varta-watch/Cargo.toml-
crates/varta-watch/Cargo.toml-[dependencies.varta-vlp]
crates/varta-watch/Cargo.toml-path = "../varta-vlp"
```

**Result:** PASS — every `[dependencies]` section is empty or path-only. No
registry crate names present.

---

### 2. Wire layout — `offset_of!` asserts present

```
$ grep -n "offset_of!" crates/varta-vlp/src/lib.rs
```

```
102:const _: () = assert!(core::mem::offset_of!(Frame, magic) == 0);
103:const _: () = assert!(core::mem::offset_of!(Frame, version) == 2);
104:const _: () = assert!(core::mem::offset_of!(Frame, status) == 3);
105:const _: () = assert!(core::mem::offset_of!(Frame, pid) == 4);
106:const _: () = assert!(core::mem::offset_of!(Frame, timestamp) == 8);
107:const _: () = assert!(core::mem::offset_of!(Frame, nonce) == 16);
108:const _: () = assert!(core::mem::offset_of!(Frame, payload) == 24);
```

**Result:** PASS — all seven asserts present covering every field.

---

### 3. No `status: ... as u8` cast remains

```
$ grep -rn "status:.*as u8" crates --include="*.rs"
```

*(no output)*

**Result:** PASS — zero hits.

---

### 4. E2E workaround gone; `Failed` arm panics

```
$ grep -n "transient, retry" crates/varta-tests/tests/end_to_end.rs
```

*(no output)*

```
$ grep -A2 "BeatOutcome::Failed" crates/varta-tests/tests/end_to_end.rs
```

```
                    BeatOutcome::Failed(e) => panic!("unexpected hard failure: {e}"),
                }
            }
```

**Result:** PASS — zero workaround lines; `Failed(_)` panics immediately.

---

### 5. Zero-alloc test file exists

`crates/varta-client/tests/zero_alloc.rs` — confirmed present.
Invocation: `cargo test -p varta-client --test zero_alloc`
Covered by Gate 3 (`cargo test --workspace`): **1 passed**.

---

## Gate results

### Gate 1 — `cargo fmt --all -- --check`

```
$ cargo fmt --all -- --check
```

*(no output)*

**Result:** PASS — clean.

---

### Gate 2 — `cargo clippy --workspace -- -D warnings`

```
$ cargo clippy --workspace -- -D warnings
    Checking varta-vlp v0.1.0 (...)
    Checking varta-tests v0.1.0 (...)
    Checking varta-client v0.1.0 (...)
    Checking varta-watch v0.1.0 (...)
    Checking varta-bench v0.1.0 (...)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.16s
```

**Result:** PASS — clean. No warnings, no errors.

---

### Gate 3 — `cargo test --workspace`

```
$ cargo test --workspace
   ...
   Finished `test` profile [unoptimized + debuginfo] target(s) in 0.59s
```

Crate-by-crate results:

| Crate / test binary | Tests | Result |
|---------------------|-------|--------|
| `varta-client` unit | 0 | ok |
| `varta-client/tests/acceptance` | 4 | ok |
| `varta-client/tests/classifier` | 4 | ok |
| `varta-client/tests/panic_feature` | 3 | ok |
| `varta-client/tests/zero_alloc` | 1 | ok |
| `varta-tests/tests/end_to_end` | 2 | ok |
| `varta-vlp` unit | 0 | ok |
| `varta-vlp/tests/frame` | 9 | ok |
| `varta-watch` unit | 24 | ok |
| `varta-watch/tests/acceptance` | 5 | ok |
| `varta-watch/tests/cli_smoke` | 4 | ok |
| `varta-watch/tests/exporter_endpoint` | 3 | ok |
| `varta-watch/tests/recovery_e2e` | 6 | ok |
| `varta-client` doctests | 1 | ok |

Note: `cli_smoke.rs:11` emits a pre-existing `unused_imports` warning for `Path`
(from the `recovery-async-spawn` epic). It does not surface under
`cargo clippy --workspace -- -D warnings` (integration test targets excluded by
default). Non-blocking; captured as Open Issue 4.

**Result:** PASS — all tests pass.

---

### Gate 4 — `cargo build --workspace --release`

```
$ cargo build --workspace --release
   Compiling varta-vlp v0.1.0 (...)
   Compiling varta-tests v0.1.0 (...)
   Compiling varta-watch v0.1.0 (...)
   Compiling varta-client v0.1.0 (...)
   Compiling varta-bench v0.1.0 (...)
    Finished `release` profile [optimized] target(s) in 0.36s
```

**Result:** PASS — release build clean.

---

### Gate 5 — `cargo test -p varta-tests --test end_to_end`

```
$ cargo test -p varta-tests --test end_to_end
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.00s
     Running tests/end_to_end.rs (...)
running 2 tests
test client_to_observer_to_recovery_full_loop ... starting
test client_to_observer_to_recovery_full_loop ... ok
test panic_handler_critical_beat_visible_in_metrics ... starting
test panic_handler_critical_beat_visible_in_metrics ... ok

test result: ok. 2 passed; 0 failed; 0 ignored
```

**Result:** PASS — both contracts satisfied.

---

### Gate 6 — `cargo test -p varta-client --test classifier`

```
$ cargo test -p varta-client --test classifier
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.13s
     Running tests/classifier.rs (...)

running 4 tests
test connection_refused_classifies_as_dropped ... ok
test enobufs_classifies_as_dropped ... ok
test permission_denied_classifies_as_failed ... ok
test wouldblock_classifies_as_dropped ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**Result:** PASS — all four classifier tests pass including ENOBUFS on macOS.

---

### Gate 7 — `cargo test -p varta-vlp`

```
$ cargo test -p varta-vlp
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.00s
     Running tests/frame.rs (...)

running 9 tests
test decode_error_implements_display_and_error ... ok
test decode_rejects_bad_status ... ok
test decode_rejects_bad_magic ... ok
test decode_rejects_bad_version ... ok
test every_status_variant_round_trips ... ok
test frame_alignment_is_eight_at_runtime ... ok
test frame_round_trip_matches_golden_bytes ... ok
test frame_size_is_thirty_two_bytes_at_runtime ... ok
test payload_preserved_at_u64_max ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**Result:** PASS — all 9 tests pass, including `frame_round_trip_matches_golden_bytes`
(wire encoding unchanged) and `every_status_variant_round_trips` (typed-status
round-trip with `Frame::new`).

---

## Decisions made

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | No production source changes | All seven gates passed on the first run against the merged epic branch. S02 and S03 delivered clean, non-regressing code. |
| D2 | `.wolf/` scaffold bootstrapped from S02 + S03 handoff content | OpenWolf rules require the scaffold before any code action. The `cerebrum.md` is the union of S02 and S03 learnings — the `.wolf/` collision noted in S03 Open Issue 2 is now resolved. |
| D3 | README open issue carried forward without fix | `crates/varta-vlp/README.md:47-50` still shows an outdated `Frame { ... status: Status::Ok as u8 }` example. Fixing it in a CI-gate session would confuse scope. Non-blocking. |

---

## Open issues (carried forward)

1. **`crates/varta-vlp/README.md:47-50`** — still shows `status: Status::Ok as u8`
   which is a lie under m1 (the field is typed `Status`). README is not compiled;
   non-blocking. A docs sweep should update it to use `Frame::new(Status::Ok, ...)`.

3. **`crates/varta-watch/src/exporter.rs:140`** — `last_status: Option<u8>`
   retained by design (S01 plan). The Prometheus gauge consumes raw bytes. An
   optional symmetry refactor to `Option<Status>` is a separate future task.

4. **`crates/varta-watch/tests/cli_smoke.rs:11`** — pre-existing unused `Path`
   import from the `recovery-async-spawn` epic. Out of scope; belongs to that
   epic's cleanup.

*(S03 Open Issue 2 — `.wolf/` scaffold collision — is now closed: this session
bootstrapped a unified scaffold on the merged epic branch.)*

---

## Net effect of the epic (M6 + m1 + m2)

The `client-protocol-hygiene` epic ships three coherent improvements to the
`varta-client` / `varta-vlp` surface. **M6** (Session 02) correctly classifies
`ENOBUFS` — a transient kernel-buffer-pressure errno — as `BeatOutcome::Dropped`
rather than `Failed`, eliminating the in-source workaround that had lived in
the end-to-end test since the codebase's first integration run; `Failed` now
means a genuine unexpected error and panics immediately in CI. **m1** (Session 03)
retypes `Frame.status` from `u8` to `Status` in memory, so decode validation
happens exactly once at the protocol boundary and the defensive
`Status::try_from_u8` calls in `varta-watch`'s observer and tracker are gone;
seven compile-time `offset_of!` asserts lock the wire layout so any accidental
padding change will fail the build rather than silently shift bytes. **m2**
(Session 03) adds `Frame::new(status, pid, timestamp, nonce, payload)` as a
`pub const fn`, removing the `magic: MAGIC, version: VERSION` boilerplate from
every callsite and making frame construction both shorter and less error-prone.
The wire protocol — 32 bytes, 8-byte aligned, status at offset 3, little-endian
integers — is byte-identical before and after the epic, as proven by the
unchanged `GOLDEN_BYTES` fixture. Residual risks worth flagging: the
`classify_send_error` function is `pub` (not `pub(crate)`) because of E0364;
it should be treated as internal-only despite its visibility. Platforms not
listed in the `cfg`-gated `ENOBUFS` constant blocks (illumos, Solaris, Windows)
will fail to compile `varta-client` — this is the intended signal to add a new
`cfg` arm rather than pull `libc`.

---

## Verdict

**GO**

Every gate passed on the first attempt. No production source changes were
required. The epic's three fixes (M6, m1, m2) are clean, tested, and
wire-compatible with the existing VLP contract.
