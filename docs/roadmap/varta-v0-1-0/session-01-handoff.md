# Session 01 — Handoff (Charter & VLP)

## Done

- `Cargo.toml` — virtual workspace (`resolver = "2"`) with five members.
- `rust-toolchain.toml` — pins `stable` + `rustfmt` + `clippy` (`profile = "minimal"`).
- `crates/varta-vlp/Cargo.toml` — package manifest with literal empty `[dependencies]`.
- `crates/varta-vlp/src/lib.rs` — full `Frame`/`Status`/`DecodeError`/`MAGIC`/`VERSION` implementation; compile-time `size_of`/`align_of` asserts; `core::error::Error` impl on `DecodeError`.
- `crates/varta-vlp/tests/frame.rs` — 9 integration tests covering golden-byte round-trip, every Status variant, bad-magic / bad-version / bad-status decode rejection, payload preservation at `u64::MAX`, runtime size + alignment, `Display` + `core::error::Error` traits.
- `crates/varta-client/{Cargo.toml,src/lib.rs}` — skeleton with empty `[dependencies]`; no public items (Session 02 lands the agent surface).
- `crates/varta-watch/{Cargo.toml,src/lib.rs,src/main.rs}` — lib + bin skeleton; binary prints a single placeholder line to stderr (`eprintln!` permitted in this binary only).
- `crates/varta-tests/{Cargo.toml,src/lib.rs}` — placeholder library; tests land in Session 06.
- `crates/varta-bench/{Cargo.toml,src/main.rs}` — placeholder binary (`fn main() {}`); subcommands land in Session 06.
- `docs/acceptance/varta-v0-1-0.md` — authoritative acceptance contract, 23 tests across S02–S06 (≥ 21 floor).
- `docs/architecture/vlp-frame.md` — byte map, `repr(C, align(8))` rationale, little-endian rationale, zero-dep rationale.
- `docs/roadmap/varta-v0-1-0/session-01-handoff.md` — this file.

## Decisions

- **Virtual workspace, no root crate.** Members are explicit, so a stray top-level package can't sneak in. `resolver = "2"` matches edition 2021.
- **Skeleton crates omit re-exports of `varta-vlp` items.** The session prompt's "re-exports point at vlp items that don't exist yet — that's fine, they'll resolve in step 6" is interpreted as *those re-exports become valid once Sessions 02/03 wire up their path deps*. Keeping the awk gate honest (literal empty `[dependencies]` everywhere in this session) is incompatible with `pub use varta_vlp::*` in skeletons that have no `varta-vlp` path dep. Sessions 02/03 add both the path dep and the re-export together.
- **Field order in `Frame` chosen so `repr(C, align(8))` produces zero padding.** `magic[2] + version[1] + status[1] + pid[4]` totals exactly 8 bytes before the three `u64` fields, so each `u64` lands on its natural alignment without compiler-inserted padding. The `const _: () = assert!(size_of::<Frame>() == 32);` line is the canonical proof.
- **No `unsafe` anywhere in `varta-vlp`.** `to_le_bytes` / `from_le_bytes` over fixed-length array slices is sufficient; transmuting `Frame` to `[u8; 32]` would force a `// SAFETY:` comment and a stronger ABI invariant for no measurable gain.
- **`Status::try_from_u8` is a free function on the enum, not `TryFrom<u8>`.** Avoids requiring `core::convert::TryFrom` import discipline downstream and keeps the API surface minimal.
- **`DecodeError` implements `core::error::Error`, not `std::error::Error`.** Stable since Rust 1.81; keeps the protocol crate `no_std`-friendly even though Varta v0.1.0 only ships on `std` targets.
- **Tests live in `tests/frame.rs` (integration), not unit tests in `lib.rs`.** Forces them through the public API the way Sessions 02+ will, and avoids accidental coupling to private items.
- **No dev-dependencies in `varta-vlp`.** Test fixtures are hand-built fixed-byte arrays; `Frame { … }` literals provide ground truth.
- **Bench placeholder uses `fn main() {}` (no I/O).** The operator rule forbids `eprintln!` outside `varta-watch`'s binary; `fn main() {}` is lint-clean.

## TDD ledger

### RED

```text
$ cargo test -p varta-vlp 2>&1 | tail -30
   Compiling varta-vlp v0.1.0 (/Users/aramirez/Code/.epic-worktrees/Varta/epic--varta-v0-1-0--s01-charter-and-vlp/crates/varta-vlp)
error[E0432]: unresolved imports `varta_vlp::DecodeError`, `varta_vlp::Frame`, `varta_vlp::Status`, `varta_vlp::MAGIC`, `varta_vlp::VERSION`
 --> crates/varta-vlp/tests/frame.rs:8:17
  |
8 | use varta_vlp::{DecodeError, Frame, Status, MAGIC, VERSION};
  |                 ^^^^^^^^^^^  ^^^^^  ^^^^^^  ^^^^^  ^^^^^^^ no `VERSION` in the root
  |                 |            |      |       |
  |                 |            |      |       no `MAGIC` in the root
  |                 |            |      no `Status` in the root
  |                 |            no `Frame` in the root
  |                 no `DecodeError` in the root

For more information about this error, try `rustc --explain E0432`.
error: could not compile `varta-vlp` (test "frame") due to 1 previous error
warning: build failed, waiting for other jobs to finish...
```

### GREEN

```text
$ cargo test -p varta-vlp 2>&1 | tail -30
   Compiling varta-vlp v0.1.0 (/Users/aramirez/Code/.epic-worktrees/Varta/epic--varta-v0-1-0--s01-charter-and-vlp/crates/varta-vlp)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.18s
     Running unittests src/lib.rs (target/debug/deps/varta_vlp-edadcba40830e57f)
     Running tests/frame.rs (target/debug/deps/frame-9901f1a1f970f4ee)
   Doc-tests varta_vlp

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 9 tests
test decode_error_implements_display_and_error ... ok
test decode_rejects_bad_magic ... ok
test decode_rejects_bad_status ... ok
test decode_rejects_bad_version ... ok
test every_status_variant_round_trips ... ok
test frame_alignment_is_eight_at_runtime ... ok
test frame_round_trip_matches_golden_bytes ... ok
test frame_size_is_thirty_two_bytes_at_runtime ... ok
test payload_preserved_at_u64_max ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Open issues

None. Workspace builds clean (`cargo build --workspace`); `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all -- --check` both pass with zero output.

## Next-session inputs

Session 02 (and any session reading this handoff) MUST read:

- `docs/claude-sessions/varta-v0-1-0/session-00-operator-rules.md` — the constraints + TDD discipline this session was bound by.
- `docs/acceptance/varta-v0-1-0.md` — authoritative test list. Session 02 owns the five S02 entries verbatim by name and file.
- `docs/architecture/vlp-frame.md` — wire layout reference; do not deviate from the byte map without amending this doc and the contract.
- `crates/varta-vlp/src/lib.rs` — `Frame`, `Status`, `DecodeError`, `MAGIC`, `VERSION`. Public API for downstream consumers.
- `crates/varta-vlp/tests/frame.rs` — example of how the public API is exercised; mirror the style.
- `crates/varta-client/Cargo.toml` and `crates/varta-client/src/lib.rs` — current skeleton; Session 02 adds the `varta-vlp = { path = "../varta-vlp" }` dependency, the public re-exports, and the agent surface (`Varta`, `BeatOutcome`, `Status`).
