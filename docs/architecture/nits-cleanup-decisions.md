# Nits-Cleanup — Locked Decisions (Session 01 charter)

This document is the single source of truth for the 11 nits flagged in the
v0.1.x review. Each section names the **current state** with concrete
`file:line` citations, the **chosen approach**, the **rationale**, the
**owning session**, and the **files touched**.

Sessions 02–07 do **not** edit the decisions below except to append a
single `**Landed in:** {commit}` line at the bottom of their nit's section.
Sessions are forbidden from re-litigating a locked decision; if a downstream
session believes a decision is wrong, it must stop and surface a charter
amendment, not silently diverge.

Status legend:
- **Locked** — operator decision, verbatim from the session-01 prompt.
- **Provisional** — inferred from anchor files; downstream owner may override
  during implementation but must record the choice in the section's
  `**Landed in:**` note.

---

## Nit map

| Nit | Title                                               | Owner | Status      |
|-----|-----------------------------------------------------|-------|-------------|
| n1  | `Frame::decode` slice-into-array fallbacks          | 02    | Provisional |
| n2  | `Slot` cannot distinguish empty from "pid 0 ok"     | 03    | Locked      |
| n3  | `status_code` helper duplicates `Status as u8`      | 04    | Locked      |
| n4  | `READ_TIMEOUT` hard-coded, not CLI-tunable          | 03    | Locked      |
| n5  | `Status` lacks `TryFrom<u8>` / label accessor       | 02    | Provisional |
| n6  | Prom exporter answers non-GET with 200 OK metrics   | 04    | Locked      |
| n7  | `panic::install` doc is ambiguous about allocation  | 05    | Provisional |
| n8  | No fuzz target for `Frame::decode`                  | 02    | Locked      |
| n9  | Misc residual cleanup (see section)                 | TBD   | Provisional |
| n10 | CI acceptance contract is an inline heredoc string  | 07    | Locked      |
| n11 | `varta-tests/src/lib.rs` is a doc-only placeholder  | 06    | Locked      |

**Parallelism note.** Sessions 02, 05, 06, 07 touch disjoint files and may
run in parallel. Sessions 03 and 04 both edit `crates/varta-watch/src/**`
and must serialise: 03 first (tracker + observer constructor change), then
04 (which `record`s the new types into `exporter.rs`).

---

### n1 — `Frame::decode` slice-into-array fallbacks

**Current state:** `crates/varta-vlp/src/lib.rs:142-167` — `Frame::decode`
validates magic and version, then for each of `pid`/`timestamp`/`nonce`/
`payload` calls `bytes[N..M].try_into().unwrap_or_else(|_| [0; K])`. The
slice lengths are statically the right size, so the `Err` arm is dead code
kept (per commit `ffaf3f2`) only to avoid `expect`'s heap-allocating panic
message in the beat-decode path.

**Decision (provisional):** rewrite the four reads using fixed-index
construction that the compiler can prove infallible without a fallback
expression. The simplest stable form is:

```rust
let pid       = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
let timestamp = u64::from_le_bytes([
    bytes[8],  bytes[9],  bytes[10], bytes[11],
    bytes[12], bytes[13], bytes[14], bytes[15],
]);
// ...nonce, payload similarly.
```

This removes the dead-`Err` arm entirely and keeps the path zero-alloc
without relying on the dead-code branch. No behaviour change; the existing
contract tests already cover round-trip correctness.

**Rationale:** the `unwrap_or_else` reads as "we have a fallback for the
case where the slice is the wrong length" — which is impossible. Removing
it shrinks the code and clarifies intent. Alternatives considered: leave
as-is (does the job, but the dead code keeps drawing reviewer eyes);
introduce a private helper `fn le4(bytes: &[u8; 32], off: usize) -> [u8; 4]`
(adds an inline helper for a 1-line task — over-engineered).

**Owner:** session 02 (`crates/varta-vlp`).
**Touches:** `crates/varta-vlp/src/lib.rs`.

---

### n2 — `Slot` cannot distinguish empty from "real beat from pid 0"

**Current state:** `crates/varta-watch/src/tracker.rs:24-48` — `Slot` carries
`pid: u32, last_nonce: u64, last_ns: u64, status: Status, stall_emitted:
bool`. `Slot::EMPTY` (line 41) zeros pid / last_nonce / last_ns and sets
`status: Status::Ok`. A freshly-zeroed slot is therefore observationally
indistinguishable from a real beat from pid 0 with status Ok and a
timestamp of 0.

**Decision:** add a private `used: bool` field to `Slot`, default `false` in
`Slot::EMPTY`. New slots created via `Tracker::record` set `used = true` at
construction. **Do not** add a `Status::Unknown` variant — that would
extend the on-wire enum and break the VLP ABI guarantee in CLAUDE.md hard
constraint #4. Update the `size_of::<Tracker>` compile-time guard at
`tracker.rs:81` if and only if the new field tightens it (today's `Slot`
size with default Rust repr is 24 B; adding a `bool` packs into the same
trailing padding byte, so the guard should still hold — confirm via
`dbg_size_of` or a temporary `const _: () = assert!(...);`).

**Rationale:** a single private bool is the minimal disambiguator. The
field is informational at v0.1.0 — existing eviction logic checks
`slot.stall_emitted` and a 10× silence threshold (`tracker.rs:150`), so
`used` does not change eviction behaviour. It serves as the discriminator
for any future iterator predicate that wants to filter sentinel rows
without resorting to pid-0 checks.

**Owner:** session 03 (`crates/varta-watch` tracker + observer).
**Touches:** `crates/varta-watch/src/tracker.rs`.

---

### n3 — `status_code` helper duplicates `Status as u8`

**Current state:** `crates/varta-watch/src/exporter.rs:128-135` — the
`status_code` helper is a hand-rolled `match` that re-encodes the four
`Status` discriminants. Two callers: `PromExporter::record` for
`Event::Beat` (line ~401) and `Event::Stall` (line ~410). `Status` is
already declared `#[repr(u8)]` in `crates/varta-vlp/src/lib.rs:36` with
explicit discriminants 0/1/2/3, so `status_code(s)` and `s as u8` produce
the same byte for every variant.

**Decision:** delete the `status_code` helper. Replace both call sites
with the direct cast `s as u8` (and `Status::Stall as u8` for the Stall
arm). Keep `status_label` as-is — it returns `&'static str` labels not
representable as a numeric cast and remains the single point of truth for
the Prometheus label text.

**Rationale:** `#[repr(u8)]` with explicit discriminants is the language's
guarantee that the cast is exact. The helper is a tautology that obscures
that guarantee. Cast is `const`, allocation-free, and the same one byte of
codegen as the helper.

**Owner:** session 04 (`crates/varta-watch` exporter).
**Touches:** `crates/varta-watch/src/exporter.rs`.

---

### n4 — `READ_TIMEOUT` hard-coded, not CLI-tunable

**Current state:** `crates/varta-watch/src/observer.rs:22` —
`const READ_TIMEOUT: Duration = Duration::from_millis(100);` is a module
constant fed into `socket.set_read_timeout` inside `finish_bind` (around
`observer.rs:264`). There is no CLI surface for it.

**Confirmed during session 01 (anchor verification, not re-investigation):**
`--socket-mode` already exists in `crates/varta-watch/src/config.rs`
(field at `config.rs:47`, parser at `config.rs:174`, default `0o600`, help
text at `config.rs:120-121`, regression tests at `config.rs:367-451`).
**Session 01 prompt's claim that n4 is "partially stale" is correct — only
`--read-timeout-ms` needs to be added.**

**Decision:** add **`--read-timeout-ms` only**. Plumb through the existing
patterns:

1. `crates/varta-watch/src/config.rs`:
   - Add `pub const DEFAULT_READ_TIMEOUT_MS: u64 = 100;` near
     `DEFAULT_SOCKET_MODE` (line 19).
   - Add `pub read_timeout: Duration` to `Config` struct (mirrors
     `socket_mode`).
   - Add `read_timeout_ms: Option<u64>` accumulator in `from_args`.
   - Add the `"--read-timeout-ms" => …` arm in the parser match,
     using the existing `parse_u64` helper.
   - Default `read_timeout: Duration::from_millis(DEFAULT_READ_TIMEOUT_MS)`
     when the flag is absent.
   - Update `Config::HELP` (lines 103-134) with a new line under
     OPTIONAL, matching the existing column alignment.

2. `crates/varta-watch/src/observer.rs`:
   - Remove the module-level `READ_TIMEOUT` constant.
   - Extend `Observer::bind` with a `read_timeout: Duration` parameter
     (signature locked in §"Process decisions" below).
   - Pass the value into `socket.set_read_timeout(Some(read_timeout))`.

3. Call sites: `crates/varta-watch/src/main.rs` and any internal test
   helper that calls `Observer::bind`. Pass `cfg.read_timeout` from
   parsed config.

4. `crates/varta-watch/tests/cli_smoke.rs:55-66` — add
   `"--read-timeout-ms"` to the `for flag in [...]` list inside
   `cli_help_lists_every_documented_flag` so the help-text audit covers
   it.

5. Default of 100 ms preserves today's hard-coded value byte-for-byte —
   no behaviour change for users who omit the flag.

**Rationale:** zero new types, mirrors the existing `--socket-mode`
precedent (same plumbing pattern, same default location), every call site
is internal so a function-signature change is cheap. Alternative — a
`Config`-style builder for `Observer::bind` — adds an indirection for one
new parameter.

**Owner:** session 03.
**Touches:**
`crates/varta-watch/src/config.rs`,
`crates/varta-watch/src/observer.rs`,
`crates/varta-watch/src/main.rs`,
`crates/varta-watch/tests/cli_smoke.rs`.

---

### n5 — `Status` lacks `TryFrom<u8>` / label accessor

**Current state:** `crates/varta-vlp/src/lib.rs:36-65` — `Status` is
`#[repr(u8)]` with `try_from_u8` as an inherent method but no
`impl TryFrom<u8> for Status`. The label table (`"ok"`, `"degraded"`,
`"critical"`, `"stall"`) lives in `crates/varta-watch/src/exporter.rs:119`
inside `status_label`, duplicating what is morally a VLP-owned mapping.

**Decision (provisional):** add `impl core::convert::TryFrom<u8> for
Status` that delegates to the existing `try_from_u8` inherent method:

```rust
impl core::convert::TryFrom<u8> for Status {
    type Error = DecodeError;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Status::try_from_u8(byte)
    }
}
```

Keep `try_from_u8` for source-compatibility — it's part of the public
docs already.

**Stretch (owner's call during session 02):** add `Status::as_str(self) ->
&'static str` returning the canonical lowercase labels and have
`varta-watch::exporter::status_label` delegate to it. If session 02 picks
this up, the exporter delete falls under n5 not n3 — record the boundary
in the `**Landed in:**` note. If session 02 skips it, the duplicated table
stays put at v0.1.x.

**Rationale:** the `TryFrom` impl is one of the standard idioms and costs
nothing — `try_from_u8` is already the canonical decoder. The label
accessor is the harder call: pulling the label table into VLP gives one
source of truth but slightly widens the public surface of the
zero-dep crate. Session 02 owns the final scope.

**Owner:** session 02.
**Touches:** `crates/varta-vlp/src/lib.rs`; optionally
`crates/varta-watch/src/exporter.rs` if the stretch is taken.

---

### n6 — Prom exporter answers non-GET with 200 OK metrics body

**Current state:** `crates/varta-watch/src/exporter.rs:248-311` —
`PromExporter::serve_one` reads up to `PROM_REQUEST_CAP` (4096 B) into a
512-byte stack buffer, **discards the buffer**, and unconditionally
writes a 200 OK with the metrics body. There is no method or path
validation; a POST, DELETE, or arbitrary garbage gets a full metrics
dump.

**Decision:** in `PromExporter::serve_one`, after the read loop exits
(either on `\r\n\r\n`, `PROM_REQUEST_CAP`, deadline, or `WouldBlock`), if
the accumulated request buffer does **not** start with the ASCII literal
`GET ` (four bytes including the trailing space), write:

```
HTTP/1.0 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n
```

then close. The existing GET path is unchanged.

**Edge cases (locked):**
- Zero bytes read (deadline before any data) → no `GET ` prefix → reply
  405. Defensive choice; a real client would not produce this.
- Read returned 1–3 bytes before `WouldBlock` → cannot match `GET ` (4
  bytes) → reply 405.
- Buffer starts with `GET\t` or `GET/` (no space) → does not match
  literal `GET ` → reply 405. HTTP/1.0 mandates space between method and
  request-target, so rejecting these is conformant.
- The `serve_one` accumulator currently writes into a 512-byte stack
  `buf` and tracks `total` but does not preserve the prefix across read
  iterations. Session 04 will need to keep the first 4 bytes accessible
  after the loop — either by checking before the first overwrite or by
  retaining the first iteration's slice. Session 04 picks the form;
  cheapest is to track the first read and short-circuit if it's < 4
  bytes or != `GET `.

**Rationale:** HTTP/1.0 minimal compliance, single allocation-free byte
compare. Returning 405 with `Allow: GET` is the explicit contract for
"this endpoint exists but doesn't accept this method".

**Owner:** session 04.
**Touches:** `crates/varta-watch/src/exporter.rs`.

---

### n7 — `panic::install` doc claims hook "operates entirely on the stack"

**Current state:** `crates/varta-client/src/panic.rs:28-32` — the docstring
under `# Allocation` states: *"The sole heap allocation is the `Box`
created by `std::panic::set_hook` at install time. The hook closure
itself operates entirely on the stack."* The wording is defensible
(the closure body uses `UnixDatagram::unbound`, `sock.connect(&path)`,
`Frame::encode` into a stack buffer, `sock.send`; the `path: PathBuf` was
moved into the closure at install), but the second sentence reads as if
nothing allocates anywhere, which is not literally true — `set_hook`'s
`Box`, the chained `prev` closure (lines 41, 61), and any kernel-side
allocation for the syscalls are all "off-stack" by some reading.

**Decision (provisional):** rewrite the `# Allocation` section to be
explicit about the boundary. Candidate replacement:

```text
/// # Allocation
///
/// Heap allocation occurs only at install time:
/// * `std::panic::set_hook` boxes the closure;
/// * `std::panic::take_hook` returns a `Box<dyn Fn>` for the chained
///   previous hook.
///
/// Inside the panic hook itself, every operation runs on stack-allocated
/// state — the captured `path` was moved in at install, the 32-byte
/// frame buffer lives in stack `[0u8; 32]`, and `UnixDatagram::unbound`
/// / `connect` / `send` perform syscalls without intermediate heap
/// allocation. The hook is therefore safe to fire from inside an OOM
/// panic.
```

Session 05 owns the final wording. If session 05 disagrees with the
"safe from OOM panic" claim (would need to audit `UnixDatagram::unbound`
on macOS / Linux to confirm), drop that sentence and keep the rest.

**Rationale:** the current sentence is technically true with charitable
reading but trips a careful reviewer. Explicit beats compact.

**Owner:** session 05 (`crates/varta-client` docs).
**Touches:** `crates/varta-client/src/panic.rs`.

---

### n8 — No fuzz target for `Frame::decode`

**Current state:** the workspace has no `fuzz/` directory and no
fuzz-target source for `Frame::decode`. The decode path is the most
externally-exposed code in `varta-vlp` (every observer datagram flows
through it), but only structured tests cover it today.

**Decision:** use the standard **cargo-fuzz** layout — a top-level
`fuzz/` directory that is **not** a workspace member. Lock the
following shape:

```
fuzz/
├── .gitignore           # target/, corpus/, artifacts/ — see below
├── Cargo.toml           # name = "varta-fuzz", edition 2021, [[bin]] frame_decode
└── fuzz_targets/
    └── frame_decode.rs  # libfuzzer_sys::fuzz_target!(|data: &[u8]| { if data.len() == 32 { let arr: &[u8; 32] = data.try_into().unwrap(); let _ = varta_vlp::Frame::decode(arr); } });
```

- The `fuzz/` directory is **outside** the workspace because cargo-fuzz
  requires nightly (`#![no_main]`, `libfuzzer-sys`), and the workspace
  is stable-pinned via `rust-toolchain.toml`. Keeping it outside means
  `cargo build --workspace` is unaffected and CI does not see it.
- Add `fuzz/target`, `fuzz/corpus`, and `fuzz/artifacts` to the
  root `.gitignore` (preferred) or a sibling `fuzz/.gitignore`.
- Single target name: `frame_decode`. Invoked locally with
  `cargo +nightly fuzz run frame_decode`. Session 02 documents the
  command in either `crates/varta-vlp/README.md` or a fresh
  `fuzz/README.md` (session 02 picks).
- **Do not add a CI step** — fuzzing is opt-in and time-bounded by the
  operator, not by the build pipeline.

**Rationale:** standard layout, nightly isolation, no impact on the
stable workspace. The 32-byte-only entry guard matches the only valid
input shape (`Frame::decode` takes `&[u8; 32]`).

**Owner:** session 02.
**Touches:** `fuzz/Cargo.toml` (new), `fuzz/fuzz_targets/frame_decode.rs`
(new), `.gitignore` (append three lines), optionally
`crates/varta-vlp/README.md` or `fuzz/README.md` for the runbook.

---

### n9 — Residual cleanup (scope TBD)

**Current state:** the operator's session-01 prompt enumerated explicit
decisions for 7 of 11 nits and stopped. The remaining four (n1, n5, n7,
n9) were inferred from the anchor files during the charter pass. Of
those four, n1/n5/n7 have plausible candidates documented above. **n9
is the residual slot.**

Plausible candidates discovered during anchor review:

1. **`varta-tests/Cargo.toml` has an empty `[dependencies]` table.**
   Cosmetic — could be deleted entirely (cargo accepts a package with
   no `[dependencies]` section). Coupled with n11 since both touch
   `crates/varta-tests`. Trivial.
2. **Duplicated `#![forbid(clippy::dbg_macro, clippy::print_stdout)]`
   headers** at the top of every library crate. Could be centralised
   via `[workspace.lints]` in the root `Cargo.toml` (requires Cargo
   1.74+, well below the stable floor we already use). Net win: fewer
   places to drift.
3. **`Tracker::find_evictable_slot`'s `threshold_ns.saturating_mul(10)`
   magic 10× factor** at `tracker.rs:150`. Could be promoted to a
   named `const EVICTION_THRESHOLD_MULTIPLIER: u64 = 10;` with a
   one-line comment on why. Tangentially in n2's territory — could be
   bundled if session 03 wants.

**Decision (provisional):** n9 stays **unassigned** at the close of
session 01. Operator picks one of the three (or names the actual n9 if
it differs from this list) before session 02 starts. The handoff
explicitly flags this as a blocker for "owner assignment" of n9 only —
the other ten nits proceed without dependency on n9's resolution.

**Owner:** TBD.
**Touches:** TBD.

---

### n10 — CI acceptance contract is an inline heredoc

**Current state:** `.github/workflows/ci.yml:55-94` defines the
`acceptance contract audit` step. The contract itself is a 22-row
heredoc string with pipe-delimited columns `name|file|kind`, then a
`while IFS='|' read` loop greps each. Edits today require touching the
workflow file; the contract is invisible to code search outside CI.

**Decision:** externalise the contract to **`tools/acceptance-contract.tsv`**
with three tab-separated columns `name<TAB>file<TAB>kind` and a leading
header comment beginning with `#`. The workflow step changes to:

```bash
while IFS=$'\t' read -r name file kind; do
  [ -z "$name" ] && continue
  case "${name#\#}" in
    "$name") ;;       # not a comment, fall through
    *) continue ;;    # comment line, skip
  esac
  case "$kind" in
    test|no-harness)
      grep -qE "^[[:space:]]*fn[[:space:]]+${name}\b" "$file" \
        || { echo "FAIL [$kind] $name @ $file"; exit 1; }
      ;;
    bench-assertion)
      grep -qF "$name" "$file" \
        || { echo "FAIL [bench] $name @ $file"; exit 1; }
      ;;
  esac
  echo "OK [$kind] $name"
done < tools/acceptance-contract.tsv
```

(Session 07 owns the exact bash; this stanza is a reference shape.)
Kind values stay `test|no-harness|bench-assertion` with identical
`grep -qE` / `grep -qF` semantics. The 22 existing entries migrate
verbatim — session 07 reads them from the current ci.yml block and
populates the TSV.

**Session-01 scaffold:** `tools/acceptance-contract.tsv` is created with
**only the header comment line** (and a trailing newline). No data
rows. Session 07 fills it.

**Rationale:** externalising the contract makes it greppable from the
checkout root, lets reviewers edit it without touching workflow YAML,
and shrinks the workflow file to a tight loop. TSV (not CSV) avoids
quoting concerns — none of the column values contain whitespace today.

**Owner:** session 07 (CI gate change).
**Touches:** `.github/workflows/ci.yml`, `tools/acceptance-contract.tsv`.

---

### n11 — `varta-tests/src/lib.rs` is a doc-only placeholder

**Current state:**
`crates/varta-tests/src/lib.rs` contains only an inner-attribute lint
header and a module docstring. The crate's actual fixtures live in
`crates/varta-tests/tests/end_to_end.rs`, declared via
`[[test]] name = "end_to_end" harness = false` in
`crates/varta-tests/Cargo.toml`. Cargo accepts a package with no
library or binary target as long as at least one `[[test]]` /
`[[bench]]` / `[[example]]` target exists.

**Decision:** delete `crates/varta-tests/src/lib.rs` and the now-empty
`crates/varta-tests/src/` directory. The crate keeps its `[[test]]`
target and the `[package]` declaration; no other `Cargo.toml` change is
required for the delete itself. (See n9 candidate #1 for the empty
`[dependencies]` table — that is a separate decision.)

**Validation (for session 06 to run after the delete):**

```
cargo test -p varta-tests --test end_to_end --all-features
cargo doc  -p varta-tests --no-deps --all-features
cargo build --workspace --all-features
```

All three must remain green.

**Rationale:** placeholder files attract drift and confuse readers
looking for the "library half" of a crate that intentionally has none.
Cargo's behaviour with no `[lib]` and at least one `[[test]]` target is
well-defined and currently used across the Rust ecosystem.

**Owner:** session 06.
**Touches:** delete `crates/varta-tests/src/lib.rs`; delete
`crates/varta-tests/src/`.

---

## Process decisions (charter-level, apply across nits)

These are not nits themselves but shape how the implementation sessions
land theirs.

### P1 — `Observer::bind` signature for n4

Add the parameter; do not introduce a builder type. The new signature is:

```rust
pub fn bind(
    path: impl AsRef<Path>,
    threshold: Duration,
    socket_mode: u32,
    read_timeout: Duration,
) -> io::Result<Self>
```

Callers update at the same site: `main.rs` plus any in-crate test
helper. No external consumers exist (the crate is workspace-internal at
v0.1.x).

### P2 — `Slot::used` default for n2

`Slot::EMPTY` sets `used: false`. Both `Tracker::record` insert paths
(fresh slot and eviction reuse) construct slots with `used: true`. The
field is informational at v0.1.x; eviction logic is unchanged.

### P3 — n6 405 framing

Buffer prefix match is performed **after** the read loop exits, on
whatever bytes were accumulated, against the four-byte ASCII literal
`GET ` (space included). Less than four bytes → 405. Anything else
non-matching → 405.

### P4 — n8 fuzz invocation doc

Session 02 picks the doc home (`crates/varta-vlp/README.md` vs
`fuzz/README.md`). Either is acceptable; the command to document is
`cargo +nightly fuzz run frame_decode`.

### P5 — n10 TSV column separator

Literal ASCII tab (0x09). Header line is a `#`-prefixed comment and
skipped by the loop. No data rows in the scaffold landed by session 01;
session 07 migrates the 22 entries.

### P6 — Decisions doc is read-only for downstream sessions

Sessions 02–07 may append exactly one `**Landed in:** {commit-sha}`
line at the bottom of their nit's section. They do **not** rewrite,
amend, or otherwise edit prior content. If a downstream session
believes a decision is wrong, it stops and surfaces a charter
amendment — silent divergence is forbidden.
