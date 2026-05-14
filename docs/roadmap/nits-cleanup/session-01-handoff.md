# Session 01 Handoff — Nits-Cleanup Charter

**Branch:** `epic/nits-cleanup--s01-charter`
**Worktree:** `/Users/aramirez/Code/.epic-worktrees/Varta/epic--nits-cleanup--s01-charter`
**Scope:** read-only audit + planning artefacts. No code under `crates/**`
or `.github/**` modified.

---

## What changed

| Path | Action | One-line summary |
|---|---|---|
| `book/src/architecture/nits-cleanup-decisions.md` | created | Single source of truth for n1–n11 decisions, with concrete `file:line` citations, owners, and a per-nit decision template downstream sessions append `**Landed in:**` notes to. |
| `tools/acceptance-contract.tsv` | created | Header-only TSV scaffold for n10. Tab-separated `name<TAB>file<TAB>kind`; session 07 fills the 22 rows currently in `.github/workflows/ci.yml:58-80`. |
| `docs/roadmap/nits-cleanup/session-01-handoff.md` | created | This file. |

**No other paths were touched.** Verified by `git diff --stat -- crates/`
and `git diff --stat -- .github/` returning empty.

---

## Decisions made and rationale

The locked decisions live in
[`book/src/architecture/nits-cleanup-decisions.md`](../../architecture/nits-cleanup-decisions.md).
The summary here is just the assignment table — the **why** for each nit
is in that doc.

| Nit | Status      | Owner | Key change                                                                 |
|-----|-------------|-------|----------------------------------------------------------------------------|
| n1  | Provisional | 02    | Replace `try_into().unwrap_or_else` with fixed-index `from_le_bytes` calls |
| n2  | Locked      | 03    | Add private `used: bool` to `Slot`                                         |
| n3  | Locked      | 04    | Delete `status_code` helper; use `s as u8`                                 |
| n4  | Locked      | 03    | Add `--read-timeout-ms` CLI flag (default 100ms); plumb through bind       |
| n5  | Provisional | 02    | Add `impl TryFrom<u8> for Status` (stretch: `Status::as_str`)              |
| n6  | Locked      | 04    | Return 405 + Allow: GET for non-GET requests on Prom endpoint              |
| n7  | Provisional | 05    | Rewrite `panic::install` `# Allocation` doc to be explicit                 |
| n8  | Locked      | 02    | Add standalone `fuzz/` dir (non-workspace), single `frame_decode` target   |
| n9  | Provisional | TBD   | Three candidates in decisions doc; awaiting operator pick                  |
| n10 | Locked      | 07    | Externalise CI acceptance contract to `tools/acceptance-contract.tsv`      |
| n11 | Locked      | 06    | Delete `crates/varta-tests/src/lib.rs` and `src/` directory                |

**Parallelism plan.** Sessions 02, 05, 06, 07 touch disjoint files and may
run in parallel. Sessions 03 → 04 must serialise (both edit
`crates/varta-watch/src/**`; 03 changes the `Observer::bind` signature
and tracker types that 04's exporter changes consume).

---

## Process-level decisions (apply across nits)

Each is documented in the decisions doc under "Process decisions":

- **P1** — `Observer::bind` gains a 4th parameter, not a builder.
  Signature: `pub fn bind(path: impl AsRef<Path>, threshold: Duration,
  socket_mode: u32, read_timeout: Duration) -> io::Result<Self>`.
- **P2** — `Slot::EMPTY` keeps `used: false`; both insert paths set
  `used: true`. Eviction logic untouched.
- **P3** — n6 prefix check runs **after** the read loop; matches the
  literal `GET ` (with trailing space) on whatever bytes accumulated.
- **P4** — n8 fuzz invocation doc location is session 02's call
  (`crates/varta-vlp/README.md` or `fuzz/README.md`).
- **P5** — n10 TSV separator is ASCII tab (0x09); header line is
  `#`-prefixed and skipped by the loop.
- **P6** — decisions doc is read-only for downstream sessions except
  for appending one `**Landed in:** {commit}` line per nit.

---

## Open issues

### Blocking next-session-start

1. **n9 has no operator decision.** The session-01 prompt enumerated
   explicit decisions for 7 of 11 nits; n9 was not specified. Three
   plausible candidates are documented in
   `book/src/architecture/nits-cleanup-decisions.md` §n9:
   - empty `[dependencies]` table in `crates/varta-tests/Cargo.toml`;
   - centralising the per-crate `#![forbid(clippy::dbg_macro,
     clippy::print_stdout)]` headers via root `[workspace.lints]`;
   - naming the magic `10` in
     `Tracker::find_evictable_slot`'s `threshold_ns.saturating_mul(10)`
     (`crates/varta-watch/src/tracker.rs:150`).

   **The other ten nits do not depend on n9's resolution** — sessions
   02-07 can proceed in parallel with n9 still TBD. Only the owner
   assignment of n9 is blocked.

### Non-blocking (provisional decisions to confirm)

2. **n1/n5/n7 are marked Provisional in the decisions doc** — they were
   inferred from anchor reads, not from the operator's verbatim list.
   Each section documents the inferred subject and the candidate fix.
   The owning session may override during implementation; if so, the
   `**Landed in:**` note records the change and the next reader is not
   blindsided.

### Operator-facing requests

3. **Is there an upstream "v0.1.x review" document that enumerates the
   original 11 nits?** I did not find one in the worktree
   (no `docs/**` file matches that pattern, and the session prompt
   provided the decisions inline). If the source review exists,
   linking it from the decisions doc would freeze the contract beyond
   any future drift in my interpretation.

---

## Next-session inputs

Listed by absolute repo-relative path so the next operator can fan out
without re-deriving anything. Every path below is a file **read** by the
named session; output paths follow the decisions doc.

### Session 02 — `varta-vlp` (n1, n5, n8)

Read:
- `book/src/architecture/nits-cleanup-decisions.md` §n1, §n5, §n8, §P4.
- `crates/varta-vlp/src/lib.rs` (lines 36-65 for Status, 142-167 for decode).
- `crates/varta-vlp/Cargo.toml` (verify edition + zero deps).
- `.gitignore` (lines 1-5 — append `fuzz/target`, `fuzz/corpus`,
  `fuzz/artifacts` under the `# Generated by Cargo` block).
- `Cargo.toml` (root) — confirm workspace has no `members = ["fuzz", …]`;
  the standalone `fuzz/` must remain outside the workspace.

Produce:
- Edits to `crates/varta-vlp/src/lib.rs` for n1 (decode rewrite) and n5
  (`TryFrom<u8>` + optional `as_str`).
- New `fuzz/Cargo.toml`, `fuzz/fuzz_targets/frame_decode.rs`.
- `.gitignore` append.
- Optional new `fuzz/README.md` or edit to
  `crates/varta-vlp/README.md` documenting the
  `cargo +nightly fuzz run frame_decode` invocation.

### Session 03 — `varta-watch` tracker + observer + config (n2, n4)

Read:
- `book/src/architecture/nits-cleanup-decisions.md` §n2, §n4, §P1, §P2.
- `crates/varta-watch/src/tracker.rs` (lines 24-48 for Slot, line 81
  for size guard).
- `crates/varta-watch/src/observer.rs` (line 22 for the constant being
  removed, line ~264 for the `set_read_timeout` call site).
- `crates/varta-watch/src/config.rs` (line 19, lines 47/103-134/174 for
  the `--socket-mode` precedent to mirror; tests at 367-451 show the
  expected coverage pattern).
- `crates/varta-watch/src/main.rs` (every call to `Observer::bind`).
- `crates/varta-watch/tests/cli_smoke.rs` (lines 55-66, the help-text
  audit list — append `--read-timeout-ms`).

Produce:
- Edits to `tracker.rs`, `observer.rs`, `config.rs`, `main.rs`, and
  `tests/cli_smoke.rs`. No new files.

### Session 04 — `varta-watch` exporter (n3, n6)

Read:
- `book/src/architecture/nits-cleanup-decisions.md` §n3, §n6, §P3.
- `crates/varta-watch/src/exporter.rs` (lines 119-135 for the two
  helpers, lines 248-311 for `serve_one`, lines 390-428 for the
  `record` callers).
- Output of session 03 (the `Slot` shape may have moved if `used` was
  added; verify before edits).

Produce:
- Edits to `exporter.rs` only. Both n3 and n6 land in the same file.

### Session 05 — `varta-client` docs (n7)

Read:
- `book/src/architecture/nits-cleanup-decisions.md` §n7.
- `crates/varta-client/src/panic.rs` (lines 28-32 for the disputed
  passage; lines 38-63 for the closure body that grounds the rewrite).
- `crates/varta-client/src/lib.rs` and `crates/varta-client/src/client.rs`
  (no edits expected; read only if the doc rewrite cross-references them).

Produce:
- Doc-only edits in `crates/varta-client/src/panic.rs`.

### Session 06 — `varta-tests` cleanup (n11, maybe part of n9)

Read:
- `book/src/architecture/nits-cleanup-decisions.md` §n11, §n9 (candidate #1).
- `crates/varta-tests/Cargo.toml`.
- `crates/varta-tests/src/lib.rs` (to be deleted).
- `crates/varta-tests/tests/end_to_end.rs` (read only — confirms the
  `[[test]]` target is intact).

Produce:
- Delete `crates/varta-tests/src/lib.rs` and the now-empty
  `crates/varta-tests/src/` directory.
- Optional: delete the empty `[dependencies]` stanza from
  `crates/varta-tests/Cargo.toml` if operator picks n9 candidate #1.

### Session 07 — CI gate (n10, maybe part of n9)

Read:
- `book/src/architecture/nits-cleanup-decisions.md` §n10, §P5, plus §n9 if
  candidate #2 (workspace lints centralisation) is selected.
- `.github/workflows/ci.yml` (lines 55-94 are the contract block).
- `tools/acceptance-contract.tsv` (header-only scaffold landed by this
  session).

Produce:
- Populate `tools/acceptance-contract.tsv` with the 22 entries
  currently in the heredoc.
- Rewrite the `acceptance contract audit` step in `ci.yml` to read
  the TSV via `while IFS=$'\t' read`.
- Optional (n9 candidate #2): add `[workspace.lints]` block to root
  `Cargo.toml` and remove the per-crate `#![forbid(...)]` headers.

---

## Quality gates run during session 01

All passing. Output captured in the session's terminal log.

- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [x] `cargo clippy --workspace --all-targets --no-default-features -- -D warnings`
- [x] `RUSTFLAGS="-D warnings" cargo test --workspace --all-features`
- [x] `cargo test --doc --workspace --all-features`
- [x] `cargo build --workspace --release`

No code under `crates/**` or `.github/**` changed, so any gate failure
here would be a pre-existing condition. Confirmed clean.
