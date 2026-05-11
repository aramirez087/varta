# Session 01 Handoff — Nits Cleanup Charter

## What changed

- `docs/architecture/nits-cleanup-decisions.md` — created. Locks design decisions for all 11 nits (n1–n11), each assigned to exactly one session (02–07).
- `tools/acceptance-contract.tsv` — created. Header-only scaffold (column comment, no data rows). Session 07 populates it from the current ci.yml inline contract.
- No code in `crates/**` changed. Only new docs and the scaffold manifest.

## Decisions made

| Nit | Decision | Session |
|-----|----------|---------|
| n1 | `.expect("len N")` → `.unwrap()` in Frame::decode | 02 |
| n2 | Add `used: bool` to Slot; no `Status::Unknown` | 03 |
| n3 | Delete `status_code()`; use `s as u8` | 04 |
| n4 | Add `--read-timeout-ms` flag (default 100ms). `--socket-mode` already exists. | 05 |
| n5 | Document Varta as `Send` but not `Sync` + static assert | 06 |
| n6 | 405 Method Not Allowed on non-GET to PromExporter | 04 |
| n7 | Reword panic.rs allocation doc claim | 06 |
| n8 | cargo-fuzz harness in `fuzz/`, excluded from workspace | 02 |
| n9 | Add macos-latest to CI strategy matrix | 07 |
| n10 | Externalise acceptance contract to TSV, read from ci.yml | 07 |
| n11 | Delete varta-tests/src/lib.rs placeholder | 07 |

## Rationale for key decisions

- **n6 (method guard)**: Path component intentionally ignored — Prometheus scrapers always GET. Path-based routing can be added later.
- **n2 (Slot::used)**: Adding `Status::Unknown` would change the wire enum, violating Session 00 hard constraint #3. `used: bool` is local to the tracker.
- **n3 (delete status_code)**: `#[repr(u8)]` discriminants are exact by construction. A manual match is dead code that can drift from the enum definition.
- **n10 (TSV manifest)**: Tab-separated without a proper parser is fragile, but it matches the existing implicit contract (pipe-separated in a shell string). The TSV at least separates data from code.

## Open issues

- Session 02 and 04 are both `parallel_safe: true` per the session manifests but touch different files (vlp + fuzz vs exporter), so they can run concurrently.
- Session 03 (tracker) and 04 (exporter) also touch different files and can run concurrently.
- Session 05 (config) touches config.rs + observer.rs + main.rs — safe to run in parallel with 02/03/04/06/07 since no file overlaps except that 05 needs Observer's constructor updated.
- Session 07 touches ci.yml + tools/acceptance-contract.tsv + varta-tests — no file overlap with 02-06.

## Next session inputs

- Decision doc: `docs/architecture/nits-cleanup-decisions.md` (all n1–n11 sections)
- Session manifests: `docs/claude-sessions/nits-cleanup/session-{02..07}-*.md`
- Current CI: `.github/workflows/ci.yml`
- Tracker: `crates/varta-watch/src/tracker.rs`
- Exporter: `crates/varta-watch/src/exporter.rs`
- Config: `crates/varta-watch/src/config.rs`
- Observer: `crates/varta-watch/src/observer.rs`
- Client: `crates/varta-client/src/client.rs`, `crates/varta-client/src/panic.rs`
- VLP: `crates/varta-vlp/src/lib.rs`
- Tests lib placeholder: `crates/varta-tests/src/lib.rs`