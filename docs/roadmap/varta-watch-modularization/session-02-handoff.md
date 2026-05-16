# Session 02 Handoff — FileExporter Migration

Date: 2026-05-16  
Branch: `epic/varta-watch-modularization--s02-config-refactor`

---

## What Was Done

Migrated `FileExporter`, `Exporter` trait, and file-export helpers from
`crates/varta-watch/src/exporter/mod.rs` into the stub
`crates/varta-watch/src/exporter/file.rs`.

### Items moved to `exporter/file.rs`

| Item | Notes |
|------|-------|
| `pub trait Exporter` | With full doc comments |
| `pub struct FileExporter` | With all fields |
| `const MAX_ROTATION_GENERATIONS: u32` | Private to file.rs |
| `impl FileExporter` | All methods: create, flush_and_sync, record_eviction_pid, after_write, rotate |
| `impl Exporter for FileExporter` | Full record + flush impl |
| `fn decimal_digits` | Private helper |
| `fn status_label` | Private helper |
| `use std::fs::{File, OpenOptions}` | Moved to file.rs |
| `use std::io::{self, BufWriter, Write}` | Moved to file.rs |
| `use std::path::{Path, PathBuf}` | Moved to file.rs |
| `use varta_vlp::Status` | Moved to file.rs (unconditional there) |
| `use crate::observer::Event` | Duplicated — file.rs for FileExporter, mod.rs retains it for PromExporter |

### Changes to `exporter/mod.rs`

- Removed all FileExporter/Exporter block (~line 13–478 of original)
- Added `pub use file::{Exporter, FileExporter};` after `use std::time::Duration;`
- Made `use varta_vlp::Status` → `#[cfg(feature = "prometheus-exporter")] use varta_vlp::Status;`
- Made `use crate::observer::Event` → `#[cfg(feature = "prometheus-exporter")] use crate::observer::Event;`
- Extended feature-gated io import: `use std::io::{self, ErrorKind, Read, Write as IoWrite};` (added `self` and `Write as IoWrite` for PromExporter's `io::` prefix usage)

---

## Decisions and Rationale

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | Config already decomposed — skip | Re-confirmed: config/ has 10 production submodules. Session-02 did the real queued work (FileExporter migration) per session-01-handoff. |
| D2 | `Exporter` trait lives in file.rs | Tightly coupled to FileExporter; PromExporter resolves it via `pub use file::Exporter` re-export. |
| D3 | `decimal_digits` and `status_label` private in file.rs | Implementation details of FileExporter only; not used by PromExporter. |
| D4 | `use varta_vlp::Status` becomes `#[cfg(feature = "prometheus-exporter")]` in mod.rs | After migration, Status:: in mod.rs only appears in PromExporter code (lines ~2700+), which is feature-gated. |
| D5 | `use crate::observer::Event` becomes `#[cfg(feature = "prometheus-exporter")]` in mod.rs | Same reason: without feature, nothing in mod.rs uses Event. |
| D6 | `use std::io::{self, ...}` added under prom cfg | PromExporter uses `io::Result`, `io::Error`, `io::ErrorKind` — needs `self` to bring `io` into scope. |

---

## Regressions / Known Issues

None. All CI checks pass:

```
cargo check -p varta-watch                             ✓
cargo check -p varta-watch --features prometheus-exporter  ✓
cargo check -p varta-watch --features secure-udp           ✓
cargo check -p varta-watch --features compile-time-config  ✓ (expected panic: VARTA_CONFIG_FILE not set)
cargo test -p varta-watch                              ✓ (2 tests pass)
cargo clippy -p varta-watch -- -D warnings             ✓
cargo clippy -p varta-watch --features prometheus-exporter -- -D warnings  ✓
cargo fmt --check                                      ✓
```

API invariants verified:
- `lib.rs`: `pub use exporter::{Exporter, FileExporter};` ✓
- `lib.rs`: `pub use exporter::PromExporter;` ✓
- `exporter/mod.rs`: `IterStage`, `STAGE_LABELS`, `DEFAULT_ITERATION_BUDGET`, `DEFAULT_SCRAPE_BUDGET` all present ✓

---

## Next-Session Inputs

### Session 03 — Migrate PromExporter into submodules

**Target files:**
- `crates/varta-watch/src/exporter/mod.rs` — after session 03, retains only `IterStage`, `STAGE_LABELS`, `DEFAULT_ITERATION_BUDGET`, `DEFAULT_SCRAPE_BUDGET`, module declarations, and re-exports
- `crates/varta-watch/src/exporter/prometheus.rs` — receives `PromExporter` struct, `GaugeRow`, `PromIpState`, all label arrays, metric impl methods, `serve_pending`, `impl Exporter for PromExporter`
- `crates/varta-watch/src/exporter/bearer_token.rs` — receives `parse_authorization_bearer`, `find_crlf`, `drain_read_to_would_block`
- `crates/varta-watch/src/exporter/http.rs` — receives `write_headers_with_len`, `write_usize`, `write_all_nonblocking`

**Critical constraints for session 03:**
- `varta_watch::exporter::IterStage` path must remain valid — used in `main.rs` lines 28, 911, 914, 1058, 1060, 1063, 1112, 1114, 1117, 1409, 1411, 1414, 1466, 1467, 1470, 1486, 1488+
- `varta_watch::exporter::STAGE_LABELS` path must remain valid — used in `main.rs` line 827
- `#[cfg(feature = "prometheus-exporter")] pub use exporter::PromExporter;` in `lib.rs` must remain valid
- `BearerToken` from `varta_vlp::crypto` — zero-on-drop; must stay inside `PromExporter` struct
- The `io` import in mod.rs (`use std::io::{self, ErrorKind, Read, Write as IoWrite};`) moves to prometheus.rs with PromExporter
- After session 03, mod.rs no longer needs prom feature-gated imports — all move to subfiles
- `impl Exporter for PromExporter` references the `Exporter` trait via `pub use file::Exporter` — this chain must remain intact

**Starting state for session 03:**
- `exporter/mod.rs` — ~3041 lines; all PromExporter content remains here
- `exporter/file.rs` — ~310 lines; FileExporter complete
- `exporter/prometheus.rs` — stub (single doc comment)
- `exporter/bearer_token.rs` — stub
- `exporter/http.rs` — stub
