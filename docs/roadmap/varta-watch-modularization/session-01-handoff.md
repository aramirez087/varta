# Session 01 Handoff — varta-watch Modularization Charter

Date: 2026-05-16  
Branch: `epic/varta-watch-modularization--s01-charter`

---

## What Was Done

### Audit of 8 largest modules

| Module | Lines | Decision |
|--------|-------|----------|
| `config/` | 10-file directory, 41k tok | Already decomposed — no action (D1) |
| `exporter.rs` | 3469 | Renamed to `exporter/mod.rs`; 4 stub subfiles created (D2–D4) |
| `end_to_end.rs` | 3411 | Stays as crate root; `mod` declarations added; 5 stub subfiles created (D7–D8) |
| `recovery.rs` | 2197 | Leave monolithic (D5) |
| `audit.rs` | 2243 | Leave monolithic (D5) |
| `main.rs` | 1773 | Out of scope — binary entry point (D6 analog) |
| `tracker.rs` | 1482 | Acceptable as-is — single type, well-structured (D6) |
| `peer_cred/` | Directory | Already decomposed — no action |

### Structural changes

1. **`exporter.rs` → `exporter/mod.rs`** — full content moved; private `mod` declarations appended at the bottom for sessions 02/03 to fill:
   - `mod file;`
   - `#[cfg(feature = "prometheus-exporter")] mod prometheus;`
   - `#[cfg(feature = "prometheus-exporter")] mod bearer_token;`
   - `#[cfg(feature = "prometheus-exporter")] mod http;`

2. **`exporter/file.rs`, `prometheus.rs`, `bearer_token.rs`, `http.rs`** — stub files created (single `//!` doc comment each).

3. **`end_to_end.rs`** — 5 `mod` declarations with explicit `#[path]` attributes inserted after `#![...]` attributes. Path attributes are required because `end_to_end.rs` is the crate root; without them `mod basic;` resolves to `tests/basic.rs` (sibling), not `tests/end_to_end/basic.rs`.

4. **`end_to_end/basic.rs`, `recovery.rs`, `observability.rs`, `reconnect.rs`, `secure_udp.rs`** — stub files created with test migration inventory in doc comments.

5. **`lib.rs`** — unchanged. `pub mod exporter;` resolves to `exporter/mod.rs` automatically.

6. **OpenWolf artifacts** — `.wolf/anatomy.md`, `.wolf/cerebrum.md`, `.wolf/memory.md`, `.wolf/buglog.json` created.

---

## Decisions and Rationale

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | `config/` already decomposed — skip | Re-scaffolding would produce duplicate module declarations (E0428). |
| D2 | `lib.rs` unchanged | `pub mod exporter;` picks up `exporter/mod.rs` automatically; no path attribute needed. |
| D3 | `exporter.rs` deleted atomically with `exporter/mod.rs` creation | Rust E0583 if both exist. |
| D4 | `IterStage`/`STAGE_LABELS` must stay at `varta_watch::exporter::*` | `main.rs` imports `use varta_watch::exporter::IterStage` (line 28) and accesses `varta_watch::exporter::STAGE_LABELS` (line 827). Sessions 02/03 must preserve this path via re-exports. |
| D5 | `recovery.rs` and `audit.rs` stay monolithic | 5 cross-module types (`CompleteOutcome`, `CompleteRecord`, `RefusedRecord`, `SpawnRecord`, `CompleteRecord`) create tight bidirectional coupling. Cost of decomposition exceeds benefit. |
| D6 | `tracker.rs` acceptable as-is | 1482 lines, single `Tracker` type, clear single responsibility. |
| D7 | `end_to_end.rs` stays as crate root | `tests/` files are binary crate roots. `tests/end_to_end/mod.rs` is not a valid integration test entry point. |
| D8 | Harness helpers stay in `end_to_end.rs` | `spawn_watch`, `TempDir`, `ChildGuard`, `http_get`, etc. are used by all scenario modules; extracting adds indirection without benefit. |
| D9 | `compile_error!` gates in `lib.rs` untouched | Structural guarantee for Class-A safety-critical profile. |

---

## Regressions / Known Issues

None. All CI checks pass:

```
cargo check --workspace                     ✓
cargo check --workspace --features prometheus-exporter  ✓
cargo check --workspace --features compile-time-config  ✓ (expected panic: VARTA_CONFIG_FILE not set)
cargo check -p varta-tests                  ✓
```

---

## Next-Session Inputs

### Session 02 — Migrate FileExporter into `exporter/file.rs`

**Target files:**
- `crates/varta-watch/src/exporter/mod.rs` — remove `FileExporter`, `Exporter` trait, `decimal_digits`, `status_label`, `MAX_ROTATION_GENERATIONS`, `DEFAULT_ITERATION_BUDGET`, `DEFAULT_SCRAPE_BUDGET` from here
- `crates/varta-watch/src/exporter/file.rs` — receive the above items

**Critical constraints:**
- `pub use file::{Exporter, FileExporter};` must appear in `exporter/mod.rs` after migration
- `DEFAULT_ITERATION_BUDGET` and `DEFAULT_SCRAPE_BUDGET` are referenced in `PromExporter::new_inner()` (inside `mod.rs`) — they must be visible to `prometheus.rs` after session 03 splits `PromExporter`
- `lib.rs` line 117: `pub use exporter::{Exporter, FileExporter};` must continue to resolve
- `Exporter` trait uses `crate::observer::Event` — import must be preserved in `file.rs`

**Items in `exporter/mod.rs` that belong in `file.rs`** (lines ~1–585 of current mod.rs, before `IterStage`):
- `use std::fs::{File, OpenOptions};` (file.rs needs these)
- `use std::io::{self, BufWriter, Write};`
- `use std::path::{Path, PathBuf};`
- `use varta_vlp::Status;`
- `use crate::observer::Event;`
- `pub trait Exporter { ... }`
- `pub struct FileExporter { ... }`
- `const MAX_ROTATION_GENERATIONS: u32`
- `impl FileExporter { ... }` (full impl including `record_eviction_pid`)
- `impl Exporter for FileExporter { ... }`
- `fn decimal_digits`, `fn status_label`

### Session 03 — Migrate PromExporter into submodules

**Target files:**
- `crates/varta-watch/src/exporter/mod.rs` — keep only `IterStage`, `STAGE_LABELS`, `DEFAULT_ITERATION_BUDGET`, `DEFAULT_SCRAPE_BUDGET`, and re-exports
- `crates/varta-watch/src/exporter/prometheus.rs` — receive `PromExporter` + all label arrays + `GaugeRow` + `PromIpState` + metric impl methods + `serve_pending` + `Exporter for PromExporter`
- `crates/varta-watch/src/exporter/bearer_token.rs` — receive `parse_authorization_bearer`, `find_crlf`, `drain_read_to_would_block`
- `crates/varta-watch/src/exporter/http.rs` — receive `write_headers_with_len`, `write_usize`, `write_all_nonblocking`

**Critical constraints:**
- `varta_watch::exporter::IterStage` path must remain valid (used in `main.rs` line 28, 911, 914, 1058, 1060, 1063, 1112, 1114, 1117, 1409, 1411, 1414, 1466, 1467, 1470, 1486, 1488+)
- `varta_watch::exporter::STAGE_LABELS` path must remain valid (used in `main.rs` line 827)
- `#[cfg(feature = "prometheus-exporter")] pub use exporter::PromExporter;` in `lib.rs` must remain valid
- `BearerToken` from `varta_vlp::crypto` — zero-on-drop; must stay inside `PromExporter` struct in `prometheus.rs`
- `IpStateTable` from `crate::ip_state_table` — currently imported in `exporter/mod.rs` under `#[cfg(feature = "prometheus-exporter")]`

### Session 04 — Migrate test scenarios into `end_to_end/` submodules

**Target files:**
- `crates/varta-tests/tests/end_to_end.rs` — remove migrated test functions, keep `main()`, `run_one()`, harness helpers
- `crates/varta-tests/tests/end_to_end/basic.rs` — 6 tests (see stub doc comment for list)
- `crates/varta-tests/tests/end_to_end/recovery.rs` — 7 tests
- `crates/varta-tests/tests/end_to_end/observability.rs` — 7 tests
- `crates/varta-tests/tests/end_to_end/reconnect.rs` — 3 tests
- `crates/varta-tests/tests/end_to_end/secure_udp.rs` — 4 tests

**Critical constraints:**
- `main()` fn stays in `end_to_end.rs` — it is the `harness = false` entry point
- `run_panic_child`, `run_agent_child`, `run_degraded_child` stay in `end_to_end.rs` (dispatched from `main()`)
- All helper functions (`spawn_watch`, `TempDir`, `ChildGuard`, `http_get`, etc.) stay in `end_to_end.rs` — submodules access them via `super::*`
- `run_one("test_name", super::basic::test_name)` call pattern in `main()` after migration
- `#[path]` attributes on all `mod` declarations in `end_to_end.rs` are already in place — session 04 does NOT need to add them (they were added in session 01)
- `#[cfg(feature = "udp")]` gate on `udp_client_to_observer_beats_and_stall` and its `run_one` call must be preserved
- `#[cfg(feature = "secure-udp")]` gates on secure_udp tests must be preserved

### Session 05 (reserved) — recovery.rs / audit.rs

No inputs. Decision D5 stands unless reversed by maintainer.

### Session 06 — CI gate

Run full CI suite after sessions 02–04 complete:
```bash
cargo build --workspace --release
cargo test --workspace
cargo test -p varta-tests --test end_to_end
cargo clippy --workspace -- -D warnings
cargo fmt --check
```
