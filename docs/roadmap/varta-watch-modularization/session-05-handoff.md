# Session 05 Handoff — Recovery & Audit Taming

**Date:** 2026-05-16  
**Branch:** `epic/varta-watch-modularization--s05-recovery-audit-taming`  
**Status:** Complete ✓

## What changed

Two monolithic Rust source files were decomposed into focused submodule directories using the impl-in-submodule pattern:

### `recovery.rs` (2197 lines) → `recovery/` directory

| File | Contents |
|------|----------|
| `recovery/mod.rs` | `Recovery` struct, `on_stall` (safety gate), public API, full test suite |
| `recovery/runner.rs` | `Outstanding` struct, `spawn_exec_child`, `take_capture_handles` |
| `recovery/reaper.rs` | `reap_finished_child`, `drain_outstanding_capture`, `emit_complete_audit` |
| `recovery/env.rs` | `apply_env` — environment isolation for recovery child processes |

### `audit.rs` (2243 lines) → `audit/` directory

| File | Contents |
|------|----------|
| `audit/mod.rs` | `RecoveryAuditLog` struct, `create()`, public API, `Drop`, integration tests |
| `audit/schema.rs` | TSV record types, `BootReason`, `AuditKind`, chain helpers, `parse_record` |
| `audit/writer.rs` | `DurableSink` trait, `FileSink`, emit/write/ring-buffer/fsync paths, unit tests |
| `audit/rotation.rs` | `RotationProgress` FSM, `TailProbe`, `drive_audit_rotation`, `probe_tail` |

## Safety invariants verified

1. **Recovery gate** — `on_stall()` (`recovery/mod.rs:714`) checks all three gates before spawning:
   - Cross-namespace check (line 719)
   - `NetworkUnverified` check (line 733)
   - `SocketModeOnly` check (line 746)
   - `spawn_exec_child` call (line 809)

2. **Fsync chain** — exactly 3 `sync_data` call sites in production code:
   - `audit/mod.rs:408` — `Drop` best-effort final sync
   - `audit/writer.rs:33` — `FileSink` impl delegates to `File::sync_data`
   - `audit/writer.rs:194` — `flush_and_sync()` cadence sync

## CI gate results

```
cargo check -p varta-watch                          ✓ clean
cargo check -p varta-watch --features prometheus-exporter  ✓ clean
VARTA_CONFIG_FILE=<cfg> cargo check --features compile-time-config  ✓ clean
cargo clippy -p varta-watch -- -D warnings          ✓ clean
cargo fmt --check                                   ✓ clean
cargo test -p varta-watch                           ✓ 264 passed, 0 failed
```

## Public API preserved

- `crate::audit::{RecoveryAuditLog, AuditConfig, CreateWarnings, SpawnRecord, CompleteRecord, RefusedRecord, CompleteOutcome, RotationOutcome, chain_enabled}` — all re-exported from `audit/mod.rs`, unchanged signatures.
- `crate::recovery::{Recovery, RecoveryOutcome}` — re-exported from `recovery/mod.rs`, unchanged.

## Visibility pattern used

`pub(in crate::audit)` on struct fields whose types are private to the audit module (`sink: BufWriter<Box<dyn DurableSink>>`, `rotation_progress: RotationProgress`). All other fields use `pub(super)`. Submodules access sibling types via `super::sibling::Type` paths.

## Next session

The epic continues with further modularization targets TBD. See `session-01-handoff.md` for the overall charter.
