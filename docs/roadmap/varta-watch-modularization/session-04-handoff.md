# Session 04 Handoff — Test Split

Date: 2026-05-16  
Branch: `epic/varta-watch-modularization--s04-test-split`

---

## What Was Done

Split `crates/varta-tests/tests/end_to_end.rs` (3426 lines, 33k tokens) into 5 scenario-focused submodules. All 27 test functions migrated; root reduced to ~350 lines of harness infrastructure.

### Files modified

| File | Change |
|------|--------|
| `crates/varta-tests/tests/end_to_end.rs` | Removed 27 test functions; updated `main()` to use `module::fn_name` pattern |
| `crates/varta-tests/tests/end_to_end/basic.rs` | Replaced stub: 6 tests |
| `crates/varta-tests/tests/end_to_end/recovery.rs` | Replaced stub: 7 tests |
| `crates/varta-tests/tests/end_to_end/observability.rs` | Replaced stub: 7 tests |
| `crates/varta-tests/tests/end_to_end/reconnect.rs` | Replaced stub: 3 tests |
| `crates/varta-tests/tests/end_to_end/secure_udp.rs` | Replaced stub: 4 feature-gated tests |
| `.wolf/anatomy.md` | Created |
| `.wolf/cerebrum.md` | Created |
| `.wolf/memory.md` | Created |
| `.wolf/buglog.json` | Created (empty) |

### Test-to-module mapping

**basic.rs** — `client_to_observer_to_recovery_full_loop`, `panic_handler_critical_beat_visible_in_metrics`, `concurrent_multi_agent_beats_visible_in_metrics`, `status_degraded_visible_in_metrics`, `clock_source_monotonic_smoke`, `clock_source_boottime_smoke` (linux-only)

**recovery.rs** — `recovery_exec_mode_touch_marker_file`, `recovery_cmd_file_mode`, `recovery_exec_file_mode`, `recovery_timeout_kill_after`, `recovery_env_isolation`, `recovery_audit_log_records_spawn_and_complete`, `recovery_audit_log_chain_survives_rotation_and_restart`

**observability.rs** — `max_beat_rate_limits_and_reports_metric`, `file_export_writes_tsv`, `file_export_rotation`, `tracker_capacity_exceeded_reports_eviction_metric`, `iteration_budget_holds_under_slow_scrape_load`, `serve_pending_seconds_separates_scrape_from_beat_path`, `hostile_frame_rejected_at_decode_with_label_emit`

**reconnect.rs** — `client_reconnect_after_observer_restart`, `client_auto_reconnect_after_dropped`, `signal_handling_graceful_shutdown`

**secure_udp.rs** — `udp_client_to_observer_beats_and_stall` (cfg udp), `secure_udp_client_to_observer_beats` (cfg secure-udp), `secure_udp_counter_wrap_continues_under_load` (cfg secure-udp+test-hooks), `secure_udp_fork_safe_under_real_fork` (cfg secure-udp+unix)

---

## Decisions Made

| Decision | Rationale |
|----------|-----------|
| Helpers stay in `end_to_end.rs` root | Per D8 from session 01: TempDir, ChildGuard, spawn_watch, drive_beats, etc. stay in root; submodules access via `super::item`. |
| `pub(super)` on all migrated functions | Required for `main()` to call `module::fn_name`. Not externally reachable; `missing_docs` lint does not fire. |
| Local `use` statements inside functions preserved as-is | Avoids shadowing conflicts (e.g. `use varta_vlp::{Frame, Status}` inside `hostile_frame_rejected_at_decode_with_label_emit`). |
| `#[allow(unsafe_code)]` preserved on `recovery_env_isolation` | Required for `unsafe { std::env::set_var(...) }` under `unsafe_op_in_unsafe_fn` deny. |
| `drive_beats` stays in root | Called only by `recovery_env_isolation` but classified as shared harness infrastructure. Accessible as `super::drive_beats` from recovery.rs. |
| Feature-gated imports in `secure_udp.rs` wrapped in `#[cfg(...)]` | Prevents unused-import warnings when features are off. `rustfmt` reorders these above stdlib imports. |

---

## Regressions / Known Issues

None. All CI gates pass:

```
cargo build --workspace           ✓
cargo test -p varta-tests --test end_to_end   ✓  (20 passed, 0 failed)
cargo test --workspace            ✓
cargo clippy --workspace -- -D warnings   ✓
cargo fmt --check                 ✓
```

---

## Next-Session Inputs

### Session 05 (reserved) — recovery.rs / audit.rs

Decision D5 stands: `crates/varta-watch/src/recovery.rs` and `crates/varta-watch/src/audit.rs` stay monolithic unless reversed by maintainer.

No file-path inputs for session 05.

### Session 06 — CI gate

Run full CI suite after sessions 02–04 complete:

```bash
cargo build --workspace --release
cargo test --workspace
cargo test -p varta-tests --test end_to_end
cargo clippy --workspace -- -D warnings
cargo fmt --check
```

Critical paths to verify in session 06:
- `crates/varta-watch/src/exporter/mod.rs` — `IterStage` and `STAGE_LABELS` still reachable from `main.rs` (sessions 02/03 work)
- `crates/varta-tests/tests/end_to_end.rs` — all 20+ tests pass end-to-end (this session's work)
- Feature-gated compile checks: `cargo check -p varta-tests --features secure-udp,test-hooks`
