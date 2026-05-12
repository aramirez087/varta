# Varta v0.1.0 — Acceptance Contract

Authoritative list of acceptance tests owned by each implementation session.
Downstream sessions MUST author tests with these exact identifiers in the listed
files. The `Test name` + `File` pair is the contract; the `Behavior` column is
descriptive. Disagreement with this contract is documented in the relevant
session handoff and never silently revised.

The CI gate (Session 08) grep-validates that every test name listed below is
present, un-ignored, and resolves to a `#[test]` (or `#[test]`-equivalent
benchmark assertion) in its declared file.

## Session 02 — varta-client core

| Test name | File | Behavior |
|---|---|---|
| `connect_succeeds_when_observer_socket_exists` | `crates/varta-client/tests/acceptance.rs` | `Varta::connect(path)` returns `Ok` when the observer's UDS is bound and reachable. |
| `beat_emits_canonical_32_byte_frame` | `crates/varta-client/tests/acceptance.rs` | `beat()` writes a 32-byte VLP frame whose decoded fields match the agent state (pid, monotonically increasing nonce, status, payload). |
| `beat_increments_nonce_monotonically` | `crates/varta-client/tests/acceptance.rs` | Successive `beat()` calls produce strictly increasing nonces (starting from 1, wrapping to 0 on exhaustion). |
| `beat_returns_dropped_when_observer_absent` | `crates/varta-client/tests/acceptance.rs` | When the observer is not listening, `beat()` returns `BeatOutcome::Dropped` (no panic, no block). |
| `beat_makes_zero_heap_allocations_after_init` | `crates/varta-client/tests/zero_alloc.rs` | A guard allocator armed after `connect()` panics on any heap allocation; 10 000 successive beats run without tripping it. |

## Session 03 — varta-watch core

| Test name | File | Behavior |
|---|---|---|
| `observer_emits_beat_per_received_frame` | `crates/varta-watch/tests/acceptance.rs` | Three frames in → three `Event::Beat` out, in order, with matching pid and nonce values. |
| `observer_emits_stall_after_threshold_elapses` | `crates/varta-watch/tests/acceptance.rs` | After one beat then silence past the configured threshold, the observer surfaces `Event::Stall` for that pid exactly once. |
| `observer_reports_decode_error_for_bad_magic` | `crates/varta-watch/tests/acceptance.rs` | A 32-byte payload of `0xFF` produces `Event::Decode(DecodeError::BadMagic)`. |
| `tracker_capacity_bounded_to_64_pids` | `crates/varta-watch/tests/acceptance.rs` | The 65th distinct pid yields `Update::CapacityExceeded`; `tracker.len() == 64` afterward. |

## Session 04 — panic-handler feature

| Test name | File | Behavior |
|---|---|---|
| `panic_handler_emits_critical_beat_before_unwind` | `crates/varta-client/tests/panic_feature.rs` | A panicking thread fires a final frame with `Status::Critical` and `nonce = u64::MAX` before unwinding. |
| `panic_handler_preserves_original_panic_outcome` | `crates/varta-client/tests/panic_feature.rs` | Installing the hook does not swallow the panic — `JoinHandle::join()` still returns `Err` carrying the original payload. |
| `panic_module_excluded_without_feature` | `crates/varta-client/tests/panic_feature.rs` | The file is gated `#![cfg(feature = "panic-handler")]`; without the feature the module and its exports do not exist (negative compile guard). |

## Session 05 — recovery, exporters, binary surface

| Test name | File | Behavior |
|---|---|---|
| `recovery_cmd_fires_once_per_stall_within_debounce` | `crates/varta-watch/tests/recovery_e2e.rs` | Two stalls inside the debounce window produce exactly one `recovery_cmd` invocation. |
| `recovery_cmd_template_substitutes_pid` | `crates/varta-watch/tests/recovery_e2e.rs` | `{pid}` in the template is replaced with the stalled pid before `/bin/sh -c` execution. |
| `prom_exporter_reports_beats_total_per_pid` | `crates/varta-watch/tests/exporter_endpoint.rs` | `GET /metrics` exposes `varta_beats_total{pid="…"} N` matching the count of accepted beats. |
| `prom_exporter_reports_stalls_total_per_pid` | `crates/varta-watch/tests/exporter_endpoint.rs` | `GET /metrics` exposes `varta_stalls_total{pid="…"} M` matching the stall count. |
| `file_exporter_appends_one_line_per_event` | `crates/varta-watch/tests/exporter_endpoint.rs` | After N events, the exporter file contains exactly N lines with a stable schema. |
| `cli_help_lists_every_documented_flag` | `crates/varta-watch/tests/cli_smoke.rs` | The compiled binary's `--help` output contains every flag documented by `Config::from_args`. |

## Session 06 — end-to-end and bench

| Test name | File | Behavior |
|---|---|---|
| `client_to_observer_to_recovery_full_loop` | `crates/varta-tests/tests/end_to_end.rs` | Real client → real observer → stall → real `recovery_cmd`; the metrics endpoint reflects the full transcript. |
| `panic_handler_critical_beat_visible_in_metrics` | `crates/varta-tests/tests/end_to_end.rs` | A child process installs the panic hook, panics, and the parent observer's `/metrics` reflects the Critical beat. |
| `bench_latency_p99_under_one_microsecond` | `crates/varta-bench/src/main.rs` (subcommand `latency`) | Steady-state `beat()` p99 < 1 µs (release build, post-warmup). |
| `bench_observer_cpu_under_zero_point_one_percent` | `crates/varta-bench/src/main.rs` (subcommand `cpu-50-agents`) | Observer process CPU < 0.1 % at 50 agents × 1 Hz. |
| `bench_binary_size_delta_under_twenty_kilobytes` | `crates/varta-bench/src/main.rs` (subcommand `binary-size`) | Linking `varta-client` adds < 20 KB to a stripped release binary vs. an empty fixture. |

---

**Total acceptance tests: 23** (5 + 4 + 3 + 6 + 5).
