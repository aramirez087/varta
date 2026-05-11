# Nits Cleanup — Design Decisions

Each nit maps to exactly one downstream session. The "Current state" describes the code as of 2026-05-11.

## n1 — Frame::decode `.expect("len N")` noise

- **Current state** (`crates/varta-vlp/src/lib.rs:153-156`): Four `.try_into().expect("len N")` calls on statically correct `[u8]` slices from a `&[u8; 32]` input.
- **Decision**: Replace all with `.unwrap()`. The indices are provably correct from the const-generic input type; `.expect()` adds dead-weight panic message strings. No behavioural change.
- **Owner**: Session 02

## n2 — Slot::EMPTY sentinel

- **Current state** (`crates/varta-watch/src/tracker.rs:41-47`): `Slot::EMPTY` uses `pid: 0` as the sentinel for unallocated slots. `Tracker::record` at line 111 compares `slot.pid == frame.pid` for lookup, which means pid 0 could theoretically collide with a real agent.
- **Decision**: Add a private `used: bool` field to `Slot` (default `false` in EMPTY). All allocation/lookup/iteration gates switch to `!slot.used` / `slot.used`. Do NOT add `Status::Unknown` — that would extend the wire enum, which is out of scope per Session 00 hard constraint #3.
- **Owner**: Session 03

## n3 — Redundant `status_code` helper

- **Current state** (`crates/varta-watch/src/exporter.rs:128-135`): `status_code(s: Status) -> u8` manually matches each variant to its discriminant. `Status` is already `#[repr(u8)]` with `Ok=0, Degraded=1, Critical=2, Stall=3`.
- **Decision**: Delete `status_code`. Every call site writes `s as u8` directly. `status_label` is kept — there is no compile-time equivalent for the string form.
- **Owner**: Session 04

## n4 — Missing `--read-timeout-ms` flag

- **Current state** (`crates/varta-watch/src/config.rs`): `--read-timeout-ms` is absent from `Config`, `HELP`, and `from_args`. The timeout is hard-coded as `const READ_TIMEOUT: Duration = Duration::from_millis(100)` in `observer.rs:22` and consumed at `observer.rs:264` via `sock.set_read_timeout(Some(READ_TIMEOUT))`.
- **Note**: The original nit mentioned `--socket-mode` as missing, but it already exists at `config.rs:174-179`. Only `--read-timeout-ms` needs adding.
- **Decision**: Add `pub read_timeout: Duration` to `Config` (default 100ms). Define `DEFAULT_READ_TIMEOUT_MS: u64 = 100`. Wire through observer construction. Extend `HELP` and `cli_help_lists_every_documented_flag` test.
- **Owner**: Session 05

## n5 — Varta thread-safety documentation

- **Current state** (`crates/varta-client/src/client.rs:107-115`): `Varta` struct has no thread-safety documentation. It is `Send` (UnixDatagram is Send) but not `Sync` (concurrent `&Varta::beat` would race on kernel-side send buffer ordering).
- **Decision**: Add a `# Thread safety` section to the `Varta` rustdoc stating `Send` but not `Sync`. Add a compile-time `Send` static assertion. Skip negative `!Sync` assertion (requires unstable negative impls); comment-only is sufficient.
- **Owner**: Session 06

## n6 — Missing HTTP method guard on PromExporter

- **Current state** (`crates/varta-watch/src/exporter.rs:248-276`): `serve_one` reads the request bytes but ignores method. Any HTTP method receives 200 with the metrics body.
- **Decision**: After the read loop, inspect the first 4 bytes. If they are not `b"GET "`, reply `HTTP/1.0 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n` and close. Reuse the existing write loop. Add a unit test for POST → 405.
- **Owner**: Session 04

## n7 — panic.rs allocation doc overclaim

- **Current state** (`crates/varta-client/src/panic.rs:31`): "The hook closure itself operates entirely on the stack." This is imprecise — kernel-side allocation inside `connect(2)` / `send(2)` is out of our control.
- **Decision**: Reword to "The hook closure body performs no heap allocations; kernel-side allocation inside connect(2) and send(2) is out of our control but does not affect the Rust allocator."
- **Owner**: Session 06

## n8 — Missing Frame::decode fuzz target

- **Current state**: No fuzz harness exists.
- **Decision**: Create top-level `fuzz/` directory with `cargo-fuzz` standard layout. `fuzz/Cargo.toml` with `libfuzzer-sys` dependency. `fuzz/fuzz_targets/frame_decode.rs` calling `Frame::decode(&buf)` on 32-byte slices. Exclude from workspace via `[workspace].exclude`. Add `fuzz/target`, `fuzz/corpus`, `fuzz/artifacts` to `.gitignore`. No CI step — fuzzing is opt-in.
- **Owner**: Session 02

## n9 — CI Linux-only matrix

- **Current state** (`.github/workflows/ci.yml:10`): `runs-on: ubuntu-latest`. No macOS testing.
- **Decision**: Convert to `strategy.matrix.os: [ubuntu-latest, macos-latest]` with `runs-on: ${{ matrix.os }}`. Keep `fail-fast: false`. All steps are POSIX-portable (cargo + awk + sed). If macOS surfaces real divergence (e.g. UDS errno differences in e2e tests), fix at the source.
- **Owner**: Session 07

## n10 — Inline acceptance contract in ci.yml

- **Current state** (`.github/workflows/ci.yml:58-80`): 22 test names embedded as a `contract='...'` heredoc in a YAML `run:` block.
- **Decision**: Externalise to `tools/acceptance-contract.tsv` (tab-separated: `name\tfile\tkind`). Rewrite the audit step to read via `while IFS=$'\t' read`. Keep the same validation logic. Remove the inline heredoc entirely.
- **Owner**: Session 07

## n11 — Empty varta-tests/src/lib.rs placeholder

- **Current state** (`crates/varta-tests/src/lib.rs`): 6-line placeholder doc comment. The crate has a `[[test]]` target that works without a `[lib]` section.
- **Decision**: Delete `crates/varta-tests/src/lib.rs` and the now-empty `crates/varta-tests/src/` directory. No Cargo.toml edits needed — `[[test]]` targets are sufficient for cargo to treat the package as valid.
- **Owner**: Session 07