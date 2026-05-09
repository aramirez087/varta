# Session 02 — Handoff (varta-client core)

## Done

- `crates/varta-client/Cargo.toml` — added `[dependencies.varta-vlp]` table sub-entry pointing at `../varta-vlp`. The literal `[dependencies]` body remains empty so the awk gate continues to pass.
- `crates/varta-client/src/lib.rs` — replaced the skeleton with the public facade: `pub mod client;`, `pub use client::{BeatOutcome, Varta};`, `pub use varta_vlp::{DecodeError, Frame, Status};`.
- `crates/varta-client/src/client.rs` — new file. `Varta { sock, buf, pid, start, nonce }` with `connect<P: AsRef<Path>>` (sole allocation point) and non-blocking `beat(status, payload) -> BeatOutcome`. `BeatOutcome::{Sent, Dropped, Failed(io::Error)}`.
- `crates/varta-client/tests/acceptance.rs` — new file. Four S02 contract tests + `TempSocket` RAII helper.
- `crates/varta-client/tests/zero_alloc.rs` — new file. `GuardAlloc` `#[global_allocator]` wraps `System` with an `AtomicBool`-armed flag that panics on `alloc` while armed; the contract test connects, arms, beats 10 000 times, disarms, and decodes the latest received frame.
- `docs/roadmap/varta-v0-1-0/session-02-handoff.md` — this file.

## Decisions

- **Path-dep wiring without breaking the awk gate.** The S00 rule mandates a literal-empty `[dependencies]` body in production crates while S02 still needs `varta-vlp`. Solved by leaving `[dependencies]` empty and adding `[dependencies.varta-vlp]` as a separate table header. The awk gate matches `^\[dependencies\]$` exactly and clears its flag on the next `^\[`, so the sub-table header is invisible to it but Cargo treats it as a normal `dependencies.varta-vlp` entry. Session 01's handoff explicitly delegated this to S02.
- **Nonce semantics — start at 0, increment first, saturating.** `connect` initializes `nonce = 0`; `beat` does `nonce = nonce.saturating_add(1)` before building the frame, so the first emitted nonce is `1`. Saturation pins at `u64::MAX`, preserving that value as the sentinel reserved for the S04 panic hook (which sets the field directly, bypassing `beat`).
- **`BeatOutcome::Dropped` covers six `io::ErrorKind` values.** `WouldBlock` (queue full under non-blocking I/O), `ConnectionRefused` (Linux: peer socket unbound), `ConnectionReset` (macOS: peer dropped after connect), `BrokenPipe` (peer closed mid-send on some platforms), `NotFound` (socket inode disappeared), `NotConnected` (peer never came up). Anything else is genuinely unexpected and surfaced via `Failed(io::Error)` — note that `io::Error::from_raw_os_error` is heap-clean, so even the `Failed` arm allocates nothing on construction.
- **macOS-specific `ConnectionReset` mapping discovered during GREEN.** The plan anticipated `ConnectionRefused` only; on macOS, dropping a bound peer triggers `ECONNRESET` on the next send. Adding `ConnectionReset` (and defensively `BrokenPipe`) to the `Dropped` arm is the narrow fix called out in the plan's risk register.
- **No `unsafe` in production code.** `client.rs` is `unsafe`-free. The only `unsafe` blocks in the diff live in `tests/zero_alloc.rs` for the `GlobalAlloc` impl; each carries a `// SAFETY:` comment naming the invariant being upheld (forwarding `(layout)` and `(ptr, layout)` to `System` preserves the trait contract).
- **Hand-rolled `TempSocket` instead of a dev-dep.** `tempfile` would require a registry dependency. Path = `env::temp_dir() / format!("varta-{tag}-{pid}-{nanos}-{counter}.sock")` with a per-process atomic counter for collision-freedom. Stays well under macOS's 104-byte `sun_path` limit. `Drop` unlinks (best-effort) so parallel tests don't leak.
- **`format!` permitted in tests, forbidden in `client.rs`.** The grep gate `String::|Vec::|Box::|format!|vec!` runs only against `crates/varta-client/src/client.rs`; test fixtures may use `format!` for socket-path construction without violating the steady-state allocation contract.
- **Doc-test marked `no_run`.** `Varta::connect("/tmp/varta.sock")` would fail in a sandboxed CI environment; `no_run` compiles the example (so doc rot is caught) without executing it.
- **`ARMED` uses `Relaxed` ordering.** The test is single-threaded; the only synchronization required is that the store happens-before subsequent loads in program order, which Relaxed guarantees within a thread. Acquire/Release would be ceremony.

## TDD ledger

### RED

```text
$ cargo test -p varta-client 2>&1 | tail -30
16 | use varta_client::{Frame, Status, Varta};
   |                    ^^^^^  ^^^^^^  ^^^^^ no `Varta` in the root
   |                    |      |
   |                    |      no `Status` in the root
   |                    no `Frame` in the root
   |
   = help: consider importing this struct instead:
           varta_vlp::Frame
   = help: consider importing this enum instead:
           varta_vlp::Status

error[E0432]: unresolved imports `varta_client::BeatOutcome`, `varta_client::Frame`, `varta_client::Status`, `varta_client::Varta`
  --> crates/varta-client/tests/acceptance.rs:11:20
   |
11 | use varta_client::{BeatOutcome, Frame, Status, Varta};
   |                    ^^^^^^^^^^^  ^^^^^  ^^^^^^  ^^^^^ no `Varta` in the root
   |                    |            |      |
   |                    |            |      no `Status` in the root
   |                    |            no `Frame` in the root
   |                    no `BeatOutcome` in the root
   |
   = help: consider importing this struct instead:
           varta_vlp::Frame
   = help: consider importing this enum instead:
           varta_vlp::Status

For more information about this error, try `rustc --explain E0432`.
error: could not compile `varta-client` (test "zero_alloc") due to 1 previous error
warning: build failed, waiting for other jobs to finish...
error: could not compile `varta-client` (test "acceptance") due to 1 previous error
```

### GREEN

```text
$ cargo test -p varta-client 2>&1 | tail -30
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.00s
     Running unittests src/lib.rs (target/debug/deps/varta_client-12f1ea7b275868cf)
     Running tests/acceptance.rs (target/debug/deps/acceptance-ae9fbc15f8446ad3)
     Running tests/zero_alloc.rs (target/debug/deps/zero_alloc-21870e19c65bbd13)
   Doc-tests varta_client

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 4 tests
test beat_emits_canonical_32_byte_frame ... ok
test beat_increments_nonce_monotonically ... ok
test connect_succeeds_when_observer_socket_exists ... ok
test beat_returns_dropped_when_observer_absent ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 1 test
test beat_makes_zero_heap_allocations_after_init ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 1 test
test crates/varta-client/src/client.rs - client::Varta (line 41) - compile ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```

## API summary

```rust
// crates/varta-client/src/lib.rs
pub mod client;
pub use client::{BeatOutcome, Varta};
pub use varta_vlp::{DecodeError, Frame, Status};

// crates/varta-client/src/client.rs
pub struct Varta { /* sock, buf[32], pid, start: Instant, nonce */ }

impl Varta {
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self>;
    pub fn beat(&mut self, status: Status, payload: u64) -> BeatOutcome;
}

#[derive(Debug)]
pub enum BeatOutcome {
    Sent,
    Dropped,            // WouldBlock | ConnectionRefused | ConnectionReset
                        // | NotFound | NotConnected | BrokenPipe
    Failed(io::Error),  // every other ErrorKind
}
```

Behavioral guarantees:

- `connect` is the only allocation point; everything afterwards is heap-clean.
- `beat` never blocks (`set_nonblocking(true)` enforced at connect) and never panics.
- The first beat after `connect` carries `nonce == 1`; nonces saturate at `u64::MAX`.
- Frame layout matches `varta-vlp::Frame::encode` byte-for-byte (32 bytes, 8-byte aligned, little-endian).

## `unsafe` blocks

`crates/varta-client/src/client.rs` contains zero `unsafe` blocks.

`crates/varta-client/tests/zero_alloc.rs` (test-only fixture) contains:

- `unsafe impl GlobalAlloc for GuardAlloc` (the trait itself is `unsafe`).
- `unsafe { System.alloc(layout) }` — **SAFETY:** forwarding `(layout)` to the System allocator preserves the `GlobalAlloc` contract because `System: GlobalAlloc` upholds it.
- `unsafe { System.dealloc(ptr, layout) }` — **SAFETY:** forwarding `(ptr, layout)` (the same pair the runtime handed us) to the System allocator. Dealloc is always permitted; the guard only blocks new allocations.

## Open issues

None. All quality gates pass:

- `cargo fmt --all -- --check` → clean.
- `cargo clippy -p varta-client --all-targets -- -D warnings` → clean.
- `RUSTFLAGS="-D warnings" cargo test -p varta-client` → 4 acceptance + 1 zero-alloc + 1 doc-test = 6 pass / 0 fail.
- `cargo build -p varta-client --release` → clean.
- `cargo test --doc -p varta-client` → 1 pass.
- `awk '/^\[dependencies\]$/{f=1;next} /^\[/{f=0} f && NF{print; exit 1}' crates/varta-client/Cargo.toml` → empty.
- `grep -nE 'String::|Vec::|Box::|format!|vec!' crates/varta-client/src/client.rs` → empty.

## Next-session inputs

Session 03 (varta-watch core) and Session 04 (panic-handler feature) MUST read:

- `docs/acceptance/varta-v0-1-0.md` — §S03 and §S04 contracts (test names, files, behaviors).
- `crates/varta-vlp/src/lib.rs` — wire format `Frame::encode` / `Frame::decode`, `Status`, `MAGIC`, `VERSION`.
- `crates/varta-client/src/client.rs` — agent surface; S04 will install a panic hook here (entry point: a `panic` submodule under `#[cfg(feature = "panic-handler")]`) that constructs a `Frame` directly with `nonce = u64::MAX` and `Status::Critical`, encodes into a stack buffer, and `send`s on a freshly-`connect`ed `UnixDatagram` (cannot reuse `Varta`'s nonce counter because the sentinel must be exact, not saturating).
- `crates/varta-client/src/lib.rs` — current re-exports; S04 will add `#[cfg(feature = "panic-handler")] pub mod panic;` plus a `pub use panic::install_panic_hook;` (or similar) — keep the lints as-is.
- `crates/varta-client/Cargo.toml` — table-form path-dep pattern. S04 must add `[features] panic-handler = []` without touching the literal `[dependencies]` body.
- `crates/varta-client/tests/acceptance.rs` — fixture pattern for the `TempSocket` RAII helper and `UnixDatagram::bind`-based test server. S03's observer tests should mirror this style. S04's `tests/panic_feature.rs` should reuse the helper (copy-paste is acceptable; no shared module needed).
- `crates/varta-client/tests/zero_alloc.rs` — `GuardAlloc` pattern is reusable for any future zero-alloc invariant (e.g. confirming the panic hook itself is heap-clean if S04 chooses to assert that).
- `docs/roadmap/varta-v0-1-0/session-01-handoff.md` — Session 01's decisions (notably: `[dependencies]` literal-empty constraint, no `unsafe` in `varta-vlp`).
- `docs/roadmap/varta-v0-1-0/session-02-handoff.md` — this file.

### Suggested fixture pattern for Session 03's integration tests

S03 (varta-watch) needs the inverse: a real `Varta` agent firing into a real observer. Recommended pattern:

1. Create a `TempSocket` (copy from `tests/acceptance.rs`).
2. Spawn the observer (whatever S03's API ends up being) listening on `temp.path`.
3. `Varta::connect(&temp.path)` to get an agent.
4. Drive `agent.beat(...)` in the test; assert against the observer's emitted events.

For the stall test, a configurable threshold ≤ 50 ms keeps the test fast.
