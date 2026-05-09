# OpenWolf

@.wolf/OPENWOLF.md

This project uses OpenWolf for context management. Read and follow .wolf/OPENWOLF.md every session. Check .wolf/cerebrum.md before generating code. Check .wolf/anatomy.md before reading files.


# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Varta is a zero-dependency health protocol library for distributed local agents written in Rust. Processes emit 32-byte heartbeats over Unix Domain Sockets; a companion observer (`varta-watch`) decodes them, detects stalls, triggers recovery commands, and exports Prometheus metrics.

## Commands

```bash
# Build
cargo build --workspace
cargo build --workspace --release

# Test
cargo test --workspace
cargo test -p varta-tests --test end_to_end   # integration tests (spawns real binaries)

# Single test
cargo test -p <crate> <test_name>

# Lint
cargo fmt --check
cargo clippy --workspace -- -D warnings

# Format
cargo fmt

# Benchmarks (host-dependent results; Apple Silicon baseline ~900 ns p99)
cargo run -p varta-bench --release -- latency
cargo run -p varta-bench --release -- cpu-50-agents
cargo run -p varta-bench --release -- binary-size

# Examples
cargo run -p varta-client --example basic
cargo run -p varta-client --example with_payload
cargo run -p varta-client --example with_panic_handler
```

## Architecture

The workspace has five crates with a strict layering:

```
varta-vlp  ←  varta-client  ←  (consumers)
           ←  varta-watch
               ↑
           varta-tests (dev only)
           varta-bench (dev only)
```

**`varta-vlp`** — wire protocol only. Defines the 32-byte `Frame` (`#[repr(C, align(8))]`) and `Status` enum (`Ok`, `Degraded`, `Critical`, `Stall`). Encode/decode operate on `[u8; 32]` stack arrays. No dependencies of any kind.

**`varta-client`** — the agent-side API. `Varta::connect()` opens a non-blocking `UnixDatagram`; `beat(status, payload)` encodes on the stack and calls `send(2)`. Returns `BeatOutcome::{Sent, Dropped, Failed}` — `WouldBlock` is `Dropped`, never an error. Optional `panic-handler` feature installs a Rust panic hook that emits a `Critical` beat before unwinding.

**`varta-watch`** — the observer binary and library. Single-threaded poll loop over UDS. Per-pid state machine tracks silence thresholds and debounced recovery commands. Exports TSV files and a Prometheus `/metrics` endpoint.

**`varta-tests`** — end-to-end contract tests (`harness = false`) that spawn real built binaries and assert against the live Prometheus endpoint. Must be run after `cargo build --release`.

**`varta-bench`** — latency, CPU, and binary-size benchmarks. Results are host-dependent and documented in `docs/benchmarks/results.md`.

## Hard Constraints

These are load-bearing invariants — do not relax them:

1. **Zero registry dependencies** in production crates (`varta-vlp`, `varta-client`, `varta-watch`). `[dependencies]` must remain empty or path-only.
2. **Zero heap allocation** on the `beat()` path after `Varta::connect()`. All steady-state code operates on stack buffers. The guard-allocator test in `varta-tests` enforces this.
3. **Non-blocking only** — the agent socket is non-blocking at connect time. Code must never call `set_nonblocking(false)` or add blocking I/O to the beat path.
4. **Frame layout is ABI-stable.** Any change to the `Frame` field layout requires a VLP version bump and updated integration tests.
5. **Edition 2021**, toolchain pinned to `stable` via `rust-toolchain.toml`. Do not change the channel without updating all five crates.
