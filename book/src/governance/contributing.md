# Contributing to Varta

First, thank you for contributing! Varta is a high-assurance health protocol, and we maintain strict architectural and safety standards.

## The Varta "Hard Constraints"

Every contribution must adhere to these load-bearing invariants:

1.  **Zero Registry Dependencies**: Production crates (`varta-vlp`, `varta-client`, `varta-watch`) must have empty `[dependencies]` sections (other than internal path dependencies).
2.  **Zero Heap Allocation**: No heap allocation is permitted on the `beat()` path after connection. We verify this with `zero_alloc` tests using a guard allocator.
3.  **Non-Blocking I/O**: The beat path must never block. `WouldBlock` is handled as `Dropped(DropReason::KernelQueueFull)`.
4.  **ABI Stability**: Any change to the 32-byte `Frame` layout is a breaking change and requires a VLP version bump.
5.  **Strict Linting**: We run with `deny(unsafe_code)` at the workspace level. Permitted unsafe blocks (e.g., for FFI) must be explicitly allowed with `#[allow(unsafe_code)]` to create an audit trail.

## Development Workflow

### Prerequisites

- Rust stable (for production builds)
- Rust nightly (for fuzzing and Miri)
- `cargo-fuzz` and `miri` components installed

### The "JUSTIFY" Rule

If you must `#[ignore]` a test, the CI will fail unless you provide a `// JUSTIFY: <reason>` comment within 2 lines of the attribute. This ensures we don't accidentally leave gaps in our safety coverage.

### Running the Suite

```bash
# Lint & Format
cargo fmt
cargo clippy --workspace -- -D warnings

# Tests
cargo test --workspace

# Fuzzing (Mandatory for protocol changes)
cargo fuzz run frame_decode -- -max_total_time=30

# Miri (UB Audit)
cargo miri test -p varta-vlp
```

## Pull Request Process

1.  **Benchmarks**: If your change touches the `beat()` path, you must run `cargo run -p varta-bench --release -- latency` and include the results in your PR description.
2.  **Documentation**: Update `design.md` or crate READMEs if logic changes.
3.  **Zero-Alloc Verification**: Ensure `cargo test -p varta-tests --test zero_alloc` still passes.

## Code of Conduct

We follow the [Contributor Covenant](CODE_OF_CONDUCT.md). Please be respectful and professional.
