## Description

<!-- Provide a clear description of the changes and the rationale behind them. -->

## Architectural Compliance

- [ ] I have read the [Hard Constraints](CONTRIBUTING.md) and confirm this PR follows them.
- [ ] This PR adds **zero** registry dependencies to production crates.
- [ ] This PR adds **zero** heap allocations to the steady-state beat path.
- [ ] If `#[ignore]` was used, it is accompanied by a `// JUSTIFY:` comment.

## Verification Results

### Automated Tests
- [ ] `cargo test --workspace` passes.
- [ ] `cargo miri test -p varta-vlp` passes (if protocol/crypto touched).
- [ ] `cargo fuzz run <target>` has been run for 30s (if decoder/roundtrip touched).

### Benchmarks
<!-- If the beat path was modified, paste the results of `cargo run -p varta-bench --release -- latency` below. -->

```text
(Paste benchmark results here)
```

## Related Issues
<!-- Link to any related issues (e.g. Fixes #123) -->
