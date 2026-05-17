# Bench Harness Results

Per-metric measurements captured by the dependency-free `varta-bench`
harness. Each row corresponds to one acceptance contract assertion in
[`docs/acceptance/varta-v0-1-0.md`](https://github.com/aramirez087/Varta/blob/main/docs/acceptance/varta-v0-1-0.md).

> Snapshot date: **2026-02-11**. `rust-toolchain.toml` pins the stable
> channel rather than a specific version, so the exact compiler will
> drift as stable advances. Re-run the harness on your own host before
> citing numbers in production decisions.

## Host

| Field          | Value                                                              |
|----------------|--------------------------------------------------------------------|
| OS             | Darwin 25.4.0 (xnu-12377.101.15) arm64                             |
| Hardware       | Apple Silicon (Mac, T6050 series)                                  |
| Rust toolchain | rustc 1.93.1 (01f6ddf75 2026-02-11) — stable channel pinned via `rust-toolchain.toml` |
| Working tree   | `epic/varta-v0-1-0--s06-integration-and-bench` clean at run time   |

## Results

| Metric          | Threshold      | Measured     | Status | Command                                                  |
|-----------------|----------------|--------------|--------|----------------------------------------------------------|
| `latency`       | p99 < 1 µs     | p99 = 916 ns | PASS   | `cargo run -p varta-bench --release -- latency`          |
| `cpu-50-agents` | < 0.1 %        | 0.0552 %     | PASS   | `cargo run -p varta-bench --release -- cpu-50-agents`    |
| `binary-size`   | Δ < 20 KB      | Δ = 3 872 B  | PASS   | `cargo run -p varta-bench --release -- binary-size`      |

Auxiliary latency metrics (same run): p50 = 584 ns, p99.9 = 1042 ns.

## Reproducibility

```bash
# Build the workspace once so varta-watch is in target/release.
cargo build --workspace --release

cargo run -p varta-bench --release -- latency
cargo run -p varta-bench --release -- cpu-50-agents       # ~35 s wall
cargo run -p varta-bench --release -- binary-size         # ~5 s wall
```

`cpu-50-agents` waits for the daemon to self-exit via
`--shutdown-after-secs 35` before snapshotting `getrusage(RUSAGE_CHILDREN)`,
so the measurement covers the full wall window over which the 50 agent
threads emit at 1 Hz. The wall is therefore the dominant cost.

## Threshold notes

- `latency`: thresholds are tagged HOST-DEPENDENT in `crates/varta-bench/src/main.rs`.
  Apple Silicon laptops show p99 ≈ 900 ns idle. Virtualised CI runners
  with noisy neighbours can spike — if the bench reports `STATUS: WARN`
  with a measured value above 1 µs, the harness is doing its job and a
  CI gate should classify it as a soft failure (warning, not red).
- `cpu-50-agents`: the daemon is mostly blocked in `recvfrom(2)` with
  the 100 ms read timeout. CPU usage scales sublinearly with agent count
  because the kernel batches wakeups. 0.0552 % of a 35 s wall is ~19 ms
  of daemon CPU.
- `binary-size`: link-time pulls in `Varta::connect`, the `Frame` codec,
  and the `BeatOutcome` enum. The diff is dominated by Rust's standard-
  library boilerplate for `UnixDatagram` plus a few KB of generated code
  for the encoder. The fixture crates use `lto = false`,
  `codegen-units = 1`, `opt-level = 3` so size comparisons are stable
  across runs.

## Status

All three contract assertions PASS on the host above. No WARN or FAIL
deviations to record for this session.
