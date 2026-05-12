# Varta Fuzz Suite

Coverage-guided fuzz testing for Varta's wire protocol, AEAD construction, tracker,
and CLI parser. Uses `cargo-fuzz` (libFuzzer) with nightly Rust.

## Prerequisites

```bash
rustup install nightly
cargo install cargo-fuzz
```

## Listing targets

```bash
cargo fuzz list
# → frame_decode, frame_roundtrip, aead_roundtrip, tracker_record, config_from_args, kdf_derive
```

## Running a target

```bash
cargo fuzz run frame_decode            # run with default corpus + max_len
cargo fuzz run frame_roundtrip -- -max_total_time=30   # 30 s limit
cargo fuzz run config_from_args corpus/config_from_args # seed corpus
```

## Targets

| Target | Crate under test | What it exercises |
|--------|-----------------|-------------------|
| `frame_decode` | `varta-vlp` | `Frame::decode` with arbitrary byte slices |
| `frame_roundtrip` | `varta-vlp` | Encode→decode bit-for-bit isomorphism |
| `aead_roundtrip` | `varta-vlp` (`crypto`) | ChaCha20-Poly1305 seal/open with tamper/wrong-key detection |
| `tracker_record` | `varta-watch` | `Tracker::record` insertion, eviction, stall detection |
| `config_from_args` | `varta-watch` | `Config::from_args` CLI argument parsing |
| `kdf_derive` | `varta-vlp` (`crypto`) | Key derivation hierarchy: determinism, one-way, collision resistance |

## CI

The `fuzz-smoke` job in `.github/workflows/ci.yml` runs all six targets for 30 seconds
each on pushes to `refs/heads/main`. Fuzz is not run on pull requests — it is too
expensive for per-commit feedback.

## Corpus

Corpus directories (`fuzz/corpus/<target>/`) are gitignored. Seed corpora should be
checked into the repository as tarballs if reproducible regression corpora are desired.
