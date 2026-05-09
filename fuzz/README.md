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
| `aead_roundtrip` | `varta-vlp` (`crypto`) | ChaCha20-Poly1305 seal/open integration boundary: tamper/wrong-key/wrong-nonce detection |
| `tracker_record` | `varta-watch` | `Tracker::record` insertion, eviction, stall detection |
| `config_from_args` | `varta-watch` | `Config::from_args` CLI argument parsing |
| `kdf_derive` | `varta-vlp` (`crypto`) | HKDF-SHA256 key derivation: determinism, domain separation, key hierarchy |

The AEAD primitives (ChaCha20, Poly1305) and KDF (HKDF-SHA256) are provided by
the externally-audited `chacha20poly1305` / `hkdf` RustCrypto crates. The fuzz
targets above exercise Varta's integration layer, not the primitives themselves.

## CI

The `fuzz-smoke` job in `.github/workflows/ci.yml` runs all six targets for 30 seconds
each on every push and pull request. Fuzz artifacts (crash reproducers) in
`fuzz/artifacts/` cause the job to fail.

## Corpus

Seed corpora under `fuzz/corpus/<target>/` are committed to the repository. The
`fuzz/artifacts/` directory is gitignored; any reproducer found by the fuzzer
should be triaged, the bug fixed, and the input committed under
`fuzz/corpus/<target>/regressions/` to prevent recurrence.
