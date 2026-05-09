#!/usr/bin/env bash
# OSS-Fuzz build script for Varta.
#
# Runs inside the image defined in `oss-fuzz/Dockerfile`.  Mirrors
# `projects/varta/build.sh` in the upstream OSS-Fuzz repo.  Produces
# one fuzz binary and matching seed-corpus zip per declared target,
# writing them into `$OUT/` where OSS-Fuzz expects them.

set -euo pipefail

cd "$SRC/varta/fuzz"

# `-O` enables optimisations; OSS-Fuzz overrides sanitizer + coverage
# flags through its own environment, so we do not pass them here.
cargo +nightly fuzz build -O

TARGETS=(
  frame_decode
  frame_roundtrip
  aead_roundtrip
  tracker_record
  config_from_args
  kdf_derive
  peer_cred_cmsg
  flag_catalogue_lookup
  bounded_index_u32
  bounded_index_ip
  outstanding_table
  ip_state_table
)

TARGET_DIR="../target/x86_64-unknown-linux-gnu/release"

for t in "${TARGETS[@]}"; do
  cp "$TARGET_DIR/$t" "$OUT/"
  if [[ -d "corpus/$t" ]]; then
    pushd "corpus/$t" >/dev/null
    zip -q "$OUT/${t}_seed_corpus.zip" .
    popd >/dev/null
  fi
done
