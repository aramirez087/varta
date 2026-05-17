# syntax=docker/dockerfile:1.7
#
# varta-watch container image.
#
# Two stages:
#   1. rust:1.84-bookworm  — cross-compile to static musl for $TARGETPLATFORM
#   2. distroless static   — final image (~3.5 MB, nonroot UID 65532)
#
# Built and published from .github/workflows/release.yml on every `v*` tag;
# CI smoke-builds (no push) on every PR via the `docker-build` job in
# .github/workflows/ci.yml. Tags published:
#   - ghcr.io/aramirez087/varta-watch:vX.Y.Z    (immutable per release)
#   - ghcr.io/aramirez087/varta-watch:latest    (moving — discouraged)
#
# Supply-chain provenance:
#   - SBOM (CycloneDX) attached via `cosign attest --type cyclonedx`
#   - Image signed via `cosign sign` (keyless, GH Actions OIDC)
#   - SLSA L3 provenance via `actions/attest-build-provenance`
# See book/src/operations/container.md for verification commands.

ARG RUST_VERSION=1.84
ARG DISTROLESS_DIGEST=sha256:20bc6c0bc4d625a22a8fde3e55f6515709b32055ef8fb9cfbddaa06d1760f838
# ^ gcr.io/distroless/static-debian12:nonroot pinned by digest. Refreshed
# by Renovate. Bump in lock-step with the matching `:debug-nonroot` digest.

# ---------- builder ----------
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-bookworm AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Static-musl link uses rust-lld + rust-shipped self-contained libs
# (`-C link-self-contained=yes`). No musl-gcc, no musl.cc cross
# tarball, no C toolchain at all — varta-watch has zero C deps, and
# the gcc wrapper was the source of a PT_INTERP regression that made
# the "static" binary still request `/lib/ld-musl-x86_64.so.1` on
# distroless. Keep `binutils` + `file` for the post-link audit step.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       binutils \
       ca-certificates \
       file \
    && rm -rf /var/lib/apt/lists/*

# Map docker $TARGETPLATFORM → rustup target triple.
RUN set -eux; \
    rustup default stable; \
    rustup update stable; \
    rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl; \
    case "$TARGETPLATFORM" in \
      linux/amd64) RUST_TARGET=x86_64-unknown-linux-musl ;; \
      linux/arm64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
      *) echo "unsupported TARGETPLATFORM=$TARGETPLATFORM" >&2; exit 1 ;; \
    esac; \
    echo "RUST_TARGET=$RUST_TARGET" > /tmp/build.env

WORKDIR /build
COPY . .

# Build with `--locked` so a drifted Cargo.lock fails the image build
# rather than silently re-resolving versions. Default features only —
# never compile-time-config (Class-A binary is excluded from public
# image per book/src/architecture/safety-profiles.md).
#
# Linker flags:
#   -C target-feature=+crt-static  → static libc (Rust 1.71+ defaults
#                                    musl to dynamic without this).
#   -C linker=rust-lld             → skip the gcc wrapper that injects
#                                    PT_INTERP into otherwise-static ELFs.
#   -C link-self-contained=yes     → use the static libs rustup ships in
#                                    rust-std-$TARGET; no system musl
#                                    package required.
#   -C relocation-model=static     → emit ET_EXEC (non-PIE). The Rust
#                                    musl target defaults to static-PIE,
#                                    which on this stack produced a PIE
#                                    that still carried PT_INTERP and
#                                    SIGSEGV'd at entry (null-deref in
#                                    SI_KERNEL — unrelocated pointer used
#                                    before crt self-reloc). Disabling
#                                    PIE removes both the interpreter
#                                    header and the broken relocation
#                                    pre-amble. See bug-370.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target,id=varta-target-${TARGETPLATFORM} \
    set -eux; \
    . /tmp/build.env; \
    echo '=== rustc cfg for target ==='; \
    rustc --print cfg --target "$RUST_TARGET" | grep -E 'target_feature|target_env' || true; \
    RUSTFLAGS='-C target-feature=+crt-static -C linker=rust-lld -C link-self-contained=yes -C relocation-model=static' \
      cargo build \
        --locked \
        --release \
        --target "$RUST_TARGET" \
        --features prometheus-exporter \
        --no-default-features \
        --features json-log \
        -p varta-watch; \
    cp "target/$RUST_TARGET/release/varta-watch" /out-varta-watch; \
    echo '=== file ==='; file /out-varta-watch; \
    echo '=== ldd ==='; ldd /out-varta-watch 2>&1 || true; \
    echo '=== readelf -l (program headers) ==='; readelf -l /out-varta-watch; \
    # Hard guards:
    #   1. distroless-static has no ELF interpreter — any PT_INTERP makes
    #      `docker run` fail with `exec: no such file or directory`.
    #   2. The Rust musl static-PIE output crashes at entry on this
    #      stack — reject ET_DYN ("pie executable") and require ET_EXEC.
    #   3. file(1) must report 'statically linked' (belt-and-suspenders
    #      against future regressions to dynamic-musl crt-static=false).
    if readelf -l /out-varta-watch | grep -q 'INTERP'; then \
      echo "FATAL: varta-watch has PT_INTERP — not statically linked" >&2; \
      exit 1; \
    fi; \
    if file /out-varta-watch | grep -q 'pie executable'; then \
      echo "FATAL: varta-watch is PIE — static-PIE crashes on this target; rebuild with -C relocation-model=static" >&2; \
      exit 1; \
    fi; \
    if ! file /out-varta-watch | grep -q 'statically linked'; then \
      echo "FATAL: file(1) does not report statically linked" >&2; \
      exit 1; \
    fi; \
    echo '=== runtime smoke (--help) ==='; \
    /out-varta-watch --help >/dev/null

# ---------- runtime ----------
FROM gcr.io/distroless/static-debian12@${DISTROLESS_DIGEST}

ARG GIT_SHA="unknown"
ARG VERSION="0.0.0"

LABEL org.opencontainers.image.title="varta-watch" \
      org.opencontainers.image.description="Varta observer — receives VLP frames and surfaces stalls." \
      org.opencontainers.image.source="https://github.com/aramirez087/Varta" \
      org.opencontainers.image.documentation="https://varta.sh/book/operations/container.html" \
      org.opencontainers.image.vendor="Varta" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}"

COPY --from=builder /out-varta-watch /usr/local/bin/varta-watch

# Distroless `:nonroot` ships UID 65532 — matches the example DaemonSet's
# `runAsUser: 65532` so the chart and the bare-Docker run land on the
# same UID without extra config.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/varta-watch"]
