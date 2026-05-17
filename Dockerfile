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

# musl-tools provides the static-linker for x86_64; aarch64-linux-musl-gcc
# comes from the cross-compiler tarball below. We avoid `cross` to keep
# the build graph in plain docker buildx — fewer moving parts in CI.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       binutils \
       ca-certificates \
       file \
       musl-tools \
       wget \
       xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Map docker $TARGETPLATFORM → rustup target triple + linker.
RUN set -eux; \
    rustup default stable; \
    rustup update stable; \
    rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl; \
    case "$TARGETPLATFORM" in \
      linux/amd64) \
        RUST_TARGET=x86_64-unknown-linux-musl; \
        case "$BUILDPLATFORM" in \
          linux/amd64) \
            LINKER=musl-gcc; \
            ;; \
          linux/arm64) \
            LINKER=x86_64-linux-musl-gcc; \
            wget -qO /tmp/x86_64-musl.tgz \
              https://musl.cc/x86_64-linux-musl-cross.tgz; \
            tar -C /opt -xzf /tmp/x86_64-musl.tgz; \
            rm /tmp/x86_64-musl.tgz; \
            ;; \
          *) echo "unsupported cross: $BUILDPLATFORM -> $TARGETPLATFORM" >&2; exit 1 ;; \
        esac; \
        ;; \
      linux/arm64) \
        RUST_TARGET=aarch64-unknown-linux-musl; \
        LINKER=aarch64-linux-musl-gcc; \
        # musl.cc cross-toolchain (static binaries, no GLIBC dependency).
        wget -qO /tmp/aarch64-musl.tgz \
          https://musl.cc/aarch64-linux-musl-cross.tgz; \
        tar -C /opt -xzf /tmp/aarch64-musl.tgz; \
        rm /tmp/aarch64-musl.tgz; \
        ;; \
      *) echo "unsupported TARGETPLATFORM=$TARGETPLATFORM" >&2; exit 1 ;; \
    esac; \
    echo "RUST_TARGET=$RUST_TARGET" > /tmp/build.env; \
    echo "LINKER=$LINKER" >> /tmp/build.env

ENV PATH="/opt/aarch64-linux-musl-cross/bin:/opt/x86_64-linux-musl-cross/bin:${PATH}"

WORKDIR /build
COPY . .

# Build with `--locked` so a drifted Cargo.lock fails the image build
# rather than silently re-resolving versions. Default features only —
# never compile-time-config (Class-A binary is excluded from public
# image per book/src/architecture/safety-profiles.md).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target,id=varta-target-${TARGETPLATFORM} \
    set -eux; \
    . /tmp/build.env; \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$LINKER" \
    CC_x86_64_unknown_linux_musl="$LINKER" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$LINKER" \
    CC_aarch64_unknown_linux_musl="$LINKER" \
    RUSTFLAGS='-C target-feature=+crt-static' \
      cargo build \
        --locked \
        --release \
        --target "$RUST_TARGET" \
        --features prometheus-exporter \
        --no-default-features \
        --features json-log \
        -p varta-watch; \
    cp "target/$RUST_TARGET/release/varta-watch" /out-varta-watch; \
    strip /out-varta-watch || true; \
    echo '=== file ==='; file /out-varta-watch; \
    echo '=== readelf -d ==='; readelf -d /out-varta-watch | head -40 || true; \
    echo '=== readelf -l (PT_INTERP) ==='; readelf -l /out-varta-watch | grep -A1 INTERP || echo 'no PT_INTERP (static)'

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
