#!/bin/sh
# install.sh — install varta-watch on Linux/macOS bare metal or VM.
#
# Pinned to a release tag; downloads the matching tar.gz, verifies
# sha256, optionally verifies the cosign signature, and (when root +
# systemd are present) drops in a unit file.
#
#   curl -fsSL https://varta.sh/install.sh | sh
#   curl -fsSL https://varta.sh/install.sh | VERSION=v0.2.0 sh
#   curl -fsSL https://varta.sh/install.sh | INSTALL_DIR=$HOME/.local/bin sh
#
# Override knobs (env vars):
#   VERSION       Release tag (default: latest)
#   INSTALL_DIR   Binary install directory (default: /usr/local/bin)
#   ASSUME_YES    1 to skip interactive confirmation (required for pipe-from-curl)
#   GH_REPO       Override repository (default: aramirez087/Varta)
#   SKIP_SYSTEMD  1 to skip systemd unit installation even on a systemd host
#   VERIFY_COSIGN 1=fail-on-missing-cosign, 0=warn-only (default: 0)

set -eu

GH_REPO="${GH_REPO:-aramirez087/Varta}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERIFY_COSIGN="${VERIFY_COSIGN:-0}"
SKIP_SYSTEMD="${SKIP_SYSTEMD:-0}"
ASSUME_YES="${ASSUME_YES:-0}"

# ---- helpers -----------------------------------------------------------

err() { printf "\033[1;31mERROR:\033[0m %s\n" "$*" >&2; exit 1; }
warn() { printf "\033[1;33mWARN:\033[0m %s\n" "$*" >&2; }
info() { printf "\033[1;34m==>\033[0m %s\n" "$*"; }
ok() { printf "\033[1;32m✓\033[0m %s\n" "$*"; }

need() {
    command -v "$1" >/dev/null 2>&1 || err "'$1' is required on \$PATH"
}

detect_triple() {
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os" in
        Linux)  os_part="unknown-linux-musl" ;;
        Darwin) os_part="apple-darwin" ;;
        *)      err "unsupported OS: $os" ;;
    esac
    case "$arch" in
        x86_64|amd64)  arch_part="x86_64" ;;
        aarch64|arm64) arch_part="aarch64" ;;
        *)             err "unsupported arch: $arch" ;;
    esac
    echo "${arch_part}-${os_part}"
}

resolve_latest_version() {
    need curl
    api_url="https://api.github.com/repos/${GH_REPO}/releases/latest"
    # GitHub API returns "tag_name": "vX.Y.Z" — grep + cut keeps deps to coreutils.
    curl -fsSL "$api_url" \
        | grep -E '"tag_name":\s*"v' \
        | head -n1 \
        | sed -E 's/.*"tag_name":\s*"(v[^"]+)".*/\1/'
}

sha256_check() {
    archive="$1"
    expected="$2"
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$archive" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
    else
        err "neither sha256sum nor shasum is available"
    fi
    if [ "$actual" != "$expected" ]; then
        err "sha256 mismatch: expected $expected, got $actual"
    fi
}

cosign_verify() {
    archive="$1"
    bundle="$2"
    if ! command -v cosign >/dev/null 2>&1; then
        if [ "$VERIFY_COSIGN" = "1" ]; then
            err "cosign not found and VERIFY_COSIGN=1"
        fi
        warn "cosign not installed — skipping signature verification (set VERIFY_COSIGN=1 to require it)"
        return 0
    fi
    cosign verify-blob \
        --bundle "$bundle" \
        --certificate-identity-regexp "^https://github.com/${GH_REPO}" \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
        "$archive" >/dev/null 2>&1 \
        || err "cosign signature verification failed for $archive"
    ok "cosign signature verified"
}

confirm() {
    prompt="$1"
    [ "$ASSUME_YES" = "1" ] && return 0
    # If we have no TTY (pipe-from-curl) and ASSUME_YES is unset, the
    # only safe action is to bail and print the manual command.
    if [ ! -t 0 ]; then
        info "(non-interactive) skipping: $prompt"
        info "    Re-run with ASSUME_YES=1 to confirm without a TTY."
        return 1
    fi
    printf "  %s [y/N] " "$prompt"
    read -r reply
    case "$reply" in
        y|Y|yes|YES) return 0 ;;
        *)           return 1 ;;
    esac
}

# ---- main flow ---------------------------------------------------------

main() {
    need curl
    need tar
    need uname

    triple="$(detect_triple)"
    if [ -z "${VERSION:-}" ]; then
        info "Resolving latest release for ${GH_REPO}…"
        VERSION="$(resolve_latest_version)"
        [ -n "$VERSION" ] || err "could not resolve latest tag from GitHub API"
        ok "latest version: ${VERSION}"
    fi

    base_url="https://github.com/${GH_REPO}/releases/download/${VERSION}"
    archive_name="varta-watch-${VERSION}-${triple}.tar.gz"
    sha_name="${archive_name}.sha256"
    bundle_name="${archive_name}.cosign.bundle"

    tmpdir="$(mktemp -d)"
    # POSIX-portable trap.
    trap 'rm -rf "$tmpdir"' EXIT INT TERM HUP

    info "Downloading ${archive_name}…"
    curl -fsSL -o "${tmpdir}/${archive_name}" "${base_url}/${archive_name}"
    curl -fsSL -o "${tmpdir}/${sha_name}"     "${base_url}/${sha_name}"
    if ! curl -fsSL -o "${tmpdir}/${bundle_name}" "${base_url}/${bundle_name}" 2>/dev/null; then
        warn "cosign bundle not present in this release — skipping signature verification"
        rm -f "${tmpdir}/${bundle_name}"
    fi

    # The .sha256 file is `<hex>  <name>`; pull the hex column.
    expected="$(awk '{print $1}' "${tmpdir}/${sha_name}")"
    sha256_check "${tmpdir}/${archive_name}" "${expected}"
    ok "sha256 verified"

    if [ -f "${tmpdir}/${bundle_name}" ]; then
        cosign_verify "${tmpdir}/${archive_name}" "${tmpdir}/${bundle_name}"
    fi

    info "Extracting…"
    tar -xzf "${tmpdir}/${archive_name}" -C "${tmpdir}"

    bin_src=""
    for candidate in \
        "${tmpdir}/varta-watch" \
        "${tmpdir}/varta-watch-${VERSION}-${triple}/varta-watch" \
        "${tmpdir}/varta-watch-${VERSION}/varta-watch"; do
        if [ -f "$candidate" ]; then
            bin_src="$candidate"
            break
        fi
    done
    [ -n "$bin_src" ] || err "varta-watch binary not found in archive"

    install_bin="${INSTALL_DIR%/}/varta-watch"
    info "Installing → ${install_bin}"
    if [ ! -w "${INSTALL_DIR%/}" ] && [ "$(id -u)" -ne 0 ]; then
        err "${INSTALL_DIR} is not writable. Re-run with sudo, or set INSTALL_DIR=\$HOME/.local/bin"
    fi
    install -m 0755 "$bin_src" "$install_bin"
    ok "binary installed"

    "$install_bin" --version 2>/dev/null || true

    # --- optional: systemd unit ----------------------------------------
    if [ "$SKIP_SYSTEMD" = "1" ]; then
        info "Skipping systemd setup (SKIP_SYSTEMD=1)"
        print_next_steps_manual
        return 0
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        info "systemd not detected — skipping unit installation"
        print_next_steps_manual
        return 0
    fi
    if [ "$(id -u)" -ne 0 ]; then
        info "Not running as root — skipping systemd unit installation"
        info "    Re-run as root to drop /etc/systemd/system/varta-watch.service"
        print_next_steps_manual
        return 0
    fi

    if confirm "Install systemd unit, 'varta' user, and bearer token?"; then
        install_systemd
        print_next_steps_systemd
    else
        info "Skipped systemd setup."
        print_next_steps_manual
    fi
}

install_systemd() {
    unit_src=""
    for candidate in \
        "${tmpdir}/varta-watch.service" \
        "${tmpdir}/varta-watch-${VERSION}-${triple}/varta-watch.service" \
        "${tmpdir}/varta-watch-${VERSION}/varta-watch.service"; do
        if [ -f "$candidate" ]; then
            unit_src="$candidate"
            break
        fi
    done
    [ -n "$unit_src" ] || err "varta-watch.service not bundled in archive"

    if ! id -u varta >/dev/null 2>&1; then
        info "Creating system user 'varta'"
        useradd --system --no-create-home --shell /usr/sbin/nologin varta
    fi

    install -d -m 0750 -o varta -g varta /etc/varta
    if [ ! -f /etc/varta/prom.token ]; then
        info "Generating /etc/varta/prom.token"
        need openssl
        umask 077
        openssl rand -hex 32 > /etc/varta/prom.token
        chmod 0400 /etc/varta/prom.token
        chown varta:varta /etc/varta/prom.token
    else
        info "Leaving existing /etc/varta/prom.token unchanged"
    fi

    install -m 0644 "$unit_src" /etc/systemd/system/varta-watch.service
    systemctl daemon-reload
    ok "systemd unit installed"
}

print_next_steps_manual() {
    cat <<EOF

Next steps:

  # Run varta-watch in the foreground for a smoke test:
  ${install_bin} --socket /tmp/varta.sock \\
                 --prom-addr 127.0.0.1:9100 \\
                 --prom-token-file /tmp/prom.token

  # Or for Docker / Kubernetes / Helm:
  https://varta.sh/book/operations/install.html

EOF
}

print_next_steps_systemd() {
    cat <<EOF

Next steps:

  systemctl enable --now varta-watch
  systemctl status varta-watch
  curl -sS -H "Authorization: Bearer \$(sudo cat /etc/varta/prom.token)" \\
       http://127.0.0.1:9100/metrics | head

Operator guide: https://varta.sh/book/operations/install.html
EOF
}

main "$@"
