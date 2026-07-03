# Install

Five paste-paths covering every mainstream operator audience. Pick the
one that matches your runtime. Every artifact in every path is built,
signed, and published by the same workflow
(`.github/workflows/release.yml`), so the supply chain is uniform
regardless of how you fetch it.

| Audience            | One-paste install                                                                                                            |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Bare metal / VM     | `curl -fsSL https://varta.sh/install.sh \| sh`                                                                               |
| Docker host         | `docker run … ghcr.io/aramirez087/varta-watch:0.3.0 …`                                                                       |
| Kubernetes (Helm)   | `helm install varta-watch oci://ghcr.io/aramirez087/charts/varta-watch --version 0.2.0 …`                                    |
| Rust developer      | `cargo binstall varta-watch`                                                                                                 |
| Source build        | `cargo install --path crates/varta-watch --features prometheus-exporter`                                                     |

> Kubernetes adopters who want raw manifests over Helm: keep using
> [`observability/examples/kubernetes/`](https://github.com/aramirez087/Varta/tree/main/observability/examples/kubernetes).
> The Helm chart's default render matches those files for container
> args, mounts, security context, ports, and probes — asserted by the
> `helm-parity` CI gate. Helm-standard labels (`helm.sh/chart`,
> `app.kubernetes.io/managed-by`) are the only deltas.

## Bare metal / VM — `install.sh`

```sh
curl -fsSL https://varta.sh/install.sh | sh
```

Knobs (env vars):

| Var            | Default            | Effect                                                       |
| -------------- | ------------------ | ------------------------------------------------------------ |
| `VERSION`      | latest release     | Pin to a specific tag, e.g. `VERSION=v0.3.0`                 |
| `INSTALL_DIR`  | `/usr/local/bin`   | Target directory for the binary                              |
| `ASSUME_YES`   | `0`                | `1` skips interactive prompts (required when piping curl)    |
| `VERIFY_COSIGN`| `0`                | `1` requires `cosign` on `$PATH` and fails if absent          |
| `SKIP_SYSTEMD` | `0`                | `1` skips systemd unit installation                          |
| `GH_REPO`      | `aramirez087/Varta`| Override repository for forks / mirrors                      |

The script:

1. Detects OS + arch and computes the matching release-asset triple.
2. Downloads the tarball + `.sha256` and verifies integrity.
3. If `cosign` is on `$PATH`, verifies the keyless signature against the
   GitHub Actions OIDC issuer + the `aramirez087/Varta` certificate
   subject (otherwise prints a recommendation and continues).
4. Copies the binary to `$INSTALL_DIR/varta-watch`.
5. On a systemd host running as root: creates the `varta` user,
   generates `/etc/varta/prom.token` (mode 0400), installs the unit at
   `/etc/systemd/system/varta-watch.service`, and prints the
   `systemctl enable --now varta-watch` invocation. Does **not** start
   the service automatically (operator-confirmation gate).

The installer itself is published as a release asset; the URL
`https://varta.sh/install.sh` redirects to the **versioned**, raw GitHub
URL so the script you run is reproducible.

## Docker

```sh
docker run -d --name varta-watch \
  --user 65532:65532 \
  --restart unless-stopped \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -v /run/varta:/run/varta \
  -v /etc/varta/prom.token:/etc/varta/prom.token:ro \
  -p 127.0.0.1:9100:9100 \
  ghcr.io/aramirez087/varta-watch:0.3.0 \
  --socket=/run/varta/varta.sock \
  --prom-addr=0.0.0.0:9100 \
  --prom-token-file=/etc/varta/prom.token \
  --self-watchdog-secs=4
```

Verify the image before pulling in production:

```sh
cosign verify ghcr.io/aramirez087/varta-watch:0.3.0 \
  --certificate-identity-regexp '^https://github.com/aramirez087/Varta' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

See [Container Image](container.md) for the full reference.

## Kubernetes (Helm)

```sh
helm install varta-watch \
  oci://ghcr.io/aramirez087/charts/varta-watch \
  --version 0.2.0 \
  --create-namespace \
  --namespace varta \
  --set prometheusToken.token=$(openssl rand -hex 32)
```

Then `helm test varta-watch -n varta` runs an in-cluster pod that
scrapes `/metrics` with the bearer token and asserts the observer is
emitting `varta_iterations_total`. See [Helm Chart](helm.md) for the
full values reference.

## Rust developer

```sh
cargo binstall varta-watch          # fetches the signed release tarball
# or
cargo install --path crates/varta-watch --features prometheus-exporter
```

`cargo binstall` resolves the platform triple via
`[package.metadata.binstall]` in
`crates/varta-watch/Cargo.toml`, pulls the same signed `.tar.gz` the
installer script uses, and verifies the sha256 sidecar before writing
to `$CARGO_HOME/bin`. No source build needed.

## Verifying the artifacts

Every release ships:

- `varta-watch-vX.Y.Z-<triple>.tar.gz`       — the binary + LICENSE + systemd unit
- `varta-watch-vX.Y.Z-<triple>.tar.gz.sha256` — checksum
- `varta-watch-vX.Y.Z-<triple>.tar.gz.cosign.bundle` — keyless cosign signature bundle
- `varta-watch-vX.Y.Z-<triple>.sbom.cdx.json` — CycloneDX SBOM
- SLSA L3 build provenance attached via GitHub's attestation API
- `install.sh` — the installer script itself (so you can verify before running)

Verify any binary tarball:

```sh
cosign verify-blob \
  --bundle varta-watch-v0.2.0-linux-amd64-musl.tar.gz.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/aramirez087/Varta' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  varta-watch-v0.2.0-linux-amd64-musl.tar.gz
```

Verify SLSA provenance (uses GitHub's verify API; no install needed):

```sh
gh attestation verify varta-watch-v0.2.0-linux-amd64-musl.tar.gz \
  --repo aramirez087/Varta
```

## Troubleshooting

- **`cosign` not found** — the install script prints a recommendation
  and continues with sha256-only verification, which is still strong
  given HTTPS + the GitHub release-asset URL. To require cosign, set
  `VERIFY_COSIGN=1`.
- **systemd unit fails to start** — `journalctl -u varta-watch -e`
  surfaces the real error. The most common cause is a missing
  `/etc/varta/prom.token` (the installer creates it; manual installs
  must do so before the first start).
- **Container exits immediately** — the binary fails fast on missing
  required flags. `docker logs varta-watch` shows the parse error.
  Compare against the canonical args in the Docker block above.
- **Helm test pod fails** — `kubectl -n varta logs <pod>` from the
  failing pod prints the exact curl output. The most common cause is a
  bearer token mismatch between the Secret and the binary's
  `--prom-token-file` mount.
