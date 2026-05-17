# Container Image

## Registry

```
ghcr.io/aramirez087/varta-watch:<version>
ghcr.io/aramirez087/varta-watch:<major>.<minor>
ghcr.io/aramirez087/varta-watch:latest        # discouraged in production
```

Multi-arch: `linux/amd64` + `linux/arm64`. Same digest for both — the
image index resolves at pull time.

## What's inside

- Base: `gcr.io/distroless/static-debian12:nonroot` (pinned by digest;
  bumped via Renovate alongside the matching `:debug-nonroot` tag).
- Binary: `varta-watch` built with `prometheus-exporter` + `json-log`
  features. Class-A (`compile-time-config`) builds are deliberately
  **not** published as the public image — see
  [Safety Profiles](../architecture/safety-profiles.md).
- User: `nonroot` (UID 65532, matches the Helm chart and the example
  DaemonSet).
- No shell, no `apt`, no busybox in the default tag. A `:debug-<ver>`
  tag with the busybox shell is published separately for triage.

## Running

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
  ghcr.io/aramirez087/varta-watch:0.2.0 \
  --uds-path=/run/varta/varta.sock \
  --prom-addr=0.0.0.0:9100 \
  --prom-token-file=/etc/varta/prom.token \
  --self-watchdog-secs=4
```

`--self-watchdog-secs 4` is useful even without systemd — the
in-process watchdog still aborts on wedge, and `--restart
unless-stopped` brings the container back up.

## Verifying the image

```sh
cosign verify ghcr.io/aramirez087/varta-watch:0.2.0 \
  --certificate-identity-regexp '^https://github.com/aramirez087/Varta' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

CycloneDX SBOM is attached via `cosign attest --type cyclonedx`:

```sh
cosign verify-attestation ghcr.io/aramirez087/varta-watch:0.2.0 \
  --type cyclonedx \
  --certificate-identity-regexp '^https://github.com/aramirez087/Varta' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  | jq -r '.payload | @base64d | fromjson | .predicate'
```

SLSA L3 build provenance is registered with GitHub:

```sh
gh attestation verify --repo aramirez087/Varta \
  oci://ghcr.io/aramirez087/varta-watch:0.2.0
```

## Image labels

Every image carries the OCI standard label set:

```
org.opencontainers.image.title         = varta-watch
org.opencontainers.image.description   = Varta observer — receives VLP frames and surfaces stalls.
org.opencontainers.image.source        = https://github.com/aramirez087/Varta
org.opencontainers.image.documentation = https://varta.sh/book/operations/container.html
org.opencontainers.image.vendor        = Varta
org.opencontainers.image.licenses      = MIT OR Apache-2.0
org.opencontainers.image.version       = <tag>
org.opencontainers.image.revision      = <git sha>
```

## Building locally

The source Dockerfile lives at the repo root and uses BuildKit's
`$TARGETPLATFORM` cross-compile pattern:

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag varta-watch:local \
  --load .          # --push for registry publishing
```

CI smokes this on every PR (`docker-build` job in
`.github/workflows/ci.yml`) so a typo in the Dockerfile fails fast
instead of breaking adopters at the next tagged release.
