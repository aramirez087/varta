# Release notes

Each tagged release ships with a hand-written notes file at
`RELEASES/<tag>.md`. The release workflow at
`.github/workflows/release.yml` fails if the matching file is missing
on tag — this is deliberate: release notes that no human wrote are not
a useful audit trail.

## Template

```markdown
# v0.2.0 — <short summary>

<one-paragraph overview>

## Highlights

- …

## Breaking changes

- (or "None.")

## Container

```
ghcr.io/aramirez087/varta-watch:0.2.0  (multi-arch: linux/amd64, linux/arm64)
```

Verify:
```sh
cosign verify ghcr.io/aramirez087/varta-watch:0.2.0 \
  --certificate-identity-regexp '^https://github.com/aramirez087/Varta' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

## Helm chart

```sh
helm install varta-watch \
  oci://ghcr.io/aramirez087/charts/varta-watch \
  --version 0.1.0 -n varta --create-namespace
```

## Full changelog

See [CHANGELOG.md](../CHANGELOG.md).
```
