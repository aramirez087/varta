# varta-watch — Helm chart

Health-protocol observer for distributed local agents.

## Install

```sh
helm install varta-watch \
  oci://ghcr.io/aramirez087/charts/varta-watch \
  --version 0.1.0 \
  --create-namespace \
  --namespace varta \
  --set prometheusToken.token=$(openssl rand -hex 32)
```

For production: provision the bearer token via your secret manager
(SOPS, External Secrets Operator, Vault) and reference it instead of
embedding the raw token in the values:

```yaml
prometheusToken:
  existingSecret:
    name: varta-prom-token
    key: token
```

## Deployment modes

| Mode      | Use when                                                                  |
| --------- | ------------------------------------------------------------------------- |
| daemonset | One observer per node. Agents share UDS via `hostPath:/run/varta`.        |
| sidecar   | Strict tenant isolation. UDS lives in an `emptyDir` inside one Pod.        |

Switch with `--set mode=daemonset` or `--set mode=sidecar`.

## Verifying the chart artifact

The chart is signed with cosign (keyless OIDC). Adopters can verify:

```sh
cosign verify oci://ghcr.io/aramirez087/charts/varta-watch:0.1.0 \
  --certificate-identity-regexp '^https://github.com/aramirez087/Varta' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

## Reference

- Values reference:   [`values.yaml`](./values.yaml)
- Operator guide:     https://varta.sh/book/operations/helm.html
- Container image:    https://varta.sh/book/operations/container.html
- Source:             https://github.com/aramirez087/Varta
