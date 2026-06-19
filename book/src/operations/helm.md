# Helm Chart

The chart at [`charts/varta-watch/`](https://github.com/aramirez087/Varta/tree/main/charts/varta-watch)
is published as an OCI artifact at
`oci://ghcr.io/aramirez087/charts/varta-watch`. Default render matches
the key observer-container fields from the raw manifests at
[`observability/examples/kubernetes/`](https://github.com/aramirez087/Varta/tree/main/observability/examples/kubernetes)
(a `helm-parity` CI gate fails the build on drift).

## Install

```sh
helm install varta-watch \
  oci://ghcr.io/aramirez087/charts/varta-watch \
  --version 0.1.1 \
  --create-namespace \
  --namespace varta \
  --set prometheusToken.token=$(openssl rand -hex 32)
```

For production, source the token from your secret manager (SOPS, ESO,
Vault Secrets Operator) and reference an existing Secret instead:

```yaml
prometheusToken:
  existingSecret:
    name: varta-prom-token   # provisioned out-of-band
    key: token
```

## Deployment modes

Switch via `--set mode=…`:

| Mode        | Object              | Use when                                                  |
| ----------- | ------------------- | --------------------------------------------------------- |
| `daemonset` | `DaemonSet`         | One observer per node. UDS via `hostPath:/run/varta`.     |
| `sidecar`   | `Deployment` (1)    | Strict tenant isolation. UDS in an `emptyDir` of one Pod. |

The chart resolves the UDS volume type per mode (host path vs.
`emptyDir`) and emits exactly one of the two object kinds.

Each workload pod includes a `uds-permissions` init container that
prepares the socket parent before `varta-watch` binds. It makes the
directory owned by the configured observer UID/GID and mode `0755`, so
Kubernetes `fsGroup` handling cannot leave `/run/varta` in a
group-writable state that the observer rejects.

## Values reference

The full reference is the chart's own
[`values.yaml`](https://github.com/aramirez087/Varta/blob/main/charts/varta-watch/values.yaml).
Most-touched knobs:

| Path                                        | Default                                   | Notes                                                                 |
| ------------------------------------------- | ----------------------------------------- | --------------------------------------------------------------------- |
| `mode`                                      | `daemonset`                               | `daemonset \| sidecar`                                                |
| `image.tag`                                 | `""` (→ `Chart.appVersion`)               | Pin to an immutable tag for production                                |
| `image.repository`                          | `ghcr.io/aramirez087/varta-watch`         |                                                                       |
| `prometheusToken.token`                     | `""`                                      | Set or use `existingSecret.name`                                      |
| `prometheusToken.existingSecret.name`       | `""`                                      | Out-of-band Secret name                                               |
| `uds.path`                                  | `/run/varta/varta.sock`                   |                                                                       |
| `uds.hostPath`                              | `/run/varta`                              | `daemonset` mode only                                                 |
| `udsInit.image.repository`                  | `busybox`                                 | Init image that prepares the UDS parent directory                     |
| `selfWatchdogSecs`                          | `4`                                       | Matches the example systemd unit's half-WatchdogSec                   |
| `extraArgs`                                 | `[]`                                      | Verbatim appended to argv                                             |
| `prometheus.bindAddr`                       | `0.0.0.0:9100`                            | `""` disables the HTTP endpoint                                       |
| `prometheus.serviceMonitor.enabled`         | `true`                                    |                                                                       |
| `prometheus.serviceMonitor.release`         | `kube-prometheus-stack`                   | Match your kube-prometheus selector                                   |
| `prometheus.podMonitor.enabled`             | `false`                                   | Alternative to ServiceMonitor                                         |
| `dashboard.enabled`                         | `true`                                    | Emits sidecar-labelled ConfigMap with the dashboard JSON              |
| `resources.{requests,limits}`               | 25m / 32 Mi / 250m / 128 Mi               |                                                                       |
| `namespace.create`                          | `true`                                    | Set false if you manage namespaces out-of-band                        |

## Helm test

```sh
helm test varta-watch -n varta
```

Runs an in-cluster Pod that scrapes `/metrics` with the bearer token
and asserts the observer is emitting `varta_iterations_total`. The pod
is cleaned up after success (`helm.sh/hook-delete-policy:
before-hook-creation,hook-succeeded`).

## Upgrading

```sh
helm upgrade varta-watch \
  oci://ghcr.io/aramirez087/charts/varta-watch \
  --version 0.2.0 \
  -n varta \
  --reuse-values
```

The chart follows SemVer independently from the `varta-watch` app
version. Breaking template changes (e.g. renaming a values key) bump
the chart's major; bumping just the appVersion (a new binary release)
bumps the chart patch.

## Verifying the chart artifact

```sh
cosign verify oci://ghcr.io/aramirez087/charts/varta-watch:0.1.1 \
  --certificate-identity-regexp '^https://github.com/aramirez087/Varta' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

## Loading the dashboard under kube-prometheus

`dashboard.enabled: true` ships a ConfigMap with the Grafana sidecar
label (default `grafana_dashboard: "1"`) — the kube-prometheus-stack
Grafana sidecar auto-imports it. If you run a custom Grafana, point its
sidecar at the chart's namespace or override `dashboard.label` /
`dashboard.labelValue` / `dashboard.namespace`.

## Migrating from raw manifests

Adopters who previously used
[`observability/examples/kubernetes/`](https://github.com/aramirez087/Varta/tree/main/observability/examples/kubernetes)
can switch to the chart with no operational disruption: the rendered
default keeps the observer container image repository, args, and mounts
in sync with the raw manifest. The CI `helm-parity` job asserts this on
every PR. Expected differences include Helm-standard labels
(`helm.sh/chart`, `app.kubernetes.io/managed-by`) and chart-managed init
containers for token staging and UDS directory preparation.
