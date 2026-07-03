# Deployment Patterns

Concrete recipes for the three most common `varta-watch` deployment
targets. All three files referenced live under
[`observability/examples/`](https://github.com/aramirez087/Varta/tree/main/observability/examples)
and are CI-linted on every push.

> **Looking for the one-paste install paths?** See
> [Install (Quickstart)](install.md) for `curl | sh`, `cargo
> binstall`, Helm, and Docker one-liners. This page is the reference
> on the underlying recipes those paths assemble.

## Pre-flight: the bearer token

`varta-watch` requires `--prom-token-file` whenever `--prom-addr` is
set. Generate the token once per host:

```bash
install -d -m 0750 -o varta -g varta /etc/varta
openssl rand -hex 32 | install -m 0400 -o varta -g varta /dev/stdin /etc/varta/prom.token
```

Anything that can read `/etc/varta/prom.token` can scrape `/metrics`.
Mirror the token to the Prometheus scraper via your secret manager
(Vault, SOPS, External Secrets Operator, etc.).

## systemd (bare metal / VM)

Drop `observability/examples/varta-watch.service` into
`/etc/systemd/system/varta-watch.service`, then:

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin varta
systemctl daemon-reload
systemctl enable --now varta-watch
systemctl status varta-watch
```

Key bindings the unit gets for free:

- `Type=notify` + `WatchdogSec=8s` — systemd will SIGABRT-then-SIGKILL
  the process if `WATCHDOG=1` doesn't arrive every 4 seconds (half of
  `WatchdogSec`).
- `--self-watchdog-secs 4` (passed in `ExecStart`) — auto-enables when
  `$WATCHDOG_USEC` is set; spawns the in-process watchdog thread that
  emits `WATCHDOG=1` and calls `process::abort()` on wedge before
  systemd has to intervene.
- Hardening flags (`ProtectSystem`, `NoNewPrivileges`,
  `MemoryDenyWriteExecute`, etc.) — defence in depth; safe to leave on
  even if your kernel ignores some of them.

Validate the unit syntactically on Linux:

```bash
systemd-analyze verify observability/examples/varta-watch.service
```

## Docker

```bash
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

Verify the image before pulling it into production:

```bash
cosign verify ghcr.io/aramirez087/varta-watch:0.3.0 \
  --certificate-identity-regexp '^https://github.com/aramirez087/Varta' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

The `--self-watchdog-secs 4` flag stays useful even without systemd —
the in-process watchdog still aborts on wedge, and Docker's
`--restart unless-stopped` brings the container back up.

## Kubernetes (kube-prometheus)

The supported path is the [Helm chart](helm.md); the raw manifests
remain for adopters who don't want Helm and are CI-asserted to match
the chart's default render.

```bash
# Helm (recommended)
helm install varta-watch \
  oci://ghcr.io/aramirez087/charts/varta-watch \
  --version 0.2.0 \
  --namespace varta --create-namespace \
  --set prometheusToken.token=$(openssl rand -hex 32)

# Or raw manifests
kubectl apply -f observability/examples/kubernetes/varta-watch.deployment.yaml
kubectl apply -f observability/examples/kubernetes/varta-watch.servicemonitor.yaml
```

Two patterns supported by the bundle:

1. **Per-node `DaemonSet`** (default): one observer per node, agents
   share the UDS via `hostPath:/run/varta`. Easiest fit for existing
   workloads not deployed as pods of their own.
2. **Sidecar**: replace the `DaemonSet` with a `Deployment` and mount
   `emptyDir: {}` at `/run/varta`. Only agents inside the same pod can
   reach the observer; useful for strict isolation (one Varta per
   tenant).

`ServiceMonitor` vs. `PodMonitor`:

- Use `ServiceMonitor` (default) when you keep the headless `Service`.
  Discovery is via `Service` endpoints; Prometheus retrieves the pod
  list from the API server.
- Use `PodMonitor` (alternative manifest provided) when you remove the
  `Service` for strict-sidecar deployments. Discovery is direct pod
  enumeration.

The `release:` label on the CRD must match your Prometheus CR's
`serviceMonitorSelector`. The kube-prometheus-stack Helm chart defaults
to `release: <chart-release-name>`; adjust accordingly.

### Loading the dashboard under kube-prometheus

Two options:

1. **`ConfigMap` with the sidecar label** (recommended — Grafana
   auto-imports):

   ```bash
   kubectl create configmap varta-grafana-dashboard \
     --from-file=observability/dashboards/varta-health.json \
     -n monitoring
   kubectl label configmap varta-grafana-dashboard \
     grafana_dashboard="1" \
     -n monitoring
   ```

2. **`grafanaDashboards` field on a `GrafanaDashboard` CR** if you run
   the [grafana-operator](https://grafana-operator.github.io/grafana-operator/).

## Class-A safety-critical builds

The `compile-time-config` Cargo feature **structurally excises** the
Prometheus exporter from the binary (see
[Compile-Time Configuration](../architecture/compile-time-config.md) and
[Safety Profiles](../architecture/safety-profiles.md)). If you're
deploying a Class-A profile:

- The deployment recipes on this page do **not** apply — `--prom-*`
  flags are not recognised by the binary, and the CI strings audit
  rejects `GET /metrics` literals in the artifact.
- Use the file exporter (`--export-file <path>`) instead. The TSV
  schema is documented in `crates/varta-watch/README.md`.
- For audit-log integrity, treat the on-disk audit log as the source of
  truth; there is no `/metrics` endpoint to scrape.

## Verifying a deployment

Sanity checks for any of the three deployment patterns:

```bash
# 1. Token authenticates.
curl -sS -H "Authorization: Bearer $(cat /etc/varta/prom.token)" \
  http://127.0.0.1:9100/metrics | head

# 2. Bad token rejected.
curl -i -H "Authorization: Bearer not-the-token" \
  http://127.0.0.1:9100/metrics
# Expect: HTTP/1.0 401 Unauthorized

# 3. Stable label set present (alert rules depend on it).
curl -sS -H "Authorization: Bearer $(cat /etc/varta/prom.token)" \
  http://127.0.0.1:9100/metrics \
  | grep -E '^varta_rate_limited_total\{reason='
# Expect: both reason="per_pid" and reason="global" lines, value 0
```
