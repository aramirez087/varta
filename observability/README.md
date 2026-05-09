# Varta observability bundle

Turn-key Prometheus + Grafana + Alertmanager assets for `varta-watch`.
Drop in as-is; tune to taste later.

For narrative ("how do these metrics map to the architecture") see the
[Monitoring & Alerting](../book/src/operations/monitoring.md) book chapter.
This directory is the loadable artifact set; the book chapter is the
operator-facing prose.

## Contents

```
observability/
├── alerts/varta.rules.yml             Prometheus alerting rules
├── recording-rules/varta.rules.yml    Pre-computed SLI metrics
├── dashboards/varta-health.json       Grafana 10.x dashboard (24 panels, 6 rows)
└── examples/
    ├── prometheus-scrape.yml          Scrape job snippet (bearer-token auth)
    ├── alertmanager.yml               Routes / receivers (PagerDuty + Slack)
    ├── varta-watch.service            systemd Type=notify unit
    └── kubernetes/                    Deployment + ServiceMonitor + PodMonitor
```

## Load order

1. **Add scrape job.** Paste `examples/prometheus-scrape.yml`'s
   `scrape_configs:` block into your `prometheus.yml`. Adjust the target
   host and `credentials_file` path. Reload Prometheus.

2. **Install recording rules.**
   ```bash
   cp recording-rules/varta.rules.yml /etc/prometheus/rules.d/
   cp alerts/varta.rules.yml /etc/prometheus/rules.d/
   curl -X POST http://localhost:9090/-/reload
   ```
   Verify under `http://prometheus/rules` — there should be two new
   rule groups, `varta-watch.sli` (recording) and three alert groups
   (`varta-watch.critical`, `varta-watch.warning`, `varta-watch.info`).

3. **Route alerts.** Paste `examples/alertmanager.yml` into your
   Alertmanager config. Replace the PagerDuty routing key and Slack
   webhook URL. Reload Alertmanager.

4. **Import the dashboard.**
   Grafana → Dashboards → New → Import → Upload `dashboards/varta-health.json`
   → select your Prometheus datasource → Import.

## Kubernetes flavour

If you run kube-prometheus / prometheus-operator, replace step 1 with the
CRDs in `examples/kubernetes/`:

```bash
kubectl apply -f examples/kubernetes/varta-watch.deployment.yaml
kubectl apply -f examples/kubernetes/varta-watch.servicemonitor.yaml
```

The `release:` label on the `ServiceMonitor` must match your Prometheus CR's
`serviceMonitorSelector` (the kube-prometheus-stack chart defaults to
`release: <chart-release-name>`).

For dashboards under kube-prometheus, add the JSON as a `ConfigMap` with
the `grafana_dashboard: "1"` label — the sidecar will auto-import.

## Compatibility matrix

| Tool                    | Tested version | Minimum |
|-------------------------|----------------|---------|
| Prometheus              | 2.55           | 2.40    |
| Alertmanager            | 0.27           | 0.25    |
| Grafana                 | 10.4           | 10.0    |
| kube-prometheus-stack   | 60.x           | 50.x    |
| prometheus-operator CRD | 0.76           | 0.70    |

## Local smoke test

To validate the bundle against a fresh `varta-watch`:

```bash
# 1. Build varta-watch with the prometheus-exporter feature.
cargo build --release -p varta-watch --features prometheus-exporter

# 2. Run a one-shot compose stack (Prometheus + Alertmanager + Grafana).
docker run -d --name prom -p 9090:9090 \
  -v $PWD/observability:/etc/prometheus/varta:ro \
  prom/prometheus:latest \
  --config.file=/etc/prometheus/varta/examples/prometheus-scrape.yml \
  --web.enable-lifecycle

# 3. Launch varta-watch with a known token.
echo "$(openssl rand -hex 32)" > /tmp/varta.token
./target/release/varta-watch \
  --socket /tmp/varta.sock \
  --prom-addr 127.0.0.1:9100 \
  --prom-token-file /tmp/varta.token &

# 4. Watch /metrics in Prometheus, import the dashboard in Grafana,
#    then kill varta-watch and wait ~1m -- VartaWatchStalled should fire.
```

## Severity convention

Every alert carries one of three `severity` labels and matching
`runbook_url`:

| Severity   | Action                          | Routing target (Alertmanager) |
|------------|---------------------------------|-------------------------------|
| `critical` | Page on-call                    | PagerDuty                     |
| `warning`  | Investigate within working day  | Slack `#varta-alerts`         |
| `info`     | Record for trend analysis       | Slack `#varta-noise`          |

## Future: jsonnet mixin migration

This bundle is hand-authored YAML + JSON deliberately — Varta is a
single-purpose agent library, not a platform, and a full jsonnet mixin
adds build toolchain without payoff at this scale.

If the asset set grows past ~3 dashboards or ~50 alerts, migrate to the
[monitoring-mixins](https://monitoring.mixins.dev/) pattern:

```
observability/
├── mixin.libsonnet       # _config + grafanaDashboards + prometheusAlerts + prometheusRules
├── vendor/               # jsonnet-bundler deps (grafonnet, prometheus-libsonnet)
├── jsonnetfile.json
└── Makefile              # `make` compiles mixin to files/{alerts,rules}.yml + files/dashboards/*.json
```

The generated `files/` directory then replaces this directory's
hand-authored content; the source of truth becomes `mixin.libsonnet`.

## Audit trail

This bundle covers the 58 metrics emitted by `varta-watch` as of the
VLP v0.2 protocol revision. Any new metric added to `crates/varta-watch`
should either:

- be referenced by at least one alert / dashboard panel, or
- be explicitly noted as "internal debug" in `book/src/operations/monitoring.md`.

The CI job `observability-lint` enforces the alert-rule → metric-name
correspondence via `tools/check_dashboard_metrics.py`.
