# Prometheus setup walkthrough

This page is the fastest path from zero to **scraping `varta-watch`**, importing
the bundled Grafana dashboard, and paging on stalls. For alert semantics see
[Monitoring & Alerting](../operations/monitoring.md).

## Prerequisites

- `varta-watch` built with the default `prometheus-exporter` feature (not the
  Class-A excised profile).
- A bearer token file when `--prom-addr` is set.

```bash
openssl rand -hex 32 | sudo tee /etc/varta/prom.token >/dev/null
sudo chmod 0400 /etc/varta/prom.token
```

## 1. Start the observer

```bash
varta-watch \
  --socket /run/varta/varta.sock \
  --threshold-ms 2000 \
  --prom-addr 127.0.0.1:9100 \
  --prom-token-file /etc/varta/prom.token \
  --self-watchdog-secs 4
```

Verify metrics locally:

```bash
curl -s -H "Authorization: Bearer $(sudo cat /etc/varta/prom.token)" \
  http://127.0.0.1:9100/metrics | head
```

## 2. Configure Prometheus scrape

Copy the job from
[`observability/examples/prometheus-scrape.yml`](https://github.com/aramirez087/Varta/blob/main/observability/examples/prometheus-scrape.yml)
into your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: varta-watch
    scheme: http
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:9100"]
    authorization:
      type: Bearer
      credentials_file: /etc/varta/prom.token
```

Reload Prometheus (`POST /-/reload` or SIGHUP).

## 3. Install recording + alert rules

```bash
sudo cp observability/recording-rules/varta.rules.yml /etc/prometheus/rules.d/
sudo cp observability/alerts/varta.rules.yml          /etc/prometheus/rules.d/
curl -X POST http://localhost:9090/-/reload
```

Confirm under **Status → Rules** that groups `varta-watch.sli` and
`varta-watch.critical` appear.

## 4. Import Grafana dashboard

Grafana → **Dashboards → Import → Upload**
[`observability/dashboards/varta-health.json`](https://github.com/aramirez087/Varta/blob/main/observability/dashboards/varta-health.json)
and select your Prometheus datasource (24 panels, stall/recovery focused).

## 5. Route Alertmanager

Merge
[`observability/examples/alertmanager.yml`](https://github.com/aramirez087/Varta/blob/main/observability/examples/alertmanager.yml)
into your Alertmanager config. Replace PagerDuty / Slack placeholders before
reload.

## Kubernetes (kube-prometheus)

Skip hand-edited `prometheus.yml` and apply:

```bash
kubectl apply -f observability/examples/kubernetes/varta-watch.deployment.yaml
kubectl apply -f observability/examples/kubernetes/varta-watch.servicemonitor.yaml
```

The `release:` label on the `ServiceMonitor` must match your Prometheus
operator selector — see [Deployment Patterns](../operations/deployment.md).

## Smoke test with a live agent

```bash
cargo run -p varta-client --example basic
```

Watch `varta_beats_total` increment and confirm the Grafana **Beats** row moves.

## Related

- [Varta vs HTTP health checks](varta-vs-http-health.md)
- [Observability bundle README](https://github.com/aramirez087/Varta/blob/main/observability/README.md)