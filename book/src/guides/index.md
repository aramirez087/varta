# Guides

Practical comparisons and setup walkthroughs for teams evaluating Varta
against familiar watchdog and observability patterns.

| Guide | When to read |
|-------|----------------|
| [Varta vs the alternatives](varta-vs-alternatives.md) | "I already have systemd / supervisord / k8s probes / an HTTP `/health` — why add this?" One decision matrix across all of them. |
| [Varta vs systemd `WatchdogSec`](varta-vs-systemd-watchdog.md) | You already rely on systemd unit watchdogs and want one observer for many agents. |
| [Varta vs HTTP `/health` checks](varta-vs-http-health.md) | Every service exposes an HTTP probe today; you want sub-microsecond beats without a sidecar HTTP stack. |
| [Prometheus setup walkthrough](prometheus-setup.md) | You need scrape config, alert rules, and a Grafana dashboard in one sitting. |

The full operator reference remains in [Monitoring & Alerting](../operations/monitoring.md).
The loadable artefact bundle lives in [`observability/`](https://github.com/aramirez087/Varta/tree/main/observability).