# Upgrade Guide

This page lists every change between Varta releases that requires
operator action. For the human-readable release prose see
[`RELEASES/`](https://github.com/aramirez087/Varta/tree/main/RELEASES);
for the full diff see
[`CHANGELOG.md`](https://github.com/aramirez087/Varta/blob/main/CHANGELOG.md).

The convention on this page: a checkbox per breaking change so you can
walk the list and tick off what you've handled.

---

## v0.1.x → v0.2.0

### Client API

- [ ] **`BeatOutcome::Dropped` now carries a `DropReason`.** Match
      against the variant or use a `_` placeholder. Variants:
      `KernelQueueFull`, `NoObserver`, `PeerGone`, `StorageFull`.

  ```rust
  // Before
  if let BeatOutcome::Dropped = outcome { … }

  // After
  if let BeatOutcome::Dropped(_) = outcome { … }
  ```

### Observer defaults (rate limiting)

The observer now ships with default-on rate limits. Reset all three to
zero if you want the v0.1 unlimited behaviour:

- [ ] `--max-beat-rate` defaults to `100` (per-pid). Disable with
      `--max-beat-rate 0`.
- [ ] `--global-beat-rate` defaults to `5000` (process-wide). Disable
      with `--global-beat-rate 0`.
- [ ] `--uds-rcvbuf-bytes` defaults to `1048576` (1 MiB). Skip tuning
      with `--uds-rcvbuf-bytes 0`.

### Shell-mode recovery removed

The `/bin/sh` recovery path is gone. Operators using shell templates
must migrate to the exec path. Passing a removed flag is now a hard
startup error.

- [ ] `--recovery-cmd <TEMPLATE>` → `--recovery-exec <PROGRAM> [ARGS…]`.
      The stalled pid is appended as the final argument.
- [ ] `--recovery-cmd-file <PATH>` → `--recovery-exec-file <PATH>`.
- [ ] `--i-accept-shell-risk` → remove; no replacement needed.

If your recovery logic relied on shell features (pipes, redirects),
wrap them in a script and exec the script:

```sh
#!/bin/sh
# /usr/local/bin/varta-recovery
PID="$1"
systemctl restart "myapp-${PID}"
```

```sh
varta-watch --recovery-exec /usr/local/bin/varta-recovery …
```

Full migration reference and rationale: [Shell-Mode Recovery
Removal](../architecture/recovery-shell-removal.md).

### Recovery child environment is isolated by default

Pre-v0.2.0 recovery children inherited the observer's full process
environment. From v0.2.0 they see **only** `PATH=/usr/bin:/bin` plus
any explicit `--recovery-env KEY=VALUE` entries.

This is the secure default; observer environments routinely carry
credentials (`AWS_*`, OAuth tokens, Vault tokens) and inheriting them
into a recovery child turns every recovery template into a credential
exfiltration vector.

- [ ] Audit your recovery scripts for environment dependencies. If they
      need any inherited variable, add it explicitly:

  ```sh
  varta-watch --recovery-env HOME=/var/log/varta --recovery-env LANG=C …
  ```

- [ ] Or, as an escape hatch, restore full inheritance:

  ```sh
  varta-watch --recovery-inherit-env …
  ```

  This emits a one-shot stderr warning at startup so the choice is
  visible in syslog / SIEM.

Full configuration matrix: [Recovery — Async Spawn → env
policy](../architecture/recovery-async-spawn.md#recovery-child-environment-policy).

### Wire format

- [ ] The frame layout is unchanged between v0.1 and v0.2. Existing
      agents continue to work. Future protocol bumps (v0.3+) will be
      called out here.

### Defaults that didn't change but worth re-verifying

- [ ] `--threshold-ms` (silence detection) — unchanged.
- [ ] `--recovery-debounce-ms` — unchanged.
- [ ] UDS socket path conventions (`/run/varta/varta.sock` is the
      canonical recommendation; the binary takes whatever you pass via
      `--socket`).

### New deployment surfaces

These are additive — adopt at your own pace:

- [ ] **Container image** — `ghcr.io/aramirez087/varta-watch:0.3.0`,
      cosign-signed with keyless OIDC, SLSA L3 provenance.
- [ ] **Helm chart** —
      `oci://ghcr.io/aramirez087/charts/varta-watch --version 0.2.0`
      (the chart version is independent of the app version).
- [ ] **`curl | sh` installer** — `https://varta.sh/install.sh`.
- [ ] **`cargo binstall varta-watch`**.
- [ ] **Python client** — `pip install varta`.

Pick a path: [Install (Quickstart)](install.md).

---

## Verifying the upgrade

After upgrading, run the standard smoke checks from [Deployment
Patterns → Verifying a deployment](deployment.md#verifying-a-deployment).
The two most important signals:

1. `varta_watch_uptime_seconds` is advancing.
2. `varta_beats_total{pid="<your_agent>"}` is non-zero and increasing.

If either is wrong, head to [Troubleshooting](troubleshooting.md).
