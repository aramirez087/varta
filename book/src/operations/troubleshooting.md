# Troubleshooting

Runtime issues after `varta-watch` is installed. For install-time
issues (cosign, systemd unit, container start) see [Install
(Quickstart) → Troubleshooting](install.md#troubleshooting).

The fastest debug surface is `/metrics`. If you can scrape it,
`varta-watch` is alive and the metric values pinpoint the layer at
fault. Every diagnostic below names the metric to check first.

---

## My agent reports `Sent` but `varta_beats_total{pid=…}` stays at 0

The observer is rejecting the beat before counting it. Walk these in
order:

1. **`varta_decode_errors_total`** — any `kind` is nonzero ⇒ wire-format
   problem. Most common: `bad_version` (agent on a different VLP
   release) or `bad_magic` (something other than a Varta agent is
   writing to the socket).

2. **`varta_frame_auth_failures_total`** — nonzero ⇒ peer-cred PID
   disagrees with the frame's claimed PID. Either an actual spoof
   attempt or the agent is calling `beat()` from a thread/process whose
   PID differs from what was wired in. Fork without re-`connect()` is
   the usual culprit (v0.2.0+ auto-detects this; older clients do not).

3. **`varta_truncated_datagrams_total`** — nonzero ⇒ kernel handed the
   observer a wrong-sized datagram. UDS frames must be exactly 32 bytes;
   secure-UDP frames must be exactly 60 (shared-key) or 64 (master-key).

4. **`varta_tracker_capacity_exceeded_total`** — nonzero ⇒ the
   tracker is at `--tracker-capacity` (default 4096) and is dropping
   beats from new pids. Raise the cap or shard (see [Deployment Ceiling
   & Sharding](../architecture/deployment-ceiling-and-sharding.md)).

5. **`varta_rate_limited_total{reason="per_pid"|"global"}`** — nonzero
   ⇒ rate limit kicked in. Defaults are 100/s per pid and 5000/s
   globally; raise or disable as appropriate (see
   [Upgrade Guide](upgrade.md#observer-defaults-rate-limiting)).

6. **Socket path mismatch.** The observer logs the path it bound to at
   startup. Confirm the agent's `Varta::connect()` argument is byte-
   identical, including any container mount remapping.

---

## `varta_status{pid=…}` shows `3` (Stall) but my process is healthy

The observer hasn't received a beat from this PID in
`--threshold-ms` (default depends on your config). Causes:

- **Agent is blocked on something synchronous** that doesn't yield to
  the beat loop. The fix is on the agent — Varta is reporting the
  truth.
- **Beat thread crashed silently.** If the agent uses the
  `panic-handler` feature, a terminal `Critical` beat should have been
  emitted. Check `varta_status` history; if it skipped from `0` to `3`
  without `2`, the panic-handler is missing or the process hard-died
  (segfault, `kill -9`, OOM).
- **Threshold is too tight for your cadence.** If your agent beats
  every 1 s but `--threshold-ms 500`, every minor scheduling hiccup
  trips a stall.

---

## Recovery never fires even though stalls are surfaced

In order of likelihood:

1. **No recovery command configured.** Recovery is opt-in. Check the
   observer was started with `--recovery-exec` or `--recovery-exec-file`.

2. **`varta_recovery_refused_total{reason="…"}`** — non-zero on one of
   these labels:

   | Label | What to do |
   |---|---|
   | `unauthenticated_transport` | Beat origin is `NetworkUnverified` (plain UDP). Recovery requires kernel-attested origin. Use UDS, or secure-UDP with master-key. |
   | `socket_mode_only` | Platform without per-datagram peer-creds (e.g. OpenBSD). No fix — recovery is structurally refused here. |
   | `cross_namespace_agent` | PID namespace mismatch. Set `--allow-cross-namespace-agents` if you trust the source, or fix the deployment (Docker `--pid=host`, k8s `hostPID: true`). |
   | `debounce_capacity` | The per-pid debounce window suppressed a duplicate spawn. Expected. |
   | `outstanding_capacity` | The `OutstandingTable` is full (≥ `--tracker-capacity`). A previous recovery is still running for every slot. Investigate why children are not exiting. |

3. **`varta_recovery_outcomes_total{outcome="spawn_failed"}` is nonzero.**
   Inspect observer stderr for the actual `io::Error`. Most common:
   `ENOENT` (program path wrong, or `PATH` doesn't include it under
   the isolated env), `EACCES` (file not executable / wrong owner).

---

## `/metrics` returns 401 even with the right token

- **Token mismatch.** Check the file the observer reads
  (`--prom-token-file`) and the value you're sending byte-for-byte
  (`xxd` both; a trailing newline counts).
- **Token file mode.** The observer refuses to load tokens from a file
  with mode broader than `0400` / `0600` and owner other than the
  observer UID.
- **Bearer header form.** The exporter accepts `Authorization: Bearer
  <hex>` only. `Token <hex>`, `Basic`, query-string credentials are all
  rejected as 401.

---

## `/metrics` is slow or times out under high pid count

- **`varta_observer_serve_pending_seconds`** — bimodal latency ⇒ the
  serve-pending stage is consuming budget. Raise `--scrape-budget-ms`
  or scrape less often.
- **`varta_scrape_budget_exhausted_total`** — incrementing ⇒ scrapes
  arriving faster than the observer can serve. The exporter falls back
  to a cached response (`varta_scrape_skipped_total` increments). This
  is a graceful degradation, not a bug.
- **`varta_prom_connections_dropped_total{reason="ip_table_full"}`** —
  the per-IP rate-limit table is full. Tune
  `--prom-rate-limit-per-sec` and `--prom-rate-limit-burst`.

---

## `varta_watch_uptime_seconds` is frozen

The self-watchdog hasn't kicked. Either the observer is wedged in a
syscall or the metric is being read from a cached scrape. Order of
investigation:

1. `ps` — is the process actually running?
2. `kill -USR1 <pid>` — observer logs current iteration state to
   stderr (if the signal handler is installed; default-on for direct
   mode, opt-out via `--signal-handler-mode disabled`).
3. If `--hw-watchdog` was passed, the kernel watchdog will reboot the
   host before this gauge can stay frozen long. Check `dmesg` for
   `watchdog: BUG` traces.
4. If `--self-watchdog-secs` was passed, the in-process watchdog
   `SIGABRT`s the process before systemd restarts it. Check
   `journalctl -u varta-watch` for the abort line.

---

## Namespace conflict on every beat in a container

`varta_tracker_namespace_conflict_total` is incrementing and beats are
refused. The observer container's PID namespace differs from the agent
container's. Fixes:

- **Docker / podman**: run the observer with `--pid=host`.
- **Kubernetes**: set `hostPID: true` on the observer Pod, OR colocate
  observer + agents in the same Pod with shared `shareProcessNamespace:
  true`.
- **Explicit override**: pass `--allow-cross-namespace-agents` to
  accept beats (but recovery for those agents will still be refused
  unless `--strict-namespace-check` is left off; see
  [Namespacing](../architecture/namespaces.md)).

---

## Where to file something the docs miss

- Wire-protocol surprises: open an issue against
  [`varta-vlp`](https://github.com/aramirez087/Varta/issues) tagged
  `protocol`.
- Observer behaviour gaps: tag `observer`.
- Anything security-shaped: see [Security](../governance/security.md)
  for private disclosure.
