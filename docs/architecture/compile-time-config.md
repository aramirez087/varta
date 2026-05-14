# Compile-time Configuration (Class-A profile)

The Class-A safety-critical profile builds `varta-watch` with the
`compile-time-config` Cargo feature.  In this profile the runtime binary
has **no argv parser**, **no Prometheus HTTP exporter**, and a single
neutral `--help` body that mentions no flag names.  Every operational
knob is supplied at compile time by `build.rs` from a static
`KEY = VALUE` file pointed to by the `VARTA_CONFIG_FILE` environment
variable.

The Class-A binary is verified by the CI `safety-profiles` job:

```sh
B=target/release/varta-watch
strings "$B" | grep -E -- "(GET /metrics|HTTP/1\.|--[a-z])"
# expect: no output
```

## When to use this profile

- Hospital VLAN deployments where every CVE surface is a liability.
- IEC 62304 Class C medical devices (insulin pumps, holter monitors,
  ventilators) where the host configuration is part of the validated
  firmware.
- Avionics / industrial-control systems where the binary must boot from
  a signed image and accept no operator input post-deployment.

For SRE / cloud deployments use the default-feature build (or
`--features prometheus-exporter` for /metrics).  The two profiles are
mutually exclusive at compile time via a `compile_error!` guard in
`crates/varta-watch/src/lib.rs`.

## Build recipe

```sh
export VARTA_CONFIG_FILE=/etc/varta/varta.conf
cargo build -p varta-watch --release \
  --no-default-features --features secure-udp,compile-time-config
```

`secure-udp` is the recommended companion feature — Class-A almost
always wants authenticated transport.  Other features that combine
cleanly with `compile-time-config`: `audit-chain`, `json-log`,
`unsafe-shell-recovery` (only when the operator's signed config
explicitly opts in via `i_accept_shell_risk = true`).

The `prometheus-exporter` feature is **forbidden** in combination with
`compile-time-config`; `cargo build` fails with a clear `compile_error!`
diagnostic.

## File grammar

Plain text, UTF-8.  Lines that begin with `#` or are entirely whitespace
are ignored.  Each remaining line is `KEY = VALUE`:

- The `=` separator may have any amount of whitespace on either side.
- `KEY` must be in the `KNOWN_KEYS` catalogue (see below).
- `VALUE` is the rest of the line after the first `=`, trimmed.
- Quoting is **not** supported — paths and strings are taken verbatim.
- Repeated singleton keys are a build error; repeated list keys
  (`recovery_env`) accumulate.
- Unknown keys are a build error that surfaces during `cargo build`.

Example:

```
# /etc/varta/varta.conf

socket = /run/varta/varta.sock
threshold_ms = 5000
socket_mode = 0600

# Recovery: exec-mode only, never shell.
recovery_exec_cmd = /usr/local/sbin/varta-recover {pid}
recovery_audit_file = /var/log/varta/recovery.tsv
recovery_audit_sync_every = 1

# Authenticated UDP listener bound to loopback.
udp_port = 8443
udp_bind_addr = 127.0.0.1
secure_key_file = /etc/varta/agent.key

# Hospital deployment: medical-device clock semantics + strict mode.
clock_source = boottime
strict_namespace_check = true
```

## Accepted keys

| Key | Type | Default | Notes |
|---|---|---|---|
| `socket` | path | *required* | UDS path the observer binds. |
| `threshold_ms` | u64 | *required* | Per-pid silence window. Minimum 10. |
| `socket_mode` | octal | `0600` | UDS file mode after bind. |
| `read_timeout_ms` | u64 | `100` | UDS read timeout per poll call. |
| `udp_port` | u16 | none | Bind a UDP listener on this port. |
| `udp_bind_addr` | ip | runtime default | Loopback for secure-UDP; 0.0.0.0 for plaintext. |
| `secure_key_file` | path | none | 64-hex-char primary key (secure-udp). |
| `accepted_key_file` | path | none | One key per line for rotation. |
| `master_key_file` | path | none | 64-hex-char master for per-agent derivation. |
| `recovery_cmd` | string | none | Shell template (requires `unsafe-shell-recovery`). |
| `recovery_exec_cmd` | string | none | `program args …` invoked via execvp. |
| `recovery_cmd_file` | path | none | Read recovery_cmd from a hardened file. |
| `recovery_exec_file` | path | none | Read recovery_exec_cmd from a hardened file. |
| `recovery_debounce_ms` | u64 | `1000` | Per-pid debounce window. |
| `recovery_env` | list-of-string | empty | `KEY=VALUE`; repeatable. |
| `recovery_timeout_ms` | u64 | none | Kill-after deadline for recovery children. |
| `recovery_audit_file` | path | none | TSV recovery audit log. |
| `recovery_audit_max_bytes` | u64 | none | Audit-file rotation byte cap. |
| `recovery_audit_sync_every` | u32 | `1` | fdatasync cadence (1 = every record). |
| `recovery_capture_stdio` | bool | `false` | Capture child stdio for audit. |
| `recovery_capture_bytes` | u32 | `4096` | Stdio capture cap. Max 1048576. |
| `file_export` | path | none | TSV event-stream sink. |
| `export_file_max_bytes` | u64 | none | Event-file rotation cap. |
| `heartbeat_file` | path | none | Per-tick liveness file. |
| `tracker_capacity` | usize | `256` | Max tracked PIDs. |
| `tracker_eviction_policy` | enum | `strict` | `strict` or `balanced`. |
| `eviction_scan_window` | usize | `256` | Max slots scanned per eviction attempt. Range [1, 4096]. |
| `max_beat_rate` | u32 | none | Per-pid beats/sec cap. |
| `clock_source` | enum | `monotonic` | `monotonic` or `boottime` (Linux only). |
| `iteration_budget_ms` | u64 | `250` | Per-iteration soft budget. Range [50, 60000]. |
| `scrape_budget_ms` | u64 | `250` | Per-serve_pending soft budget. Range [50, 60000]. |
| `shutdown_after_secs` | u64 | none | Self-terminate after this uptime. |
| `shutdown_grace_ms` | u64 | `5000` | Drop blocking time during shutdown. Minimum 100. |
| `self_watchdog_secs` | u64 | none | Self-watchdog deadline (auto-enables under systemd). |
| `hw_watchdog` | path | none | Hardware watchdog device (`/dev/watchdog`). |
| `i_accept_plaintext_udp` | bool | `false` | Runtime acknowledgement. |
| `i_accept_shell_risk` | bool | `false` | Runtime acknowledgement. |
| `i_accept_recovery_on_secure_udp` | bool | `false` | Recovery on secure-UDP transport. |
| `i_accept_recovery_on_plaintext_udp` | bool | `false` | Recovery on plaintext UDP. |
| `i_accept_secure_udp_non_loopback` | bool | `false` | Non-loopback secure-UDP bind. |
| `allow_cross_namespace_agents` | bool | `false` | Permit cross-PID-namespace beats. |
| `strict_namespace_check` | bool | `false` | Fatal exit on cross-namespace agent. |
| `inject_wedge_ms` | u64 | none | Test-hooks only (requires `test-hooks` feature). |

## Operational contract

- `--help` (and any other argv) is rejected at startup.  The binary
  exits non-zero with the neutral diagnostic
  *"this binary was configured at compile time; refusing to accept
  command-line arguments"*.
- Diagnostic messages in stderr / sd_notify use neutral wording — no
  `--flag-name` strings appear anywhere in the binary.  See the
  cerebrum entry on `pub const &str` being unconditionally linked for
  the rationale.
- The configuration file is consumed once, at `cargo build` time.  The
  resulting binary is **immutable**: redeployment requires a new build.
  This is the structural feature operators rely on for Class-A
  release-gating.

## See also

- [Safety profiles overview](safety-profiles.md)
- [Peer authentication](peer-authentication.md) — key-file requirements
- [Observer liveness](observer-liveness.md) — self-watchdog wiring
