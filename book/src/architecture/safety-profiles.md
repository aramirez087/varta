# Safety Profiles

`varta-watch` ships with a **two-layer gate** for every structurally-dangerous
capability: a **compile-time Cargo feature** that must be explicitly enabled,
AND a **runtime flag** that must be passed by the operator.  Neither layer
alone is sufficient; both must be active.

This document defines what "production-safe" means for Varta and how to verify
a binary before deploying it to a safety-critical environment.

## Profile matrix

| Profile | Features | argv | /metrics | Recovery |
|---|---|---|---|---|
| SRE / cloud | `prometheus-exporter` (+ optional `unsafe-*`) | full GNU-style parser | HTTP `/metrics` + Bearer-token | exec only |
| Class-A safety-critical | `secure-udp,compile-time-config` | none (build-time fixed) | absent | exec only |

The two profiles are mutually exclusive: `prometheus-exporter` cannot
combine with `compile-time-config` (a `compile_error!` in
`crates/varta-watch/src/lib.rs` rejects the combination at build time).
This is the structural guarantee Class-A builds rest on — the Class-A
binary cannot ship with an HTTP server linked in.

---

## Production-safe build

A production-safe `varta-watch` binary is built with **default features only**:

```sh
cargo build -p varta-watch --release
```

No `--features` argument is needed or wanted.  Default features are empty.

### What is absent from a production-safe build

| Dangerous capability | Cargo feature | Runtime flag |
|---|---|---|
| Plaintext (unauthenticated) UDP listener | `unsafe-plaintext-udp` | `--i-accept-plaintext-udp` |

Shell-mode recovery (`/bin/sh -c`) has been **permanently removed** from all
build profiles.  `/bin/sh` does not appear in any `varta-watch` binary,
regardless of feature flags.  Use `--recovery-exec` for all recovery
configurations.

Without the compile-time feature, the code path is **not linked** into the
binary.  A misconfigured deployment cannot accidentally enable the dangerous
path at runtime.

### Verification recipe

```sh
cargo build -p varta-watch --release
strings target/release/varta-watch | grep -F "/bin/sh" && echo "FAIL" || echo "OK"
```

The `strings` check is belt-and-suspenders: because `/bin/sh` is structurally
absent, the literal cannot appear in any binary regardless of features.

---

## Unsafe features

### `unsafe-plaintext-udp`

Compiles in the plaintext `UdpListener` transport.  Any device with network
access to the bound port can inject heartbeats, suppress stall detection, or
trigger false recovery commands.

```toml
# varta-watch/Cargo.toml
[features]
unsafe-plaintext-udp = ["udp-core"]
```

Even with this feature, the listener **will not bind** unless
`--i-accept-plaintext-udp` is also passed at runtime.

This feature is **structurally unavailable in Class-A builds** —
`compile-time-config` + `unsafe-plaintext-udp` is rejected by a
`compile_error!` in `crates/varta-watch/src/lib.rs`.  Mission-critical
deployments must use `secure-udp` (AEAD-authenticated, bounded per-sender
replay state) for any UDP transport; plaintext UDP has no replay protection and
can be used by a network attacker to suppress stall detection.

---

## Class-A safety-critical features

### `prometheus-exporter` (opt-in HTTP exposition)

The Prometheus `/metrics` endpoint, the bearer-token loader, the per-IP
rate-limit table, and every `--prom-*` argv flag live behind this
feature.  When absent the binary contains zero HTTP / TCP-accept code
and the only exporter linked is `FileExporter` (one-way append-only
TSV sink — no listener, no network surface).

```toml
[features]
prometheus-exporter = []
```

Verification recipe (default build, feature off):

```sh
cargo build -p varta-watch --release
B=target/release/varta-watch
strings "$B" | grep -E -- "(GET /metrics|HTTP/1\.|WWW-Authenticate|Bearer realm)" \
  && echo "FAIL" || echo "OK"
```

### `compile-time-config` (no argv parser, no runtime config)

Replaces the runtime argv parser with a build-script-generated constant
populated from `$VARTA_CONFIG_FILE` (a `KEY = VALUE` text file).  When
the feature is on:

- `Config::from_args` is excluded from compilation; the 292-arm match
  block carrying every `--flag-name` literal is not linked.
- `Config::HELP` is a neutral one-liner that contains no flag names.
- The binary refuses any argv tokens with `CompileTimeArgvForbidden`.

Cannot be combined with `prometheus-exporter`, `libc-signal-mode`, or
`unsafe-plaintext-udp` — each combination is rejected at compile time by
a dedicated `compile_error!` in `lib.rs`.  The Class-A binary is
structurally free of the HTTP exporter, the libc-signal indirection, and
the plaintext UDP listener; none of those code paths can be linked in.

```sh
export VARTA_CONFIG_FILE=/etc/varta/varta.conf
cargo build -p varta-watch --release \
  --no-default-features --features secure-udp,compile-time-config
```

Verification recipe:

```sh
B=target/release/varta-watch
FORBIDDEN="GET /metrics|HTTP/1\.|WWW-Authenticate|--socket|--prom-addr|--help|--i-accept|/bin/sh"
strings "$B" | grep -E -- "$FORBIDDEN" && echo "FAIL" || echo "OK"
```

See [compile-time-config.md](compile-time-config.md) for the canonical
KEY=VALUE grammar and key catalogue.

---

## Recommended transport for recovery

Use `--recovery-exec` for all recovery deployments.  It invokes the program
directly via `execvp(2)` with no shell involved; shell metacharacters have no
effect and `/bin/sh` is never spawned.

---

## Miri policy

Miri (`cargo miri test`) runs on every push under `-Zmiri-strict-provenance` and covers
the three unsafe-code clusters that cannot be audited by reading alone:

| Cluster | Miri target | What it proves |
|---|---|---|
| `peer_cred` cmsg pointer-walk | `cargo miri test -p varta-watch --lib peer_cred` | No UB in the hand-written `cmsghdr` traversal; synthetic buffers only — no syscalls |
| Tracker slot-index arithmetic | `cargo miri test -p varta-watch --lib tracker` | No out-of-bounds indexing or stale pointer reads in the fixed-capacity slot array |
| Client classifier | `cargo miri test -p varta-client --test classifier` | `BeatError` is `Copy`-safe and `errno` extraction has no provenance issues |

Tests that require real syscalls (Unix datagram bind, `recvmsg`, process spawn) carry
`#[cfg_attr(miri, ignore)]` so they are silently skipped when Miri runs, without
requiring a separate test-filter command.

---

## Clock source for stall detection

Stall threshold accounting depends on a monotonic time source.  Which "monotonic"
is *correct* depends on the deployment profile:

| Profile | `--clock-source` | Rationale |
|---|---|---|
| SRE / cloud server / VM | `monotonic` (default) | `CLOCK_MONOTONIC` pauses on host suspend, hypervisor pause, and live-migration freeze.  A 30-minute host-suspend-for-maintenance must NOT fan out a stall alert across every agent. |
| Medical implant / holter / insulin pump (Linux) | `boottime` (Linux only) | `CLOCK_BOOTTIME` advances during suspend.  A 4-hour deep-sleep IS a 4-hour silence; stall detection MUST fire on wake-up regardless of whether the device suspended itself. |
| Embedded sensor with deep sleep (Linux) | `boottime` (Linux only) | Same as medical — battery-conscious devices that aggressively suspend need stall semantics that count the suspended time. |
| macOS / iOS-hosted device with sleep semantics | `monotonic-raw` (macOS / iOS only) | `CLOCK_MONOTONIC_RAW` on Darwin is backed by `mach_continuous_time` and advances through sleep — the Darwin equivalent of Linux's `CLOCK_BOOTTIME`. |

### Platform support

`boottime` semantics require Linux's `CLOCK_BOOTTIME` clock (clk_id `7`,
available since 2.6.39). The Darwin equivalent is `CLOCK_MONOTONIC_RAW`
(`clk_id = 4`), backed by `mach_continuous_time`; it advances through
sleep just like `CLOCK_BOOTTIME`. Because the same numeric `clk_id = 4`
on Linux refers to `CLOCK_MONOTONIC_RAW` with *different* semantics (it
opts out of NTP slewing but still pauses during suspend), the two are
exposed as distinct `ClockSource` variants — `boottime` (Linux only) and
`monotonic-raw` (macOS / iOS only) — and each is rejected at startup on
the other family with `ConfigError::ClockSourceUnsupported`.

BSD operators have only `monotonic`: no kernel clock on FreeBSD /
NetBSD / OpenBSD / DragonFly advances through suspend in a way usable
by `clock_gettime(2)`.

Example rejection messages:

```text
clock source `boottime` is not supported on `macos` (Linux only; on
macOS use `monotonic-raw` for advance-through-sleep semantics)
```

```text
clock source `monotonic-raw` is not supported on `linux` (macOS / iOS
only; on Linux use `boottime` for advance-through-sleep semantics)
```

This is structural enforcement: a misconfigured medical-device
deployment exits non-zero rather than silently picking a clock that
pauses on sleep.

### Self-watchdog alignment

The in-process self-watchdog (`--self-watchdog-secs`) reads the same kernel
clock as the observer.  An operator who configures `boottime` for the
observer gets watchdog deadline accounting that also advances during
suspend; an SRE operator on `monotonic` gets identical-to-historical
watchdog behaviour minus the previous wall-clock NTP-backward-step
foot-gun.

### Verification recipe (Linux)

```sh
# Confirm the configured clock source is in effect.
journalctl -u varta-watch | grep -i 'clock'   # binary logs no startup banner today;
                                              # operators can read /proc/<pid>/maps
                                              # to confirm clock_gettime imports.

# Behavioural smoke test — requires a real suspend / resume cycle:
systemctl suspend && sleep 60 && systemctl resume
curl -fsS http://localhost:9090/metrics -H "Authorization: Bearer <hex>" \
  | grep -E 'varta_(stall_total|beats_total|watch_uptime_seconds)'
# Expect: with --clock-source boottime, varta_stall_total advanced during the
# suspend window; with --clock-source monotonic, it did not.
```

### Cross-reference

The `secure-udp` transport applies the same "no surprises on the beat path"
posture: the IV-prefix derivation (H6) reads OS entropy only at `connect()`
and `reconnect()` — every steady-state beat uses a deterministic HKDF
counter-mode expansion.  Together, H6 + H7 keep the agent and observer
loops free of any syscall that can block or stall under suspend.

---

## Cross-references

- [Observer liveness](observer-liveness.md) — defending against `varta-watch`
  itself crashing or hanging
- [Peer authentication](peer-authentication.md) — kernel-level PID attestation
  and transport trust classification
