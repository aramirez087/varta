# Peer Authentication

Varta's observer trusts the kernel, not the wire. Two layers of defence
in-depth ensure that process identity cannot be spoofed by anything that
can reach the Unix Domain Socket.

## Layer 1: socket file permissions (`--socket-mode`)

After `bind(2)`, the observer `chmod`s the socket file to `0600` by
default (owner read and write only).  Only processes running under the
same UID as the observer can `connect(2)` to the socket.

| Flag               | Default | Format | Behaviour |
|--------------------|---------|--------|-----------|
| `--socket-mode`    | `0600`  | Octal (e.g. `0660`) | File mode applied via `chmod(2)` after bind.  Pass `0660` to allow group access. |

## Layer 2: kernel credential verification

### Linux

The observer sets `SO_PASSCRED` on the socket after binding.  Every
`recvmsg(2)` call then receives a `SCM_CREDENTIALS` ancillary message
containing a `struct ucred { pid, uid, gid }` populated by the kernel.
The observer compares `ucred.pid` against `frame.pid` from the VLP wire
format.  If they disagree the frame is silently dropped and
`varta_frame_auth_failures_total` is incremented.  The `ucred.uid`
field is implicitly trusted by Layer 1 (`--socket-mode 0600` already
restricts access to the owning UID), but could be checked as a
fail-safe if a permission bypass is ever discovered.

### macOS

On macOS, the observer first attempts `getsockopt(LOCAL_PEERTOKEN)`
immediately after each `recvmsg(2)`. `LOCAL_PEERTOKEN` returns an
`audit_token_t` containing the sender's PID, UID, GID, and audit
information. Because the observer is single-threaded and calls
`getsockopt` immediately after `recvmsg`, no other datagram can arrive
between the two syscalls.

When `LOCAL_PEERTOKEN` succeeds, the observer performs the same PID +
UID verification as on Linux. When it fails (e.g. on older macOS
versions or unconnected `SOCK_DGRAM` where the kernel doesn't expose
per-datagram credentials), the observer falls back to two separate
`getsockopt` calls:

1. `LOCAL_PEERPID` (0x0002) — returns the peer's PID directly.
2. `LOCAL_PEERCRED` (0x0001) — returns a `struct xucred` with the
   peer's UID in `cr_uid`.

If the fallback also fails, the observer falls back to the sentinel
PID 0 — relying on `--socket-mode 0600` as the primary defence.

### FreeBSD, DragonFly BSD, NetBSD

On FreeBSD-family platforms, the observer sets `LOCAL_CREDS` on the
socket (value `0x0002` on FreeBSD/DragonFly, `0x0001` on NetBSD).  Every
`recvmsg(2)` then receives a `SCM_CREDS` ancillary message containing a
`struct cmsgcred { cmcred_pid, cmcred_uid, cmcred_euid, cmcred_gid, ... }`
populated by the kernel.  The observer extracts `cmcred_pid` and
`cmcred_euid` and performs the same PID + UID verification as on Linux.

The ancillary buffer is sized at 256 bytes — sufficient for the 84-byte
`cmsgcred` with generous headroom for future kernel extensions.

> **Note:** On platforms other than Linux, macOS, FreeBSD, DragonFly, and
> NetBSD (OpenBSD, Solaris, illumos, etc.), `varta-watch` emits a startup
> warning via stderr:
> `"per-datagram PID verification is unavailable. The only defence is
> --socket-mode (default 0600); any process under the same UID can
> impersonate any PID."` This is by design — the kernel does not expose
> per-datagram peer credentials for unconnected `SOCK_DGRAM` on these
> platforms. Containers that run multiple processes under the same UID
> should be aware of this limitation.

## UDP transport authentication

For network-based agents that emit beats over UDP, the trust model is
**cryptographic**, not kernel-attested.  UDP has no peer-credential
mechanism on any platform — `recvmsg(2)` cannot tell the observer who
sent a datagram, only where it claims to be from.  Varta therefore
requires authentication at the AEAD layer, and refuses to bind an
unauthenticated UDP listener without two layers of explicit opt-in.

### Compile-time features (`crates/varta-watch/Cargo.toml`)

| Cargo feature           | What it enables                                                 | Production posture       |
|-------------------------|-----------------------------------------------------------------|--------------------------|
| `secure-udp`            | `SecureUdpListener` (ChaCha20-Poly1305 AEAD + per-sender replay) | **Recommended**          |
| `unsafe-plaintext-udp`  | `UdpListener` (no authentication)                                | **Forbidden in production** |
| `udp-core`              | Internal — shared UDP socket wiring                              | (transitive)             |

A build that does not include `unsafe-plaintext-udp` cannot link the
plaintext path at all.  Passing `--udp-port` without keys to such a build
hard-errors at startup; there is no warn-and-continue path.

### Runtime selection rules

When `--udp-port` is set, the observer chooses exactly one listener:

1. If `--features secure-udp` is compiled in **and** `--key-file` /
   `--master-key-file` resolve to a usable key, bind `SecureUdpListener`.
2. Otherwise, only the plaintext path remains.  It is bound *only* if
   both `--features unsafe-plaintext-udp` is compiled in **and**
   `--i-accept-plaintext-udp` was passed on the command line.
3. Any other configuration is a hard error (`InvalidInput`).

When the plaintext path is taken, a high-visibility `varta_warn!` is
emitted at startup naming the bound address, so the choice appears in
SIEM / syslog logs:

> `UDP on <addr> is running WITHOUT authentication (--i-accept-plaintext-udp).`
> `Any device with network reach to this port can inject heartbeats, suppress`
> `stall detection, or trigger false recovery commands. NOT for production /`
> `safety-critical use.`

`--i-accept-plaintext-udp` is intentionally verbose: an operator who
types it is making an explicit statement that this build is for
development or testing, not for a hospital VLAN.

### Why no kernel-level UDP credentials

Unix Domain Sockets carry `SCM_CREDENTIALS` / `LOCAL_PEERTOKEN` /
`SCM_CREDS` per-datagram.  UDP carries none of those.  Even on a single
host where `--udp-bind-addr 127.0.0.1` is used, any local process can
send to that port — there is no equivalent of `--socket-mode 0600` for
network sockets.  AEAD is the only durable defence.

## Recovery command authentication boundary

`--recovery-cmd` (inline shell) and `--recovery-cmd-file` (file-based
shell) both spawn `/bin/sh -c <template>` with the observer's full
process authority.  In a safety-critical deployment a recovery template
like `systemctl restart {service}` or `kill -9 {pid}` can terminate
unrelated production processes if the template body is mis-edited or if
shell metacharacters appear unexpectedly.

To prevent accidental shell-mode deployment, **shell mode requires
`--i-accept-shell-risk` at runtime**.  Without that flag, startup
hard-errors with a message that recommends `--recovery-exec` (which
calls `execvp(2)` directly — no shell, no metacharacter interpretation,
no injection surface).  This applies to both the inline and file-based
forms; the shell-injection risk is identical regardless of where the
template comes from.

`--recovery-exec` and `--recovery-exec-file` do **not** require an
accept flag — they are the default-safe path.

## Prometheus `/metrics` endpoint exposure

The `/metrics` endpoint is HTTP/1.0 plaintext with no authentication.
The observer applies four layers of protection so that a hostile actor
on the same network cannot exhaust file descriptors or starve the
observer's poll loop with a connection flood:

1. **Serve budget** — at most `PROM_MAX_CONNECTIONS_PER_SERVE=8` accepted
   connections per outer poll tick, and a 100 ms wall-clock deadline.
2. **Drain budget** — after the serve budget is exhausted, an
   additional `PROM_MAX_DRAIN_PER_SERVE=50` connections may be accepted
   and immediately closed, so the kernel accept queue does not back up.
3. **Per-source-IP token bucket** — every accepted connection (in both
   serve and drain phases) decrements a per-IP token bucket sized by
   `--prom-rate-limit-burst` (default 10) and refilled at
   `--prom-rate-limit-per-sec` (default 5).  Connections from an IP
   whose bucket is empty are closed without serving and counted as
   `varta_prom_connections_dropped_total{reason="rate_limit"}`.
4. **Per-IP table cap** — the per-IP map is bounded to 1024 entries;
   when full, stale entries (no activity in 60 s) are evicted first,
   then if necessary the oldest entry is force-evicted and counted as
   `varta_prom_connections_dropped_total{reason="ip_table_full"}`.

### Bind-address recommendation

`--prom-addr` accepts any local socket address, but for hospital
deployment the recommended posture is to bind loopback
(`127.0.0.1:<port>` or `[::1]:<port>`) and expose `/metrics` only
through a reverse proxy or a firewalled management interface.  The
observer emits a startup `varta_warn!` whenever the bound address is
non-loopback, to surface the exposure in audit logs:

> `/metrics is bound to a non-loopback address (<addr>); any host that can`
> `reach this port can scrape it.`

## Recovery command environment isolation

When `--recovery-env KEY=VALUE` is specified (repeatable), the recovery
child process runs with a sanitized environment:

1. The child's environment is cleared entirely.
2. `PATH` is set to `/usr/bin:/bin` (sufficient to locate common tools).
3. Only the explicitly-listed `KEY=VALUE` pairs are exported.

Without `--recovery-env`, the child inherits the observer's full
environment (backward compatible).  This flag provides defense-in-depth
against environment-variable-based injection vectors (e.g. a malicious
`LD_PRELOAD` or `IFS` in the observer's environment that could affect
`/bin/sh -c` behaviour).

Shell-mode recovery is gated by `--i-accept-shell-risk` at startup
(see the "Recovery command authentication boundary" section above).
When the flag *is* set, the observer still emits a single audit-trail
`varta_warn!` at startup so that the choice is captured in any SIEM /
syslog ingest alongside the other startup banners.

## Template safety

The `{pid}` substitution in `--recovery-cmd` is safe regardless of the
authentication outcome.  A `u32` PID formatted as a decimal string
contains only the characters `0`–`9` and can never carry shell
metacharacters (`;`, `|`, `&`, `$`, `` ` ``, etc.).

## Metrics

| Metric                                                | Type    | Description |
|-------------------------------------------------------|---------|-------------|
| `varta_frame_auth_failures_total`                     | counter | Incremented every time a frame's claimed PID does not match the kernel-verified sender PID (Linux only). |
| `varta_beats_total{pid="..."}`                        | counter | Per-PID total of accepted beats (only incremented after authentication passes). |
| `varta_prom_connections_dropped_total{reason="..."}` | counter | `/metrics` connections accepted but closed before serving.  Reasons: `drain` (serve budget exhausted), `rate_limit` (per-IP token bucket empty), `ip_table_full` (per-IP state map force-evicted). |

## Trust model summary

```
 Process ── connect(2) to UDS ──┐
                                   ├─ [FAIL]  Kernel blocks (Layer 1: --socket-mode 0600, wrong UID)
                                   ├─ [PASS]  Layer 2: SO_PASSCRED → ucred.pid (Linux)
                                   │          Layer 2: LOCAL_PEERTOKEN → audit_token.pid (macOS, best-effort)
                                   │          Layer 2: LOCAL_CREDS → cmsgcred.pid (FreeBSD, DragonFly, NetBSD)
                                   │          ├─ [PID MISMATCH] → Drop frame + bump counter
                                   │          ├─ [UID MISMATCH] → Drop frame as IoError
                                   │          └─ [PID MATCH + UID MATCH] →
                                   ↓
                              [SUCCESS]  Observer trusts the PID → tracks,
                                         surfaces stalls, triggers --recovery-cmd
                                         with {pid} substitution.
```

The trust boundary is the kernel: a frame is only accepted if the kernel
attests that the sending process's PID matches the one encoded in the
VLP frame and that the sending process runs under the observer's UID.
On Linux this is enforced per-datagram via `SO_PASSCRED`; on macOS via
`getsockopt(LOCAL_PEERTOKEN)` with `LOCAL_PEERPID`/`LOCAL_PEERCRED` fallback;
on FreeBSD / DragonFly / NetBSD via `LOCAL_CREDS` + `SCM_CREDS`.  Platforms
without kernel-level credential passing fall back to `--socket-mode 0600`.

## Security limitations

### No forward secrecy

The KDF derives per-agent and per-epoch keys from a single master key.
An epoch key can decrypt frames from past epochs if the agent key is
compromised. True forward secrecy requires bidirectional ephemeral key
exchange (e.g. X25519), which is incompatible with the connectionless,
one-way heartbeat model.

When the master key is rotated, all agents must be updated atomically.
The observer reads the master key once at startup from `--master-key-file`. To
rotate keys, restart the observer with the new master key file. SIGHUP-based
hot-reload is planned for a future release.

### Little-endian only

The VLP wire format uses little-endian integer encoding natively.
Protocol correctness depends on the host being little-endian (all tier-1
targets — x86_64 and aarch64 — satisfy this). Building on a big-endian
host is a compile error. See `docs/architecture/vlp-frame.md` for design
rationale.
