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

macOS exposes `LOCAL_PEERTOKEN` / `LOCAL_PEERPID` for connected local
sockets, but Varta's production UDS transport is a pathname
`SOCK_DGRAM` observer socket receiving from unconnected clients. On that
socket shape, Darwin returns `ENOTCONN` for the peer-token and peer-pid
queries after `recvmsg(2)`, so the observer cannot bind `frame.pid` to a
kernel-attested sender.

The implementation still attempts the Darwin peer queries so connected
test fixtures catch constant or ABI drift, but pathname UDS beats
resolve to the PID-0 sentinel and are tagged `BeatOrigin::SocketModeOnly`.
Recovery is intentionally refused for those beats.

The Darwin queries are:

1. `LOCAL_PEERPID` (0x0002) — returns the peer's PID directly.
2. `LOCAL_PEERCRED` (0x0001) — returns a `struct xucred` with the
   peer's UID in `cr_uid`.
3. `LOCAL_PEERTOKEN` (0x0006) — returns an `audit_token_t` containing
   the peer's PID and effective UID on connected local sockets.

### FreeBSD, DragonFly BSD, NetBSD

On FreeBSD-family platforms, the observer sets `LOCAL_CREDS` on the
socket (value `0x0002` on FreeBSD/DragonFly, `0x0001` on NetBSD).  Every
`recvmsg(2)` then receives a `SCM_CREDS` ancillary message containing a
`struct cmsgcred { cmcred_pid, cmcred_uid, cmcred_euid, cmcred_gid, ... }`
populated by the kernel.  The observer extracts `cmcred_pid` and
`cmcred_euid` and performs the same PID + UID verification as on Linux.

The ancillary buffer is sized at 256 bytes — sufficient for the 84-byte
`cmsgcred` with generous headroom for future kernel extensions.

### illumos / Solaris

On illumos and Solaris the observer sets `SO_RECVUCRED` (value `0x0400`,
level `SOL_SOCKET = 0xffff`) on the socket.  Every `recvmsg(2)` then
receives a `SCM_UCRED` ancillary message whose payload is an **opaque
`ucred_t`**.  The layout of `ucred_t` is not a stable ABI contract, so
field extraction goes through the `ucred_getpid(3C)` and `ucred_geteuid(3C)`
accessor functions from the system's C library rather than a direct struct
cast.

This is a genuine per-datagram credential mechanism: the kernel attests
the sender's identity on each `recvmsg(2)`, not just at connection time.
The ancillary buffer is sized at 1 024 bytes to accommodate the additional
audit and MAC-label attributes that illumos attaches under Trusted Solaris
/ labelled-zone configurations.

**`ucred_t` lifetime invariant.** Both `ucred_getpid(3C)` and
`ucred_geteuid(3C)` are called inside `extract_pid_uid` while the cmsg
buffer is still on the `recv_authenticated` stack frame.  Neither call
stores the pointer past its return; the buffer is released after the call
completes.

**Zone isolation.** `ucred_getzoneid(3C)` is available for extracting the
Solaris zone-id of the sender (analogous to the Linux PID-namespace inode).
Cross-zone detection is a planned follow-up; for now, `peer_pid_ns_inode`
is `None` on illumos/Solaris, which disables the cross-container recovery
refusal.  See `book/src/architecture/namespaces.md` for the planned gate.

### Platform support summary

| Platform | Mechanism | Per-datagram? | Recovery-eligible? |
|---|---|---|---|
| Linux | `SO_PASSCRED` + `SCM_CREDENTIALS` (`struct ucred`) | Yes | Yes |
| macOS pathname UDS | socket file permissions only (`LOCAL_PEERTOKEN` requires a connected local socket) | **No** | **No** |
| FreeBSD / DragonFly / NetBSD | `LOCAL_CREDS` + `SCM_CREDS` (`struct cmsgcred`) | Yes | Yes |
| illumos / Solaris | `SO_RECVUCRED` + `SCM_UCRED` + `ucred_t` (opaque) | Yes | Yes |
| OpenBSD, AIX, HP-UX, other Unix | none — `--socket-mode 0600` only | **No** | **No** |

### Socket-mode-only fallback

On platforms that do not provide per-datagram kernel credential passing
for Varta's pathname UDS transport (currently: macOS, OpenBSD, and any
other Unix not listed above), `varta-watch`
falls back to a plain `recv(2)` receive path and tags each beat with
`BeatOrigin::SocketModeOnly`.

**Trust model for SocketModeOnly beats.** The only defence is filesystem
permissions (`--socket-mode 0600`, the default).  Any process running
under the same UID as the observer can reach the socket and forge
`frame.pid`.  Recovery commands **must not and do not fire** for these
beats — the recovery gate at `recovery.rs::on_stall` refuses with
`RecoveryOutcome::RefusedSocketModeOnly` and increments the Prometheus
counter `varta_recovery_refused_total{reason="socket_mode_only"}`.  The
audit log records the refusal with `reason=socket_mode_only`.

At startup, `varta-watch` emits a warning on stderr when compiled for a
socket-mode-only platform:

```
[WARN] per-datagram PID verification is unavailable on this platform.
The only defence is --socket-mode (default 0600). Any process under the
same UID can impersonate any PID. Beats will be tagged SocketModeOnly;
recovery commands will not fire.
```

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

1. If `--features secure-udp` is compiled in **and** `--key-file`,
   `--accepted-key-file`, or `--master-key-file` resolve to usable key
   material, bind `SecureUdpListener`.
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

Unix Domain Sockets can carry `SCM_CREDENTIALS` / `SCM_CREDS`
per-datagram on supported kernels.  UDP carries none of those.  Even on a single
host where `--udp-bind-addr 127.0.0.1` is used, any local process can
send to that port — there is no equivalent of `--socket-mode 0600` for
network sockets.  AEAD is the only durable defence.

## Recovery eligibility and transport-origin gating

Recovery commands (`--recovery-exec` and `--recovery-exec-file`) take the
**stalled agent's `frame.pid`** and substitute it into
the spawned process (`kill -9 {pid}`, `systemctl restart agent@{pid}.service`,
etc.).  That makes recovery a privileged action that targets an arbitrary
process by id — and means the wire-level `frame.pid` must be tied back to
the *real* sending process, not just to whoever holds an AEAD key.

### The trust invariant

A recovery command MUST NEVER fire for a pid whose beat lifetime is not
**kernel-attested**.  In practice that means:

| Transport     | Kernel-attested?         | Recovery-eligible by default? |
|---------------|--------------------------|-------------------------------|
| UDS on Linux / supported BSDs / illumos / Solaris | Yes — `SO_PASSCRED` / `SCM_CREDS` / `SCM_UCRED` | **Yes** |
| UDS on macOS pathname sockets / OpenBSD / other socket-mode-only targets | No — socket file permissions only | No |
| Plaintext UDP | No — `peer_pid` is always 0                          | No                            |
| Secure UDP    | No — frame is *cryptographically* authenticated but the kernel does not attest the sending process; a holder of the AEAD key (or a per-agent key derived from a leaked master key) can forge a beat for any pid | No                            |

Internally each beat is tagged with a `BeatOrigin`
(`KernelAttested` vs `NetworkUnverified`).  The tracker pins the origin on
the slot's first beat and rejects subsequent beats from a different
origin as `Event::OriginConflict` (counter:
`varta_origin_conflict_total`).  First-origin-wins prevents an attacker on
an untrusted transport from "tainting" a slot that legitimately belongs to
a kernel-attested agent.

### Two-layer enforcement

1. **Startup hard-error.**  If any `--recovery-exec` / `--recovery-exec-file`
   is configured *and* `--udp-port`
   is set, the daemon refuses to start with
   `ConfigError::RecoveryRequiresAuthenticatedTransport`.  Operators must
   pass `--i-accept-recovery-on-unauthenticated-transport` to proceed.
   The flag is verbose by design (matches the `--i-accept-<risk>`
   convention) and shows up in `cargo tree` / startup banners.

2. **Runtime origin gate.**  Even with the accept flag, `Recovery::on_stall`
   refuses to spawn the recovery command when the stalled slot's pinned
   origin is `NetworkUnverified`.  The refusal returns the typed
   `RecoveryOutcome::RefusedUnauthenticatedSource { pid }`, increments
   `varta_recovery_refused_total{reason="unauthenticated_transport"}`, and
   emits a structured `refused` record into the recovery audit log
   (`--recovery-audit-file`).  To enable UDP-origin recovery the operator
   must construct the `Recovery` with
   `with_allow_unauthenticated_source(true)` — a second, conscious choice
   on top of the startup flag.

### Why secure-UDP isn't enough

The secure-UDP master-key mode binds `frame.pid` to the 4-byte PID prefix
in `iv_random[0..4]` and derives a per-agent key from the master key.
That is a useful *cryptographic* binding for the UDP threat model — a
holder of a single derived agent key cannot forge frames for *other*
pids.  But the binding lives at the protocol layer, not at the kernel
layer:

- A leak of the **shared key** lets anyone forge any pid.
- A leak of the **master key** lets anyone derive any agent key.
- A leak of **any per-agent key** still lets that agent forge its own pid
  to misbehave (e.g. stop sending → trigger recovery against its own pid
  during legitimate maintenance windows).

Kernel attestation has no such failure mode: the kernel knows which
process owns the socket fd, and that knowledge cannot be forged by any
amount of key material.  This is why Varta classifies all UDP variants
(plain and secure) as `NetworkUnverified` for the recovery-eligibility
decision.

## Recovery command authentication boundary

`--recovery-exec` and `--recovery-exec-file` invoke the program directly
via `execvp(2)` — no shell, no metacharacter interpretation, no injection
surface.  The stalled pid is appended as the final argument: never
interpolated into a command string.

Shell-mode recovery (`--recovery-cmd` / `--recovery-cmd-file`) was
**permanently removed**.  All builds — SRE, Class-A, and default — use
exec-only recovery.  No opt-in flag is required; exec-mode is the only
available recovery mode.

## Prometheus `/metrics` endpoint exposure

The `/metrics` endpoint is HTTP/1.0 with **mandatory bearer-token
authentication**.  When `--prom-addr` is set, `--prom-token-file` is
required: the observer refuses to start without it.  Every scrape must
send `Authorization: Bearer <hex>` where `<hex>` is the lowercase 64-byte
hex form of the file's 32 random bytes (the format produced by
`openssl rand -hex 32`).  Missing or wrong tokens get
`HTTP/1.0 401 Unauthorized` and bump `varta_prom_auth_failures_total`.

The token file is loaded through the same hardened validator that
guards `--key-file` (see "Secret-file validation" below): regular file,
no symlinks, owned by the observer UID, mode `0o600` or stricter,
opened with `O_NOFOLLOW`.

The endpoint also retains four DoS-protection layers from earlier work,
so that a hostile scraper cannot exhaust file descriptors or starve the
observer's poll loop even before the auth check runs:

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

### Token comparison is constant-time

The exporter compares the presented and expected tokens via
`varta_vlp::ct_eq` — the same constant-time XOR-and-OR routine that
guards Poly1305 tag verification.  This prevents byte-by-byte timing
oracles from leaking the prefix of the token to a remote scraper.

### Bind-address recommendation

The bearer token is the authoritative authentication boundary.  Loopback
bind (`127.0.0.1:<port>` or `[::1]:<port>`) behind a reverse proxy
remains the recommended posture for defense in depth, but is no longer
the *only* defense.  The observer still emits a startup `varta_warn!`
whenever the bound address is non-loopback, so the exposure is visible
in audit logs.

### Prometheus scrape config

The standard `authorization:` block injects the bearer token verbatim:

```yaml
scrape_configs:
  - job_name: 'varta'
    static_configs:
      - targets: ['varta-host:9100']
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/varta-prom.token
```

The `credentials_file` should be the **same** content as
`--prom-token-file` on the observer; Prometheus reads it with the same
0600-or-stricter expectation.

## Secret-file validation

Every file containing key material — `--key-file`, `--accepted-key-file`,
`--master-key-file`, and the new `--prom-token-file` — flows through
`validate_secret_file` in `varta-watch/src/config.rs`.  The validator
enforces:

1. The path is **not a symlink** (`symlink_metadata` + `is_symlink`).
2. The path resolves to a **regular file** (not a directory, FIFO,
   block/char device, etc.).
3. The mode is **`0o600` or stricter** (`mode & 0o077 == 0`).
4. The file is **owned by the observer's UID** (kernel-attested via
   `stat.uid`, not derived from the env).
5. The file is opened with **`O_NOFOLLOW`** to close the TOCTOU window
   between the metadata check and the read.

A failure on any of these aborts startup with a typed `ConfigError`
naming the failing constraint (`insecure permissions ...`, `must not be
a symlink`, `owned by uid X, expected uid Y`, etc.).

## Why environment-variable keys are gone

Earlier releases offered `--key-env <NAME>` as a key-source fallback.
That flag is **removed**.  Passing it now returns
`ConfigError::RemovedFlag` with an inline migration hint pointing at
`--key-file`.  The motivation:

- On Linux, `/proc/<pid>/environ` is readable by any process running
  under the same UID; a peer with a UDS connection to the observer
  (which already has UID-restricted access) can read the master key out
  of the observer's own environment.
- In containers, `docker inspect <container>` exposes every environment
  variable to anyone with read access to the Docker socket — typically
  all members of the `docker` group, which is often a superset of the
  in-container UID.
- `systemd-journald` captures process environment on demand for crash
  reports; an env-var key ends up in `/var/log/journal` indefinitely.

File-based keys avoid all three exposures and slot into the same
ownership/permission model as TLS private keys, SSH host keys, and any
other long-lived secret an operator already knows how to manage.

The `Key` type in `varta_vlp::crypto` also lost its `Copy` derive and
gained a `Drop` impl that volatile-zeros the secret bytes before the
allocation is returned to the stack, closing a small but real leak
surface in core dumps and ASLR-defeated speculative reads.

## Shutdown grace and systemd

`--shutdown-grace-ms` (default 5000, minimum 100) bounds the time
`Recovery::drop` blocks waiting for outstanding recovery children to
exit after issuing SIGKILL during shutdown.  Children that outlive the
grace are abandoned to PID 1 for reaping; the observer process exits
either way, so the bound on shutdown latency is deterministic.

In a systemd unit, `TimeoutStopSec` must be **at least
`shutdown_grace_ms + 2 s`** (roughly: grace + reap margin) to ensure
that systemd does not SIGKILL the observer mid-grace and leak an
unreaped recovery child:

```ini
[Service]
Environment=VARTA_SHUTDOWN_GRACE_MS=5000
ExecStart=/usr/local/bin/varta-watch --shutdown-grace-ms ${VARTA_SHUTDOWN_GRACE_MS} ...
TimeoutStopSec=7s
KillMode=mixed
```

`KillMode=mixed` is recommended: systemd sends SIGTERM to the main
observer process only; the observer then runs its own Drop sequence to
kill+reap any recovery children it had spawned.  This is what the
shutdown-grace tunable is designed around.

## Recovery command environment isolation

When `--recovery-env KEY=VALUE` is specified (repeatable), the recovery
child process runs with a sanitized environment:

1. The child's environment is cleared entirely.
2. `PATH` is set to `/usr/bin:/bin` (sufficient to locate common tools).
3. Only the explicitly-listed `KEY=VALUE` pairs are exported.

Without `--recovery-env`, the child inherits `PATH=/usr/bin:/bin` only
(secure default since 2026-05-14).  This eliminates `LD_PRELOAD`, `IFS`,
and other environment-injection vectors from recovery children entirely.

## Exec safety

The `{pid}` substitution in `--recovery-exec` args is safe: a `u32` PID
formatted as a decimal string contains only the characters `0`–`9` and
can never carry shell metacharacters (`;`, `|`, `&`, `$`, `` ` ``, etc.).
Furthermore, since exec-mode never passes arguments through a shell,
metacharacter interpretation is structurally impossible.

## Metrics

| Metric                                                | Type    | Description |
|-------------------------------------------------------|---------|-------------|
| `varta_frame_auth_failures_total`                     | counter | Incremented every time a frame's claimed PID does not match the kernel-verified sender PID (Linux only). |
| `varta_beats_total{pid="..."}`                        | counter | Per-PID total of accepted beats (only incremented after authentication passes). |
| `varta_prom_connections_dropped_total{reason="..."}` | counter | `/metrics` connections accepted but closed before serving.  Reasons: `drain` (serve budget exhausted), `rate_limit` (per-IP token bucket empty), `ip_table_full` (per-IP state map force-evicted). |
| `varta_prom_auth_failures_total`                     | counter | `/metrics` scrapes that arrived without `Authorization: Bearer <hex>` or with a wrong token.  Always emitted on every scrape (even at zero), so `absent()` alert rules stay green-on-green until the first incident. |
| `varta_recovery_refused_total{reason="..."}`         | counter | Recovery commands NOT spawned because of a structural safety gate. Only reason currently defined: `unauthenticated_transport` (stalled slot's pinned origin was `NetworkUnverified` and the operator did not enable UDP-origin recovery). Emitted at zero on every scrape. |
| `varta_origin_conflict_total`                        | counter | Beats dropped because the slot's pinned transport origin disagreed with the beat's origin (first-origin-wins). Non-zero values indicate either operator misconfiguration (same pid emitted from two transports) or an active spoofing attempt. |

## Trust model summary

```
 Process ── connect(2) to UDS ──┐
                                   ├─ [FAIL]  Kernel blocks (Layer 1: --socket-mode 0600, wrong UID)
                                   ├─ [PASS]  Layer 2: SO_PASSCRED → ucred.pid (Linux)
                                   │          Layer 2: LOCAL_CREDS → cmsgcred.pid (FreeBSD, DragonFly, NetBSD)
                                   │          ├─ [PID MISMATCH] → Drop frame + bump counter
                                   │          ├─ [UID MISMATCH] → Drop frame as IoError
                                   │          └─ [PID MATCH + UID MATCH] →
                                   ↓
                              [SUCCESS]  Observer trusts the PID → tracks,
                                         surfaces stalls, triggers --recovery-exec
                                         with {pid} as the final argument.
```

The trust boundary is the kernel: a frame is only accepted if the kernel
attests that the sending process's PID matches the one encoded in the
VLP frame and that the sending process runs under the observer's UID.
On Linux this is enforced per-datagram via `SO_PASSCRED`; on FreeBSD /
DragonFly / NetBSD via `LOCAL_CREDS` + `SCM_CREDS`.  macOS pathname
datagram sockets and platforms without kernel-level credential passing fall
back to `--socket-mode 0600`.

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

### Panic-hook entropy policy (secure UDP)

`install_panic_handler_secure_udp` reads 8 bytes of cryptographic entropy at
install time (`getrandom(2)` on Linux, `getentropy(3)` on macOS/BSD, falling
back to `/dev/urandom`). The IV is pre-computed once so that no file I/O
occurs inside the panic handler itself (async-signal-safety).

**Fail-closed default:** if all entropy sources fail — common in chrooted
environments without a mounted `/dev` — the function returns
`Err(PanicInstallError::EntropyUnavailable)` and the hook is NOT registered.
This prevents a panic-time Critical frame from reusing a deterministic IV
under the same AEAD key, which would be a catastrophic nonce-reuse failure.

**Degraded-entropy opt-in:** use
`install_panic_handler_secure_udp_accept_degraded_entropy` to fall back to a
non-cryptographic IV derived from PID, TID, monotonic time, and a counter
(SipHash-2-4). This always succeeds but accepts nonce-reuse risk if the
process panics more than once. The verbose function name is intentional
structural enforcement matching the project's `--i-accept-<risk>` convention.

### Little-endian only

The VLP wire format uses little-endian integer encoding natively.
Protocol correctness depends on the host being little-endian (all tier-1
targets — x86_64 and aarch64 — satisfy this). Building on a big-endian
host is a compile error. See `book/src/architecture/vlp-frame.md` for design
rationale.

### Panic-hook key lifetime — accepted residual

The secure-UDP panic handler (`install_panic_handler_secure_udp`,
`install_panic_handler_secure_udp_accept_degraded_entropy`) captures a `Key`
by move into a `Box<dyn Fn>` registered via `std::panic::set_hook`. The Box
is the **single owner** of the captured `Key` for the lifetime of the
process — `Key` is `!Clone` (see `crates/varta-vlp/src/crypto/mod.rs`), so
no duplicate of the secret bytes can exist anywhere else in the address
space.

The `!Clone` invariant pins the *count* of in-memory copies to one. The
remaining concern is the *lifetime* of that one copy on process exit:

* **Normal hook replacement** (`std::panic::take_hook`): the prior Box is
  dropped, the captured `Key`'s `ZeroizeOnDrop` fires, and the 32 secret
  bytes are wiped before the heap page is returned to the allocator. OK.
* **`panic = "unwind"` profile, normal process exit**: the panic-hook Box
  is leaked by the runtime — `Drop` is **not** called on registry-held
  objects at exit. The captured `Key` bytes persist in heap memory until
  the kernel reclaims the page. Linux does not zero pages on reclaim
  (memory contents are reused; zero-on-allocation guarantees apply only
  to *new* allocations into the same process).
* **`panic = "abort"` profile**: the panic-hook closure never runs, but
  `set_hook` still owns the Box — same residual as the normal-exit case.
  Additionally, no `Drop` runs anywhere during `abort()`.

This residual is **accepted**: there is no async-signal-safe mechanism
that can reliably wipe a heap-resident secret at process exit. `atexit`
handlers do not run on `abort()`, are not async-signal-safe, and race the
panic hook firing. `mlock` / `memfd_secret` cannot prevent the kernel
from copying the page during scheduler context switches or core dumps.
The minimum-surface design is to keep the captured `Key` alive in a
single Box and treat the OS process boundary as the security boundary:
inspecting the memory of a live process requires `ptrace` or
`/proc/<pid>/mem` privileges, at which point all in-memory secrets in
any design are accessible.

---

## Cross-references

- [Safety profiles](safety-profiles.md) — compile-time feature gating for dangerous recovery paths; production-safe build verification recipe
- [Observer liveness](observer-liveness.md) — defending against `varta-watch` itself crashing or hanging
- [VLP transports](vlp-transports.md) — transport-level trust classification and `BeatOrigin` semantics
