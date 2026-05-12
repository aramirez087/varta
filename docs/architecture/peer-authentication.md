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

On macOS, the observer attempts `getsockopt(LOCAL_PEERTOKEN)` immediately
after each `recvmsg(2)`. `LOCAL_PEERTOKEN` returns an `audit_token_t`
containing the sender's PID, UID, GID, and audit information. Because the
observer is single-threaded and calls `getsockopt` immediately after
`recvmsg`, no other datagram can arrive between the two syscalls.

When `LOCAL_PEERTOKEN` succeeds, the observer performs the same PID + UID
verification as on Linux. When it fails (e.g. on older macOS versions or
when the kernel does not expose per-datagram credentials for unconnected
`SOCK_DGRAM`), the observer falls back to the sentinel PID 0 — relying
on `--socket-mode 0600` as the primary defence.

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

When `--recovery-cmd` (inline shell template) is used, the observer
emits a stderr warning recommending `--recovery-cmd-file` (with
restrictive file permissions) or `--recovery-exec` (no shell) for
production deployments.

## Template safety

The `{pid}` substitution in `--recovery-cmd` is safe regardless of the
authentication outcome.  A `u32` PID formatted as a decimal string
contains only the characters `0`–`9` and can never carry shell
metacharacters (`;`, `|`, `&`, `$`, `` ` ``, etc.).

## Metrics

| Metric                          | Type    | Description |
|---------------------------------|---------|-------------|
| `varta_frame_auth_failures_total` | counter | Incremented every time a frame's claimed PID does not match the kernel-verified sender PID (Linux only). |
| `varta_beats_total{pid="..."}`  | counter | Per-PID total of accepted beats (only incremented after authentication passes). |

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
`getsockopt(LOCAL_PEERTOKEN)` when available; on FreeBSD / DragonFly /
NetBSD via `LOCAL_CREDS` + `SCM_CREDS`.  Platforms without kernel-level
credential passing fall back to `--socket-mode 0600`.
