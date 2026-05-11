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

Apple's `AF_UNIX` `SOCK_DGRAM` implementation does not expose a reliable
per-datagram PID on the server side of an unconnected socket.
`LOCAL_CREDS` (`setsockopt`) is not supported for `SOCK_DGRAM` on
current macOS versions, and `LOCAL_PEERPID` (`getsockopt`) is only
available for connected sockets.

On macOS, per-datagram PID verification is therefore **not performed** — the observer
accepts any well-formed frame from a process that can reach the socket.
The primary defence on macOS is **Layer 1** (`--socket-mode 0600`).

#### Future work: macOS

Apple's recommended approach for inter-process identity verification is
App Sandbox entitlements (`com.apple.security.temporary-exception.mach`),
not raw credential passing over `AF_UNIX`.  For a cross-platform Rust
tool with a zero-registry-dependency constraint, `--socket-mode 0600`
is the most pragmatic and reliable option.  If `LOCAL_CREDS` gains
stable `SOCK_DGRAM` support in a future macOS release, the observer
could adopt the same `recvmsg` + credential-parse path used on Linux.

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
                                  ├─ [PASS]  Layer 2: SO_PASSCRED → ucred.pid (Linux only)
                                  │          ├─ [PID MISMATCH] → Drop frame + bump counter
                                  │          └─ [PID MATCH]    →
                                  ↓
                             [SUCCESS]  Observer trusts the PID → tracks,
                                        surfaces stalls, triggers --recovery-cmd
                                        with {pid} substitution.
```

The trust boundary is the kernel: a frame is only accepted if the kernel
attests that the sending process's PID matches the one encoded in the
VLP frame.  On Linux this is enforced per-datagram; on macOS the same
UID is trusted by process isolation.
