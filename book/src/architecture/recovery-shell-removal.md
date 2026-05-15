# Shell-Mode Recovery Removal

Shell-mode recovery (`RecoveryMode::Shell`, `--recovery-cmd`,
`--recovery-cmd-file`, `--i-accept-shell-risk`, Cargo feature
`unsafe-shell-recovery`) has been **permanently removed** from all build
profiles of `varta-watch`.

## Rationale

The shell path (`/bin/sh -c <template>`) was a shell-injection surface.  Even
with the two-layer gate (compile feature + runtime flag), the presence of a
`/bin/sh` invocation in the observer binary represents an unnecessary RCE
vector.  The exec path (`--recovery-exec`) subsumes every legitimate use case
without `/bin/sh` involvement.

Specific risks that motivated the removal:

1. **Shell injection** — a template containing `$1` and constructed from
   any operator-controlled input (config file, environment variable) can be
   weaponised to execute arbitrary commands with the observer's authority.
2. **Hardened container incompatibility** — containers built with `no-new-privs`
   or `seccomp` profiles that block `execve("/bin/sh", ...)` would silently
   fail recovery without any error surfaced to the operator.
3. **ABI assumption** — the path `/bin/sh` is a POSIX assumption but not
   a guarantee.  Musl-based or busybox-minimal images may place the shell
   elsewhere or omit it entirely.
4. **Strings-audit regression** — the presence of `/bin/sh` in the binary
   caused the Class-A profile strings audit to require a feature-conditional
   exemption.  Removal makes the audit unconditional.

## Migration guide

| Removed flag | Replacement | Notes |
|---|---|---|
| `--recovery-cmd <TEMPLATE>` | `--recovery-exec <PROGRAM> [ARGS...]` | The stalled pid is appended as the final argument by the observer. |
| `--recovery-cmd-file <PATH>` | `--recovery-exec-file <PATH>` | File must contain the program path (and optional fixed args) on a single line, mode 0600. |
| `--i-accept-shell-risk` | *(removed — no replacement needed)* | `--recovery-exec` requires no opt-in flag. |

### Before

```sh
varta-watch \
  --socket /run/varta/agents.sock \
  --threshold-ms 5000 \
  --recovery-cmd "systemctl restart myapp-\$1" \
  --i-accept-shell-risk
```

### After

```sh
varta-watch \
  --socket /run/varta/agents.sock \
  --threshold-ms 5000 \
  --recovery-exec /usr/local/bin/restart-myapp
```

Where `/usr/local/bin/restart-myapp` is a script or binary that receives
the stalled pid as `$1` (passed directly by the observer, not via shell
expansion).

### Using a wrapper script

If your recovery logic requires shell features (pipes, conditionals), write
a thin wrapper script and invoke it via `--recovery-exec`:

```sh
#!/bin/sh
# /usr/local/bin/varta-recovery
set -euo pipefail
PID="$1"
echo "stall detected for pid $PID" >> /var/log/varta-recovery.log
systemctl restart "myapp-${PID}"
```

```sh
varta-watch \
  --socket /run/varta/agents.sock \
  --threshold-ms 5000 \
  --recovery-exec /usr/local/bin/varta-recovery
```

The shell is now invoked once, inside a dedicated file that is under version
control and auditable — not expanded from a command-line string at runtime.

## Compile-time enforcement

Passing any of the removed flags now produces a hard error at startup:

```
error: --recovery-cmd has been removed; use --recovery-exec instead
```

This ensures operators whose deployment scripts still reference the old flags
are notified immediately rather than silently running without recovery.

## Cross-references

- [Safety profiles](safety-profiles.md) — how `/bin/sh` absence is audited
- [Peer authentication](peer-authentication.md) — why exec-only recovery is
  consistent with the `KernelAttested` recovery gate
