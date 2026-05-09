# PID-namespace semantics

Varta agents and the `varta-watch` observer can run on the same host but in
different Linux PID namespaces (typical when agents run in containers and the
observer on the host, or vice-versa). This document defines what the protocol
does in that case, why, and how operators configure it.

## Problem statement

`std::process::id()` (called by `Varta::beat()`) returns the agent's PID **in
the calling process's PID namespace** (see `pid_namespaces(7)`). The observer's
kernel-attested peer PID (`SO_PASSCRED` / `SCM_CREDS` / `SCM_UCRED`) is the
PID **as seen from the observer's namespace**.

Two consequences when namespaces differ:

1. **The numeric pid is meaningless across the boundary.** PID 17 in container
   A is a different process from PID 17 on the host. `kill(2)` against PID 17
   in the observer's namespace targets the observer-namespace process, not the
   agent.
2. **Collisions are guaranteed.** Every container's first process is PID 1.
   Two containerized agents binding the same observer socket will both claim
   PID 1.

## Threat model

| Scenario | Risk |
|---|---|
| Host observer, host agents | None. |
| Host observer, agent in `--pid=host` container | None — agent uses host PIDs. |
| Host observer, agent in private-PID container | Cross-namespace: kill targets wrong process. |
| Two private-PID containers, shared observer | Pid collisions: containers claim same pid. |
| Container observer, host agents | Cross-namespace. |

## Detection

On Linux, every process's PID namespace has a unique inode exposed at
`/proc/<pid>/ns/pid` (`stat(1)` it, or `readlink(1)` for the canonical
`pid:[NNNN]` form). Two processes share a PID namespace iff their
`/proc/<pid>/ns/pid` symlinks resolve to the same inode.

`varta-watch` caches its own inode at startup
(`crate::peer_cred::observer_pid_namespace_inode()`) and, for every
kernel-attested beat, reads the peer's inode
(`crate::peer_cred::read_pid_namespace_inode(peer_pid)`). Both helpers are
allocation-free; the per-beat read is one `readlink(2)` syscall into a stack
buffer (sub-microsecond on modern Linux).

Non-Linux platforms (macOS, BSD) return `None` from both helpers and the
comparison short-circuits to "match". UDP listeners set `peer_pid_ns_inode =
None` because there is no kernel attestation; the existing UDP recovery
refusal gate is the relevant protection there.

## Mitigation by deployment style

| Deployment | Default behaviour | Operator action |
|---|---|---|
| Single namespace (host or container) | Pass-through. | None. |
| Containerized agents with `--pid=host` | Pass-through (same kernel-attested ns). | None. |
| Containerized agents with private PID namespace | Beats dropped at receive; recovery refused. Audit log shows `reason=cross_namespace_agent`. | Either fix the deployment (run agents with `--pid=host`) or accept the risk via `--allow-cross-namespace-agents` *and* arrange out-of-band PID translation in the recovery template. |
| Mixed: some agents same-ns, some cross-ns | Same-ns agents work; cross-ns agents refused and audit-logged. | Same as above; the gate is per-beat. |
| Operator wants fail-fast on misconfigure | Defaults silently drop and audit. | Pass `--strict-namespace-check` — daemon exits non-zero on first cross-ns beat. |

## Audit and metrics inventory

| Surface | Linux signal |
|---|---|
| `varta_frame_namespace_mismatch_total` (counter) | Kernel-attested frames dropped at receive (peer ns ≠ observer ns). |
| `varta_tracker_namespace_conflict_total` (counter) | Beats dropped because the slot's pinned ns inode disagreed with the beat's (first-namespace-wins). |
| `varta_recovery_refused_total{reason="cross_namespace_agent"}` (counter) | Stalls refused at recovery time because the slot's ns inode differed from the observer's. |
| `varta_recovery_outcomes_total{outcome="refused_cross_namespace"}` (counter) | Same event, broken down on the outcome axis. |
| Audit log record with `reason=cross_namespace_agent` | TSV record in `--recovery-audit-file`. |
| `Event::NamespaceConflict` | Emitted to consumers via `Observer::poll()` so file/Prom exporters can record it. |

All counters are emitted at every scrape even at zero, so `absent()` alert
rules stay green-on-green until the first event.

## API surface

- `Observer::observer_pid_namespace_inode() -> Option<u64>` — returns the
  observer's cached PID-namespace inode (Linux only).
- `Observer::with_allow_cross_namespace(bool) -> Self` — opt out of the
  default refuse-and-audit behaviour. Wired from
  `--allow-cross-namespace-agents`.
- `Observer::drain_cross_namespace_drops() -> u64` — counter drain.
- `Observer::drain_namespace_conflicts() -> u64` — counter drain.
- `Tracker::pid_ns_inode_of(pid: u32) -> Option<Option<u64>>` — observer-side
  introspection.
- `Recovery::with_allow_cross_namespace(bool) -> Self` — same opt-out at the
  recovery layer.
- `Recovery::on_stall(pid, origin, cross_namespace_agent: bool)` — caller-supplied
  cross-ns flag (typically derived from
  `Event::Stall::pid_ns_inode` vs `Observer::observer_pid_namespace_inode()`).
- `Recovery::take_refused_cross_namespace() -> u64` — counter drain.
- `RecoveryOutcome::RefusedCrossNamespace { pid }` — refusal variant.

## CLI flags

```
--allow-cross-namespace-agents   Permit beats and recovery for agents whose
                                 kernel-attested PID namespace differs from
                                 the observer's. Default off — beats dropped
                                 at receive (counted) and recovery refused
                                 (audit + counter).

--strict-namespace-check         Fatal startup error on first cross-namespace
                                 beat. Default off — log + counter only.
```

## Edge cases

- **`/proc/<peer_pid>/ns/pid` unreadable** (`ptrace_may_access` denial, peer
  exited between `recvmsg` and `readlink`, `/proc` not mounted): the helper
  returns `None`. The tracker's `None → Some` upgrade allows one-shot
  recovery so a transient `/proc` unavailability does not pin a slot as
  permanently unknown.
- **Existing `frame.pid != peer_pid` check fires first** for most real
  cross-namespace traffic (the two namespaces almost always produce different
  numeric pids for the same process). The namespace gate is belt-and-suspenders
  for the surprising case where the pids happen to collide.
- **`unsafe_code = "deny"`** is workspace-wide. The new `readlink` FFI follows
  the established `peer_cred.rs` pattern (`extern "C"` + one-line `unsafe { ... }`
  blocks with a SAFETY comment).
- **Frame ABI** is unchanged — the 32-byte `Frame` is not touched. All state
  lives observer-side.

## Cross-references

- [`vlp-transports.md`](vlp-transports.md) — overall transport model.
- [`peer-authentication.md`](peer-authentication.md) — kernel-attested PID and
  the `BeatOrigin` trust classification.
- `pid_namespaces(7)` and `user_namespaces(7)` man pages — kernel reference.
