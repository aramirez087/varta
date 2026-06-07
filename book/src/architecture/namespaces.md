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

## PID recycling within a namespace (generation token)

A PID is not a stable identity even *within* one namespace: the kernel
recycles it once the holding process exits. If agent A (PID 1234) dies and the
OS reuses 1234 for a fresh agent B, B's first beat carries `nonce = 1` while
the observer's slot for PID 1234 still holds A's high-water nonce. Without
extra signal, B's low-nonce beats are rejected as out-of-order, the slot's
`last_ns` freezes, a **false stall** fires, and recovery is misdirected against
the healthy new process — all with no attacker involved. On Linux UDS
(`KernelAttested`) recovery is *permitted*, so this can kill or restart an
unrelated bystander; on macOS UDS (`SocketModeOnly`) and all UDP
(`NetworkUnverified`) recovery is already refused, so the residual there is
limited to monitoring accuracy.

The fix binds slot identity to **`(pid, generation)`**, where `generation` is
the kernel-attested process start-time — field 22 (`starttime`) of
`/proc/<pid>/stat`, read via `crate::peer_cred::read_pid_start_time(peer_pid)`
(allocation-free, one `open`/`read`/`close` into a stack buffer, parsed from
the last `)` so a `comm` containing spaces or parentheses cannot fool it). Two
processes that share a PID value cannot share a start-time, because the first
holds the PID until it exits.

When a beat for an already-tracked pid carries a **different** `Some(_)`
generation, the slot is reset to a fresh agent (nonce baseline, origin,
namespace inode, and silence timer all re-pinned) and the event is counted as
`varta_tracker_pid_recycle_total`. The generation check runs **before** the
origin / namespace / nonce checks — a recycled process legitimately differs on
all of them. A `None` on either side ("generation unknown": non-Linux, UDP, or
unreadable `/proc`) is treated leniently by the tracker and never triggers a
reset, so prior PID-only behaviour is preserved exactly for non-recovery
transports and for already-pinned slots whose peer vanished. When the slot's
pinned generation is `None` and a later beat carries `Some(_)` with an
**accepted** nonce, the token is pinned in place (same rule as the
namespace-inode `None → Some` upgrade) so a subsequent recycle can compare
`(Some(G1), Some(G2))` instead of staying stuck at `None`. Out-of-order frames
must not pin generation. Replay protection is untouched: a low nonce under the
**same** generation is still dropped as out-of-order.

For Linux UDS first contact, the observer requires that `Some(generation)`
before the slot may pin recovery-eligible `KernelAttested` origin. If the
sender exits after `recvmsg(2)` but before the `/proc/<pid>/stat` start-time
read, the beat is still observable, but it is recorded as `SocketModeOnly`.
A later accepted beat that can read a concrete generation may upgrade the slot
to `KernelAttested`. This keeps transient dying-gasp frames from breaking
monitoring while preventing an unpinned numeric PID from driving `{pid}`
recovery after PID recycle.

The same generation is revalidated when a kernel-attested slot first becomes a
stall candidate. If `/proc/<pid>/stat` now returns a concrete **different**
generation, the old slot is retired and no `Event::Stall` is emitted. This
closes the silent-death case where no new beat arrives to trigger the beat-time
recycle gate: a dead agent's stale `KernelAttested` origin must not drive
recovery against a healthy process that inherited the PID. A missing generation
read at stall time remains fail-open, because it may simply mean the original
agent exited and recovery should still restart it.

**Cost.** Beat-time recycle detection requires re-reading the generation on
*every* admitted `KernelAttested` beat — there is no way to observe PID reuse
without re-stat-ing the peer. This adds one `/proc/<pid>/stat`
`open`/`read`/`close` (three syscalls, allocation-free) per beat, on top of the
existing `/proc/<pid>/ns/pid` namespace read. The read is deferred until after
the global rate limiter admits the frame, so a flood cannot force a `/proc`
read per packet. Stall-time revalidation adds the same stack-buffered read only
for kernel-attested slots that have already crossed the stall threshold.
Non-Linux and non-attested transports skip the read entirely
(`read_pid_start_time` returns `None`).

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
| `varta_tracker_pid_recycle_total` (counter) | Stale slot identities reset or retired because a kernel-attested process start-time mismatch proved the pid was recycled to a new process (recycle-safe identity). |
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
- `Observer::drain_pid_recycles() -> u64` — counter drain (PID-recycle slot resets/retirements).
- `Tracker::record_with_generation(frame, now_ns, threshold_ns, origin, peer_pid_ns_inode, peer_generation)` — the generation-aware record path; `Tracker::record(..)` is a shim passing `peer_generation = None`.
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
- **`/proc/<peer_pid>/stat` unreadable on first contact**: the helper returns
  `None`, so the beat is tracked as `SocketModeOnly` until a later accepted
  Linux UDS beat can pin `Some(generation)`. Missing generation remains
  fail-open only after a slot already has recovery-eligible identity pinned.
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
