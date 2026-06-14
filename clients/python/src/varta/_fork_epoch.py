"""Process-lineage epoch for fork-safe inherited client state.

Mirrors ``crates/varta-client/src/fork_epoch.rs``. A process-wide counter is
incremented from an ``os.register_at_fork`` child callback on every
``fork(2)``. Each :class:`varta.Varta` snapshots the epoch at connect time and
reconnects when it changes.

This closes an AEAD nonce-reuse hole that a bare PID comparison cannot detect.
A descendant that inherits a secure-UDP session (16-byte salt + IV
prefix/counter) and is *later reassigned its ancestor's connect-time PID* via
PID recycling would pass ``pid == connect_pid`` and skip the reconnect,
re-deriving an IV prefix its ancestor already used under the same
ChaCha20-Poly1305 key — a catastrophic ``(key, nonce)`` collision. The lineage
epoch differs after any ``fork(2)``, so the mismatch is caught regardless of
how the PID was reassigned.
"""

from __future__ import annotations

import os

_epoch = 0
_registered = False


def _advance_child_epoch() -> None:
    # Runs in the child after ``fork(2)``. Deliberately a single integer
    # increment: CPython runs the callback under the GIL and rebinding an
    # ``int`` is atomic, so no lock is taken — acquiring one here could
    # deadlock against a lock another thread held at fork time.
    global _epoch
    _epoch += 1


def register() -> int:
    """Install the process-wide child callback (idempotent) and return the epoch.

    Every :class:`varta.Varta` constructor calls this before returning an
    inheritable agent — falling back to bare PID equality would reintroduce
    AEAD nonce reuse after PID recycling.

    On platforms without ``fork(2)`` (e.g. Windows) ``os.register_at_fork`` is
    absent; the epoch stays ``0``, which is correct because no fork can occur.

    A benign race that registers the callback more than once only advances the
    epoch by more than one per fork — still a strict change — so no lock is
    required to guard the one-time registration.
    """
    global _registered
    if not _registered and hasattr(os, "register_at_fork"):
        os.register_at_fork(after_in_child=_advance_child_epoch)
    _registered = True
    return _epoch


def current() -> int:
    """Return the calling process's current lineage epoch."""
    return _epoch
