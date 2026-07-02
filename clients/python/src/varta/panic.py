"""Excepthook-based panic emitters — mirror Rust's ``install_panic_handler``.

Python's :data:`sys.excepthook` fires on uncaught exceptions. Hard
crashes (``SIGSEGV``, ``SIGABRT``, etc.) do *not* trigger the excepthook
and instead bypass the interpreter entirely; for those, optionally
register :func:`faulthandler.enable` against the same socket file
descriptor (kwarg ``faulthandler=True``).

All installers:

* Bind the underlying socket at install time so the hook itself does no
  syscalls that might fail. Mirrors the Rust async-signal-safety
  contract (`crates/varta-client/src/panic.rs`).
* Chain the existing :data:`sys.excepthook` so other libraries' hooks
  (e.g. Sentry) keep firing.
* Emit a single VLP frame with ``status=Status.CRITICAL`` and
  ``nonce=NONCE_TERMINAL`` so the observer can identify it as a panic
  beat (the only frame allowed to carry the terminal nonce).
"""

from __future__ import annotations

import faulthandler
import os
import socket
import sys
import threading
import time
from typing import Callable, Optional, Tuple

from ._vlp import FRAME_BYTES, NONCE_TERMINAL, Status, encode_into
from ._vlp_secure import (
    CryptographyMissingError,
    KEY_BYTES,
    derive_panic_iv_prefix,
    encode_shared,
)

__all__ = [
    "PanicInstallError",
    "EntropyUnavailable",
    "SocketBind",
    "install_excepthook_uds",
    "install_excepthook_udp",
    "install_excepthook_secure_udp",
]


Address = Tuple[str, int]
_TIMESTAMP_INVALID = 0xFFFFFFFFFFFFFFFF
_TERMINAL_CLOCK_EPOCH_NS = time.monotonic_ns()
_last_terminal_timestamp = 0
_terminal_timestamp_lock = threading.Lock()
_excepthook_lock = threading.Lock()
_previous_excepthook: Optional[Callable[..., None]] = None
_active_emit: Optional[Callable[[], None]] = None
_active_close: Optional[Callable[[], None]] = None


def _reset_terminal_timestamp_lock_after_fork() -> None:
    global _terminal_timestamp_lock, _excepthook_lock

    # A child cannot release a lock held by a vanished parent thread.
    _terminal_timestamp_lock = threading.Lock()
    _excepthook_lock = threading.Lock()


_register_at_fork = getattr(os, "register_at_fork", None)
if _register_at_fork is not None:
    _register_at_fork(after_in_child=_reset_terminal_timestamp_lock_after_fork)


class PanicInstallError(Exception):
    """Base class for installation failures."""


class EntropyUnavailable(PanicInstallError):
    """:func:`os.urandom` could not produce IV material at install time."""


class SocketBind(PanicInstallError):
    """The underlying socket could not be created/bound at install time."""


def _claim_terminal_timestamp(previous: int, raw: int) -> Optional[int]:
    if previous >= _TIMESTAMP_INVALID - 1:
        return None
    candidate = max(1, raw, previous + 1)
    if candidate >= _TIMESTAMP_INVALID:
        return None
    return candidate


def _next_terminal_timestamp() -> Optional[int]:
    global _last_terminal_timestamp

    raw = max(1, time.monotonic_ns() - _TERMINAL_CLOCK_EPOCH_NS)
    with _terminal_timestamp_lock:
        candidate = _claim_terminal_timestamp(_last_terminal_timestamp, raw)
        if candidate is not None:
            _last_terminal_timestamp = candidate
        return candidate


def _build_critical_frame_with_meta(
    payload: int = 0,
) -> Optional[Tuple[bytes, int, int]]:
    """Build a Critical+NONCE_TERMINAL frame, returning ``(frame, pid, ts)``.

    The PID and timestamp baked into the frame are returned so the secure
    emitter can feed the *same* values into the panic IV-prefix KDF — the
    nonce and the authenticated plaintext must agree on them.
    """
    timestamp = _next_terminal_timestamp()
    if timestamp is None:
        return None
    pid = os.getpid() & 0xFFFFFFFF
    buf = bytearray(FRAME_BYTES)
    encode_into(
        buf,
        Status.CRITICAL,
        pid,
        timestamp,
        NONCE_TERMINAL,
        payload & 0xFFFFFFFF,
    )
    return bytes(buf), pid, timestamp


def _build_critical_frame(payload: int = 0) -> Optional[bytes]:
    meta = _build_critical_frame_with_meta(payload)
    return None if meta is None else meta[0]


def _varta_excepthook(exc_type, exc_value, exc_tb):  # type: ignore[no-untyped-def]
    with _excepthook_lock:
        emit = _active_emit
        prev = _previous_excepthook

    if emit is not None:
        try:
            emit()
        except Exception:  # pragma: no cover - hook must not propagate
            pass
    if prev is not None:
        prev(exc_type, exc_value, exc_tb)


def _install_excepthook(emit: Callable[[], None], close: Callable[[], None]) -> None:
    global _previous_excepthook, _active_emit, _active_close

    old_close: Optional[Callable[[], None]]
    with _excepthook_lock:
        old_close = _active_close
        _active_emit = emit
        _active_close = close
        if sys.excepthook is not _varta_excepthook:
            _previous_excepthook = sys.excepthook
            sys.excepthook = _varta_excepthook

    if old_close is not None:
        try:
            old_close()
        except OSError:
            pass


def install_excepthook_uds(
    path: str,
    *,
    faulthandler_signals: bool = False,
) -> None:
    """Install a critical-beat emitter against the UDS at ``path``.

    Binds the socket at install time. Chains the existing
    :data:`sys.excepthook`. If ``faulthandler_signals=True``, also calls
    :func:`faulthandler.enable` against the socket's file descriptor so
    fatal signals (``SIGSEGV``, ``SIGABRT``, etc.) dump traceback to the
    observer's socket as a side channel. Note: faulthandler writes a
    Python traceback, not a VLP frame — the observer will not decode it
    as a beat. Treat it as an out-of-band debugging aid.
    """
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.connect(path)
    except OSError as exc:
        raise SocketBind(str(exc)) from exc

    def emit() -> None:
        try:
            frame = _build_critical_frame()
            if frame is not None:
                sock.send(frame)
        except OSError:
            pass

    _install_excepthook(emit, sock.close)
    if faulthandler_signals:
        faulthandler.enable(file=sock.fileno(), all_threads=True)


def install_excepthook_udp(
    addr: Address,
    *,
    faulthandler_signals: bool = False,
) -> None:
    """Install a critical-beat emitter over UDP."""
    try:
        family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("", 0) if family == socket.AF_INET else ("", 0, 0, 0))
        sock.connect(addr)
    except OSError as exc:
        raise SocketBind(str(exc)) from exc

    def emit() -> None:
        try:
            frame = _build_critical_frame()
            if frame is not None:
                sock.send(frame)
        except OSError:
            pass

    _install_excepthook(emit, sock.close)
    if faulthandler_signals:
        faulthandler.enable(file=sock.fileno(), all_threads=True)


def install_excepthook_secure_udp(addr: Address, key: bytes) -> None:
    """Install a critical-beat emitter over secure UDP.

    Fails closed: ``os.urandom`` is invoked once at install time; if it
    raises, :class:`EntropyUnavailable` propagates and no hook is
    installed (the original :data:`sys.excepthook` keeps running).

    Fork- and PID-recycle-safe by construction: every fire derives its IV
    prefix from the install-time salt plus the per-fire
    ``(pid, timestamp, counter)`` via :func:`derive_panic_iv_prefix`. The
    strictly-monotonic timestamp guarantees a unique nonce across
    ``fork(2)`` and PID recycling without any PID-equality probe or in-hook
    entropy read — mirroring the Rust
    ``install_panic_handler_secure_udp`` contract (a former
    ``pid != install_pid`` fast path was unsound: a descendant reassigned
    the installer's PID would reuse the inherited ``(prefix, counter=0)``).

    Requires the ``cryptography`` package. Raises
    :class:`varta._vlp_secure.CryptographyMissingError` if missing.
    """
    if len(key) != KEY_BYTES:
        raise ValueError(f"key must be {KEY_BYTES} bytes")

    try:
        salt = os.urandom(16)
    except OSError as exc:
        raise EntropyUnavailable(str(exc)) from exc

    try:
        family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("", 0) if family == socket.AF_INET else ("", 0, 0, 0))
        sock.connect(addr)
    except OSError as exc:
        raise SocketBind(str(exc)) from exc

    # Verify cryptography is reachable before we register the hook so the
    # failure surfaces at install time rather than during a panic.
    try:
        derive_panic_iv_prefix(salt, 0, 0, 0)
        encode_shared(key, b"\x00" * 8, 0, b"\x00" * FRAME_BYTES)
    except CryptographyMissingError:
        sock.close()
        raise

    state = {
        "salt": salt,
        "counter": 0,
    }

    def emit() -> None:
        try:
            meta = _build_critical_frame_with_meta()
            if meta is None:
                return
            plaintext, pid, timestamp = meta
            counter = int(state["counter"])
            state["counter"] = counter + 1
            iv_prefix = derive_panic_iv_prefix(state["salt"], pid, timestamp, counter)
            wire = encode_shared(key, iv_prefix, counter, plaintext)
            sock.send(wire)
        except OSError:
            pass
        except Exception:  # pragma: no cover - hook must not propagate
            pass

    _install_excepthook(emit, sock.close)
