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
import time
from typing import Callable, Tuple

from ._vlp import FRAME_BYTES, NONCE_TERMINAL, Status, encode_into
from ._vlp_secure import (
    CryptographyMissingError,
    KEY_BYTES,
    derive_iv_prefix,
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


class PanicInstallError(Exception):
    """Base class for installation failures."""


class EntropyUnavailable(PanicInstallError):
    """:func:`os.urandom` could not produce IV material at install time."""


class SocketBind(PanicInstallError):
    """The underlying socket could not be created/bound at install time."""


def _build_critical_frame(payload: int = 0) -> bytes:
    buf = bytearray(FRAME_BYTES)
    encode_into(
        buf,
        Status.CRITICAL,
        os.getpid() & 0xFFFFFFFF,
        time.monotonic_ns() & 0xFFFFFFFFFFFFFFFF,
        NONCE_TERMINAL,
        payload & 0xFFFFFFFF,
    )
    return bytes(buf)


def _chain_excepthook(emit: Callable[[], None]) -> None:
    prev = sys.excepthook

    def hook(exc_type, exc_value, exc_tb):  # type: ignore[no-untyped-def]
        try:
            emit()
        except Exception:  # pragma: no cover - hook must not propagate
            pass
        if prev is not None:
            prev(exc_type, exc_value, exc_tb)

    sys.excepthook = hook


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
            sock.send(_build_critical_frame())
        except OSError:
            pass

    _chain_excepthook(emit)
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
            sock.send(_build_critical_frame())
        except OSError:
            pass

    _chain_excepthook(emit)
    if faulthandler_signals:
        faulthandler.enable(file=sock.fileno(), all_threads=True)


def install_excepthook_secure_udp(addr: Address, key: bytes) -> None:
    """Install a critical-beat emitter over secure UDP.

    Fails closed: ``os.urandom`` is invoked once at install time; if it
    raises, :class:`EntropyUnavailable` propagates and no hook is
    installed (the original :data:`sys.excepthook` keeps running).

    Detects ``fork(2)`` at hook-call time by comparing the current PID to
    the snapshot captured at install. On mismatch, re-reads
    :func:`os.urandom` inside the hook to rotate the IV salt — matches
    the Rust ``install_panic_handler_secure_udp`` contract.

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
        derive_iv_prefix(salt, 0)
        encode_shared(key, b"\x00" * 8, 0, b"\x00" * FRAME_BYTES)
    except CryptographyMissingError:
        sock.close()
        raise

    state = {
        "salt": salt,
        "pid": os.getpid(),
        "counter": 0,
    }

    def emit() -> None:
        try:
            pid = os.getpid()
            if pid != state["pid"]:
                try:
                    state["salt"] = os.urandom(16)
                except OSError:
                    return
                state["pid"] = pid
                state["counter"] = 0
            iv_prefix = derive_iv_prefix(state["salt"], 0)
            counter = int(state["counter"])
            state["counter"] = counter + 1
            plaintext = _build_critical_frame()
            wire = encode_shared(key, iv_prefix, counter, plaintext)
            sock.send(wire)
        except OSError:
            pass
        except Exception:  # pragma: no cover - hook must not propagate
            pass

    _chain_excepthook(emit)


