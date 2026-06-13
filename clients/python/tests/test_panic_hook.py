"""Tests for ``varta.panic.install_excepthook_*``."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from typing import Tuple

import pytest

from varta import NONCE_TERMINAL, Status
from varta._vlp import decode
from varta.panic import (
    _claim_terminal_timestamp,
    PanicInstallError,
    SocketBind,
    install_excepthook_uds,
)


def test_terminal_timestamp_claim_is_strict_across_clock_reset_and_collision() -> None:
    first = _claim_terminal_timestamp(0, 100)
    assert first == 100
    reset = _claim_terminal_timestamp(first, 5)
    assert reset == 101
    equal = _claim_terminal_timestamp(reset, 101)
    assert equal == 102
    assert _claim_terminal_timestamp(0xFFFFFFFFFFFFFFFE, 1) is None


@pytest.fixture
def saved_excepthook():
    saved = sys.excepthook
    yield
    sys.excepthook = saved


def test_install_excepthook_uds_emits_critical_frame(
    bound_uds_listener: Tuple[socket.socket, Path], saved_excepthook
) -> None:
    listener, path = bound_uds_listener
    listener.setblocking(False)

    install_excepthook_uds(os.fspath(path))

    # Trigger the hook directly — pytest catches uncaught exceptions
    # itself, so we simulate the call.
    try:
        raise RuntimeError("boom")
    except RuntimeError:
        sys.excepthook(*sys.exc_info())

    data, _ = listener.recvfrom(64)
    frame = decode(data)
    assert frame.status is Status.CRITICAL
    assert frame.nonce == NONCE_TERMINAL
    assert frame.pid == os.getpid()
    assert 0 < frame.timestamp < 0xFFFFFFFFFFFFFFFF


def test_install_excepthook_uds_chains_previous_hook(
    bound_uds_listener: Tuple[socket.socket, Path], saved_excepthook
) -> None:
    _, path = bound_uds_listener
    state = {"prev_called": False}
    saved = sys.excepthook

    def prev_hook(exc_type, exc_value, exc_tb):
        state["prev_called"] = True
        # Do NOT re-raise; keep test deterministic.

    sys.excepthook = prev_hook
    install_excepthook_uds(os.fspath(path))
    try:
        raise ValueError("test")
    except ValueError:
        sys.excepthook(*sys.exc_info())
    assert state["prev_called"], "previous excepthook must still fire"
    sys.excepthook = saved


def test_install_excepthook_uds_raises_socket_bind_on_missing_path(
    tmp_uds_path: Path,
) -> None:
    # tmp_uds_path is unused — no listener bound — connect must raise.
    with pytest.raises(SocketBind):
        install_excepthook_uds(os.fspath(tmp_uds_path))


def test_panic_install_error_hierarchy() -> None:
    # SocketBind and EntropyUnavailable both descend from PanicInstallError.
    from varta.panic import EntropyUnavailable, SocketBind as SB

    assert issubclass(SB, PanicInstallError)
    assert issubclass(EntropyUnavailable, PanicInstallError)
