"""Shared pytest fixtures for the Varta Python client tests."""

from __future__ import annotations

import itertools
import os
import shutil
import socket
import tempfile
import time
from pathlib import Path
from typing import Iterator, Tuple

import pytest

# cerebrum 2026-05-15: unique tempdir paths in tests need an atomic
# counter to avoid same-process collisions on coarse-clock CI runners.
_COUNTER = itertools.count()


def _unique_tag() -> str:
    return f"{os.getpid()}-{time.monotonic_ns() & 0xFFFFFF}-{next(_COUNTER)}"


@pytest.fixture
def tmp_uds_path() -> Iterator[Path]:
    """A short UDS path under the system tempdir.

    macOS / BSD ``sun_path`` is 104 chars; pytest's nested ``tmp_path``
    exceeds that limit. We rebuild a fresh, short directory ourselves.
    """
    parent = Path(tempfile.gettempdir()) / f"varta-{_unique_tag()}"
    parent.mkdir(mode=0o755, exist_ok=False)
    try:
        yield parent / "varta.sock"
    finally:
        shutil.rmtree(parent, ignore_errors=True)


@pytest.fixture
def bound_uds_listener(tmp_uds_path: Path) -> Iterator[Tuple[socket.socket, Path]]:
    """A UDS socket bound at a unique tempdir path that silently drops every
    datagram. Yields (listener, path); cleans up the socket file on exit.

    Mirrors the Rust ``bind_listener()`` helper in
    ``crates/varta-client/src/client.rs::tests``.
    """
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    listener.bind(os.fspath(tmp_uds_path))
    try:
        yield listener, tmp_uds_path
    finally:
        listener.close()
        try:
            tmp_uds_path.unlink()
        except FileNotFoundError:
            pass


@pytest.fixture
def repo_root() -> Path:
    """Path to the repository root (four levels up from this test file)."""
    return Path(__file__).resolve().parents[3]


@pytest.fixture
def vectors_path(repo_root: Path) -> Path:
    return repo_root / "tools" / "vlp-test-vectors.json"
