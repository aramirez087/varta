"""Platform-specific errno constants required for parity with the Rust
``varta-client::classify_send_error``.

These values are hard-coded so the base ``pip install varta`` install
remains stdlib-only on every supported platform. The Rust client makes
the same choice (`crates/varta-client/src/client.rs:22-60`) and gates
on compile-time targets. Python sees ``platform.system()`` at runtime.

If you are porting the client to a new platform, add the ``ENOBUFS``
value here and extend :data:`SUPPORTED_PLATFORMS`.
"""

from __future__ import annotations

import errno as _errno
import sys

__all__ = [
    "ENOBUFS",
    "ENOSPC",
    "EAGAIN",
    "EWOULDBLOCK",
    "ECONNREFUSED",
    "ECONNRESET",
    "ENOTCONN",
    "EPIPE",
    "ENOENT",
    "UnsupportedPlatformError",
]


class UnsupportedPlatformError(RuntimeError):
    """Raised at import time when running on an unsupported platform."""


_LINUX_ENOBUFS = 105
_BSD_ENOBUFS = 55  # macOS / iOS / FreeBSD / NetBSD / OpenBSD / DragonFly
# Solaris / illumos ENOBUFS = 132 (confirmed against rust-libc
# ``src/unix/solarish/mod.rs``; matches the Rust client and the Node client).
# NOT 111 — that is Linux's ECONNREFUSED and is undefined on solarish, so the
# old value silently routed real send-buffer backpressure to ``failed`` instead
# of ``Dropped(KERNEL_QUEUE_FULL)`` (this is the Python sibling of Rust bug-470).
_SOLARIS_ENOBUFS = 132  # Solaris / illumos


def _select_enobufs() -> int:
    platform = sys.platform
    if platform.startswith("linux"):
        return _LINUX_ENOBUFS
    if platform in ("darwin", "ios") or platform.startswith(
        ("freebsd", "netbsd", "openbsd", "dragonfly")
    ):
        return _BSD_ENOBUFS
    if platform in ("sunos5", "solaris", "illumos"):
        return _SOLARIS_ENOBUFS
    # Fall back to the Python `errno` module if it knows the symbol on
    # this platform — gives us a chance on platforms we did not list
    # explicitly without silently using the wrong number.
    return getattr(_errno, "ENOBUFS", _LINUX_ENOBUFS)


ENOBUFS: int = _select_enobufs()
ENOSPC: int = _errno.ENOSPC
EAGAIN: int = _errno.EAGAIN
EWOULDBLOCK: int = _errno.EWOULDBLOCK
ECONNREFUSED: int = _errno.ECONNREFUSED
ECONNRESET: int = _errno.ECONNRESET
ENOTCONN: int = _errno.ENOTCONN
EPIPE: int = _errno.EPIPE
ENOENT: int = _errno.ENOENT
