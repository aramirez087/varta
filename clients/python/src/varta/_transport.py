"""Transport abstraction for the Varta agent.

The :class:`BeatTransport` ABC mirrors the Rust trait of the same name
(`crates/varta-client/src/transport.rs`). Concrete implementations:

* :class:`UdsTransport` — Unix domain datagram socket.
* :class:`UdpTransport` — connected UDP socket.
* :class:`SecureUdpTransport` — UDP + ChaCha20-Poly1305 AEAD (requires
  ``cryptography``; raises :class:`CryptographyMissingError` on use).

Every transport must guarantee:

1. Non-blocking I/O at construction (``setblocking(False)``).
2. ``send(buf)`` accepts a 32-byte ``bytes``-like, returns ``FRAME_BYTES``
   only after a full logical heartbeat is accepted, and raises ``OSError``
   on kernel-level failure.
3. ``reconnect()`` rebuilds the underlying socket from the original
   construction parameters. Cold path; allocation is allowed.
"""

from __future__ import annotations

import abc
import errno
import os
import socket
from typing import Optional, Tuple, Union

from ._vlp import FRAME_BYTES
from ._vlp_secure import (
    KEY_BYTES,
    SECURE_MASTER_BYTES,
    SECURE_SHARED_BYTES,
    derive_iv_prefix,
    encode_master,
    encode_shared,
)

__all__ = [
    "BeatTransport",
    "UdsTransport",
    "UdpTransport",
    "SecureUdpTransport",
]


def _closed_socket_error() -> OSError:
    return OSError(errno.EBADF, "transport is closed")


class BeatTransport(abc.ABC):
    """Transport contract for :class:`varta.Varta`.

    Implementations must be non-blocking; the agent layer translates
    :class:`BlockingIOError` and other ``OSError`` subclasses into the
    :class:`varta.BeatOutcome` taxonomy via
    :func:`varta.classify_send_error`.
    """

    @abc.abstractmethod
    def send(self, buf: bytes) -> int:
        """Send the 32-byte frame ``buf`` over the underlying socket.

        Returns ``FRAME_BYTES`` on full logical success. Positive short writes
        are not successful heartbeats; the agent treats any other return value
        as ``Failed(WriteZero)``. Raises ``OSError`` (including
        ``BlockingIOError``) on failure.
        """

    @abc.abstractmethod
    def reconnect(self) -> None:
        """Rebuild the socket without destroying the current one on failure."""

    def close(self) -> None:  # pragma: no cover - default is no-op
        """Best-effort cleanup; subclasses override if they own a socket."""


# ---------------------------------------------------------------------------
# UDS
# ---------------------------------------------------------------------------


def _uds_socket(path: str) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        sock.connect(path)
    except OSError:
        sock.close()
        raise
    return sock


class UdsTransport(BeatTransport):
    """Unix-domain-datagram transport. Default for ``Varta.connect``."""

    __slots__ = ("_path", "_sock")

    def __init__(self, path: Union[str, "os.PathLike[str]"]) -> None:
        self._path = os.fspath(path)
        self._sock: Optional[socket.socket] = _uds_socket(self._path)

    def send(self, buf: bytes) -> int:
        sock = self._sock
        if sock is None:
            raise _closed_socket_error()
        return sock.send(buf)

    def reconnect(self) -> None:
        sock = _uds_socket(self._path)
        old = self._sock
        self._sock = sock
        if old is not None:
            try:
                old.close()
            except OSError:
                pass

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __del__(self) -> None:  # pragma: no cover - GC path
        try:
            self.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------


Address = Tuple[str, int]


def _udp_socket(addr: Address) -> socket.socket:
    family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        sock.bind(("", 0) if family == socket.AF_INET else ("", 0, 0, 0))
        sock.connect(addr)
    except OSError:
        sock.close()
        raise
    return sock


class UdpTransport(BeatTransport):
    """Connected UDP datagram transport (cleartext)."""

    __slots__ = ("_addr", "_sock")

    def __init__(self, addr: Address) -> None:
        self._addr = addr
        self._sock: Optional[socket.socket] = _udp_socket(self._addr)

    def send(self, buf: bytes) -> int:
        sock = self._sock
        if sock is None:
            raise _closed_socket_error()
        return sock.send(buf)

    def reconnect(self) -> None:
        sock = _udp_socket(self._addr)
        old = self._sock
        self._sock = sock
        if old is not None:
            try:
                old.close()
            except OSError:
                pass

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __del__(self) -> None:  # pragma: no cover
        try:
            self.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Secure UDP — ChaCha20-Poly1305 AEAD.
# ---------------------------------------------------------------------------

# A 32-bit AEAD counter exhausts at 2^32. The Rust transport rotates the
# IV prefix when the counter is about to wrap; we mirror that behaviour
# so cross-implementation traces stay aligned.
_AEAD_COUNTER_LIMIT = 0xFFFFFFFF


class SecureUdpTransport(BeatTransport):
    """ChaCha20-Poly1305 AEAD over UDP.

    Two construction modes:

    * **Shared key** — both observer and agent are configured with the
      same 32-byte pre-shared key. Wire frame is 60 bytes.
    * **Master key** — observer holds a master key; agent passes its
      PID to derive a per-agent key via HKDF. Wire frame is 64 bytes
      (4-byte PID prefix is AAD).

    Session IV state (16-byte salt + 8-byte derived prefix + 32-bit
    counter) lives in process memory. Salt is read from :func:`os.urandom`
    at connect time and after any :meth:`reconnect` — the structural
    guarantee against AEAD nonce reuse across ``fork(2)``.
    """

    __slots__ = (
        "_addr",
        "_key",
        "_master_key",
        "_sock",
        "_session_salt",
        "_iv_prefix",
        "_iv_prefix_index",
        "_iv_counter",
    )

    def __init__(
        self,
        addr: Address,
        *,
        key: Optional[bytes] = None,
        master_key: Optional[bytes] = None,
    ) -> None:
        if (key is None) == (master_key is None):
            raise ValueError("provide exactly one of key or master_key")
        if key is not None and len(key) != KEY_BYTES:
            raise ValueError(f"key must be {KEY_BYTES} bytes")
        if master_key is not None and len(master_key) != KEY_BYTES:
            raise ValueError(f"master_key must be {KEY_BYTES} bytes")
        self._addr = addr
        self._key = key
        self._master_key = master_key
        self._sock: Optional[socket.socket] = None
        self._session_salt = b""
        self._iv_prefix = b""
        self._iv_prefix_index = 0
        self._iv_counter = 0
        self._open()

    def _open(self) -> None:
        sock, session_salt, iv_prefix = self._prepare_session()
        self._sock = sock
        self._session_salt = session_salt
        self._iv_prefix = iv_prefix
        self._iv_prefix_index = 0
        self._iv_counter = 0

    def _prepare_session(self) -> Tuple[socket.socket, bytes, bytes]:
        sock = _udp_socket(self._addr)
        try:
            session_salt = os.urandom(16)
            iv_prefix = derive_iv_prefix(session_salt, 0)
        except BaseException:
            try:
                sock.close()
            except OSError:
                pass
            raise
        return sock, session_salt, iv_prefix

    def send(self, buf: bytes) -> int:
        sock = self._sock
        if sock is None:
            raise _closed_socket_error()
        if len(buf) != FRAME_BYTES:
            raise ValueError("secure-UDP transport expects a 32-byte plaintext frame")
        # Compute the nonce-wrap into locals; transport state is mutated only
        # after the kernel accepts the datagram (commit-on-success), so a
        # Dropped send never advances the prefix index or resets the counter.
        # The prior code rotated the prefix BEFORE the syscall, leaving the
        # prefix rotated when a non-blocking send raised BlockingIOError at the
        # wrap boundary (the Python sibling of the Go fix).
        prefix_index = self._iv_prefix_index
        counter = self._iv_counter
        iv_prefix = self._iv_prefix
        if counter >= _AEAD_COUNTER_LIMIT:
            if prefix_index >= _AEAD_COUNTER_LIMIT:
                self.reconnect()
                sock = self._sock
                if sock is None:
                    raise _closed_socket_error()
                prefix_index = self._iv_prefix_index
                counter = self._iv_counter
                iv_prefix = self._iv_prefix
            else:
                prefix_index += 1
                counter = 0
                iv_prefix = derive_iv_prefix(self._session_salt, prefix_index)
        if self._master_key is not None:
            agent_pid = os.getpid() & 0xFFFFFFFF
            wire = encode_master(
                self._master_key, agent_pid, iv_prefix, counter, buf
            )
            assert len(wire) == SECURE_MASTER_BYTES
        else:
            assert self._key is not None
            wire = encode_shared(self._key, iv_prefix, counter, buf)
            assert len(wire) == SECURE_SHARED_BYTES
        sent = sock.send(wire)
        if sent != len(wire):
            return 0
        # Commit-on-success: only advance state after the kernel accepts the
        # full encrypted datagram. A Dropped or short send must not consume a
        # nonce or burn a prefix.
        self._iv_prefix_index = prefix_index
        self._iv_prefix = iv_prefix
        self._iv_counter = counter + 1
        return FRAME_BYTES

    def reconnect(self) -> None:
        sock, session_salt, iv_prefix = self._prepare_session()
        old = self._sock
        self._sock = sock
        self._session_salt = session_salt
        self._iv_prefix = iv_prefix
        self._iv_prefix_index = 0
        self._iv_counter = 0
        if old is not None:
            try:
                old.close()
            except OSError:
                pass

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    # Test hooks (parity with Rust `set_iv_counter_for_test` etc.).
    def _set_iv_counter_for_test(self, value: int) -> None:
        self._iv_counter = value & 0xFFFFFFFF

    def _set_iv_prefix_index_for_test(self, value: int) -> None:
        self._iv_prefix_index = value & 0xFFFFFFFF
        self._iv_prefix = derive_iv_prefix(self._session_salt, self._iv_prefix_index)

    def _iv_prefix_for_test(self) -> bytes:
        return self._iv_prefix

    def _iv_prefix_index_for_test(self) -> int:
        return self._iv_prefix_index

    def _iv_counter_for_test(self) -> int:
        return self._iv_counter

    def __del__(self) -> None:  # pragma: no cover
        try:
            self.close()
        except Exception:
            pass
