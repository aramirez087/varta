"""Transport abstraction for the Varta agent.

The :class:`BeatTransport` ABC mirrors the Rust trait of the same name
(`crates/varta-client/src/transport.rs`). Concrete implementations:

* :class:`UdsTransport` — Unix domain datagram socket.
* :class:`UdpTransport` — connected UDP socket.
* :class:`SecureUdpTransport` — UDP + ChaCha20-Poly1305 AEAD (requires
  ``cryptography``; raises :class:`CryptographyMissingError` on use).

Every transport must guarantee:

1. Non-blocking I/O at construction (``setblocking(False)``).
2. ``send(buf)`` accepts a 32-byte ``bytes``-like and raises ``OSError``
   on kernel-level failure.
3. ``reconnect()`` rebuilds the underlying socket from the original
   construction parameters. Cold path; allocation is allowed.
"""

from __future__ import annotations

import abc
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

        Returns the number of bytes the kernel accepted. Raises
        ``OSError`` (including ``BlockingIOError``) on failure.
        """

    @abc.abstractmethod
    def reconnect(self) -> None:
        """Rebuild the underlying socket. Cold path; allocation OK."""

    def close(self) -> None:  # pragma: no cover - default is no-op
        """Best-effort cleanup; subclasses override if they own a socket."""


# ---------------------------------------------------------------------------
# UDS
# ---------------------------------------------------------------------------


class UdsTransport(BeatTransport):
    """Unix-domain-datagram transport. Default for ``Varta.connect``."""

    __slots__ = ("_path", "_sock")

    def __init__(self, path: Union[str, "os.PathLike[str]"]) -> None:
        self._path = os.fspath(path)
        self._sock: Optional[socket.socket] = None
        self._open()

    def _open(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.setblocking(False)
            sock.connect(self._path)
        except OSError:
            sock.close()
            raise
        self._sock = sock

    def send(self, buf: bytes) -> int:
        assert self._sock is not None
        return self._sock.send(buf)

    def reconnect(self) -> None:
        self.close()
        self._open()

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
        self._sock: Optional[socket.socket] = None
        self._open()

    def _open(self) -> None:
        self._sock = _udp_socket(self._addr)

    def send(self, buf: bytes) -> int:
        assert self._sock is not None
        return self._sock.send(buf)

    def reconnect(self) -> None:
        self.close()
        self._open()

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
        self._sock = _udp_socket(self._addr)
        self._session_salt = os.urandom(16)
        self._iv_prefix_index = 0
        self._iv_counter = 0
        self._iv_prefix = derive_iv_prefix(self._session_salt, self._iv_prefix_index)

    def _rotate_prefix(self) -> None:
        self._iv_prefix_index += 1
        self._iv_counter = 0
        self._iv_prefix = derive_iv_prefix(self._session_salt, self._iv_prefix_index)

    def send(self, buf: bytes) -> int:
        assert self._sock is not None
        if len(buf) != FRAME_BYTES:
            raise ValueError("secure-UDP transport expects a 32-byte plaintext frame")
        if self._iv_counter >= _AEAD_COUNTER_LIMIT:
            # Cold path: rotate the prefix BEFORE the syscall so a Dropped
            # send does not advance the counter past its wrap boundary.
            self._rotate_prefix()
        counter = self._iv_counter
        if self._master_key is not None:
            agent_pid = os.getpid() & 0xFFFFFFFF
            wire = encode_master(
                self._master_key, agent_pid, self._iv_prefix, counter, buf
            )
            assert len(wire) == SECURE_MASTER_BYTES
        else:
            assert self._key is not None
            wire = encode_shared(self._key, self._iv_prefix, counter, buf)
            assert len(wire) == SECURE_SHARED_BYTES
        sent = self._sock.send(wire)
        # Commit-on-success: only advance the counter after the kernel
        # accepts the datagram. A Dropped send must not consume a nonce.
        self._iv_counter = counter + 1
        return sent

    def reconnect(self) -> None:
        self.close()
        self._open()

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    # Test hooks (parity with Rust `set_iv_counter_for_test` etc.).
    def _set_iv_counter_for_test(self, value: int) -> None:
        self._iv_counter = value & 0xFFFFFFFF

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
