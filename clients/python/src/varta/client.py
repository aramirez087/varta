"""Agent surface — :class:`Varta` connects to the observer and emits
fire-and-forget 32-byte VLP frames.

The semantics mirror the Rust reference at
``crates/varta-client/src/client.rs``. Python cannot match the Rust
zero-heap guarantee on the beat path (``struct.pack_into`` writes to a
pre-allocated buffer but the surrounding method call still allocates
small Python objects); the rest of the contract — non-blocking I/O,
per-emission ``os.getpid()``, fork auto-recovery, four-way ``Dropped``
taxonomy — is preserved.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Optional, Union

from ._errno import (
    EAGAIN,
    ECONNREFUSED,
    ECONNRESET,
    ENOBUFS,
    ENOENT,
    ENOSPC,
    ENOTCONN,
    EPIPE,
    EWOULDBLOCK,
)
from ._transport import (
    Address,
    BeatTransport,
    SecureUdpTransport,
    UdpTransport,
    UdsTransport,
)
from ._vlp import (
    FRAME_BYTES,
    NONCE_TERMINAL,
    StatusLike,
    encode_into,
)

__all__ = [
    "Varta",
    "BeatOutcome",
    "DropReason",
    "BeatError",
    "classify_send_error",
]


# ---------------------------------------------------------------------------
# BeatOutcome / DropReason / BeatError
# ---------------------------------------------------------------------------


class DropReason(str, Enum):
    """Reason a :class:`BeatOutcome` was classified as ``Dropped``.

    String-valued so the wire-side metrics label matches the Rust
    ``Display`` impl directly.
    """

    KERNEL_QUEUE_FULL = "kernel queue full"
    NO_OBSERVER = "no observer"
    PEER_GONE = "peer gone"
    STORAGE_FULL = "storage full"


@dataclass(frozen=True)
class BeatError:
    """Payload of ``BeatOutcome.failed``.

    Carries the underlying ``OSError.errno`` and the symbolic error name
    so callers can log without re-raising. Returns to a full ``OSError``
    via :meth:`to_oserror`.
    """

    errno: int
    kind: str  # e.g. "ENOENT", "EPERM", or "Other" when no symbolic name is known

    UNKNOWN_ERRNO: ClassVar[int] = 0

    def to_oserror(self) -> OSError:
        return OSError(self.errno, os.strerror(self.errno) if self.errno else self.kind)

    @classmethod
    def from_oserror(cls, exc: OSError) -> "BeatError":
        return cls(
            errno=exc.errno or cls.UNKNOWN_ERRNO,
            kind=_errno_name(exc.errno) if exc.errno else type(exc).__name__,
        )


_BEAT_OUTCOME_SENT = "sent"
_BEAT_OUTCOME_DROPPED = "dropped"
_BEAT_OUTCOME_FAILED = "failed"


@dataclass(frozen=True)
class BeatOutcome:
    """Result of a single :meth:`Varta.beat` call.

    Modeled as a tagged dataclass because Python lacks Rust's algebraic
    enums. Use the :meth:`sent`, :meth:`dropped`, and :meth:`failed`
    constructors; pattern-match via the ``kind`` field or the boolean
    convenience properties.
    """

    kind: str  # one of "sent", "dropped", "failed"
    reason: Optional[DropReason] = None
    error: Optional[BeatError] = None

    @classmethod
    def sent(cls) -> "BeatOutcome":
        return cls(_BEAT_OUTCOME_SENT)

    @classmethod
    def dropped(cls, reason: DropReason) -> "BeatOutcome":
        return cls(_BEAT_OUTCOME_DROPPED, reason=reason)

    @classmethod
    def failed(cls, error: BeatError) -> "BeatOutcome":
        return cls(_BEAT_OUTCOME_FAILED, error=error)

    @property
    def is_sent(self) -> bool:
        return self.kind == _BEAT_OUTCOME_SENT

    @property
    def is_dropped(self) -> bool:
        return self.kind == _BEAT_OUTCOME_DROPPED

    @property
    def is_failed(self) -> bool:
        return self.kind == _BEAT_OUTCOME_FAILED

    def __str__(self) -> str:
        if self.is_sent:
            return "sent"
        if self.is_dropped:
            assert self.reason is not None
            return f"dropped: {self.reason.value}"
        assert self.error is not None
        return f"failed: errno={self.error.errno} kind={self.error.kind}"


def _errno_name(code: Optional[int]) -> str:
    if code is None:
        return "Unknown"
    import errno as _errno_module

    for name in dir(_errno_module):
        if not name.startswith("E"):
            continue
        if getattr(_errno_module, name) == code:
            return name
    return f"errno_{code}"


def classify_send_error(exc: OSError) -> BeatOutcome:
    """Translate a ``socket.send`` ``OSError`` into a :class:`BeatOutcome`.

    Mirrors ``crates/varta-client/src/client.rs::classify_send_error``:

    1. Raw errno match against the platform-specific ``ENOBUFS`` constant.
    2. Symbolic mapping for ``EAGAIN`` / ``EWOULDBLOCK`` (kernel queue
       full), ``ECONNREFUSED``/``ENOENT`` (no observer),
       ``ECONNRESET``/``ENOTCONN``/``EPIPE`` (peer gone), and
       ``ENOSPC`` (storage full).
    3. Anything else surfaces as :meth:`BeatOutcome.failed`.

    Exported because authors of custom :class:`BeatTransport`
    implementations are likely to want the same bucketing.
    """
    code = exc.errno
    if code == ENOBUFS:
        return BeatOutcome.dropped(DropReason.KERNEL_QUEUE_FULL)
    if isinstance(exc, BlockingIOError) or code in (EAGAIN, EWOULDBLOCK):
        return BeatOutcome.dropped(DropReason.KERNEL_QUEUE_FULL)
    if code in (ECONNREFUSED, ENOENT):
        return BeatOutcome.dropped(DropReason.NO_OBSERVER)
    if code in (ECONNRESET, ENOTCONN, EPIPE):
        return BeatOutcome.dropped(DropReason.PEER_GONE)
    if code == ENOSPC:
        return BeatOutcome.dropped(DropReason.STORAGE_FULL)
    return BeatOutcome.failed(BeatError.from_oserror(exc))


# ---------------------------------------------------------------------------
# Varta agent
# ---------------------------------------------------------------------------


def _monotonic_ns() -> int:
    # Indirection so unit tests can monkeypatch the clock without touching
    # ``time.monotonic_ns`` globally.
    return time.monotonic_ns()


_U64_MAX = 0xFFFFFFFFFFFFFFFF


class Varta:
    """Agent-side handle that owns a :class:`BeatTransport` and a 32-byte
    scratch buffer.

    Construct via the classmethods :meth:`connect`, :meth:`connect_udp`,
    :meth:`connect_secure_udp`, or :meth:`connect_secure_udp_with_master`.
    Every subsequent :meth:`beat` reuses the scratch buffer.
    """

    __slots__ = (
        "_transport",
        "_buf",
        "_start_ns",
        "_nonce",
        "_consecutive_dropped",
        "_reconnect_after",
        "_last_timestamp",
        "_clock_regressions",
        "_connect_pid",
        "_fork_recoveries",
    )

    def __init__(self, transport: BeatTransport) -> None:
        self._transport = transport
        self._buf = bytearray(FRAME_BYTES)
        self._start_ns = _monotonic_ns()
        self._nonce = 0
        self._consecutive_dropped = 0
        self._reconnect_after = 0
        self._last_timestamp = 0
        self._clock_regressions = 0
        self._connect_pid = os.getpid()
        self._fork_recoveries = 0

    # --- constructors ---------------------------------------------------

    @classmethod
    def connect(cls, path: Union[str, "os.PathLike[str]"]) -> "Varta":
        """Connect to the observer's UDS at ``path``. Returns a ready agent."""
        return cls(UdsTransport(path))

    @classmethod
    def connect_udp(cls, addr: Address) -> "Varta":
        """Connect to the observer over plaintext UDP."""
        return cls(UdpTransport(addr))

    @classmethod
    def connect_secure_udp(cls, addr: Address, key: bytes) -> "Varta":
        """Connect to the observer over ChaCha20-Poly1305 AEAD over UDP.

        Raises :class:`varta._vlp_secure.CryptographyMissingError` if the
        ``cryptography`` package is not installed.
        """
        return cls(SecureUdpTransport(addr, key=key))

    @classmethod
    def connect_secure_udp_with_master(
        cls, addr: Address, master_key: bytes
    ) -> "Varta":
        """Connect using a master key; per-agent key is HKDF-derived."""
        return cls(SecureUdpTransport(addr, master_key=master_key))

    # --- public API -----------------------------------------------------

    def beat(self, status: StatusLike, payload: int = 0) -> BeatOutcome:
        """Emit one VLP frame and return the outcome.

        Detects ``fork(2)`` by comparing the current PID to the
        connect-time snapshot. On mismatch, refreshes the transport
        (re-reading OS entropy for secure-UDP) BEFORE the frame is built.
        See ``crates/varta-client/src/client.rs:514-593`` for the
        canonical reference.
        """
        pid = os.getpid()
        if pid != self._connect_pid:
            try:
                self._transport.reconnect()
            except OSError as exc:
                return BeatOutcome.failed(BeatError.from_oserror(exc))
            self._connect_pid = pid
            self._fork_recoveries = _saturating_add(self._fork_recoveries, 1)
            self._nonce = 0
            self._start_ns = _monotonic_ns()
            self._last_timestamp = 0
            self._consecutive_dropped = 0

        if self._nonce < NONCE_TERMINAL - 1:
            self._nonce += 1
        else:
            _warn_nonce_wrapping()
            self._nonce = 0

        raw_elapsed = max(0, _monotonic_ns() - self._start_ns)
        if raw_elapsed > _U64_MAX:
            raw_elapsed = _U64_MAX
        if raw_elapsed < self._last_timestamp:
            self._clock_regressions = _saturating_add(self._clock_regressions, 1)
        self._last_timestamp = max(self._last_timestamp, raw_elapsed)
        timestamp = self._last_timestamp

        encode_into(
            self._buf,
            status,
            pid & 0xFFFFFFFF,
            timestamp,
            self._nonce,
            payload & 0xFFFFFFFF,
        )

        outcome = self._send_frame()
        if outcome.is_dropped:
            self._consecutive_dropped = _saturating_add(self._consecutive_dropped, 1)
            if (
                self._reconnect_after > 0
                and self._consecutive_dropped >= self._reconnect_after
            ):
                try:
                    self._transport.reconnect()
                except OSError:
                    # Failed reconnect leaves the counter saturated so the
                    # next Dropped beat re-crosses the threshold and retries
                    # immediately, rather than re-arming a full
                    # reconnect_after-beat window.
                    return outcome
                # Reset only on a successful reconnect.
                self._consecutive_dropped = 0
                return self._send_frame()
            return outcome

        self._consecutive_dropped = 0
        return outcome

    def reconnect(self) -> None:
        """Explicitly rebuild the transport. Use after observer restarts."""
        self._transport.reconnect()
        self._connect_pid = os.getpid()

    def set_reconnect_after(self, n: Optional[int]) -> None:
        """Auto-reconnect after ``n`` consecutive ``Dropped`` outcomes.

        ``None`` or ``0`` disables auto-reconnect (the default).
        """
        self._reconnect_after = int(n) if n else 0
        self._consecutive_dropped = 0

    def clock_regressions(self) -> int:
        """Saturating count of platform-clock regressions observed.

        Suggested Prometheus label: ``varta_client_clock_regression_total``.
        """
        return self._clock_regressions

    def fork_recoveries(self) -> int:
        """Saturating count of fork auto-recovery events.

        Suggested Prometheus label: ``varta_client_fork_recoveries_total``.
        """
        return self._fork_recoveries

    def close(self) -> None:
        self._transport.close()

    def __enter__(self) -> "Varta":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- internal -------------------------------------------------------

    def _send_frame(self) -> BeatOutcome:
        try:
            self._transport.send(bytes(self._buf))
            return BeatOutcome.sent()
        except OSError as exc:
            return classify_send_error(exc)

    # Test hooks (parity with the Rust `set_connect_pid_for_test` and
    # friends). Underscore-prefixed so they do not appear in public dir().
    def _set_connect_pid_for_test(self, pid: int) -> None:
        self._connect_pid = int(pid)

    def _set_nonce_for_test(self, value: int) -> None:
        self._nonce = int(value)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _saturating_add(value: int, delta: int) -> int:
    new_value = value + delta
    if new_value > _U64_MAX:
        return _U64_MAX
    return new_value


_NONCE_WRAP_WARNED = False


def _warn_nonce_wrapping() -> None:
    global _NONCE_WRAP_WARNED
    if _NONCE_WRAP_WARNED:
        return
    _NONCE_WRAP_WARNED = True
    try:
        sys.stderr.write("[varta] nonce exhausted; wrapping to 0\n")
    except Exception:  # pragma: no cover
        pass
