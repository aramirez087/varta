"""VLP v0.2 wire encode / decode + CRC-32C.

The normative wire specification lives at ``book/src/spec/vlp.md``. This
module is the canonical Python implementation that the production
:class:`varta.Varta` client builds on top of. The verifier-grade twin
at ``tools/reference-implementations/python/vlp.py`` is kept in step but
exists for a different stability contract (pinned to the spec version,
not to this package's semver).

Standard library only. Python 3.8+.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Tuple, Union

__all__ = [
    "MAGIC",
    "VERSION",
    "NONCE_TERMINAL",
    "FRAME_BYTES",
    "Status",
    "DecodeError",
    "Frame",
    "crc32c",
    "encode",
    "encode_into",
    "decode",
]

MAGIC: bytes = b"\x56\x41"  # "VA"
VERSION: int = 0x02
NONCE_TERMINAL: int = 0xFFFFFFFFFFFFFFFF
FRAME_BYTES: int = 32


class Status(IntEnum):
    """Beat status — matches the 1-byte wire value at offset 3.

    ``STALL`` is observer-synthesized; agents MUST NOT emit it on the wire.
    :class:`DecodeError` with ``kind="StallOnWire"`` is raised if it appears.
    """

    OK = 0
    DEGRADED = 1
    CRITICAL = 2
    STALL = 3


_STATUS_BY_NAME = {
    "ok": Status.OK,
    "degraded": Status.DEGRADED,
    "critical": Status.CRITICAL,
    "stall": Status.STALL,
}


StatusLike = Union[Status, int, str]


class DecodeError(Exception):
    """Raised on any wire-format validation failure.

    The ``kind`` attribute is the spec-defined error variant name, which
    matches the strings in ``tools/vlp-test-vectors.json``:

        BadMagic, BadVersion, BadCrc, BadStatus, StallOnWire,
        BadPid, BadTimestamp, BadNonce.
    """

    __slots__ = ("kind",)

    def __init__(self, kind: str, detail: str = "") -> None:
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind


# ---------------------------------------------------------------------------
# CRC-32C (Castagnoli) — RFC 3720 appendix B.
# ---------------------------------------------------------------------------

_POLY_REFLECTED = 0x82F63B78


def _build_crc_table() -> Tuple[int, ...]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ _POLY_REFLECTED if c & 1 else c >> 1
        table.append(c)
    return tuple(table)


_CRC_TABLE: Tuple[int, ...] = _build_crc_table()


def crc32c(data: bytes) -> int:
    """Compute the CRC-32C (Castagnoli) checksum of ``data``.

    Reflected polynomial 0x82F63B78, init 0xFFFFFFFF, refin/refout,
    xorout 0xFFFFFFFF. Matches RFC 3720 appendix B and the canonical
    Rust implementation at ``crates/varta-vlp/src/crc32c.rs``.
    """
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Frame
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Frame:
    """Decoded view of a 32-byte VLP v0.2 frame."""

    status: Status
    pid: int
    timestamp: int
    nonce: int
    payload: int


def _coerce_status(status: StatusLike) -> Status:
    if isinstance(status, str):
        try:
            return _STATUS_BY_NAME[status.lower()]
        except KeyError as exc:
            raise ValueError(f"unknown status name: {status!r}") from exc
    return Status(status)


def encode(
    status: StatusLike,
    pid: int,
    timestamp: int,
    nonce: int,
    payload: int,
) -> bytes:
    """Encode a single VLP v0.2 frame into a fresh ``bytes`` of length 32.

    The hot path of the production client uses :func:`encode_into` against
    a pre-allocated scratch buffer to keep per-beat allocation minimal.
    """
    buf = bytearray(FRAME_BYTES)
    encode_into(buf, status, pid, timestamp, nonce, payload)
    return bytes(buf)


def encode_into(
    buf: bytearray,
    status: StatusLike,
    pid: int,
    timestamp: int,
    nonce: int,
    payload: int,
) -> None:
    """Encode a single VLP v0.2 frame into ``buf`` (must be ``len == 32``).

    Reuses the caller's buffer so steady-state beats avoid allocating a
    fresh frame object per emission. Python cannot match the Rust client's
    zero-heap guarantee — :mod:`struct` returns new ``bytes`` internally —
    but reusing the destination buffer at least eliminates the wrapper
    allocation.
    """
    if len(buf) != FRAME_BYTES:
        raise ValueError(f"buffer must be exactly {FRAME_BYTES} bytes")
    status_int = int(_coerce_status(status))
    struct.pack_into(
        "<2sBBIQQI",
        buf,
        0,
        MAGIC,
        VERSION,
        status_int,
        pid,
        timestamp,
        nonce,
        payload,
    )
    struct.pack_into("<I", buf, 28, crc32c(bytes(buf[:28])))


def decode(buf: bytes) -> Frame:
    """Decode a 32-byte VLP v0.2 frame.

    Raises :class:`DecodeError` on the first failed validation step. See
    ``book/src/spec/vlp.md`` §5 for the normative decode order:
    magic → version → CRC → status (incl. Stall rejection) → pid →
    timestamp → nonce.
    """
    if len(buf) != FRAME_BYTES:
        raise DecodeError("BadMagic", f"length {len(buf)} != {FRAME_BYTES}")
    if buf[0:2] != MAGIC:
        raise DecodeError("BadMagic", buf[0:2].hex())
    if buf[2] != VERSION:
        raise DecodeError("BadVersion", f"0x{buf[2]:02x}")

    (stored_crc,) = struct.unpack("<I", buf[28:32])
    computed_crc = crc32c(buf[0:28])
    if stored_crc != computed_crc:
        raise DecodeError(
            "BadCrc", f"expected {computed_crc:08x}, got {stored_crc:08x}"
        )

    status_byte = buf[3]
    if status_byte not in (Status.OK, Status.DEGRADED, Status.CRITICAL, Status.STALL):
        raise DecodeError("BadStatus", f"0x{status_byte:02x}")
    if status_byte == Status.STALL:
        raise DecodeError("StallOnWire")

    (pid,) = struct.unpack("<I", buf[4:8])
    (timestamp,) = struct.unpack("<Q", buf[8:16])
    (nonce,) = struct.unpack("<Q", buf[16:24])
    (payload,) = struct.unpack("<I", buf[24:28])

    if pid in (0, 1):
        raise DecodeError("BadPid", str(pid))
    if timestamp == 0xFFFFFFFFFFFFFFFF:
        raise DecodeError("BadTimestamp")
    if nonce == NONCE_TERMINAL and status_byte != Status.CRITICAL:
        raise DecodeError(
            "BadNonce",
            f"nonce=NONCE_TERMINAL paired with status=0x{status_byte:02x}",
        )

    return Frame(
        status=Status(status_byte),
        pid=pid,
        timestamp=timestamp,
        nonce=nonce,
        payload=payload,
    )
