"""Python reference implementation of VLP v0.2 base frame.

Non-normative. The authoritative specification is at
`book/src/spec/vlp.md`. This module exists so an external reader can
confirm their understanding of the byte layout against working code
without needing a Rust toolchain.

Requires Python 3.8+. Standard library only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum


MAGIC = b"\x56\x41"  # "VA"
VERSION = 0x02
NONCE_TERMINAL = 0xFFFFFFFFFFFFFFFF


class Status(IntEnum):
    OK = 0
    DEGRADED = 1
    CRITICAL = 2
    STALL = 3  # observer-synthesized only — MUST NOT appear on the wire


STATUS_BY_NAME = {
    "ok": Status.OK,
    "degraded": Status.DEGRADED,
    "critical": Status.CRITICAL,
}


class DecodeError(Exception):
    """Raised on any wire-format validation failure.

    The `kind` attribute is the spec-defined error variant name, which
    matches the strings in `tools/vlp-test-vectors.json`:

        BadMagic, BadVersion, BadCrc, BadStatus, StallOnWire,
        BadPid, BadTimestamp, BadNonce.
    """

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind


# ---------------------------------------------------------------------------
# CRC-32C (Castagnoli)
# ---------------------------------------------------------------------------

_POLY_REFLECTED = 0x82F63B78


def _build_crc_table() -> tuple[int, ...]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ _POLY_REFLECTED if c & 1 else c >> 1
        table.append(c)
    return tuple(table)


_CRC_TABLE = _build_crc_table()


def crc32c(data: bytes) -> int:
    """Compute the CRC-32C (Castagnoli) checksum of *data*.

    Reflected polynomial 0x82F63B78, init 0xFFFFFFFF, refin/refout,
    xorout 0xFFFFFFFF. Matches RFC 3720 appendix B.
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
    status: Status
    pid: int
    timestamp: int
    nonce: int
    payload: int


def encode(
    status: int | str | Status,
    pid: int,
    timestamp: int,
    nonce: int,
    payload: int,
) -> bytes:
    """Encode a single VLP v0.2 frame into 32 bytes."""
    if isinstance(status, str):
        status = STATUS_BY_NAME[status]
    status = Status(status)
    head = struct.pack(
        "<2sBBIQQI",
        MAGIC,
        VERSION,
        int(status),
        pid,
        timestamp,
        nonce,
        payload,
    )
    assert len(head) == 28
    return head + struct.pack("<I", crc32c(head))


def decode(buf: bytes) -> Frame:
    """Decode a 32-byte VLP v0.2 frame.

    Raises ``DecodeError`` on the first failed validation step. See
    `book/src/spec/vlp.md` §5 for the normative decode order.
    """
    if len(buf) != 32:
        raise DecodeError("BadMagic", f"length {len(buf)} != 32")
    if buf[0:2] != MAGIC:
        raise DecodeError("BadMagic", buf[0:2].hex())
    if buf[2] != VERSION:
        raise DecodeError("BadVersion", f"0x{buf[2]:02x}")

    stored_crc, = struct.unpack("<I", buf[28:32])
    computed_crc = crc32c(buf[0:28])
    if stored_crc != computed_crc:
        raise DecodeError("BadCrc", f"expected {computed_crc:08x}, got {stored_crc:08x}")

    status_byte = buf[3]
    if status_byte not in (Status.OK, Status.DEGRADED, Status.CRITICAL, Status.STALL):
        raise DecodeError("BadStatus", f"0x{status_byte:02x}")
    if status_byte == Status.STALL:
        raise DecodeError("StallOnWire")

    pid, = struct.unpack("<I", buf[4:8])
    timestamp, = struct.unpack("<Q", buf[8:16])
    nonce, = struct.unpack("<Q", buf[16:24])
    payload, = struct.unpack("<I", buf[24:28])

    if pid in (0, 1):
        raise DecodeError("BadPid", str(pid))
    if timestamp == 0xFFFFFFFFFFFFFFFF:
        raise DecodeError("BadTimestamp")
    if nonce == NONCE_TERMINAL and status_byte != Status.CRITICAL:
        raise DecodeError("BadNonce", f"nonce=NONCE_TERMINAL paired with status=0x{status_byte:02x}")

    return Frame(
        status=Status(status_byte),
        pid=pid,
        timestamp=timestamp,
        nonce=nonce,
        payload=payload,
    )
