"""VLP v0.2 secure-transport wire encode / decode.

Provides:

* HKDF-SHA256 key derivation (stdlib ``hashlib`` + ``hmac``).
* ChaCha20-Poly1305 shared-key and master-key seal/open. The AEAD
  primitive requires the third-party ``cryptography`` package; importing
  this module without it is fine, but calling any seal/open function
  raises :class:`CryptographyMissingError` with an actionable hint.

The normative spec lives at ``book/src/spec/vlp-secure.md``.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Tuple

__all__ = [
    "SECURE_SHARED_BYTES",
    "SECURE_MASTER_BYTES",
    "KEY_BYTES",
    "IV_RANDOM_BYTES",
    "IV_COUNTER_BYTES",
    "TAG_BYTES",
    "CryptographyMissingError",
    "hkdf_sha256",
    "derive_agent_key",
    "derive_iv_prefix",
    "derive_epoch_key",
    "encode_shared",
    "decode_shared",
    "encode_master",
    "decode_master",
]

SECURE_SHARED_BYTES = 60
SECURE_MASTER_BYTES = 64
KEY_BYTES = 32
IV_RANDOM_BYTES = 8
IV_COUNTER_BYTES = 4
TAG_BYTES = 16


class CryptographyMissingError(ImportError):
    """The ``cryptography`` package is required for AEAD seal/open but is
    not installed. ``pip install 'varta[secure]'`` resolves this.
    """


# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869) — stdlib only.
# ---------------------------------------------------------------------------


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    hash_len = hashlib.sha256().digest_size
    if length > 255 * hash_len:
        raise ValueError("HKDF expand: requested length too large")
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 (extract + expand)."""
    return _hkdf_expand(_hkdf_extract(salt, ikm), info, length)


# ---------------------------------------------------------------------------
# Domain-specific key derivations — book/src/spec/vlp-secure.md §6.
# ---------------------------------------------------------------------------


def derive_agent_key(master_key: bytes, agent_id: int) -> bytes:
    """HKDF-SHA256 derive_agent_key. Returns 32 bytes."""
    if len(master_key) != KEY_BYTES:
        raise ValueError(f"master_key must be {KEY_BYTES} bytes")
    info = b"varta-agent-v1\x00" + struct.pack("<I", agent_id)
    return hkdf_sha256(ikm=master_key, salt=b"", info=info, length=KEY_BYTES)


def derive_iv_prefix(session_salt: bytes, prefix_index: int) -> bytes:
    """HKDF-SHA256 derive_iv_prefix. Returns 8 bytes.

    The Rust reference passes ``None`` (empty salt) to HKDF-Extract; the
    16-byte session salt is the IKM. See ``book/src/spec/vlp-secure.md``
    §6.2 and the cerebrum note dated 2026-05-16.
    """
    if len(session_salt) != 16:
        raise ValueError("session_salt must be 16 bytes")
    info = b"varta-iv-prefix-v1\x00" + struct.pack("<I", prefix_index)
    return hkdf_sha256(ikm=session_salt, salt=b"", info=info, length=IV_RANDOM_BYTES)


def derive_epoch_key(agent_key: bytes, epoch: int) -> bytes:
    """HKDF-SHA256 derive_epoch_key. Returns 32 bytes."""
    if len(agent_key) != KEY_BYTES:
        raise ValueError(f"agent_key must be {KEY_BYTES} bytes")
    info = b"varta-epoch-v1\x00" + struct.pack("<Q", epoch)
    return hkdf_sha256(ikm=agent_key, salt=b"", info=info, length=KEY_BYTES)


# ---------------------------------------------------------------------------
# AEAD wrapping — requires ``cryptography``.
# ---------------------------------------------------------------------------


def _aead_class():  # type: ignore[no-untyped-def]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except ImportError as exc:
        raise CryptographyMissingError(
            "varta secure-UDP transport requires the `cryptography` package; "
            "install with `pip install 'varta[secure]'`"
        ) from exc
    return ChaCha20Poly1305


def _nonce(iv_random: bytes, iv_counter: int) -> bytes:
    return iv_random + struct.pack("<I", iv_counter)


def encode_shared(
    key: bytes, iv_random: bytes, iv_counter: int, plaintext: bytes
) -> bytes:
    """Produce a 60-byte shared-key secure frame."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"key must be {KEY_BYTES} bytes")
    if len(iv_random) != IV_RANDOM_BYTES:
        raise ValueError(f"iv_random must be {IV_RANDOM_BYTES} bytes")
    if len(plaintext) != 32:
        raise ValueError("plaintext must be a 32-byte VLP frame")
    nonce = _nonce(iv_random, iv_counter)
    ct_and_tag = _aead_class()(key).encrypt(nonce, plaintext, associated_data=None)
    return iv_random + struct.pack("<I", iv_counter) + ct_and_tag


def decode_shared(key: bytes, wire: bytes) -> bytes:
    """Recover the 32-byte plaintext from a 60-byte shared-key wire frame."""
    if len(wire) != SECURE_SHARED_BYTES:
        raise ValueError(f"wire must be {SECURE_SHARED_BYTES} bytes")
    iv_random = wire[0:8]
    (iv_counter,) = struct.unpack("<I", wire[8:12])
    ct_and_tag = wire[12:60]
    nonce = _nonce(iv_random, iv_counter)
    return _aead_class()(key).decrypt(nonce, ct_and_tag, associated_data=None)


def encode_master(
    master_key: bytes,
    agent_pid: int,
    iv_random: bytes,
    iv_counter: int,
    plaintext: bytes,
) -> bytes:
    """Produce a 64-byte master-key secure frame."""
    if len(master_key) != KEY_BYTES:
        raise ValueError(f"master_key must be {KEY_BYTES} bytes")
    if len(iv_random) != IV_RANDOM_BYTES:
        raise ValueError(f"iv_random must be {IV_RANDOM_BYTES} bytes")
    if len(plaintext) != 32:
        raise ValueError("plaintext must be a 32-byte VLP frame")
    agent_key = derive_agent_key(master_key, agent_pid)
    aad = struct.pack("<I", agent_pid)
    nonce = _nonce(iv_random, iv_counter)
    ct_and_tag = _aead_class()(agent_key).encrypt(nonce, plaintext, associated_data=aad)
    return aad + iv_random + struct.pack("<I", iv_counter) + ct_and_tag


def decode_master(master_key: bytes, wire: bytes) -> bytes:
    """Recover the 32-byte plaintext from a 64-byte master-key wire frame."""
    if len(wire) != SECURE_MASTER_BYTES:
        raise ValueError(f"wire must be {SECURE_MASTER_BYTES} bytes")
    aad = wire[0:4]
    (agent_pid,) = struct.unpack("<I", aad)
    iv_random = wire[4:12]
    (iv_counter,) = struct.unpack("<I", wire[12:16])
    ct_and_tag = wire[16:64]
    agent_key = derive_agent_key(master_key, agent_pid)
    nonce = _nonce(iv_random, iv_counter)
    return _aead_class()(agent_key).decrypt(nonce, ct_and_tag, associated_data=aad)


def derive_session_iv_prefix(session_salt: bytes, prefix_index: int) -> Tuple[bytes, int]:
    """Convenience wrapper returning (iv_prefix, prefix_index).

    Kept for symmetry with the Rust transport API; callers usually want
    :func:`derive_iv_prefix` directly.
    """
    return derive_iv_prefix(session_salt, prefix_index), prefix_index
