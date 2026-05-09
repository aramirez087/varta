"""Secure-transport reference for VLP v0.2.

Implements:

* HKDF-SHA256 key derivation (stdlib `hashlib` + `hmac` — no third-party deps).
* ChaCha20-Poly1305 shared-key and master-key seal/open (requires the
  third-party ``cryptography`` package — install via ``pip install cryptography``).

Non-normative. See `book/src/spec/vlp-secure.md` for the authoritative
spec.
"""

from __future__ import annotations

import hashlib
import hmac
import struct


# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869)
# ---------------------------------------------------------------------------


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
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
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# ---------------------------------------------------------------------------
# Domain-specific key derivations (mirror book/src/spec/vlp-secure.md §6).
# ---------------------------------------------------------------------------


def derive_agent_key(master_key: bytes, agent_id: int) -> bytes:
    """HKDF-SHA256 derive_agent_key. Returns 32 bytes."""
    assert len(master_key) == 32
    info = b"varta-agent-v1\x00" + struct.pack("<I", agent_id)
    assert len(info) == 19, "info string length should be 15 + 4 = 19"
    return hkdf_sha256(ikm=master_key, salt=b"", info=info, length=32)


def derive_iv_prefix(session_salt: bytes, prefix_index: int) -> bytes:
    """HKDF-SHA256 derive_iv_prefix. Returns 8 bytes.

    The Rust reference passes ``None`` (empty salt) to HKDF-Extract; the
    16-byte session salt is the IKM. See `book/src/spec/vlp-secure.md` §6.2.
    """
    assert len(session_salt) == 16
    info = b"varta-iv-prefix-v1\x00" + struct.pack("<I", prefix_index)
    assert len(info) == 23
    return hkdf_sha256(ikm=session_salt, salt=b"", info=info, length=8)


def derive_epoch_key(agent_key: bytes, epoch: int) -> bytes:
    """HKDF-SHA256 derive_epoch_key. Returns 32 bytes."""
    assert len(agent_key) == 32
    info = b"varta-epoch-v1\x00" + struct.pack("<Q", epoch)
    assert len(info) == 23
    return hkdf_sha256(ikm=agent_key, salt=b"", info=info, length=32)


# ---------------------------------------------------------------------------
# AEAD wrapping (requires ``cryptography``).
# ---------------------------------------------------------------------------


def _aead():
    """Lazy import so the base-frame Python ref does not require pip deps."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    return ChaCha20Poly1305


def encode_shared(key: bytes, iv_random: bytes, iv_counter: int, plaintext: bytes) -> bytes:
    """Produce a 60-byte shared-key secure frame."""
    assert len(key) == 32 and len(iv_random) == 8 and len(plaintext) == 32
    nonce = iv_random + struct.pack("<I", iv_counter)
    ct_and_tag = _aead()(key).encrypt(nonce, plaintext, associated_data=None)
    return iv_random + struct.pack("<I", iv_counter) + ct_and_tag


def decode_shared(key: bytes, wire: bytes) -> bytes:
    """Recover the 32-byte plaintext frame from a 60-byte shared-key wire frame."""
    assert len(wire) == 60
    iv_random = wire[0:8]
    iv_counter = struct.unpack("<I", wire[8:12])[0]
    ct_and_tag = wire[12:60]
    nonce = iv_random + struct.pack("<I", iv_counter)
    return _aead()(key).decrypt(nonce, ct_and_tag, associated_data=None)


def encode_master(master_key: bytes, agent_pid: int, iv_random: bytes,
                  iv_counter: int, plaintext: bytes) -> bytes:
    """Produce a 64-byte master-key secure frame."""
    assert len(master_key) == 32 and len(iv_random) == 8 and len(plaintext) == 32
    agent_key = derive_agent_key(master_key, agent_pid)
    aad = struct.pack("<I", agent_pid)
    nonce = iv_random + struct.pack("<I", iv_counter)
    ct_and_tag = _aead()(agent_key).encrypt(nonce, plaintext, associated_data=aad)
    return aad + iv_random + struct.pack("<I", iv_counter) + ct_and_tag


def decode_master(master_key: bytes, wire: bytes) -> bytes:
    """Recover the 32-byte plaintext from a 64-byte master-key wire frame."""
    assert len(wire) == 64
    aad = wire[0:4]
    agent_pid = struct.unpack("<I", aad)[0]
    iv_random = wire[4:12]
    iv_counter = struct.unpack("<I", wire[12:16])[0]
    ct_and_tag = wire[16:64]
    agent_key = derive_agent_key(master_key, agent_pid)
    nonce = iv_random + struct.pack("<I", iv_counter)
    return _aead()(agent_key).decrypt(nonce, ct_and_tag, associated_data=aad)
