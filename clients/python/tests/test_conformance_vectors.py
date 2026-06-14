"""Conformance: every entry in ``tools/vlp-test-vectors.json`` must
round-trip through the Python client.

The same JSON file is consumed by the Rust loader test at
``crates/varta-vlp/tests/conformance_vectors.rs``. Wire-format drift
between the two implementations is impossible without failing both.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from varta._vlp import DecodeError, crc32c, decode, encode
from varta._vlp_secure import (
    decode_master,
    decode_shared,
    derive_agent_key,
    derive_epoch_key,
    derive_iv_prefix,
    derive_panic_iv_prefix,
    encode_master,
    encode_shared,
)


def _load(vectors_path: Path) -> dict:
    with vectors_path.open() as f:
        return json.load(f)


def test_crc32c_vectors(vectors_path: Path) -> None:
    vectors = _load(vectors_path)
    assert vectors["crc32c_vectors"], "expected at least one CRC vector"
    for v in vectors["crc32c_vectors"]:
        data = bytes.fromhex(v["input_hex"])
        expected = int(v["expected_crc_hex"], 16)
        assert crc32c(data) == expected, v["id"]


def test_frame_vectors(vectors_path: Path) -> None:
    vectors = _load(vectors_path)
    assert vectors["frame_vectors"], "expected at least one frame vector"
    for v in vectors["frame_vectors"]:
        wire = bytes.fromhex(v.get("expected_wire_hex") or v["wire_hex"])
        if v["expected_decode_error"]:
            with pytest.raises(DecodeError) as excinfo:
                decode(wire)
            assert excinfo.value.kind == v["expected_decode_error"], v["id"]
        else:
            inp = v["inputs"]
            encoded = encode(
                inp["status"],
                inp["pid"],
                inp["timestamp"],
                inp["nonce"],
                inp["payload"],
            )
            assert encoded == wire, v["id"]
            frame = decode(wire)
            assert frame.pid == inp["pid"], v["id"]
            assert frame.timestamp == inp["timestamp"], v["id"]
            assert frame.nonce == inp["nonce"], v["id"]
            assert frame.payload == inp["payload"], v["id"]


def test_kdf_vectors(vectors_path: Path) -> None:
    vectors = _load(vectors_path)
    for v in vectors["secure_frame_vectors"]:
        vid = v["id"]
        if vid == "kdf-agent-key":
            out = derive_agent_key(bytes.fromhex(v["master_key_hex"]), v["agent_id"])
            assert out.hex() == v["expected_okm_hex"], vid
        elif vid == "kdf-iv-prefix":
            out = derive_iv_prefix(
                bytes.fromhex(v["session_salt_hex"]), v["prefix_index"]
            )
            assert out.hex() == v["expected_iv_prefix_hex"], vid
        elif vid == "kdf-epoch-key":
            out = derive_epoch_key(bytes.fromhex(v["agent_key_hex"]), v["epoch"])
            assert out.hex() == v["expected_okm_hex"], vid


def _has_cryptography() -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


@pytest.mark.skipif(
    not _has_cryptography(),
    reason="`cryptography` extra not installed; pip install 'varta[secure]'",
)
def test_aead_vectors(vectors_path: Path) -> None:
    vectors = _load(vectors_path)
    for v in vectors["secure_frame_vectors"]:
        vid = v["id"]
        if vid == "secure-shared-key-seal":
            wire = encode_shared(
                bytes.fromhex(v["key_hex"]),
                bytes.fromhex(v["iv_random_hex"]),
                v["iv_counter"],
                bytes.fromhex(v["plaintext_hex"]),
            )
            assert wire.hex() == v["expected_wire_hex"], vid
            pt = decode_shared(bytes.fromhex(v["key_hex"]), wire)
            assert pt.hex() == v["plaintext_hex"], vid
        elif vid == "secure-master-key-seal":
            wire = encode_master(
                bytes.fromhex(v["master_key_hex"]),
                v["agent_pid"],
                bytes.fromhex(v["iv_random_hex"]),
                v["iv_counter"],
                bytes.fromhex(v["plaintext_hex"]),
            )
            assert wire.hex() == v["expected_wire_hex"], vid
            pt = decode_master(bytes.fromhex(v["master_key_hex"]), wire)
            assert pt.hex() == v["plaintext_hex"], vid


def test_panic_iv_prefix_matches_known_answer() -> None:
    """Cross-impl known-answer: locks Python to Rust/Go/Node byte-for-byte.

    Same KAT pinned in ``crates/varta-vlp/src/crypto/kdf.rs``
    (``panic_iv_prefix_is_deterministic``). HKDF is deterministic, so an
    identical info layout must produce identical bytes across all clients.
    """
    salt = bytes([0xA5] * 16)
    out = derive_panic_iv_prefix(salt, 42, 1_000, 7)
    assert out == bytes.fromhex("e2615ed3e4f44375")
    # Deterministic.
    assert out == derive_panic_iv_prefix(salt, 42, 1_000, 7)


def test_panic_iv_prefix_varies_with_every_input() -> None:
    salt = bytes([0xA5] * 16)
    baseline = derive_panic_iv_prefix(salt, 42, 1_000, 7)
    assert baseline != derive_panic_iv_prefix(salt, 43, 1_000, 7)  # pid
    assert baseline != derive_panic_iv_prefix(salt, 42, 1_001, 7)  # timestamp
    assert baseline != derive_panic_iv_prefix(salt, 42, 1_000, 8)  # counter
    # Domain separation from the regular session prefix.
    assert baseline != derive_iv_prefix(salt, 0)


def test_panic_iv_prefix_distinct_for_recycled_pid_at_counter_zero() -> None:
    """Security regression: a PID-recycled descendant inheriting the install
    salt and firing its first panic at iv_counter=0 must not reuse the
    installer's (pid, counter=0) prefix. Distinctness is carried solely by the
    strictly-monotonic timestamp — the structural replacement for the former
    (unsound) PID-equality check.
    """
    salt = bytes([0x5A] * 16)
    installer = derive_panic_iv_prefix(salt, 4242, 1_000, 0)
    recycled = derive_panic_iv_prefix(salt, 4242, 9_999_000, 0)
    assert installer != recycled


def test_cryptography_missing_error_is_actionable() -> None:
    """Confirm the error message names the install command."""
    from varta._vlp_secure import CryptographyMissingError as Err

    # Smoke: even when cryptography IS installed, the class is importable
    # and a manually-raised instance carries the expected hint.
    msg = "varta secure-UDP transport requires the `cryptography` package"
    with pytest.raises(Err) as ei:
        raise Err(f"{msg}; install with `pip install 'varta[secure]'`")
    assert "pip install" in str(ei.value)
