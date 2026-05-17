#!/usr/bin/env python3
"""Run the VLP conformance suite against the Python reference implementation.

Usage:

    python3 verify_vectors.py [PATH_TO_JSON]

Default JSON path is `../../vlp-test-vectors.json` (relative to this script).

Exits 0 on full pass. Secure-frame vectors require the third-party
``cryptography`` package — they are skipped (with a warning) if it is
not installed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import vlp


def main(argv: list[str]) -> int:
    here = Path(__file__).resolve().parent
    default = here.parent.parent / "vlp-test-vectors.json"
    path = Path(argv[1]) if len(argv) > 1 else default
    doc = json.loads(path.read_text())

    failures: list[str] = []

    # ----- CRC -----
    for v in doc["crc32c_vectors"]:
        got = vlp.crc32c(bytes.fromhex(v["input_hex"]))
        want = int(v["expected_crc_hex"], 16)
        if got != want:
            failures.append(f"crc/{v['id']}: got {got:08x}, want {want:08x}")
    print(f"crc32c_vectors:        {len(doc['crc32c_vectors'])} OK")

    # ----- Frames -----
    roundtrip = 0
    error = 0
    for v in doc["frame_vectors"]:
        kind = v["kind"]
        if kind == "encode_decode_roundtrip":
            i = v["inputs"]
            wire = vlp.encode(i["status"], i["pid"], i["timestamp"],
                              i["nonce"], i["payload"])
            if wire.hex() != v["expected_wire_hex"]:
                failures.append(
                    f"frame/{v['id']}: encode mismatch\n"
                    f"  got  {wire.hex()}\n"
                    f"  want {v['expected_wire_hex']}"
                )
                continue
            decoded = vlp.decode(bytes.fromhex(v["expected_wire_hex"]))
            if decoded.pid != i["pid"] or decoded.timestamp != i["timestamp"] \
                    or decoded.nonce != i["nonce"] or decoded.payload != i["payload"]:
                failures.append(f"frame/{v['id']}: decode roundtrip mismatch")
                continue
            roundtrip += 1
        elif kind == "decode_error":
            try:
                vlp.decode(bytes.fromhex(v["wire_hex"]))
                failures.append(f"frame/{v['id']}: expected error, got OK")
                continue
            except vlp.DecodeError as e:
                if e.kind != v["expected_decode_error"]:
                    failures.append(
                        f"frame/{v['id']}: expected {v['expected_decode_error']}, "
                        f"got {e.kind} ({e})"
                    )
                    continue
                error += 1
        else:
            failures.append(f"frame/{v['id']}: unknown kind {kind}")
    print(f"frame_vectors:         {roundtrip} round-trips, {error} error vectors OK")

    # ----- Secure frames -----
    secure_done = 0
    secure_skipped = 0
    try:
        import vlp_secure  # noqa: F401
        have_secure = True
        # Probe AEAD availability separately.
        try:
            vlp_secure._aead()
        except ImportError:
            print("  (skip) cryptography package not installed — secure_frame_vectors skipped.")
            print("         Install with: pip install cryptography")
            have_secure = False
    except ImportError:
        have_secure = False

    if have_secure:
        for v in doc["secure_frame_vectors"]:
            kind = v["kind"]
            try:
                if kind == "shared_key_seal":
                    wire = vlp_secure.encode_shared(
                        bytes.fromhex(v["key_hex"]),
                        bytes.fromhex(v["iv_random_hex"]),
                        v["iv_counter"],
                        bytes.fromhex(v["plaintext_hex"]),
                    )
                    if wire.hex() != v["expected_wire_hex"]:
                        failures.append(f"secure/{v['id']}: wire mismatch")
                        continue
                elif kind == "master_key_seal":
                    derived = vlp_secure.derive_agent_key(
                        bytes.fromhex(v["master_key_hex"]),
                        v["agent_pid"],
                    )
                    if derived.hex() != v["derived_agent_key_hex"]:
                        failures.append(f"secure/{v['id']}: agent-key derivation mismatch")
                        continue
                    wire = vlp_secure.encode_master(
                        bytes.fromhex(v["master_key_hex"]),
                        v["agent_pid"],
                        bytes.fromhex(v["iv_random_hex"]),
                        v["iv_counter"],
                        bytes.fromhex(v["plaintext_hex"]),
                    )
                    if wire.hex() != v["expected_wire_hex"]:
                        failures.append(f"secure/{v['id']}: wire mismatch")
                        continue
                elif kind == "kdf_agent_key":
                    derived = vlp_secure.derive_agent_key(
                        bytes.fromhex(v["master_key_hex"]),
                        v["agent_id"],
                    )
                    if derived.hex() != v["expected_okm_hex"]:
                        failures.append(f"secure/{v['id']}: HKDF mismatch")
                        continue
                elif kind == "kdf_iv_prefix":
                    derived = vlp_secure.derive_iv_prefix(
                        bytes.fromhex(v["session_salt_hex"]),
                        v["prefix_index"],
                    )
                    if derived.hex() != v["expected_iv_prefix_hex"]:
                        failures.append(f"secure/{v['id']}: HKDF mismatch")
                        continue
                elif kind == "kdf_epoch_key":
                    derived = vlp_secure.derive_epoch_key(
                        bytes.fromhex(v["agent_key_hex"]),
                        v["epoch"],
                    )
                    if derived.hex() != v["expected_okm_hex"]:
                        failures.append(f"secure/{v['id']}: HKDF mismatch")
                        continue
                else:
                    failures.append(f"secure/{v['id']}: unknown kind {kind}")
                    continue
                secure_done += 1
            except Exception as e:
                failures.append(f"secure/{v['id']}: exception {e!r}")
        print(f"secure_frame_vectors:  {secure_done} OK")
    else:
        secure_skipped = len(doc["secure_frame_vectors"])
        print(f"secure_frame_vectors:  {secure_skipped} skipped (no cryptography pkg)")

    if failures:
        print()
        print("FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print()
    print("ALL VECTORS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
