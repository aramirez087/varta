"""Varta agent over ChaCha20-Poly1305 AEAD UDP.

Requires the ``cryptography`` package — ``pip install 'varta[secure]'``.

Run alongside varta-watch configured with the matching key::

    KEY_HEX=$(python3 -c 'import os; print(os.urandom(32).hex())')
    echo "$KEY_HEX" > /tmp/varta.key
    chmod 600 /tmp/varta.key
    varta-watch --udp-port 4040 --udp-bind-addr 127.0.0.1 \\
        --key-file /tmp/varta.key --threshold-ms 2000 &
    python secure_udp.py 127.0.0.1 4040 /tmp/varta.key
"""

from __future__ import annotations

import binascii
import sys
import time

from varta import Status, Varta


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: secure_udp.py HOST PORT KEY_FILE", file=sys.stderr)
        return 2
    host, port_str, key_file = argv[1], argv[2], argv[3]
    with open(key_file, "rb") as f:
        key_hex = f.read().strip()
    key = binascii.unhexlify(key_hex)
    if len(key) != 32:
        print(f"key must decode to 32 bytes (got {len(key)})", file=sys.stderr)
        return 2

    with Varta.connect_secure_udp((host, int(port_str)), key) as agent:
        while True:
            outcome = agent.beat(Status.OK)
            if outcome.is_dropped:
                print(f"varta: beat dropped ({outcome.reason.value})", file=sys.stderr)
            time.sleep(0.5)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
