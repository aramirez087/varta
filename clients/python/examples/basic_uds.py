"""Minimal Varta beat loop — connect once, emit Status.OK every 500 ms.

Run alongside varta-watch::

    varta-watch --socket /tmp/varta.sock --threshold-ms 2000 &
    python basic_uds.py /tmp/varta.sock
"""

from __future__ import annotations

import sys
import time

from varta import Status, Varta


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else "/tmp/varta.sock"
    with Varta.connect(path) as agent:
        while True:
            outcome = agent.beat(Status.OK)
            if outcome.is_dropped:
                print(f"varta: beat dropped ({outcome.reason.value})", file=sys.stderr)
            elif outcome.is_failed:
                print(f"varta: beat failed: {outcome}", file=sys.stderr)
            time.sleep(0.5)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
