"""Beat loop that packs queue depth and last error code into the 32-bit payload.

Layout: high 16 bits = queue_depth, low 16 bits = last_error_code.
The observer treats the payload opaquely; decoding is the agent's concern.

Run alongside varta-watch::

    varta-watch --socket /tmp/varta.sock --threshold-ms 2000 &
    python with_payload.py /tmp/varta.sock
"""

from __future__ import annotations

import sys
import time

from varta import Status, Varta


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else "/tmp/varta.sock"
    queue_depth = 0
    last_error = 0
    with Varta.connect(path) as agent:
        while True:
            payload = ((queue_depth & 0xFFFF) << 16) | (last_error & 0xFFFF)
            outcome = agent.beat(Status.OK, payload)
            if outcome.is_dropped:
                print(f"varta: beat dropped ({outcome.reason.value})", file=sys.stderr)
            time.sleep(0.5)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
