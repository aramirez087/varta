"""Demonstrates ``varta.panic.install_excepthook_uds``.

Any uncaught exception emits a single ``Status.CRITICAL`` frame with
``nonce=NONCE_TERMINAL`` so the observer can distinguish a structured
panic from a regular Critical beat.

Run alongside varta-watch::

    varta-watch --socket /tmp/varta.sock --threshold-ms 2000 &
    python with_panic_handler.py /tmp/varta.sock
"""

from __future__ import annotations

import sys
import time

from varta import Status, Varta
from varta.panic import install_excepthook_uds


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else "/tmp/varta.sock"
    install_excepthook_uds(path)

    with Varta.connect(path) as agent:
        agent.beat(Status.OK)
        time.sleep(0.1)
        # Force an uncaught exception. The installed excepthook emits a
        # critical beat before the interpreter prints the traceback.
        raise RuntimeError("simulated agent panic")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
