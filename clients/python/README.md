# Varta — Python client

[![PyPI](https://img.shields.io/pypi/v/varta.svg)](https://pypi.org/project/varta/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Production Python client for the [Varta](https://github.com/aramirez087/Varta)
health protocol. Emits 32-byte VLP heartbeats to a `varta-watch`
observer over Unix Domain Sockets, plaintext UDP, or
ChaCha20-Poly1305-encrypted UDP.

```bash
pip install varta                # base client (stdlib only)
pip install 'varta[secure]'      # adds secure-UDP via `cryptography`
```

## Quickstart

```python
import time
from varta import Varta, Status

with Varta.connect("/run/varta/varta.sock") as agent:
    while True:
        outcome = agent.beat(Status.OK)
        if outcome.is_dropped:
            # Observer absent, kernel queue full, peer gone, or disk full.
            # Treat as a no-op; the next beat will retry.
            pass
        time.sleep(0.5)
```

## API parity with `varta-client` (Rust)

| Rust                                                | Python                                                                   |
| --------------------------------------------------- | ------------------------------------------------------------------------ |
| `Varta::connect(path)`                              | `Varta.connect(path)`                                                    |
| `Varta::connect_udp(addr)`                          | `Varta.connect_udp(addr)`                                                |
| `Varta::connect_secure_udp(addr, key)`              | `Varta.connect_secure_udp(addr, key)`                                    |
| `Varta::connect_secure_udp_with_master(addr, mkey)` | `Varta.connect_secure_udp_with_master(addr, mkey)`                       |
| `Varta::beat(status, payload) -> BeatOutcome`       | `Varta.beat(status, payload) -> BeatOutcome`                             |
| `BeatOutcome::{Sent, Dropped, Failed}`              | `BeatOutcome` (tagged dataclass: `.is_sent` / `.is_dropped` / `.is_failed`) |
| `DropReason::{KernelQueueFull, NoObserver, PeerGone, StorageFull}` | `DropReason` (`StrEnum`) — same four variants                |
| `BeatError { errno, kind }`                         | `BeatError(errno, kind)` frozen dataclass                                |
| `classify_send_error`                               | `classify_send_error(exc)`                                               |
| `Varta::reconnect`, `set_reconnect_after`           | Same names                                                               |
| `Varta::clock_regressions()`, `fork_recoveries()`   | Same names                                                               |
| `install_panic_handler*`                            | `varta.panic.install_excepthook_*`                                       |

## Hard invariants

The Python client preserves the Rust client's wire-level contract:

1. **Non-blocking I/O.** Every socket is `setblocking(False)`. A
   kernel-queue-full send surfaces as
   `BeatOutcome.dropped(DropReason.KERNEL_QUEUE_FULL)`, never a block.
2. **Per-emission `os.getpid()`.** No PID caching — forked children
   report their own identity on the next beat. Fork auto-recovery
   refreshes the transport (and, for secure-UDP, re-reads OS entropy)
   before the frame leaves the child.
3. **Wire-format conformance.** The package ships a test that loads
   `tools/vlp-test-vectors.json` (the same fixture the Rust crate
   verifies against) and asserts byte-equality for every CRC, frame,
   and AEAD vector. Drift between languages is impossible without
   breaking both tests in the same PR.

### Latency non-goal

Python cannot match the ~1 µs-per-beat budget of the Rust client.
Measured cost on the project's bench host is **~15–30 µs per `beat()`**
including frame allocation, syscall, and outcome dispatch. The Python
client is intended for tooling, batch jobs, web-app sidecars, and
adapters — not for tight inner loops emitting kilo-beats per second.

## Secure UDP

`pip install 'varta[secure]'` pulls in
[`cryptography`](https://pypi.org/project/cryptography/), which provides
the ChaCha20-Poly1305 primitive. Without the extra, the secure-UDP
constructors raise an actionable
`varta._vlp_secure.CryptographyMissingError` at call time. Base
encode/decode and the panic-hook UDS/UDP variants remain stdlib-only.

## Panic hook

```python
from varta.panic import install_excepthook_uds

install_excepthook_uds("/run/varta/varta.sock")
# any uncaught exception now emits a Status.CRITICAL beat
```

Python's `sys.excepthook` does **not** fire on hard crashes (`SIGSEGV`,
`SIGABRT`). Pass `faulthandler_signals=True` to also wire
`faulthandler.enable()` against the bound socket as a side channel for
those events. The output is a Python traceback, not a VLP frame —
useful for postmortem, but not a structured beat.

The Rust `accept-degraded-entropy` variant is **intentionally not
implemented** in Python: that feature exists for embedded targets that
lack `/dev/urandom`; CPython itself does not run on such targets.

## See also

- [Normative wire spec](../../book/src/spec/vlp.md)
- [Conformance vectors](../../tools/vlp-test-vectors.json)
- [Rust agent crate](../../crates/varta-client/)
- [Observer](../../crates/varta-watch/)
- [Changelog](CHANGELOG.md)
