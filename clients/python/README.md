# Varta — Python client

[![PyPI](https://img.shields.io/pypi/v/varta.svg)](https://pypi.org/project/varta/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Production Python client for the [Varta](https://github.com/aramirez087/Varta) health protocol.

```bash
pip install varta                # base client (stdlib only)
pip install 'varta[secure]'      # adds secure-UDP via the cryptography package
```

Requires Python 3.8+. Linux and macOS. The base install has zero third-party dependencies.

## What is Varta?

Varta is a health protocol for processes running on the same host (or same network segment). Your process calls `agent.beat()` on a fixed schedule — typically every 500 ms. A companion observer (`varta-watch`) watches the socket, detects when beats stop arriving, and fires a configurable recovery command.

The wire is 32 bytes per beat. No HTTP, no JSON. The base client uses only the Python standard library.

## Quickstart

```python
import sys
import time
from varta import Varta, Status

# connect() opens a non-blocking Unix Domain Socket to varta-watch.
# Use as a context manager so the socket closes automatically on exit.
with Varta.connect("/run/varta/varta.sock") as agent:
    while True:
        # beat() encodes and sends a 32-byte VLP frame.
        # It never blocks — if the queue is full it returns a Dropped outcome.
        outcome = agent.beat(Status.OK)

        if outcome.is_dropped:
            # Normal: observer restarted, queue momentarily full.
            # The observer's stall-detection fires if silence lasts too long.
            pass
        elif outcome.is_failed:
            # Abnormal: OS error, socket in bad state.
            print(f"varta: beat failed: {outcome}", file=sys.stderr)

        time.sleep(0.5)
```

## How it works

`beat()` encodes a 32-byte frame (PID, timestamp, status, 32-bit payload, CRC) and sends it to `varta-watch`. The observer tracks the last-seen timestamp per PID. If a PID goes silent longer than `--threshold-ms`, the observer marks it stalled and fires any configured recovery command.

No polling. No persistent connection state beyond the socket file descriptor.

## Which transport?

| Transport | When to use |
| --------- | ----------- |
| **UDS** (`Varta.connect`) | Same-host deployment. The observer reads kernel peer credentials (`SCM_CREDENTIALS` on Linux, `LOCAL_PEERTOKEN` on macOS), granting `BeatOrigin::KernelAttested` status. **Only kernel-attested beats are eligible for observer-driven recovery commands.** |
| **UDP** (`Varta.connect_udp`) | Same-host or LAN when UDS is unavailable. Beats are `NetworkUnverified`; recovery is refused by the observer. |
| **Secure UDP** (`Varta.connect_secure_udp`) | Same use case as UDP, plus ChaCha20-Poly1305 AEAD encryption for beat confidentiality. Still refused for recovery. Requires `pip install 'varta[secure]'`. |

For same-host Python agents, UDS is the recommended transport.

## Status values

`beat()` carries one of three status values. The observer surfaces all three through Prometheus.

| Status | When to send |
| ------ | ------------ |
| `Status.OK` | Everything is working normally. Send this the vast majority of the time. |
| `Status.DEGRADED` | Running but unhealthy: high error rate, queue backlog, slow dependency. Not treated as a stall — recorded but does not trigger recovery. |
| `Status.CRITICAL` | About to terminate due to an unrecoverable error. Typically sent by the panic hook, not your main beat loop. |

## Beat outcome

`beat()` returns a `BeatOutcome` with three boolean properties:

| Property | Meaning | Recommended action |
| -------- | ------- | ------------------ |
| `.is_sent` | Frame handed to the kernel. | Nothing. |
| `.is_dropped` | Frame not sent. `.reason` is one of `KERNEL_QUEUE_FULL`, `NO_OBSERVER`, `PEER_GONE`, or `STORAGE_FULL`. | Log at debug level or ignore. |
| `.is_failed` | Unexpected error (encoding bug, OS resource exhaustion). | Log at warn. Consider calling `agent.reconnect()`. |

A `is_dropped` outcome is not a bug. Occasional drops are invisible to the observer — only sustained silence triggers a stall.

## Payload field

`beat(status, payload=0)` accepts an optional 32-bit unsigned integer. The observer stores it verbatim and exposes it in the Prometheus `varta_agent_payload` gauge. Use it to pack any two metrics you want correlated with liveness:

```python
from varta import Status, Varta

queue_depth = 128
last_error  = 3

# High 16 bits = queue depth. Low 16 bits = last error code.
payload = ((queue_depth & 0xFFFF) << 16) | (last_error & 0xFFFF)
status  = Status.DEGRADED if last_error else Status.OK

with Varta.connect("/run/varta/varta.sock") as agent:
    agent.beat(status, payload)
```

The encoding convention is yours to decide. The observer does not interpret the payload field.

## Panic hook

```python
from varta.panic import install_excepthook_uds

# Register once at startup — before any threads are created.
install_excepthook_uds("/run/varta/varta.sock")

# Any uncaught exception now emits Status.CRITICAL + nonce=NONCE_TERMINAL
# before the interpreter prints the traceback and exits.
```

`install_excepthook_udp` and `install_excepthook_secure_udp` provide equivalent hooks for non-UDS deployments. All three pre-bind their socket at install time — no allocation happens in the exception hook itself.

Python's `sys.excepthook` does **not** fire on hard crashes (`SIGSEGV`, `SIGABRT`). Pass `faulthandler_signals=True` to also wire `faulthandler.enable()` against the bound socket as a side channel for those events. The output is a Python traceback, not a structured VLP frame — useful for postmortem, but not a beat.

## Secure UDP

```python
# pip install 'varta[secure]'
import binascii
from varta import Status, Varta

with open("/etc/varta/secure.key") as f:
    key = binascii.unhexlify(f.read().strip())  # 32 raw bytes

with Varta.connect_secure_udp(("127.0.0.1", 9443), key) as agent:
    agent.beat(Status.OK)
```

Without the `secure` extra, `connect_secure_udp` raises `CryptographyMissingError` at call time. The base UDS/UDP transports remain stdlib-only.

## API parity with `varta-client` (Rust)

| Rust                                                | Python                                                                   |
| --------------------------------------------------- | ------------------------------------------------------------------------ |
| `Varta::connect(path)`                              | `Varta.connect(path)`                                                    |
| `Varta::connect_udp(addr)`                          | `Varta.connect_udp((host, port))`                                        |
| `Varta::connect_secure_udp(addr, key)`              | `Varta.connect_secure_udp((host, port), key)`                            |
| `Varta::connect_secure_udp_with_master(addr, mkey)` | `Varta.connect_secure_udp_with_master((host, port), mkey)`               |
| `Varta::beat(status, payload) -> BeatOutcome`       | `agent.beat(status, payload=0) -> BeatOutcome`                           |
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
   refreshes the transport (and, for secure-UDP, re-reads entropy from
   `/dev/urandom`) before the frame leaves the child.
3. **Wire-format conformance.** The package ships a test that loads
   `tools/vlp-test-vectors.json` (the same fixture the Rust crate
   verifies against) and asserts byte-equality for every CRC, frame,
   and AEAD vector. Drift between languages is impossible without
   breaking both test suites in the same PR.

## Latency note

Python cannot match the ~1 µs-per-beat budget of the Rust client. Measured cost on the project's bench host is **~15–30 µs per `beat()`** including frame allocation, syscall, and outcome dispatch. The Python client is intended for tooling, batch jobs, web-app sidecars, and adapters — not for tight inner loops emitting kilo-beats per second.

## Non-goals

- **Recovery commands for UDP beats.** Only UDS beats are kernel-attested; UDP and secure-UDP beats never trigger observer-driven recovery.
- **Sub-microsecond latency.** Use the Rust `varta-client` for that.
- **The `accept-degraded-entropy` variant.** This feature exists for embedded targets that lack `/dev/urandom`; CPython does not run on such targets.

## See also

- [Normative wire spec](../../book/src/spec/vlp.md)
- [Conformance vectors](../../tools/vlp-test-vectors.json)
- [Rust agent crate](../../crates/varta-client/)
- [Go client](../go/)
- [Node.js client](../node/)
- [Observer](../../crates/varta-watch/)
- [Changelog](CHANGELOG.md)
