# Python client

[![PyPI](https://img.shields.io/pypi/v/varta.svg)](https://pypi.org/project/varta/)

The Python client (`pip install varta`) is a first-class peer of the
Rust `varta-client` crate. It tracks the same wire-format contract,
passes the same `tools/vlp-test-vectors.json` conformance suite, and
interoperates with the same `varta-watch` observer binary.

## Install

```bash
pip install varta                # base client (stdlib only)
pip install 'varta[secure]'      # adds secure-UDP via `cryptography`
```

Requires Python 3.8+. Runs on Linux and macOS. The base install carries
zero third-party dependencies; the `secure` extra pulls in
[`cryptography`](https://pypi.org/project/cryptography/) for the
ChaCha20-Poly1305 AEAD primitive.

## 20-line example

```python
import time
from varta import Varta, Status, DropReason

with Varta.connect("/run/varta/varta.sock") as agent:
    while True:
        outcome = agent.beat(Status.OK)
        if outcome.is_dropped:
            # Four-way taxonomy mirrors the Rust client:
            assert outcome.reason in {
                DropReason.KERNEL_QUEUE_FULL,
                DropReason.NO_OBSERVER,
                DropReason.PEER_GONE,
                DropReason.STORAGE_FULL,
            }
        time.sleep(0.5)
```

For UDP and secure-UDP transports, fork-safety, the panic-hook family,
and the full parity matrix see the package README in the repo:
[`clients/python/README.md`](https://github.com/aramirez087/Varta/blob/main/clients/python/README.md).

## Stability

- **Wire format**: VLP v0.2, governed by [the spec](../spec/vlp.md).
- **Python API**: independent semver, tracked in
  [`clients/python/CHANGELOG.md`](https://github.com/aramirez087/Varta/blob/main/clients/python/CHANGELOG.md).

## Source

- [PyPI page](https://pypi.org/project/varta/)
- [GitHub source](https://github.com/aramirez087/Varta/tree/main/clients/python)
- [Issue tracker](https://github.com/aramirez087/Varta/issues)
