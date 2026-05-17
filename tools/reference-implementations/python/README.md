# Python reference implementation — VLP v0.2

Non-normative. The authoritative specification is at
[`book/src/spec/vlp.md`](../../../book/src/spec/vlp.md) and
[`book/src/spec/vlp-secure.md`](../../../book/src/spec/vlp-secure.md).
This directory exists so a Python developer can confirm their
understanding of the wire format against working code without needing a
Rust toolchain.

## Files

* `vlp.py` — base 32-byte VLP frame: `encode`, `decode`, `crc32c`,
  `Status`, `DecodeError`. **Standard library only.** Python 3.8+.
* `vlp_secure.py` — HKDF-SHA256 key derivations (stdlib `hashlib` +
  `hmac`) and ChaCha20-Poly1305 seal/open (requires the third-party
  [`cryptography`](https://pypi.org/project/cryptography/) package).
* `verify_vectors.py` — drives the cross-language conformance vectors
  from `tools/vlp-test-vectors.json` against both modules.

## Run the conformance suite

```sh
# Base spec only (stdlib):
python3 verify_vectors.py

# Including secure-transport vectors (needs cryptography):
python3 -m venv .venv
source .venv/bin/activate
pip install cryptography
python verify_vectors.py
```

A clean exit code of `0` plus the line `ALL VECTORS PASSED` means the
implementation agrees with every vector in
[`tools/vlp-test-vectors.json`](../../vlp-test-vectors.json).

## Building a client

Minimal agent loop in pure Python:

```python
import os, socket, time
import vlp

sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sock.setblocking(False)
sock.connect("/tmp/varta.sock")

start = time.monotonic_ns()
nonce = 1
while True:
    elapsed = time.monotonic_ns() - start
    try:
        sock.send(vlp.encode("ok", os.getpid(), elapsed, nonce, 0))
    except BlockingIOError:
        pass  # observer not draining — VLP requires fail-fast, never block
    nonce = (nonce + 1) if nonce < vlp.NONCE_TERMINAL - 1 else 0
    time.sleep(0.5)
```

The reference Rust observer (`varta-watch`) will decode these frames
and emit Prometheus metrics under `varta_*`.
