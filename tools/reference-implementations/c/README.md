# C99 reference implementation — VLP v0.2 (base spec only)

Non-normative. Authoritative spec: [`book/src/spec/vlp.md`](../../../book/src/spec/vlp.md).

This directory covers the **32-byte base frame only**. Secure-transport
AEAD verification (ChaCha20-Poly1305) is not implemented in this
reference — adding it well requires linking libsodium or vendoring a
sizeable ChaCha20-Poly1305 implementation, and the Python / Go / Rust
references already validate the secure-transport spec.

For a C client that needs secure transport, see
[`book/src/spec/vlp-secure.md`](../../../book/src/spec/vlp-secure.md) §2
for the AEAD requirements and bind libsodium's
`crypto_aead_chacha20poly1305_ietf_*` API.

## Files

* `vlp.h` / `vlp.c` — C99, stdlib only (`<stdint.h>`, `<string.h>`).
  ~150 lines including the CRC-32C table.
* `gen_vectors_header.py` — Python helper that bakes
  `tools/vlp-test-vectors.json` into a C header at build time.
* `verify_vectors.c` — drives the generated header against `vlp.h`.
* `Makefile` — `make verify` regenerates the header and runs the suite.

## Run

```sh
cd tools/reference-implementations/c
make verify
```

Expected output: `crc32c_vectors: 5 OK`, `frame_vectors: 6 round-trips,
9 error vectors OK`, followed by `ALL VECTORS PASSED (base spec)`.

## Building a client

```c
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "vlp.h"

int main(void) {
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/varta.sock", sizeof(addr.sun_path) - 1);
    connect(fd, (struct sockaddr*)&addr, sizeof(addr));

    uint8_t wire[VARTA_FRAME_BYTES];
    uint64_t nonce = 1;
    for (;;) {
        varta_encode(VARTA_STATUS_OK, getpid(), monotonic_ns(), nonce, 0, wire);
        send(fd, wire, sizeof(wire), 0);   /* dropped on EWOULDBLOCK by design */
        if (nonce == VARTA_NONCE_TERMINAL - 1) nonce = 0; else ++nonce;
        usleep(500000);
    }
}
```

(`monotonic_ns()` left to the implementer — `clock_gettime(CLOCK_MONOTONIC)`
on Linux/macOS, `QueryPerformanceCounter` on Windows.)
