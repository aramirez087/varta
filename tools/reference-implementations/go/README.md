# Go reference implementation — VLP v0.2

Non-normative. The authoritative specification is at
[`book/src/spec/vlp.md`](../../../book/src/spec/vlp.md) and
[`book/src/spec/vlp-secure.md`](../../../book/src/spec/vlp-secure.md).

## Files

* `vlp.go` — base 32-byte frame: `Encode`, `Decode`, `CRC32C`, `Status`,
  `DecodeError`. Standard library only.
* `vlp_secure.go` — HKDF-SHA256 (stdlib `crypto/sha256` + `crypto/hmac`)
  plus ChaCha20-Poly1305 seal (requires `golang.org/x/crypto`).
* `verify_vectors.go` — drives the cross-language conformance suite.
* `go.mod` — declares the `golang.org/x/crypto` dependency.

## Run

```sh
cd tools/reference-implementations/go
go mod download          # fetch golang.org/x/crypto on first run
go run .                 # runs every vector
```

`go run . ../../vlp-test-vectors.json` overrides the JSON path.

## Building a client

```go
package main

import (
    "net"
    "os"
    "time"

    vlp "github.com/aramirez087/Varta/tools/reference-implementations/go"
)

func main() {
    sock, _ := net.Dial("unixgram", "/tmp/varta.sock")
    defer sock.Close()
    if err := sock.(*net.UnixConn).SetWriteBuffer(64); err != nil { /* ignore */ }

    start := time.Now()
    var nonce uint64 = 1
    for {
        elapsed := uint64(time.Since(start).Nanoseconds())
        wire := vlp.Encode(vlp.StatusOk, uint32(os.Getpid()), elapsed, nonce, 0)
        _, _ = sock.Write(wire[:])  // non-blocking; drop on WouldBlock
        if nonce == vlp.NonceTerminal-1 {
            nonce = 0
        } else {
            nonce++
        }
        time.Sleep(500 * time.Millisecond)
    }
}
```
