# Go client

[![Go Reference](https://pkg.go.dev/badge/github.com/aramirez087/Varta/clients/go.svg)](https://pkg.go.dev/github.com/aramirez087/Varta/clients/go)

The Go client (`go get github.com/aramirez087/Varta/clients/go`) is a first-class peer of the Rust `varta-client` crate. It tracks the same wire-format contract, passes the same `tools/vlp-test-vectors.json` conformance suite, and interoperates with the same `varta-watch` observer binary.

## Install

```bash
go get github.com/aramirez087/Varta/clients/go
```

Requires Go 1.21+. The base module (UDS + plaintext UDP) has no registry dependencies. `ConnectSecureUDP` adds `golang.org/x/crypto`.

## 20-line example

```go
package main

import (
    "log"
    "time"

    varta "github.com/aramirez087/Varta/clients/go"
)

func main() {
    // Connect once. path must match --socket on your observer.
    agent, err := varta.Connect("/run/varta/varta.sock")
    if err != nil {
        log.Fatal(err)
    }
    defer agent.Close()

    for {
        if outcome := agent.Beat(varta.StatusOK, 0); outcome.IsDropped() {
            log.Printf("varta: dropped (%s)", outcome.DropReason())
        }
        time.Sleep(500 * time.Millisecond)
    }
}
```

For payload encoding, fork-safety, the panic-handler subpackage, the full transport comparison, and the complete API parity matrix see the package README:
[`clients/go/README.md`](https://github.com/aramirez087/Varta/blob/main/clients/go/README.md).

## Transports

| Transport | Status | Notes |
| --------- | ------ | ----- |
| Unix Domain Sockets | Supported | `varta.Connect(path)`. Stdlib-only. The only transport classified `BeatOrigin::KernelAttested`, making it the only Go transport eligible for observer-driven recovery. |
| Plaintext UDP | Supported | `varta.ConnectUDP(host, port)`. Connected-mode socket. Beats classified `NetworkUnverified`; recovery refused. |
| Secure UDP (ChaCha20-Poly1305) | Supported | `varta.ConnectSecureUDP(host, port, key)`. Adds `golang.org/x/crypto`. |
| Master-key secure UDP | Supported | `varta.ConnectSecureUDPWithMaster(host, port, masterKey)` |

## Stability

- **Wire format**: VLP v0.2, governed by [the spec](../spec/vlp.md).
- **Go API**: independent semver, tracked in
  [`clients/go/CHANGELOG.md`](https://github.com/aramirez087/Varta/blob/main/clients/go/CHANGELOG.md).

## Source

- [pkg.go.dev reference](https://pkg.go.dev/github.com/aramirez087/Varta/clients/go)
- [GitHub source](https://github.com/aramirez087/Varta/tree/main/clients/go)
- [Issue tracker](https://github.com/aramirez087/Varta/issues)
