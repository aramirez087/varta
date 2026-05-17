# Varta — Go client

[![Go Reference](https://pkg.go.dev/badge/github.com/aramirez087/Varta/clients/go.svg)](https://pkg.go.dev/github.com/aramirez087/Varta/clients/go)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Production Go client for the [Varta](https://github.com/aramirez087/Varta)
health protocol. Emits 32-byte VLP heartbeats to a `varta-watch`
observer over Unix Domain Sockets, plaintext UDP, or
ChaCha20-Poly1305-encrypted UDP.

```bash
go get github.com/aramirez087/Varta/clients/go
```

## Quickstart

```go
package main

import (
    "time"

    varta "github.com/aramirez087/Varta/clients/go"
)

func main() {
    agent, err := varta.Connect("/run/varta/varta.sock")
    if err != nil {
        panic(err)
    }
    defer agent.Close()

    for {
        outcome := agent.Beat(varta.StatusOK, 0)
        if outcome.IsDropped() {
            // Observer absent, kernel queue full, peer gone, or disk full.
            // Treat as a no-op; the next beat will retry.
        }
        time.Sleep(500 * time.Millisecond)
    }
}
```

## API parity with `varta-client` (Rust)

| Rust                                                | Go                                                                       |
| --------------------------------------------------- | ------------------------------------------------------------------------ |
| `Varta::connect(path)`                              | `varta.Connect(path)`                                                    |
| `Varta::connect_udp(addr)`                          | `varta.ConnectUDP(host, port)`                                           |
| `Varta::connect_secure_udp(addr, key)`              | `varta.ConnectSecureUDP(host, port, key)`                                |
| `Varta::connect_secure_udp_with_master(addr, mkey)` | `varta.ConnectSecureUDPWithMaster(host, port, masterKey)`                |
| `Varta::beat(status, payload) -> BeatOutcome`       | `agent.Beat(status, payload) BeatOutcome`                                |
| `BeatOutcome::{Sent, Dropped, Failed}`              | `BeatOutcome` (tagged: `.IsSent()` / `.IsDropped()` / `.IsFailed()`)     |
| `DropReason::{KernelQueueFull, NoObserver, PeerGone, StorageFull}` | `DropReason` constants — same four variants                |
| `BeatError { errno, kind }`                         | `BeatError{Errno, Kind}` struct                                          |
| `classify_send_error`                               | `varta.ClassifySendError(err)`                                           |
| `Varta::reconnect`, `set_reconnect_after`           | `agent.Reconnect()`, `agent.SetReconnectAfter(n)`                        |
| `Varta::clock_regressions()`, `fork_recoveries()`   | `agent.ClockRegressions()`, `agent.ForkRecoveries()`                     |
| `install_panic_handler*`                            | `panic.InstallSignalHandler*` + `panic.Run(fn)`                          |

## Hard invariants

The Go client preserves the Rust client's wire-level contract:

1. **Non-blocking I/O.** Every socket is set non-blocking at dial time.
   A kernel-queue-full send surfaces as
   `BeatOutcome.Dropped(KernelQueueFull)`, never a block.
2. **Per-emission `os.Getpid()`.** No PID caching — forked children
   report their own identity on the next beat. Fork auto-recovery
   refreshes the transport (and, for secure-UDP, re-reads OS entropy)
   before the frame leaves the child.
3. **Wire-format conformance.** The package ships a test that loads
   `tools/vlp-test-vectors.json` (the same fixture the Rust crate and
   Python client verify against) and asserts byte-equality for every
   CRC, frame, and AEAD vector. Drift between languages is impossible
   without breaking three test suites in the same PR.

### Latency non-goal

Go's per-beat cost (goroutine scheduler, GC overhead, single syscall
through the `net` package) sits in the **~5–15 µs** band — slower than
the Rust client's ~1 µs but faster than the Python client's ~20 µs.
Intended for sidecars, daemons, operator tooling, and Prometheus
exporters — not for tight inner loops emitting kilo-beats per second.

## Secure UDP

Secure-UDP pulls in `golang.org/x/crypto/chacha20poly1305` (the only
registry dependency this module carries). The base UDS/UDP transport is
stdlib-only.

```go
key := make([]byte, 32) // load from a Kubernetes secret, vault, etc.
agent, err := varta.ConnectSecureUDP("observer.varta.svc.cluster.local", 9443, key)
```

The 16-byte session salt is read from `crypto/rand` at dial time and
again on every `Reconnect()` — the structural guarantee against AEAD
nonce reuse across `fork(2)`.

## Panic equivalent

Go has no `sys.excepthook`. Two complementary mechanisms cover the
gap:

```go
import "github.com/aramirez087/Varta/clients/go/panic"

// 1) Terminating signals — SIGTERM / SIGINT / SIGQUIT / SIGHUP.
//    On signal, emits Status=Critical + Nonce=NonceTerminal, then
//    re-raises the signal so the process terminates normally.
if err := panic.InstallSignalHandlerUDS("/run/varta/varta.sock"); err != nil {
    log.Fatal(err)
}

// 2) Go-runtime panics (nil deref, slice OOB, explicit panic). Wrap
//    main work in panic.Run; the deferred recover emits a Critical
//    beat then re-panics so the stack trace and exit code are
//    preserved.
panic.Run(func() {
    runApplication()
})
```

The Go runtime owns `SIGSEGV` / `SIGABRT` / `SIGBUS`; `signal.Notify`
cannot intercept them reliably. `panic.Run` closes that gap for any
Go-language panic. Together the two mechanisms cover the same surface
as Python's `sys.excepthook` + `faulthandler`.

## See also

- [Normative wire spec](../../book/src/spec/vlp.md)
- [Conformance vectors](../../tools/vlp-test-vectors.json)
- [Rust agent crate](../../crates/varta-client/)
- [Python client](../python/)
- [Observer](../../crates/varta-watch/)
- [Changelog](CHANGELOG.md)
