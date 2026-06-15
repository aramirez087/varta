# Varta — Go client

[![Go Reference](https://pkg.go.dev/badge/github.com/aramirez087/Varta/clients/go.svg)](https://pkg.go.dev/github.com/aramirez087/Varta/clients/go)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Production Go client for [Varta](https://varta.sh) — docs at [varta.sh/book](https://varta.sh/book/).

```bash
go get github.com/aramirez087/Varta/clients/go
```

## What is Varta?

Varta is a health protocol for processes running on the same host (or the same network segment). Your process calls `Beat()` on a fixed schedule — typically every 500 ms. A companion observer (`varta-watch`) watches the socket, detects when beats stop arriving, and fires a configurable recovery command.

The wire is 32 bytes per beat. No HTTP, no JSON, no allocations on the hot path.

## Quickstart

```go
package main

import (
    "log"
    "time"

    varta "github.com/aramirez087/Varta/clients/go"
)

func main() {
    // Connect opens a non-blocking Unix Domain Socket to varta-watch.
    // The path must match the --socket flag on your observer.
    agent, err := varta.Connect("/run/varta/varta.sock")
    if err != nil {
        log.Fatal(err)
    }
    defer agent.Close()

    for {
        // Beat encodes a 32-byte VLP frame and sends it.
        // It never blocks: if the kernel send queue is full, it returns Dropped.
        outcome := agent.Beat(varta.StatusOK, 0)

        if outcome.IsDropped() {
            // Normal: observer restarted, queue momentarily full, disk full.
            // Do nothing — the next beat will go through.
            // The observer's stall-detection fires if silence lasts too long.
        } else if outcome.IsFailed() {
            // Abnormal: OS resource exhaustion or socket in bad state.
            log.Printf("varta: beat failed: %v", outcome.Err())
        }
        time.Sleep(500 * time.Millisecond)
    }
}
```

## How it works

`Beat()` encodes a 32-byte frame (PID, timestamp, status, 32-bit payload, CRC) and sends it over a socket. `varta-watch` tracks the last-seen timestamp for each PID. If a PID goes silent longer than `--threshold-ms`, the observer marks it stalled and fires any configured recovery command.

No polling. No persistent connection state. No heap allocation after `Connect()`.

## Which transport?

| Transport | When to use |
| --------- | ----------- |
| **UDS** (`Connect`) | Same-host deployment. On observer platforms with pathname-datagram peer credentials (Linux and supported BSD/illumos/Solaris targets), beats become `BeatOrigin::KernelAttested` and are eligible for observer-driven recovery. macOS pathname UDS is `SocketModeOnly`, so recovery is refused there. |
| **UDP** (`ConnectUDP`) | Cross-host or same-host when UDS is unavailable. Beats are classified `NetworkUnverified`; recovery is refused by the observer. |
| **Secure UDP** (`ConnectSecureUDP`) | Same use case as UDP, plus ChaCha20-Poly1305 AEAD encryption for beat confidentiality. Still refused for recovery. |

For same-host Go agents, UDS is the recommended transport. Use UDP or secure-UDP only when UDS is unavailable or the observer is on a different machine.

## Status values

`Beat()` carries one of three status values. The observer surfaces all three through Prometheus.

| Status | When to send |
| ------ | ------------ |
| `StatusOK` | Everything is working normally. Send this the vast majority of the time. |
| `StatusDegraded` | Running but unhealthy: high error rate, queue backlog, slow dependency. Not treated as a stall — the observer records it but does not trigger recovery. |
| `StatusCritical` | About to terminate due to an unrecoverable error. Typically sent by the panic handler, not your main beat loop. |

## Beat outcome

`Beat()` returns a `BeatOutcome` describing what happened to the frame.

| Outcome | Meaning | Recommended action |
| ------- | ------- | ------------------ |
| `Sent` | Frame handed to the kernel. | Nothing. |
| `Dropped` | Frame not sent. Check `.DropReason()`: `KernelQueueFull`, `NoObserver`, `PeerGone`, or `StorageFull`. | Log at debug level or ignore. |
| `Failed` | Unexpected error (encoding bug, OS resource exhaustion). | Log at warn. Consider calling `agent.Reconnect()`. |

A `Dropped` outcome is not a bug. Occasional drops are invisible to the observer — only sustained silence triggers a stall.

## Payload field

`Beat(status, payload)` accepts a 32-bit unsigned integer as the second argument. The observer stores it verbatim and exposes it in the Prometheus `varta_agent_payload` gauge. Use it to pack any two metrics you want correlated with liveness:

```go
// High 16 bits = queue depth. Low 16 bits = last error code.
queueDepth := uint16(currentQueueLen)
lastErr    := uint16(lastErrorCode)
payload    := (uint32(queueDepth) << 16) | uint32(lastErr)

status := varta.StatusOK
if lastErr > 0 {
    status = varta.StatusDegraded
}
agent.Beat(status, payload)
```

The encoding convention is yours to decide. The observer does not interpret the payload field.

## Panic handler

Go has no `sys.excepthook`. Two complementary mechanisms close that gap:

```go
import vpanic "github.com/aramirez087/Varta/clients/go/panic"

// 1. Terminating signals — SIGTERM, SIGINT, SIGQUIT, SIGHUP.
//    On signal, emits Status=Critical + Nonce=NonceTerminal,
//    then re-raises the original signal so the process exits normally.
if err := vpanic.InstallSignalHandlerUDS("/run/varta/varta.sock"); err != nil {
    log.Fatal(err)
}

// 2. Go runtime panics (nil deref, slice out-of-bounds, explicit panic).
//    Wrap your main work in Run; the deferred recover emits a Critical
//    beat, then re-panics so the original stack trace and exit code are
//    preserved.
vpanic.Run(func() {
    runApplication()
})
```

`InstallSignalHandlerUDP` and `InstallSignalHandlerSecureUDP` provide equivalent hooks for non-UDS deployments. All three pre-bind their socket at install time — no allocation or DNS resolution happens inside the signal handler.

The Go runtime owns `SIGSEGV`/`SIGABRT`/`SIGBUS`; `signal.Notify` cannot intercept those, so `vpanic.Run` closes that gap for any Go-language panic. Together the two mechanisms cover the same surface as Python's `sys.excepthook` + `faulthandler`.

## Secure UDP

```go
// key must be exactly 32 bytes. Load from a Kubernetes secret, Vault, HSM, etc.
key, err := os.ReadFile("/etc/varta/secure.key")
if err != nil || len(key) != 32 {
    log.Fatal("need a 32-byte key file")
}

agent, err := varta.ConnectSecureUDP("127.0.0.1", 9443, key)
```

Secure-UDP uses ChaCha20-Poly1305 AEAD from `golang.org/x/crypto/chacha20poly1305` — the only registry dependency this module carries. The base UDS/UDP transport is stdlib-only.

A 16-byte session salt is read from `crypto/rand` at dial time and again on every `Reconnect()`. This is the structural guarantee against AEAD nonce reuse across `fork(2)`: a forked child reinitialises its AEAD session before its first beat leaves the process.

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
   A kernel-queue-full send surfaces as `BeatOutcome.Dropped(KernelQueueFull)`,
   never a block.
2. **Per-emission `os.Getpid()`.** No PID caching — forked children report
   their own identity on the next beat. Fork auto-recovery refreshes the
   transport (and, for secure-UDP, re-reads entropy from `crypto/rand`)
   before the frame leaves the child.
3. **Wire-format conformance.** The package ships a test that loads
   `tools/vlp-test-vectors.json` (the same fixture the Rust crate and
   Python client verify against) and asserts byte-equality for every CRC,
   frame, and AEAD vector. Drift between languages is impossible without
   breaking three test suites in the same PR.

## Latency note

Go's per-beat cost sits in the **~5–15 µs** band (goroutine scheduler, GC overhead, one syscall through the `net` package). That is slower than the Rust client (~1 µs) but faster than the Python client (~20 µs). The Go client is designed for sidecars, daemons, operator tooling, and Prometheus exporters — not for tight inner loops emitting kilo-beats per second.

## Non-goals

- **Recovery commands for UDP beats.** Only UDS beats are kernel-attested; UDP and secure-UDP beats never trigger observer-driven recovery.
- **Sub-microsecond latency.** Use the Rust `varta-client` crate for that.
- **Zero registry dependencies.** The base module (UDS + plaintext UDP) is stdlib-only. `ConnectSecureUDP` adds `golang.org/x/crypto`. If zero deps is a hard requirement, stay on UDS or plaintext UDP.

## See also

- [Normative wire spec](../../book/src/spec/vlp.md)
- [Conformance vectors](../../tools/vlp-test-vectors.json)
- [Rust agent crate](../../crates/varta-client/)
- [Python client](../python/)
- [Node.js client](../node/)
- [Observer](../../crates/varta-watch/)
- [Changelog](CHANGELOG.md)
