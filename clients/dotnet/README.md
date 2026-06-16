# Varta.Client — .NET client for Varta VLP v0.2

[![NuGet](https://img.shields.io/nuget/v/Varta.Client.svg)](https://www.nuget.org/packages/Varta.Client/)

`Varta.Client` is the official .NET (C#) client for the
[Varta](https://github.com/aramirez087/Varta) zero-overhead health
protocol. A Varta agent emits 32-byte heartbeats to a local observer
(`varta-watch`) that detects stalls, triggers recovery commands, and
exports Prometheus metrics.

This package is a first-class peer of the Rust, Python, Go, and Node
clients — independent semver, identical wire format, identical
public surface.

```bash
dotnet add package Varta.Client
```

## What is Varta?

Varta is a health protocol for processes running on the same host (or same network segment). Your process calls `agent.Beat()` on a fixed schedule — typically every 500 ms. A companion observer (`varta-watch`) watches the socket, detects when beats stop arriving, and fires a configurable recovery command.

The wire is 32 bytes per beat. No HTTP, no JSON. The base client uses only the .NET BCL.

## Quickstart

```csharp
using Varta;

using var agent = global::Varta.Varta.Connect("/run/varta/observer.sock");

while (true)
{
    BeatOutcome outcome = agent.Beat(Status.Ok, payload: 0);
    if (outcome.IsDropped)
    {
        // Backpressure or observer absent — application decides what
        // to do, the call itself never blocks or throws.
    }
    await Task.Delay(500);
}
```

## How it works

`Beat()` encodes a 32-byte frame (PID, timestamp, status, 32-bit payload, CRC-32C) and sends it to `varta-watch`. The observer tracks the last-seen timestamp per PID. If a PID goes silent longer than `--threshold-ms`, the observer marks it stalled and fires any configured recovery command.

No polling. No persistent connection state beyond the socket file descriptor.

## Which transport?

| Transport | When to use |
| --------- | ----------- |
| **UDS** (`Varta.Connect`) | Same-host deployment. On observer platforms with pathname-datagram peer credentials (Linux and supported BSD/illumos/Solaris targets), beats become `BeatOrigin::KernelAttested` and are eligible for observer-driven recovery. macOS pathname UDS is `SocketModeOnly`, so recovery is refused there. |
| **UDP** (`Varta.ConnectUdp`) | Same-host or LAN when UDS is unavailable (or on Windows). Beats are `NetworkUnverified`; recovery is refused by the observer. |
| **Secure UDP** (`Varta.ConnectSecureUdp`) | Same use case as UDP, plus ChaCha20-Poly1305 AEAD encryption for beat confidentiality. Still refused for recovery. |

For same-host .NET agents, UDS is the recommended transport.

## Status values

`Beat()` carries one of three status values. The observer surfaces all three through Prometheus.

| Status | When to send |
| ------ | ------------ |
| `Status.Ok` | Everything is working normally. Send this the vast majority of the time. |
| `Status.Degraded` | Running but unhealthy: high error rate, queue backlog, slow dependency. Not treated as a stall — recorded but does not trigger recovery. |
| `Status.Critical` | About to terminate due to an unrecoverable error. Typically sent by the signal handler, not your main beat loop. |

## Beat outcome

`Beat()` returns a `BeatOutcome` with three boolean properties:

| Property | Meaning | Recommended action |
| -------- | ------- | ------------------ |
| `.IsSent` | Frame handed to the kernel. | Nothing. |
| `.IsDropped` | Frame not sent. Check `.Reason`: `KernelQueueFull`, `NoObserver`, `PeerGone`, or `StorageFull`. | Log at debug level or ignore. |
| `.IsFailed` | Unexpected error (encoding bug, OS resource exhaustion). | Log at warn. Consider calling `agent.Reconnect()`. |

A `IsDropped` outcome is not a bug. Occasional drops are invisible to the observer — only sustained silence triggers a stall.

## Payload field

`Beat(status, payload)` accepts an optional 32-bit unsigned integer. The observer stores it verbatim and exposes it in the Prometheus `varta_agent_payload` gauge. Use it to pack any two metrics you want correlated with liveness:

```csharp
uint queueDepth = 128;
uint lastError  = 3;

// High 16 bits = queue depth. Low 16 bits = last error code.
uint payload = ((queueDepth & 0xFFFFu) << 16) | (lastError & 0xFFFFu);
var status = lastError > 0 ? Status.Degraded : Status.Ok;

agent.Beat(status, payload);
```

The encoding convention is yours to decide. The observer does not interpret the payload field.

## Unix Domain Sockets

UDS is the canonical same-host transport. It is eligible for observer-driven recovery only when the observer platform can attach pathname-datagram peer credentials.

```csharp
using var agent = global::Varta.Varta.Connect("/run/varta/observer.sock");
```

UDS uses `AF_UNIX` + `SOCK_DGRAM`. On Linux and supported BSD/illumos/Solaris observer targets, the kernel attaches peer credentials and the observer records `BeatOrigin::KernelAttested`; on macOS pathname UDS, the observer records `SocketModeOnly`, so recovery is refused.

### Windows

There is no `SOCK_DGRAM` `AF_UNIX` support in the .NET BCL on Windows (only `SOCK_STREAM`). `Varta.Connect(socketPath)` throws `PlatformNotSupportedException` on Windows — use `ConnectUdp` / `ConnectSecureUdp` against a loopback observer instead. Same posture as `@varta-health/client` (Node).

## Signal handler

Register once at startup. Any terminating signal (`SIGTERM` / `SIGINT` / `SIGQUIT` / `SIGHUP`) emits a `Critical` beat with `nonce=NONCE_TERMINAL` before the process exits.

```csharp
using Varta.Panic;

using IDisposable sig = SignalHandler.InstallUds("/run/varta/observer.sock");
// SIGTERM / SIGINT / SIGQUIT / SIGHUP now emit a Critical+NONCE_TERMINAL
// frame to the observer before the process exits.
```

For deferred emission inside an exception pipeline:

```csharp
using Varta.Panic;

SignalHandler.Run(() =>
{
    // Any exception that escapes fires Critical+NONCE_TERMINAL,
    // logs the stack trace, then re-throws.
    DoWork();
});
```

The handler runs on .NET's dedicated signal-handling thread (not the real signal-handler context), so `Socket.Send` is safe inside.

**`.NET 10 Caveat`:** The runtime no longer auto-graceful-shuts on SIGTERM ([breaking change](https://learn.microsoft.com/en-us/dotnet/core/compatibility/core-libraries/10.0/sigterm-signal-handler)). This handler emits the beat and returns; the host process is still responsible for orderly shutdown.

## Secure UDP

```csharp
using Varta;

// key must be exactly 32 raw bytes. Load from appsettings, Key Vault, etc.
byte[] key = Convert.FromHexString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
using var agent = global::Varta.Varta.ConnectSecureUdp("127.0.0.1", 9443, key);
agent.Beat(Status.Ok, payload: 0);
```

ChaCha20-Poly1305 and HKDF-SHA256 come from the .NET BCL (`System.Security.Cryptography`) — no extra NuGet packages required.

## API parity with `varta-client` (Rust)

| Rust                                                | .NET                                                                    |
| --------------------------------------------------- | ----------------------------------------------------------------------- |
| `Varta::connect(path)` (UDS)                        | `Varta.Connect(path)`                                                   |
| `Varta::connect_udp(addr)`                          | `Varta.ConnectUdp(host, port)`                                          |
| `Varta::connect_secure_udp(addr, key)`              | `Varta.ConnectSecureUdp(host, port, key)`                               |
| `Varta::connect_secure_udp_with_master(addr, mkey)` | `Varta.ConnectSecureUdpWithMaster(host, port, masterKey)`               |
| `Varta::beat(status, payload) -> BeatOutcome`       | `agent.Beat(status, payload) -> BeatOutcome`                            |
| `BeatOutcome::{Sent, Dropped, Failed}`              | `BeatOutcome` (`.IsSent` / `.IsDropped` / `.IsFailed`)                   |
| `DropReason::{KernelQueueFull, NoObserver, PeerGone, StorageFull}` | `DropReason` enum — same four variants              |
| `BeatError { errno, kind }`                         | `BeatError` with `Errno` and `Kind` fields                              |
| `classify_send_error`                               | `BeatOutcome.ClassifySendError(exc)`                                    |
| `Varta::reconnect`, `set_reconnect_after`           | `agent.Reconnect()`, `agent.SetReconnectAfter(n)`                       |
| `Varta::clock_regressions()`, `fork_recoveries()`   | `agent.ClockRegressions()`, `agent.ForkRecoveries()`                    |
| `install_panic_handler*`                            | `SignalHandler.InstallUds/Udp/SecureUdp` + `SignalHandler.Run(action)` |

## Hard invariants

The .NET client preserves the Rust client's wire-level contract:

1. **Non-blocking I/O.** Every socket is non-blocking. A kernel-queue-full send surfaces as `BeatOutcome.Dropped(DropReason.KernelQueueFull)`, never a block.
2. **Per-emission `Process.GetCurrentProcess().Id`.** No PID caching — child processes (via `Process.Start`) report their own identity on the next beat. Fork auto-recovery refreshes the transport (and, for secure-UDP, re-reads entropy) before the frame leaves the child.
3. **Wire-format conformance.** The package ships tests that load `tools/vlp-test-vectors.json` (the same fixture the Rust crate verifies against) and assert byte-equality for every CRC, frame, and AEAD vector. Drift between languages is impossible without breaking both test suites in the same PR.

## Latency note

.NET's per-beat cost sits in the **~10–50 µs** band (GC overhead, BCL abstractions, one syscall). That is slower than the Rust client (~1 µs) but comparable to Go (~5–15 µs). The .NET client is designed for sidecars, long-running services, HTTP middleware, and operator tooling — not for tight inner loops emitting kilo-beats per second.

## Non-goals

- **Windows UDS.** UDP / Secure UDP only.
- **Async `BeatAsync`.** `Beat()` performs a single non-blocking `send(2)`; an async wrapper would be pure overhead.
- **Connection-pool / hot-reload of keys.** Construct a new `Varta` agent instance and dispose the old one.
- **AOT-friendliness audit.** Should work under PublishAot (no reflection in the hot path), but is not yet verified in CI.

## Stability

- **Wire format:** VLP v0.2, governed by `book/src/spec/vlp.md` in the workspace. Cross-language byte-equality is enforced by the conformance test suite.
- **.NET API:** independent semver, tracked in [`clients/dotnet/CHANGELOG.md`](https://github.com/aramirez087/Varta/blob/main/clients/dotnet/CHANGELOG.md).
- **.NET version:** `net8.0` (LTS) and `net10.0` (LTS) minimum.

## See also

- [Normative wire spec](../../book/src/spec/vlp.md)
- [Conformance vectors](../../tools/vlp-test-vectors.json)
- [Rust agent crate](../../crates/varta-client/)
- [Python client](../python/)
- [Go client](../go/)
- [Node.js client](../node/)
- [Observer](../../crates/varta-watch/)
- [Changelog](CHANGELOG.md)

## Building & testing

```bash
dotnet build clients/dotnet/Varta.slnx -c Release
dotnet test  clients/dotnet/tests/Varta.Client.Tests -c Release \
  --filter "FullyQualifiedName!~Interop"
```

Interop tests against a live `varta-watch`:

```bash
cargo build --release -p varta-watch --features prometheus-exporter
VARTA_WATCH_BIN=$(pwd)/target/release/varta-watch \
  dotnet test clients/dotnet/tests/Varta.Client.Tests -c Release \
  --filter "FullyQualifiedName~Interop"
```

## License

`MIT OR Apache-2.0`, at your option. Same as the Varta workspace.
