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

## Transports

| Factory | Wire | Where |
|---------|------|-------|
| `Varta.Connect(socketPath)` | UDS (AF_UNIX SOCK_DGRAM) | Linux, macOS |
| `Varta.ConnectUdp(host, port)` | plaintext UDP, 32 B | all OSes |
| `Varta.ConnectSecureUdp(host, port, key)` | ChaCha20-Poly1305 AEAD, 60 B | all OSes (`ChaCha20Poly1305.IsSupported`) |
| `Varta.ConnectSecureUdpWithMaster(host, port, masterKey)` | ChaCha20-Poly1305 AEAD, 64 B (HKDF per-agent key, `agent_pid` as AAD) | all OSes |

UDS is the recommended transport in production: the observer
authenticates the sender via kernel-attested peer credentials, which no
network transport can match.

## Windows

There is no SOCK_DGRAM AF_UNIX support in the .NET BCL on Windows
(only SOCK_STREAM). `Varta.Connect(socketPath)` throws
`PlatformNotSupportedException` on Windows — use `ConnectUdp` /
`ConnectSecureUdp` against a loopback observer instead. Same posture
as `@varta-health/client` (Node).

## Parity with the Rust client

| Feature | Rust (`varta-client`) | This package |
|---------|------------------------|--------------|
| Non-blocking `beat()` | ✅ | ✅ |
| Returns `BeatOutcome` (Sent / Dropped / Failed) | ✅ | ✅ |
| `DropReason` taxonomy (KernelQueueFull / NoObserver / PeerGone / StorageFull) | ✅ | ✅ |
| 32-byte VLP v0.2 frame with CRC-32C (Castagnoli) | ✅ | ✅ |
| ChaCha20-Poly1305 secure UDP (shared + master) | ✅ | ✅ |
| Fork-safety (PID snapshot at connect; auto-reconnect on mismatch) | ✅ | ✅ |
| Saturating fork-recovery + clock-regression counters | ✅ | ✅ |
| Panic-equivalent installs Critical + NONCE_TERMINAL beat on signal | ✅ | ✅ (`Varta.Panic.SignalHandler`) |
| Conformance against `tools/vlp-test-vectors.json` | ✅ | ✅ |

## Signal handler ("panic" equivalent)

```csharp
using Varta.Panic;

using IDisposable sig = SignalHandler.InstallUds("/run/varta/observer.sock");
// SIGTERM / SIGINT / SIGQUIT / SIGHUP now emit a Critical+NONCE_TERMINAL
// frame to the observer before the process exits.

SignalHandler.Run(() =>
{
    // Any escaped exception fires the same Critical+NONCE_TERMINAL emit
    // (defer/recover analogue) and is then re-thrown.
});
```

The handler runs on .NET's dedicated signal-handling thread (not the
real signal-handler context), so `Socket.Send` is safe inside.

.NET 10 caveat: the runtime no longer auto-graceful-shuts on SIGTERM
([breaking change](https://learn.microsoft.com/en-us/dotnet/core/compatibility/core-libraries/10.0/sigterm-signal-handler)).
This handler emits the beat and returns; the host process is still
responsible for orderly shutdown.

## Non-goals

- **Windows UDS.** UDP / Secure UDP only.
- **Async `BeatAsync`.** `Beat()` performs a single non-blocking
  `send(2)`; an async wrapper would be pure overhead.
- **Connection-pool / hot-reload of keys.** Construct a new `Varta`
  agent instance and dispose the old one.
- **AOT-friendliness audit.** Should work under PublishAot (no
  reflection in the hot path), but is not yet verified in CI.

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
