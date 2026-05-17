# .NET client

[![NuGet](https://img.shields.io/nuget/v/Varta.Client.svg)](https://www.nuget.org/packages/Varta.Client/)

The .NET client (`dotnet add package Varta.Client`) is a first-class
peer of the Rust `varta-client` crate. It tracks the same wire-format
contract, passes the same `tools/vlp-test-vectors.json` conformance
suite, and interoperates with the same `varta-watch` observer binary.

## Install

```bash
dotnet add package Varta.Client
```

Targets `net8.0` (LTS) and `net10.0` (LTS). Pure managed code —
ChaCha20-Poly1305 (`System.Security.Cryptography.ChaCha20Poly1305`),
HKDF-SHA256 (`System.Security.Cryptography.HKDF`), and POSIX signals
(`System.Runtime.InteropServices.PosixSignalRegistration`) all come
from the BCL. Zero native dependencies.

## 20-line example

```csharp
using Varta;

using var agent = global::Varta.Varta.Connect("/run/varta/observer.sock");

while (true)
{
    BeatOutcome outcome = agent.Beat(Status.Ok, payload: 0);
    if (outcome.IsDropped)
    {
        // Four-way taxonomy mirrors the Rust client:
        DropReason _ = outcome.Reason;
    }
    else if (outcome.IsFailed)
    {
        Console.Error.WriteLine($"varta beat failed: {outcome.Error}");
    }
    await Task.Delay(500);
}
```

For secure UDP, fork-safety, the signal-handler family, and the full
parity matrix see the package README in the repo:
[`clients/dotnet/README.md`](https://github.com/aramirez087/Varta/blob/main/clients/dotnet/README.md).

## Transports

| Transport | Status | Notes |
| --------- | ------ | ----- |
| Unix Domain Sockets | Supported (Linux, macOS) | `Varta.Connect(path)`. The only transport classified `BeatOrigin::KernelAttested`, so it is the only .NET transport eligible for observer-driven recovery. `PlatformNotSupportedException` on Windows. |
| Plaintext UDP | Supported | `Varta.ConnectUdp(host, port)`. Connected-mode socket; on Linux ICMP `port unreachable` surfaces as `DropReason.NoObserver` on a subsequent beat. |
| Secure UDP (ChaCha20-Poly1305) | Supported | `Varta.ConnectSecureUdp(host, port, key)` |
| Master-key secure UDP | Supported | `Varta.ConnectSecureUdpWithMaster(host, port, masterKey)` |

## Stability

- **Wire format**: VLP v0.2, governed by [the spec](../spec/vlp.md).
- **.NET API**: independent semver, tracked in
  [`clients/dotnet/CHANGELOG.md`](https://github.com/aramirez087/Varta/blob/main/clients/dotnet/CHANGELOG.md).

## Source

- [NuGet page](https://www.nuget.org/packages/Varta.Client/)
- [GitHub source](https://github.com/aramirez087/Varta/tree/main/clients/dotnet)
- [Issue tracker](https://github.com/aramirez087/Varta/issues)
