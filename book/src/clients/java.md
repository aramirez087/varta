# JVM (Java) client

[![Maven Central](https://img.shields.io/maven-central/v/health.varta/varta-client.svg)](https://central.sonatype.com/artifact/health.varta/varta-client)

The JVM client (`implementation("health.varta:varta-client:0.2.0")`) is a
first-class peer of the Rust `varta-client` crate. It tracks the same
wire-format contract, passes the same `tools/vlp-test-vectors.json`
conformance suite, and interoperates with the same `varta-watch`
observer binary.

## Install

```kotlin
// build.gradle.kts
dependencies {
    implementation("health.varta:varta-client:0.2.0")
    // UDS transport requires a SOCK_DGRAM AF_UNIX provider.
    runtimeOnly("com.kohlschutter.junixsocket:junixsocket-core:2.10.1")
}
```

Targets JDK 17 LTS minimum (Spring Boot 3.x baseline). The base jar has
**zero runtime dependencies** — ChaCha20-Poly1305 comes from standard
JCE (`Cipher.getInstance("ChaCha20-Poly1305")`, JDK 11+), HKDF-SHA256 is
implemented in-process via `javax.crypto.Mac`, CRC-32C uses the
hardware-accelerated `java.util.zip.CRC32C` (JDK 9+).

No shipping JDK exposes `SOCK_DGRAM` AF_UNIX in standard NIO, so the
client probes the classpath at `connect()` time and uses either
`junixsocket` (recommended) or a future zero-dep FFM module on JDK 22+.

## 20-line example

```java
import health.varta.*;
import java.nio.file.Path;

try (Varta agent = Varta.connect(Path.of("/run/varta/observer.sock"))) {
    while (true) {
        BeatOutcome outcome = agent.beat(Status.OK, 0);
        if (outcome instanceof BeatOutcome.Dropped d) {
            // Four-way taxonomy mirrors the Rust client:
            DropReason _ = d.reason();
        } else if (outcome instanceof BeatOutcome.Failed f) {
            System.err.println("varta beat failed: " + f.error());
        }
        Thread.sleep(500);
    }
}
```

For secure UDP, fork-safety, the signal-handler family, and the full
parity matrix see the package README in the repo:
[`clients/java/README.md`](https://github.com/aramirez087/Varta/blob/main/clients/java/README.md).

## Transports

| Transport | Status | Notes |
| --------- | ------ | ----- |
| Unix Domain Sockets | Supported (Linux, macOS) | `Varta.connect(path)`. Requires a UDS provider on the classpath (`junixsocket` recommended). Classified `BeatOrigin::KernelAttested` only on observer platforms with pathname-UDS peer credentials; macOS observers treat pathname UDS as socket-mode-only, so recovery is refused. `NoUdsTransportException` on Windows. |
| Plaintext UDP | Supported | `Varta.connectUdp(addr)`. Connected-mode `DatagramChannel`; on Linux ICMP `port unreachable` surfaces as `Dropped(NO_OBSERVER)` on a subsequent beat. |
| Secure UDP (ChaCha20-Poly1305) | Supported | `Varta.connectSecureUdp(addr, key)` |
| Master-key secure UDP | Supported | `Varta.connectSecureUdpWithMaster(addr, masterKey)` |

## Stability

- **Wire format**: VLP v0.2, governed by [the spec](../spec/vlp.md).
- **JVM API**: independent semver, tracked in
  [`clients/java/CHANGELOG.md`](https://github.com/aramirez087/Varta/blob/main/clients/java/CHANGELOG.md).

## Source

- [Maven Central page](https://central.sonatype.com/artifact/health.varta/varta-client)
- [GitHub source](https://github.com/aramirez087/Varta/tree/main/clients/java)
- [Issue tracker](https://github.com/aramirez087/Varta/issues)
