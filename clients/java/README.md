# varta-client — JVM client for Varta VLP v0.2

[![Maven Central](https://img.shields.io/maven-central/v/health.varta/varta-client.svg)](https://central.sonatype.com/artifact/health.varta/varta-client)

`health.varta:varta-client` is the official JVM client for the
[Varta](https://github.com/aramirez087/Varta) zero-overhead health
protocol. A Varta agent emits 32-byte heartbeats to a local observer
(`varta-watch`) that detects stalls, triggers recovery commands, and
exports Prometheus metrics.

This package is a first-class peer of the Rust, Python, Go, Node, and
.NET clients — independent semver, identical wire format, identical
public surface.

```kotlin
// build.gradle.kts
dependencies {
    implementation("health.varta:varta-client:0.1.0")
    // UDS transport requires a SOCK_DGRAM AF_UNIX provider.
    // junixsocket is the recommended default (no shipping JDK provides
    // SOCK_DGRAM AF_UNIX in-box, as of JDK 22).
    runtimeOnly("com.kohlschutter.junixsocket:junixsocket-core:2.10.1")
}
```

```xml
<!-- pom.xml -->
<dependency>
  <groupId>health.varta</groupId>
  <artifactId>varta-client</artifactId>
  <version>0.1.0</version>
</dependency>
<dependency>
  <groupId>com.kohlschutter.junixsocket</groupId>
  <artifactId>junixsocket-core</artifactId>
  <version>2.10.1</version>
  <scope>runtime</scope>
</dependency>
```

## What is Varta?

Varta is a health protocol for processes running on the same host (or
same network segment). Your process calls `agent.beat(Status.OK)` on a
fixed schedule — typically every 500 ms. A companion observer
(`varta-watch`) watches the socket, detects when beats stop arriving,
and fires a configurable recovery command.

The wire is 32 bytes per beat. No HTTP, no JSON. The base client uses
only the JDK (zero runtime dependencies).

## Quickstart

```java
import health.varta.*;
import java.nio.file.Path;

try (Varta agent = Varta.connect(Path.of("/run/varta/observer.sock"))) {
    while (true) {
        BeatOutcome outcome = agent.beat(Status.OK, 0);
        if (outcome.isDropped()) {
            // Backpressure or observer absent. The call never blocks
            // and never throws — the application decides what to do.
        }
        Thread.sleep(500);
    }
}
```

## How it works

`beat()` encodes a 32-byte frame (PID, monotonic timestamp, status,
nonce, 32-bit payload, CRC-32C) and sends it to `varta-watch`. The
observer tracks the last-seen timestamp per PID. If a PID goes silent
longer than `--threshold-ms`, the observer marks it stalled and fires
any configured recovery command.

No polling. No persistent connection state beyond the socket file
descriptor.

## Which transport?

| Transport | When to use |
| --- | --- |
| **UDS** (`Varta.connect(path)`) | Same-host deployment. On observer platforms with pathname-datagram peer credentials (Linux and supported BSD/illumos/Solaris targets), beats become `BeatOrigin::KernelAttested` and are eligible for observer-driven recovery. macOS pathname UDS is `SocketModeOnly`, so recovery is refused there. |
| **UDP** (`Varta.connectUdp(addr)`) | Same-host or LAN when UDS is unavailable (or on Windows). Beats are `NetworkUnverified`; recovery is refused by the observer. |
| **Secure UDP** (`Varta.connectSecureUdp(addr, key)`) | Same use case as UDP, plus ChaCha20-Poly1305 AEAD encryption for beat confidentiality. Still refused for recovery. |

For same-host JVM agents, UDS is the recommended transport.

### UDS provider

No shipping JDK (through 22+) provides `SOCK_DGRAM` `AF_UNIX` —
`UnixDomainSocketAddress` (JDK 16+) is hard-coded `SOCK_STREAM`. The
client probes for a provider at `connect()` time:

| Provider | When discovered | Requirements |
| --- | --- | --- |
| **FFM** (`varta-client-ffm`, future) | JDK 22+ with `health.varta:varta-client-ffm` on the classpath | Zero registry deps; needs `--enable-native-access=ALL-UNNAMED` |
| **junixsocket** | `com.kohlschutter.junixsocket:junixsocket-core` on the classpath | Recommended for JDK 17/21. Bundles native libs for Linux/macOS/Windows. |

If neither provider is present, `Varta.connect(path)` throws
`NoUdsTransportException` with a message naming both remediation
paths.

## Status values

`beat()` carries one of three status values. The observer surfaces all
three through Prometheus.

| Status | When to send |
| --- | --- |
| `Status.OK` | Everything is working normally. Send this the vast majority of the time. |
| `Status.DEGRADED` | Running but unhealthy: high error rate, queue backlog, slow dependency. Not treated as a stall — recorded but does not trigger recovery. |
| `Status.CRITICAL` | About to terminate due to an unrecoverable error. Typically sent by the signal handler, not your main beat loop. |

## Beat outcome

`beat()` returns a `BeatOutcome` modelled as a sealed interface (Java 17+).

| Variant | Meaning | Recommended action |
| --- | --- | --- |
| `Sent` | Frame handed to the kernel. | Nothing. |
| `Dropped(reason)` | Frame not sent. `reason` is one of `KERNEL_QUEUE_FULL`, `NO_OBSERVER`, `PEER_GONE`, `STORAGE_FULL`. | Log at debug or ignore. |
| `Failed(error)` | Unexpected error (encoding bug, OS resource exhaustion). | Log at warn. Consider `agent.reconnect()`. |

A `Dropped` outcome is not a bug. Occasional drops are invisible to the
observer — only sustained silence triggers a stall.

```java
BeatOutcome outcome = agent.beat(Status.OK, 0);
if (outcome instanceof BeatOutcome.Dropped d) {
    log.debug("dropped: {}", d.reason());
} else if (outcome instanceof BeatOutcome.Failed f) {
    log.warn("failed: {} ({})", f.error().kind(), f.error().errno());
}
// JDK 21+ users can use pattern-switch:
//   switch (outcome) {
//       case BeatOutcome.Sent s    -> {}
//       case BeatOutcome.Dropped d -> log.debug("dropped: {}", d.reason());
//       case BeatOutcome.Failed f  -> log.warn("failed: {}", f.error());
//   }
```

## Payload field

`beat(status, payload)` accepts an optional 32-bit signed integer (the
observer interprets it as unsigned). The observer stores it verbatim
and exposes it in the Prometheus `varta_agent_payload` gauge.

## Unix Domain Sockets

UDS is the canonical same-host transport and the only JVM transport
eligible for observer-driven recovery.

```java
try (Varta agent = Varta.connect(Path.of("/run/varta/observer.sock"))) { ... }
```

### Windows

Neither junixsocket's nor the (future) FFM provider exposes `AF_UNIX`
`SOCK_DGRAM` on Windows in a portable, kernel-attested way. On
Windows, use `Varta.connectUdp(...)` against a loopback observer
instead. Same posture as the Node.js client.

## Signal handler

Register once at startup. Any terminating signal
(`SIGTERM`/`SIGINT`/`SIGQUIT`/`SIGHUP`) — or any JVM exit — emits a
`CRITICAL` beat with `nonce = NONCE_TERMINAL` before the process exits.

```java
import health.varta.panic.SignalHandler;

try (AutoCloseable sig = SignalHandler.installShutdownHookUds(
        Path.of("/run/varta/observer.sock"))) {
    // ... application code ...
}
```

`installShutdownHookUds` works on all OSes (uses
`Runtime.addShutdownHook`). For explicit POSIX signal trapping
(distinguish SIGTERM from SIGINT), use `installSignalHandlerUds`
(Linux/macOS only — Windows throws).

The handler runs on the JVM's shutdown thread (not real signal
context), so `channel.write` inside is safe.

## Secure UDP

```java
import health.varta.*;
import java.net.InetSocketAddress;
import java.util.HexFormat;

byte[] keyBytes = HexFormat.of().parseHex(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
Key key = Key.fromBytes(keyBytes);

try (Varta agent = Varta.connectSecureUdp(
        new InetSocketAddress("127.0.0.1", 9443), key)) {
    agent.beat(Status.OK, 0);
}
```

ChaCha20-Poly1305 comes from the standard JCE (`Cipher.getInstance("ChaCha20-Poly1305")`,
since JDK 11). HKDF-SHA256 is implemented in-process via
`javax.crypto.Mac` (~30 lines). Zero extra dependencies.

## API parity with `varta-client` (Rust)

| Rust | JVM |
| --- | --- |
| `Varta::connect(path)` | `Varta.connect(path)` |
| `Varta::connect_udp(addr)` | `Varta.connectUdp(addr)` |
| `Varta::connect_secure_udp(addr, key)` | `Varta.connectSecureUdp(addr, key)` |
| `Varta::connect_secure_udp_with_master(addr, mkey)` | `Varta.connectSecureUdpWithMaster(addr, mkey)` |
| `Varta::beat(status, payload) -> BeatOutcome` | `agent.beat(status, payload)` |
| `BeatOutcome::{Sent, Dropped, Failed}` | `BeatOutcome` sealed interface, same three variants |
| `DropReason` (4 variants) | `DropReason` enum, same four variants |
| `BeatError { errno, kind }` | `BeatError(int errno, String kind)` record |
| `Varta::reconnect / set_reconnect_after` | `agent.reconnect()` / `agent.setReconnectAfter(n)` |
| `Varta::clock_regressions / fork_recoveries` | `agent.clockRegressions()` / `agent.forkRecoveries()` |
| `install_panic_handler*` | `SignalHandler.installShutdownHook*` / `installSignalHandler*` |

## Hard invariants

The JVM client preserves the Rust client's wire-level contract:

1. **Non-blocking I/O.** Every socket is non-blocking. A
   kernel-queue-full send surfaces as
   `Dropped(KERNEL_QUEUE_FULL)`, never a block.
2. **Per-emission `ProcessHandle.current().pid()`.** No PID caching.
   Child processes report their own identity on the next beat. Fork
   auto-recovery refreshes the transport (and, for Secure UDP,
   re-reads entropy) before the frame leaves the child.
3. **Wire-format conformance.** The package ships tests that load
   `tools/vlp-test-vectors.json` and assert byte-equality for every
   CRC, frame, and AEAD vector. Drift between languages is impossible
   without breaking both test suites in the same PR.
4. **Zero runtime deps in the base jar.** A `verifyZeroRuntimeDeps`
   Gradle task fails the build if anything leaks into
   `runtimeClasspath`. junixsocket is `compileOnly` + `testImplementation`
   only — users opt in by adding it themselves.

## Latency note

The JVM client's per-beat cost sits in the **~5–20 µs band** under HotSpot
C2 after warmup (one `Cipher.init` + one `clock_gettime` + one
non-blocking `send(2)`). Slower than Rust (~1 µs) but comparable to Go.
Designed for sidecars, long-running services, web middleware, and
operator tooling — not for tight inner loops emitting kilo-beats per
second.

JMH `BeatLatencyBenchmark` results target **0 bytes/op** on the happy
path after warmup. See `benchmarks/`.

## Non-goals

- **Kotlin coroutines / Reactor / RxJava wrappers.** `beat()` is
  non-blocking sync; an async wrapper would be pure overhead.
- **Spring Boot starter.** Would force a Spring transitive dep. May
  ship as a separate artifact in a later release.
- **Micrometer adapter.** The agent exposes `forkRecoveries()` and
  `clockRegressions()`; register your own gauges.
- **SLF4J.** The base jar uses `System.err.println` for the single
  nonce-wrap warning. No logging-API dependency.
- **Android.** Use the Rust client compiled via cross-compilation, or
  wait for a dedicated `varta-client-android` artifact.
- **`module-info.java`.** v0.1 ships an automatic module
  (`Automatic-Module-Name: health.varta.client`). Reconsidered in v0.2+
  once the multi-module story settles.

## Stability

- **Wire format:** VLP v0.2, governed by `book/src/spec/vlp.md` in the
  workspace. Cross-language byte-equality enforced by the conformance
  test suite.
- **JVM API:** independent semver, tracked in
  [`CHANGELOG.md`](CHANGELOG.md).
- **JVM version:** JDK 17 (LTS) minimum.

## See also

- [Normative wire spec](../../book/src/spec/vlp.md)
- [Conformance vectors](../../tools/vlp-test-vectors.json)
- [Rust agent crate](../../crates/varta-client/)
- [Python client](../python/)
- [Go client](../go/)
- [Node.js client](../node/)
- [.NET client](../dotnet/)
- [Observer](../../crates/varta-watch/)
- [Changelog](CHANGELOG.md)

## Building & testing

```bash
cd clients/java
./gradlew :lib:test --tests "*" --tests "!*Interop*"
```

Interop tests against a live `varta-watch`:

```bash
cargo build --locked --release -p varta-watch --features prometheus-exporter
cd clients/java
VARTA_WATCH_BIN=$(pwd)/../../target/release/varta-watch \
  ./gradlew :lib:test --tests "*Interop*"
```

JMH micro-benchmarks:

```bash
cd clients/java && ./gradlew :benchmarks:jmh
```

## License

`MIT OR Apache-2.0`, at your option. Same as the Varta workspace.
