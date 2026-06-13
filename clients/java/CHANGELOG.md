# Changelog — Varta JVM client

All notable changes to the `health.varta:varta-client` Maven Central
artifact are documented here. Versioning is independent of the Rust
workspace and follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Panic/shutdown terminal frames now carry a strictly increasing
  process-monotonic timestamp instead of a constant zero. The observer uses
  this timestamp to reject terminal replays, so a second genuine failure from
  the same JVM PID is no longer discarded. Concurrent handler invocations are
  also serialized with a non-blocking guard to protect the shared frame and
  secure-UDP nonce state.

## [0.1.0] — initial release

- First-class JVM client peer of `crates/varta-client`, published as
  `health.varta:varta-client` on Maven Central.
- Targets JDK 17+ (Spring Boot 3.x baseline). Pure managed code; base
  jar has zero runtime dependencies.
- Transports: UDS (Linux/macOS, `AF_UNIX` + `SOCK_DGRAM` via the
  user-supplied `junixsocket` provider), UDP (plaintext, dev-only),
  and Secure UDP (ChaCha20-Poly1305 AEAD, shared-key or master-key
  modes).
- Wire format: VLP v0.2 (32-byte base frame, CRC-32C/Castagnoli
  trailer). Conformance enforced byte-for-byte against
  `tools/vlp-test-vectors.json`.
- Panic-equivalent: `health.varta.panic.SignalHandler.installShutdownHook*`
  (universal, JVM shutdown hook) and `installSignalHandler*`
  (POSIX-only, `sun.misc.Signal` trap for SIGTERM/SIGINT/SIGQUIT/SIGHUP)
  emit a `CRITICAL` + `NONCE_TERMINAL` beat before the process exits.
- Fork-safety: `Varta.beat` snapshots PID at `connect` time, detects
  `fork(2)` on every beat, and rebuilds the transport (rotating the
  Secure UDP IV salt). Observable via `Varta.forkRecoveries()`.
- Windows: UDP and Secure UDP only. `Varta.connect(socketPath)` throws
  `NoUdsTransportException` on Windows (no `SOCK_DGRAM` AF_UNIX in
  shipping JDKs). See README.
- API surface modelled with Java 17 sealed interfaces: `BeatOutcome`
  permits `Sent`, `Dropped(reason)`, `Failed(error)`.
