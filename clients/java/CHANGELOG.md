# Changelog — Varta JVM client

All notable changes to the `health.varta:varta-client` Maven Central
artifact are documented here. Versioning is independent of the Rust
workspace and follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- **Secure-UDP reconnects before terminal AEAD nonce exhaustion.** The JVM
  client intentionally uses `Integer.MAX_VALUE` as its conservative local
  counter boundary, but the double-exhaustion state still followed the ordinary
  prefix-rotation path and could overflow the signed prefix index. It now
  treats that terminal state as session exhaustion and runs the existing
  transactional reconnect before sealing another frame, preserving
  commit-on-success semantics for the ordinary wrap beat.

### Fixed

- **Short successful sends are no longer committed as delivered beats.** The
  agent now requires transports to report the full 32-byte logical frame before
  returning `Sent`; positive short writes surface as `Failed(WriteZero)` and
  leave nonce/timestamp state uncommitted. Secure UDP also verifies the full
  60- or 64-byte AEAD wire frame before advancing IV state.

- **Solaris/illumos `ENOBUFS` is now classified as
  `Dropped(KERNEL_QUEUE_FULL)`.** The numeric junixsocket errno table handled
  Linux `105` and BSD/macOS `55` but missed solarish `132`, so real send-buffer
  backpressure on Solaris/illumos could surface as `Failed` instead of a
  transient dropped beat. This now matches the Rust, Python, and Node clients.

- **Secure-UDP `reconnect()` is now transactional and never throws an unchecked
  exception.** It reconnected the inner socket first and only then called
  `rotateSession()` to refresh the IV state (entropy read + KDF). If that
  refresh failed — `SecureRandom`/KDF unavailable, entropy exhausted, seccomp
  restriction — it threw an unchecked `IllegalStateException`, which is NOT
  caught by `beat()`'s fork-recovery `catch (IOException)` and so escaped
  `beat()` entirely, crashing the caller's beat loop (a never-throws-contract
  violation); and it left the transport with a freshly-reconnected socket paired
  with stale IV state. `reconnect()` now prepares all fallible session material
  (entropy + IV prefix) into locals first, surfacing any failure as a checked
  `IOException` (so `beat()` returns `Failed`), and only then reconnects the
  socket and commits — so a failure leaves the transport entirely unchanged.
  Mirrors the Rust and .NET prepare-then-commit reconnect.

- **POSIX signal panic handler no longer clobbers the host's own signal
  handler.** `SignalHandler.installSignalHandler*` installed a
  `sun.misc.Signal` handler that, on `SIGTERM`/`SIGINT`/`SIGQUIT`/`SIGHUP`,
  emitted the terminal beat and then called `System.exit(128 + signum)`. That
  captured the previously-installed handler but never invoked it — a host that
  had registered its own `sun.misc.Signal` handler (custom teardown, a JNI
  library) had it silently bypassed, the JVM sibling of the Node
  `removeAllListeners` clobber. The handler now emits, **restores the previously
  installed handler, and re-raises** the signal, so that handler (or the JVM
  default disposition, which still runs shutdown hooks) runs and the process
  exits with the conventional `128 + signum` status. Mirrors the cross-client
  contract — Node re-raises after removing its own listener, Go uses
  `signal.Reset` + re-raise, and the Rust/Python hooks chain to the previous
  hook. The `installShutdownHook*` installers are unaffected.

- **A failed fork-recovery reconnect now surfaces as `Failed`, not `Dropped`.**
  When `beat()` detects a `fork(2)` (the cached connect PID no longer matches)
  it reconnects the transport before emitting. If that `reconnect()` threw, the
  exception was routed through `ErrnoClassifier.classify(e)`, which maps
  recognised conditions — e.g. a "Connection refused" `SocketException` — to
  `Dropped(NO_OBSERVER)`. A fork-recovery reconnect failure is a *terminal*
  error (the fork invalidated the old socket and a new one could not be
  established), so reporting `Dropped` told the caller the beat path was still
  operational and invited an indefinite retry loop instead of escalating the
  hard failure. The fork-recovery path now returns
  `BeatOutcome.failed(new BeatError(0, "ReconnectFailed"))` unconditionally,
  matching the Rust reference (`BeatOutcome::Failed`) and the Go, Python, Node,
  and .NET clients. The regular auto-reconnect path (a send that keeps dropping)
  still uses `ErrnoClassifier` and is unaffected.

- **Secure-UDP: the IV-prefix rotation at the counter-wrap boundary is now
  commit-on-success.** `SecureUdpTransport.send` rotated the committed prefix
  index, re-derived the IV prefix (an HKDF on the hot beat path), and reset the
  counter *unconditionally before* the datagram was sent; only the post-send
  `counter++` was gated on success. A failed send (`WouldBlock`/`ENOBUFS`) at
  the single beat where `counter == Integer.MAX_VALUE` therefore burned a prefix
  index and left the committed IV state inconsistent with what was transmitted.
  The wrap is now computed into locals and committed only after a successful
  send, so a retry re-sends the same `(prefix, counter)` — matching the Rust
  reference's commit-on-success contract. (No nonce reuse was reachable; this is
  a state-machine / contract fix.)
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
