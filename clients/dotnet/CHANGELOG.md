# Changelog — Varta .NET client

All notable changes to the `Varta.Client` NuGet package are documented
here. Versioning is independent of the Rust workspace and follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **`Beat()` no longer throws when a fork-recovery reconnect fails.** The
  fork-detection branch called `_transport.Reconnect()` unguarded, so if the
  forked child could not re-establish the socket the `SocketException`
  propagated straight out of `Beat()` and crashed the caller's beat loop —
  violating the documented never-throws contract. A failed fork reconnect is
  now caught and surfaced as `BeatOutcome.Failed`, matching the Rust reference
  and the Go/Python/Node clients; the connect PID is left unchanged so the next
  beat retries the reconnect.
- **Regular beat: the wire timestamp now saturates instead of overflowing.**
  `Varta.Beat` computed the timestamp as `(ulong)(elapsedTicks * 100L)` in
  signed-`long` arithmetic with no clamp. After a multi-century single-handle
  uptime that overflows `long` into a negative value whose `(ulong)` cast lands
  near the reserved `u64::MAX` `BadTimestamp` sentinel — which the observer
  drops. Conversion now saturates (`SaturatingNanosFromTicks`), matching the
  panic path (`SignalHandler.BuildCriticalFrame`) and the Rust client
  (`elapsed().as_nanos().min(u64::MAX as u128) as u64`). The regular beat was
  the lone unguarded converter.

### Security

- Secure-UDP panic emitter (`SignalHandler.InstallSecureUdp`) now derives its
  ChaCha20-Poly1305 IV prefix from a 16-byte install-time salt plus the
  per-fire `(pid, timestamp)` via HKDF-SHA256 (`Hkdf.DerivePanicIvPrefix`),
  matching the Rust/Go/Python/Node clients byte-for-byte (shared KAT
  `e2615ed3e4f44375`). The previous build sealed every panic frame with a raw
  8-byte entropy IV at `ivCounter = 0`, guarded only by an install-PID-equality
  probe that re-read entropy on a detected fork(2). That probe is defeatable
  under PID recycling (a descendant reassigned the installer's exact PID reuses
  the inherited prefix at counter 0) and left cross-process collision at the
  64-bit birthday bound (~2³² frames under one shared key). Binding the nonce to
  the authenticated `(salt, pid, monotonic timestamp)` makes reuse structurally
  impossible across fork(2) and PID recycling and raises the residual
  cross-process bound to the 128-bit salt. Wire format and on-the-wire
  compatibility are unchanged.

### Fixed

- Panic emitters now claim terminal timestamps from a process-wide monotonic
  high-water mark. Wall-clock rollback, equal samples, and handler replacement
  can no longer make a later genuine panic look like a replay.

- `Varta.Beat()` now rejects observer-only status byte `0x03` (for example
  `(Status)0x03`) with `BeatOutcome.Failed(InvalidInput)` before
  reconnecting or sending. `Stall` is synthesized by `varta-watch` and is
  forbidden on the wire.

- Auto-reconnect (`SetReconnectAfter`) now resets the consecutive-dropped
  counter only after a *successful* `Reconnect()`, matching the frozen
  cross-client contract (Rust `varta-client`). Previously the counter was
  zeroed before the reconnect attempt, so a failed reconnect during a
  sustained observer outage re-armed a full `reconnectAfter`-beat window
  instead of retrying on the very next dropped beat.
- `Beat` now resets the consecutive-dropped counter on a `Failed` outcome
  (not only on `Sent`), so a transient unexpected error no longer leaves a
  spurious reconnect armed for the next drop.
- `SetReconnectAfter` now resets the consecutive-dropped counter, so a
  re-armed threshold gates future drops rather than firing on a
  previously-saturated counter (parity with the other clients).

## [0.1.0] — initial release

- First-class .NET client peer of `crates/varta-client`, published as
  `Varta.Client` on NuGet.
- Targets `net8.0` and `net10.0`. Pure managed code, no native
  dependencies.
- Transports: UDS (Linux/macOS, `AF_UNIX` + `SOCK_DGRAM`), UDP
  (plaintext, dev-only), and Secure UDP (ChaCha20-Poly1305 AEAD,
  shared-key or master-key modes).
- Wire format: VLP v0.2 (32-byte base frame, CRC-32C/Castagnoli
  trailer). Conformance is enforced by `tools/vlp-test-vectors.json`.
- Panic-equivalent: `Varta.Panic.SignalHandler.InstallUds/UDP/SecureUDP`
  registers `PosixSignalRegistration` handlers for
  SIGTERM/SIGINT/SIGQUIT/SIGHUP and emits a `Critical` +
  `NONCE_TERMINAL` beat before the process exits.
- Fork-safety: `Varta.Beat` snapshots PID at `Connect` time, detects
  fork(2) on every beat, and rebuilds the transport (rotating the
  Secure UDP IV salt). Observable via `Varta.ForkRecoveries`.
- Windows: UDP and Secure UDP only. `Varta.Connect(socketPath)` throws
  `PlatformNotSupportedException` on Windows. See README.
