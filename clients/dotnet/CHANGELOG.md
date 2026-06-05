# Changelog — Varta .NET client

All notable changes to the `Varta.Client` NuGet package are documented
here. Versioning is independent of the Rust workspace and follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

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
