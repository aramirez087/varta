# Changelog — Varta Go client

All notable changes to the Go client live here. Versions follow
[Semantic Versioning](https://semver.org). The wire protocol version is
governed independently — see `book/src/spec/vlp.md` in the workspace.

## [Unreleased]

### Fixed

- UDS, UDP, and secure-UDP reconnects are now transactional: replacement
  sockets and secure-session material are prepared before the active
  transport is retired. A failed reconnect no longer leaves the agent with
  a nil connection that panics on the next `Beat()`.

- `Varta.Beat()` now rejects observer-only status byte `3` (for example
  `varta.Status(3)`) with `BeatOutcomeFailed(InvalidInput)` before
  reconnecting or sending. `Stall` is synthesized by `varta-watch` and is
  forbidden on the wire.

- Auto-reconnect (`SetReconnectAfter`) now resets the consecutive-dropped
  counter only after a *successful* `Reconnect()`, matching the frozen
  cross-client contract (Rust `varta-client`). Previously the counter was
  zeroed before the reconnect attempt, so a failed reconnect during a
  sustained observer outage re-armed a full `reconnectAfter`-beat window
  instead of retrying on the very next dropped beat.

## [0.1.0] — 2026-05-17

Initial release. Production Go client for the Varta health protocol.

### Added

- `Varta` agent with `Connect()` (UDS), `ConnectUDP()`,
  `ConnectSecureUDP()`, and `ConnectSecureUDPWithMaster()` constructors
  mirroring the Rust `varta-client` crate and the Python client.
- `Beat(status, payload)` returning a `BeatOutcome` tagged value
  (`Sent` / `Dropped` / `Failed`) with the four-way `DropReason`
  taxonomy.
- `ClassifySendError(err)` exported for custom transport authors.
- Saturating counters `ClockRegressions()` and `ForkRecoveries()`.
- Fork auto-detection: a PID-change between `Connect*()` and the next
  `Beat()` triggers an in-process `Reconnect()` so secure-UDP IV state
  is rotated before any frame leaves the child process.
- `panic.InstallSignalHandlerUDS/UDP/SecureUDP` — terminating-signal
  handler that emits a `Status=Critical` + `Nonce=NonceTerminal` frame
  before re-raising the signal.
- `panic.Run(fn)` — defer/recover wrapper that emits a Critical frame
  on any Go-runtime panic then re-panics so the runtime can print the
  stack and exit normally.
- Wire-format conformance against `tools/vlp-test-vectors.json`
  (CRC-32C, base frames, KDF derivations, AEAD seal/open).

### Stability

- Wire format: VLP v0.2, governed by `book/src/spec/vlp.md`.
- Go API: 0.x — refinements may land without deprecation cycles
  until 1.0.
