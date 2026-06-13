# Changelog — Varta Node.js client

All notable changes to the Node.js client live here. Versions follow
[Semantic Versioning](https://semver.org). The wire protocol version is
governed independently — see `book/src/spec/vlp.md` in the workspace.

## [Unreleased]

### Fixed

- UDS, UDP, and secure-UDP reconnects now construct the replacement
  socket before retiring the active one. A failed reconnect preserves
  the usable connection and, for secure UDP, the complete AEAD session.
  Late error/connect/send callbacks from a retired UDP socket are also
  generation-scoped, so they can no longer poison or flush frames
  through the replacement socket.

- `Varta.beat()` now rejects observer-only `Status.Stall` inputs
  (`Status.Stall`, `"stall"`, or `3`) with `{ kind: "failed",
  error.kind: "InvalidInput" }` before reconnecting or sending. `Stall`
  is synthesized by `varta-watch` and is forbidden on the wire.

- Auto-reconnect (`setReconnectAfter`) now resets the consecutive-dropped
  counter only after a *successful* `reconnect()`, matching the frozen
  cross-client contract (Rust `varta-client`). Previously the counter was
  zeroed before the reconnect attempt, so a failed reconnect during a
  sustained observer outage re-armed a full `reconnectAfter`-beat window
  instead of retrying on the very next dropped beat.

## [0.2.2] — 2026-05-29

### Fixed

- First npm publish of `0.2.1` failed with `E404` because the package
  had never been published and the Trusted Publisher binding was
  registered under the wrong npm org. No code changes; version bump to
  republish under the corrected `@varta-health` scope binding.

## [0.2.1] — 2026-05-17

### Fixed

- Documentation: corrected npm package name from `@varta/client` to `@varta-health/client` in all README and book documentation.

## [0.2.0] — 2026-05-17

Lift the two documented v0.1.0 limitations.

### Added

- `Varta.connectUds(path)` constructor. Reaches API parity with the
  Rust, Python, and Go clients. UDS gives the observer kernel-attested
  peer credentials (`BeatOrigin::KernelAttested`) so Node agents now
  qualify for recovery commands.
- `panic.installSignalHandlerUds(path)` parallel to the UDP variant.
  Pre-binds a UDS socket at install time so emission is alloc-free
  in the hot path.
- `UdsTransport` and `UdsUnavailableError` exported from
  `@varta-health/client` for custom-transport authors.

### Changed

- `UdpTransport` and `SecureUdpTransport` now use connected-mode
  sockets (`dgram.Socket.connect`). ICMP `port unreachable` is routed
  through the socket's error event and surfaces as
  `{ kind: "dropped", reason: DropReason.NoObserver }` on the next
  beat (1–2 beat latency). Previously every send to a dead observer
  reported `Sent`; the agent had no way to observe the failure.

### Optional dependency

- `node-unix-socket` (`^0.2.7`, MIT, napi-rs prebuilds for
  darwin-x64/arm64 and linux-x64/arm64 gnu+musl). Listed under
  `optionalDependencies` — install never fails on a platform without
  a published prebuild; UDP/secure-UDP work everywhere.

### Notes

- macOS ICMP propagation is best-effort; peer-gone may stay
  invisible at the agent layer on darwin. Observer-side stall
  detection remains the canonical signal.
- Windows still unsupported (no AF_UNIX SOCK_DGRAM path).

## [0.1.0] — 2026-05-17

Initial release. Production client for the Varta health protocol.

### Added

- `Varta` agent with `Varta.connectUdp()` and
  `Varta.connectSecureUdp()` / `Varta.connectSecureUdpWithMaster()`
  constructors. UDS transport is intentionally deferred to a future
  release — see "Non-goals" in `README.md`.
- `beat(status, payload)` returning a `BeatOutcome` tagged union
  (`sent` / `dropped` / `failed`) with the four-way `DropReason`
  taxonomy mirroring the Rust, Python, and Go clients.
- `classifySendError(err)` exported for custom transport authors.
- Saturating counters `clockRegressions()` and `forkRecoveries()`
  (returned as `bigint`).
- Fork auto-detection: a PID change between connect and the next
  `beat()` triggers a transparent `reconnect()` so secure-UDP IV
  state is rotated before any frame leaves the child process.
- `panic.installSignalHandlerUdp` / `installSignalHandlerSecureUdp`
  — emit a `Status.Critical` frame with `nonce=NONCE_TERMINAL` on
  uncaught exceptions, unhandled rejections, or terminating signals.
- `panic.run(fn)` defer/recover-style wrapper.
- Wire-format conformance against `tools/vlp-test-vectors.json`
  (CRC-32C, base frames, HKDF derivations, AEAD seal/open).
- Full TypeScript types shipped (`.d.ts`); zero npm runtime
  dependencies — ChaCha20-Poly1305 and HKDF-SHA256 come from
  Node's built-in `node:crypto`.

### Stability

- Wire format: VLP v0.2, governed by `book/src/spec/vlp.md`.
- Node.js API: 0.x — refinements may land without deprecation cycles
  until 1.0.
- Minimum Node.js version: 18 LTS.
