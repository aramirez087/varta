# Changelog — Varta Node.js client

All notable changes to the Node.js client live here. Versions follow
[Semantic Versioning](https://semver.org). The wire protocol version is
governed independently — see `book/src/spec/vlp.md` in the workspace.

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
