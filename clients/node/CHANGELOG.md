# Changelog — Varta Node.js client

All notable changes to the Node.js client live here. Versions follow
[Semantic Versioning](https://semver.org). The wire protocol version is
governed independently — see `book/src/spec/vlp.md` in the workspace.

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
