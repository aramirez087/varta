# Changelog — Varta Python client

All notable changes to the Python client live here. Versions follow
[Semantic Versioning](https://semver.org). The wire protocol version is
governed independently — see `book/src/spec/vlp.md` in the workspace.

## [0.1.0] — 2026-05-16

Initial release. Production client for the Varta health protocol.

### Added

- `Varta` agent with `connect()` (UDS), `connect_udp()`,
  `connect_secure_udp()`, and `connect_secure_udp_with_master()`
  constructors mirroring the Rust `varta-client` crate.
- `beat(status, payload)` returning a `BeatOutcome` tagged dataclass
  (`sent` / `dropped` / `failed`) with the four-way `DropReason`
  taxonomy.
- `classify_send_error(exc)` exported for custom transport authors.
- Saturating counters `clock_regressions()` and `fork_recoveries()`.
- Fork auto-detection: a PID-change between `connect()` and the next
  `beat()` triggers an in-process `reconnect()` so secure-UDP IV state
  is rotated before any frame leaves the child process.
- `varta.panic.install_excepthook_uds/udp/secure_udp` family — emit a
  `Status.CRITICAL` frame with `nonce=NONCE_TERMINAL` on uncaught
  exceptions; optional `faulthandler` integration for hard crashes.
- Wire-format conformance against `tools/vlp-test-vectors.json`
  (CRC-32C, base frames, KDF derivations, AEAD seal/open).
- Type hints throughout; `py.typed` marker per PEP 561.

### Stability

- Wire format: VLP v0.2, governed by `book/src/spec/vlp.md`.
- Python API: 0.x — refinements may land without deprecation cycles
  until 1.0.
