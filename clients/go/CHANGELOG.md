# Changelog — Varta Go client

All notable changes to the Go client live here. Versions follow
[Semantic Versioning](https://semver.org). The wire protocol version is
governed independently — see `book/src/spec/vlp.md` in the workspace.

## [Unreleased]

## [0.2.0] — 2026-07-03

### Security

- **Secure-UDP reconnects before terminal AEAD nonce exhaustion.** At
  `(prefixIndex, counter) == (u32::MAX, u32::MAX)`, the transport previously
  advanced the prefix index with normal `uint32` arithmetic, wrapping to
  prefix index `0` under the same session salt and reopening the original nonce
  stream. It now treats the per-session nonce space as exhausted and runs the
  existing transactional reconnect before sealing another frame; a failed
  emergency reconnect leaves the prior socket and AEAD state unchanged.

- **Secure-UDP panic handler: closed an AEAD nonce-reuse hole under PID
  recycling.** The handler detected `fork(2)` by comparing the live PID to the
  install-time PID and only re-randomized its IV salt on a mismatch. A
  descendant that inherited the install state and was later reassigned the
  installer's exact PID passed the equality check, re-derived the same
  `DeriveIVPrefix(salt, 0)` prefix, and sealed its first panic frame under the
  installer's `(key, nonce)` — a ChaCha20-Poly1305 nonce collision (keystream
  + Poly1305 one-time-key recovery → plaintext disclosure and forgery of
  attested panic frames). The handler now derives **every** prefix from
  `DerivePanicIVPrefix(salt, pid, timestamp, counter)`, mixing the
  strictly-monotonic terminal timestamp so the nonce is unique across
  `fork(2)` and PID recycling without any PID-equality probe or in-hook
  entropy read. Mirrors the Rust reference (`derive_panic_iv_prefix`) and is
  byte-for-byte identical across the Rust/Python/Node clients (shared
  known-answer vector). Wire-transparent — no observer or spec change.

### Fixed

- Repeated `panic.InstallSignalHandlerUDS/UDP/SecureUDP` calls now close the
  retired emitter socket when publishing the replacement. Previously every
  reinstall leaked one descriptor, and a stale in-flight emitter could still
  write a terminal frame to the old observer after the latest handler had been
  installed.

- `Reconnect()` now clears the consecutive-dropped counter. A manual reconnect
  after a dropped beat starts a fresh `SetReconnectAfter` window instead of
  letting the next drop immediately reconnect and retry again.

- **`Beat()` after `Close()` now returns `Failed(Closed)` without touching the
  transport.** The Go agent previously closed only the transport; UDS/UDP
  transports nil their socket on close, so a later `Beat()` could panic while
  sending through a nil connection, or run fork/reconnect side effects on an
  already-closed agent. `Close()` is now idempotent at the agent layer,
  `Beat()` fails closed before PID/fork/reconnect/send work, and explicit
  `Reconnect()` is rejected once the agent is closed.

- **Short successful sends are no longer committed as delivered beats.** The
  agent now requires transports to report the full 32-byte logical frame before
  returning `Sent`; a positive short send, or secure UDP's `io.ErrShortWrite`
  after a partial encrypted write, surfaces as `Failed(WriteZero)` and leaves
  nonce/timestamp state uncommitted. Secure UDP also verifies the full 60- or
  64-byte AEAD wire frame before advancing IV state.

- **Secure-UDP nonce-wrap rotation now honours commit-on-success.** At the
  32-bit IV-counter boundary, `SecureUDPTransport.Send` called `rotatePrefix()`
  — which advances `prefixIndex`, resets `counter` to 0, and re-derives the IV
  prefix — *before* the `Write`. A Dropped send (`EWOULDBLOCK`/`ENOBUFS` under
  backpressure, or any transient socket error) at that boundary therefore left
  the transport's prefix index and counter rotated even though no frame reached
  the wire, contradicting the documented contract ("the transport rotates the
  prefix when the counter is about to wrap so a Dropped send never advances past
  the boundary") and the cross-client invariant that no send-path state mutates
  on a Dropped send. The wrap is now computed into locals and committed only
  after a successful `Write`, mirroring the Rust `NonceAdvance` pattern and the
  Java client fix. The regular-counter path was already correct; only the wrap
  rotation was eager. Wire format unchanged.

- Panic emitters now claim terminal timestamps from a process-wide monotonic
  high-water mark. Clock rollback, equal samples, and handler replacement can
  no longer make a later genuine panic look like a replay.

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
