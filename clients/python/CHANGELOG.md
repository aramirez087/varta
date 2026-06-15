# Changelog — Varta Python client

All notable changes to the Python client live here. Versions follow
[Semantic Versioning](https://semver.org). The wire protocol version is
governed independently — see `book/src/spec/vlp.md` in the workspace.

## [Unreleased]

### Fixed

- **Secure-UDP nonce-wrap rotation now honours commit-on-success.** At the
  32-bit IV-counter boundary, `SecureUdpTransport.send` rotated the IV prefix
  (`_iv_prefix_index += 1`, `_iv_counter = 0`, re-derive `_iv_prefix`) *before*
  the `socket.send` syscall. A Dropped send — a non-blocking socket raising
  `BlockingIOError`/`EWOULDBLOCK` under backpressure — at that boundary
  therefore left the transport's prefix index and counter rotated even though
  no datagram reached the kernel, contradicting the contract the code comment
  itself claimed ("rotate … so a Dropped send does not advance the counter past
  its wrap boundary") and the cross-client invariant that no send-path state
  mutates on a Dropped send. The wrap is now computed into locals and committed
  only after the syscall returns, mirroring the Rust reference and the Go client
  fix. The regular-counter path was already correct; only the wrap rotation was
  eager. Wire format unchanged.

- **Solaris / illumos: corrected the `ENOBUFS` errno value (111 → 132).**
  `_errno.py` hard-coded the solarish `ENOBUFS` as `111`, but the real
  `<sys/errno.h>` value is `132` (`111` is Linux's `ECONNREFUSED` and is
  undefined on solarish). On Solaris/illumos a genuine send-buffer `ENOBUFS`
  therefore never matched `classify_send_error`'s `code == ENOBUFS` branch and
  was misclassified as a hard `BeatOutcome.failed` instead of
  `Dropped(KERNEL_QUEUE_FULL)`, breaking the dropped-beat taxonomy and the
  `set_reconnect_after` auto-recovery (which counts only `Dropped`). Matches the
  Rust reference and the Node client; this is the Python sibling of Rust
  bug-470.

### Security

- **Beat path: closed an AEAD nonce-reuse hole under fork + PID recycling.**
  `Varta.beat` detected `fork(2)` by comparing only the live PID to the
  connect-time PID. A descendant that inherited a secure-UDP session
  (16-byte salt + IV prefix/counter) and was *later reassigned its ancestor's
  connect-time PID* through PID recycling passed `pid == connect_pid`, skipped
  the reconnect, and re-derived an IV prefix its ancestor had already used
  under the same key — a ChaCha20-Poly1305 `(key, nonce)` collision
  (keystream + Poly1305 one-time-key recovery → plaintext disclosure and
  frame forgery). `beat` now also compares a process-lineage epoch
  (`varta._fork_epoch`, an `os.register_at_fork` child-callback counter) and
  reconnects when *either* the PID or the epoch changes, so the re-seed fires
  regardless of how the PID was reassigned. Mirrors the Rust reference
  (`fork_epoch.rs`, bug-442). Wire-transparent — no observer or spec change.

- **Secure-UDP panic hook: closed an AEAD nonce-reuse hole under PID
  recycling.** The hook detected `fork(2)` by comparing the live PID to the
  install-time PID and only re-randomized its IV salt on a mismatch. A
  descendant that inherited the install state and was later reassigned the
  installer's exact PID passed the equality check, re-derived the same
  `derive_iv_prefix(salt, 0)` prefix, and sealed its first panic frame under
  the installer's `(key, nonce)` — a ChaCha20-Poly1305 nonce collision
  (keystream + Poly1305 one-time-key recovery → plaintext disclosure and
  forgery of attested panic frames). The hook now derives **every** prefix
  from `derive_panic_iv_prefix(salt, pid, timestamp, counter)`, mixing the
  strictly-monotonic terminal timestamp so the nonce is unique across
  `fork(2)` and PID recycling without any PID-equality probe or in-hook
  entropy read. Mirrors the Rust reference (`derive_panic_iv_prefix`) and is
  byte-for-byte identical across the Rust/Go/Node clients (shared
  known-answer vector). Wire-transparent — no observer or spec change.

### Fixed

- Panic emitters now claim terminal timestamps from a process-wide monotonic
  high-water mark. Clock rollback, equal samples, and handler replacement can
  no longer make a later genuine panic look like a replay. Forked children
  also reset the timestamp-claim lock so they cannot inherit it permanently
  locked by a vanished parent thread.

- UDS, UDP, and secure-UDP reconnects are now transactional: replacement
  sockets and secure-session material are prepared before the active
  transport is retired. A failed reconnect no longer leaves the agent with
  `_sock = None`, which previously made the next `beat()` raise an internal
  `AssertionError`.

- `Varta.beat()` now rejects observer-only `Status.STALL` inputs
  (`Status.STALL`, `"stall"`, or `3`) with `BeatOutcome.failed`
  / `InvalidInput` before reconnecting or sending. `Stall` is synthesized
  by `varta-watch` and is forbidden on the wire.

- Auto-reconnect (`set_reconnect_after`) now resets the consecutive-dropped
  counter only after a *successful* `reconnect()`, matching the frozen
  cross-client contract (Rust `varta-client`). Previously the counter was
  zeroed before the reconnect attempt, so a failed reconnect during a
  sustained observer outage re-armed a full `reconnect_after`-beat window
  instead of retrying on the very next dropped beat.

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
