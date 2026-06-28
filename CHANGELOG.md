# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Turnkey deployment surface for `varta-watch`.** Five one-paste install
  paths now cover the mainstream operator audiences — `curl |
  sh` installer, multi-arch GHCR container image, Helm chart, `cargo
  binstall`, and a tagged GitHub Release with signed binary tarballs.
  Every artifact is built and signed by the same workflow
  (`.github/workflows/release.yml`): tag-driven, OIDC-only credentials,
  multi-arch buildx, CycloneDX SBOMs via syft, cosign keyless signing,
  SLSA L3 build provenance via `actions/attest-build-provenance`, and
  Helm chart push to `oci://ghcr.io/aramirez087/charts/varta-watch`. New
  CI gates (`docker-build`, `helm-lint`, `helm-parity`,
  `installer-syntax`) keep the deployment surface from rotting between
  releases — `helm-parity` in particular fails the build if the chart's
  default render drifts from the raw manifests under
  `observability/examples/kubernetes/`. New book pages:
  `operations/install.md`, `operations/container.md`,
  `operations/helm.md`. The `RELEASES/` directory hosts a hand-written
  release-notes file per tag; the workflow refuses to publish without
  one (no auto-generated release notes).

### Fixed

- **Go, Python, Java, and .NET secure-UDP no longer reuse or overflow terminal
  AEAD nonce state at double exhaustion (bug-539).** The earlier
  commit-on-success fixes covered the ordinary counter-wrap beat, but the final
  per-session state where both the IV counter and IV prefix index are exhausted
  still diverged outside Rust/Node. Go and .NET could wrap back toward the
  original session prefix, Python raised from the u32 HKDF packing path, and
  Java could overflow its conservative signed boundary. All four clients now
  treat the per-session nonce space as exhausted and run the existing
  transactional secure-session reconnect before reserving another nonce; failed
  emergency reconnects leave the previous AEAD state untouched.
- **Node secure-UDP no longer wraps the AEAD nonce space back to the original
  session prefix (bug-535).** When both the 32-bit IV counter and 32-bit prefix
  index were exhausted, `SecureUdpTransport` wrapped `prefixIndex` to `0` under
  the same session salt, eventually reusing the original ChaCha20-Poly1305
  nonce stream. The Node client now mirrors the Rust reference: double
  exhaustion triggers a transactional secure-session reconnect before another
  frame is built, and failed emergency reconnects leave the prior AEAD state
  unchanged.
- **Forked Rust clients remain nonce-safe after PID recycling (bug-442).** `Varta` and
  direct `SecureUdpTransport` callers now pair PID checks with a process-lineage
  epoch advanced by `pthread_atfork` in every child. A descendant that later
  receives the original connect-time PID can no longer bypass secure-session
  refresh and reuse an inherited ChaCha20-Poly1305 nonce. The beat path adds
  one lock-free atomic load and preserves the zero-allocation, non-blocking,
  zero-dependency, and wire-compatibility contracts.
- **Authenticated rejection events can no longer bypass global rate limiting
  (bug-441).** AEAD-valid secure-UDP payloads that failed inner VLP decoding,
  and kernel-authenticated UDS frames with a forged PID, previously produced
  unbounded rejection events without consuming the shared token bucket.
  Decode and authentication failures now use the same global admission
  accounting as valid frames, while preserving per-PID-first accounting and
  the tracked terminal-frame exception.
- **`--hw-watchdog` now rejects non-device paths (bug-439).** Previously any
  writable regular file was accepted, received NUL kicks, and let the observer
  start with no hardware reboot protection. `HwWatchdog::open` now validates
  the opened descriptor and fails startup unless it is a character device.
- **`--recovery-timeout-ms 0` no longer silently neuters recovery (bug-434).**
  The flag is the kill-after deadline for a still-running recovery child; the
  reap gate kills a child once `spawned_at.elapsed() >= recovery_timeout`. A
  value of `0` made that comparison (`elapsed() < ZERO`) always false, so every
  still-running child was `kill(2)`'d on the very first reap tick — killing the
  documented `systemctl restart agent@{pid}` case before it could complete. A
  new `MIN_RECOVERY_TIMEOUT_MS = 100` floor (`RecoveryTimeoutTooLow`) is enforced
  across all three config paths (argv parser, Class-A `validate_runtime`, and
  `build.rs`), mirroring the `MIN_SELF_WATCHDOG_SECS` recipe. The never-kill
  default is still reached by omitting the flag — `None`, never `0`.
- **`--recovery-audit-max-bytes` now has a minimum floor (bug-435).** The audit
  writer arms rotation on `bytes_written >= max` with no implicit floor, so a
  tiny or zero cap rotated roughly once per record and shredded the IEC 62304
  Class C audit trail to the last ~5 records while the hash chain stayed linear
  — i.e. with no tamper-evidence signal that history was discarded. A new
  `MIN_RECOVERY_AUDIT_MAX_BYTES = 4096` floor (`RecoveryAuditMaxBytesTooLow`) is
  enforced across the same three config paths. Unbounded growth is still reached
  by omitting the flag.
- **Secure-UDP replay refusals are no longer mislabelled as decrypt failures
  (bug-435).** A replay from a known sender (AEAD tag valid, but the inner VLP
  nonce/timestamp did not advance past the recorded high-water mark) incremented
  `varta_frame_decrypt_failures_total`, conflating a replay with an AEAD/tag
  failure on operator dashboards. Replay refusals now increment a dedicated
  `varta_secure_replay_refused_total` counter.

- **Secure-UDP PID recycle no longer false-stalls or recovery-kills the
  healthy newcomer.** When the OS handed a recently-vacated PID to a new
  process, its fresh secure session (new IV prefix, VLP nonce restarting at 1)
  was rejected as an aged-out replay by both the listener's per-sender
  high-water mark and the tracker's nonce-monotonicity check — neither carries a
  kernel start-time generation on the network path. The dead predecessor's slot
  stayed silence-latched for up to the 10-minute eviction TTL, false-stalling
  the newcomer and, under `--i-accept-recovery-on-secure-udp`, firing recovery
  against it. A wall-clock `SESSION_RESTART_GAP` (5 s) now separates a genuine
  recycle from a replay — a live sender never presents a non-advancing nonce on
  an aged-out prefix — so the listener admits the recycled session and the
  tracker resets the slot (surfaced as `varta_tracker_pid_recycle_total`),
  bounding the lockout to the gap. Replays against an actively-beating sender,
  and all kernel-attested UDS paths, are unaffected.

- **Go, Python, Node.js, and .NET panic emitters preserve terminal replay
  ordering.** Terminal frames now claim timestamps from one process-wide
  monotonic high-water mark in each runtime. Clock rollback, coarse equal
  samples, and handler replacement can no longer make a genuine later panic
  look like a replay; exhausted timestamp space fails closed.

- **Rust panic hooks preserve terminal replay ordering across reinstallation.**
  UDS, UDP, and secure-UDP panic emitters now claim timestamps from one
  process-wide atomic high-water mark. Concurrent panics and a newly installed
  hook can no longer emit equal or decreasing terminal timestamps that the
  observer rejects as replays; exhaustion drops before the invalid
  `u64::MAX` timestamp sentinel.

- **Node reconnects are transactional and generation-safe.** UDS, UDP, and
  secure-UDP transports now prepare a replacement before closing the active
  socket, preserving the current connection and AEAD session when setup fails.
  Async callbacks from retired UDP sockets are scoped to their socket
  generation and can no longer poison or flush frames through the replacement.

- **Go and Python reconnect failures no longer corrupt the client.** Their
  UDS, UDP, and secure-UDP transports now prepare replacement sockets and
  AEAD session state before atomically swapping out the active transport.
  Failed reconnects preserve the prior connection instead of making the next
  health beat panic (Go) or raise `AssertionError` (Python).

- **Agent clients reject observer-only `Stall` status before sending.**
  `Status::Stall` / wire byte `0x03` is synthesized by `varta-watch` and
  `Frame::decode` rejects it on the wire. Rust, Python, Node.js, Go, and
  .NET clients now return a structured `Failed(InvalidInput)` result for
  `beat(Stall)` / equivalent cast or string forms without reconnecting,
  advancing nonce state, or writing a datagram.

### Changed

- **Breaking: `BeatOutcome::Dropped` now carries a `DropReason` payload.**
  `classify_send_error` returns `Dropped(DropReason)` instead of the unit
  variant `Dropped`. Operators can now distinguish kernel buffer pressure
  (`KernelQueueFull`) from observer-absent (`NoObserver`) from peer-teardown
  (`PeerGone`) from disk-full (`StorageFull`). Migrate match arms:
  `BeatOutcome::Dropped => …` → `BeatOutcome::Dropped(_) => …` (ignoring
  reason) or match the specific `DropReason` variant for richer diagnostics.
  `DropReason` is `Copy + Eq`, fits in one byte, and adds no heap footprint
  to the steady-state beat path.

### Security
- **Default-on UDS rate limiting closes same-UID flood gap.** Three layered
  defenses are now enabled by default for all out-of-the-box deployments:
  (1) **Per-pid rate limit** (`--max-beat-rate 100`): beats arriving faster
  than 100/s from the same pid are dropped. Previously `None` (unlimited) by
  default; now requires `--max-beat-rate 0` to disable.
  (2) **Global token bucket** (`--global-beat-rate 5000 --global-beat-burst 10000`):
  a shared bucket across all senders gates frames *before* namespace /
  per-pid classification, defeating per-pid rotation attacks where an
  attacker cycles fake pids to keep every per-pid bucket empty. Set
  `--global-beat-rate 0` to disable.
  (3) **`SO_RCVBUF` tuning** (`--uds-rcvbuf-bytes 1048576`): enlarges the
  kernel datagram queue to ~32 k frames so brief flood bursts don't drop
  legitimate beats before the poll loop drains. The kernel-granted size is
  surfaced as `varta_observer_uds_rcvbuf_bytes` (gauge). Set
  `--uds-rcvbuf-bytes 0` to leave the kernel default. **Breaking default**
  for operators relying on unbounded per-pid beat rates — use
  `--max-beat-rate 0 --global-beat-rate 0` to restore previous behaviour.
- **`varta_rate_limited_total` is now labelled.** The metric now emits two
  series: `varta_rate_limited_total{reason="per_pid"}` and
  `{reason="global"}`, both always present even at zero. Existing dashboards
  and alerting rules that matched the bare `varta_rate_limited_total` scalar
  should use `sum without(reason)(varta_rate_limited_total)` to recover the
  aggregate.

- **Recovery child environment is now isolated by default.** Pre-change,
  `Recovery::apply_env` short-circuited when `recovery_env` was empty, so
  recovery subprocesses inherited the observer's full process environment —
  any `AWS_*`, `GOOGLE_APPLICATION_CREDENTIALS`, `*_TOKEN`, OAuth bearer, or
  database URL set on the observer would leak into every recovery command.
  The blast radius was silent: a misconfigured or compromised
  `--recovery-cmd` / `--recovery-exec` (or any binary on the recovery
  allowlist) became a credential-exfiltration vector. The new default
  clears the child's environment and sets `PATH=/usr/bin:/bin` plus any
  explicit `--recovery-env KEY=VALUE` entries. The new
  `--recovery-inherit-env` flag (or `recovery_inherit_env=true` in
  `VARTA_CONFIG_FILE`) restores legacy inheritance; when set, the observer
  emits a one-shot stderr warning naming the risk. See
  `book/src/architecture/recovery-async-spawn.md` §7a for the migration
  guide. **Breaking behavioural change** for operators whose recovery
  templates relied on inherited variables (e.g. `$HOME`) — failures are
  loud (the recovery command itself fails), not silent.
- **Zero `HashMap` in `varta-watch` production code.** The two remaining `std::collections::HashMap` sites (`Recovery.outstanding` and `PromExporter.ip_state`) have been replaced with a new generic `BoundedIndex<K>` (Murmur3 finalizer + 64-step linear probe + sentinel-encoded `slot_idx`) plus slab-backed wrappers (`OutstandingTable`, `IpStateTable`). `PidIndex` is now a thin newtype over `BoundedIndex<u32>`. Every map-like structure in `varta-watch` now has a tight WCET bound suitable for DO-178C-style worst-case analysis; SipHash randomisation and rehash-induced latency are structurally excluded. Three new Prometheus counters surface probe-budget exhaustion (`varta_tracker_pid_index_probe_exhausted_total`, `varta_recovery_outstanding_probe_exhausted_total`, `varta_prom_ip_state_probe_exhausted_total`) — all should remain at 0 at load factor ≤ 0.5. A new fail-closed `RecoveryOutcome::RefusedOutstandingCapacity` variant fires when the outstanding-child table is at capacity, mirroring the existing `RefusedDebounceCapacity` pattern.
- **Continuous fuzzing posture upgraded to nightly long-form + OSS-Fuzz.** The CI `fuzz-smoke` job picks up the previously-missing `flag_catalogue_lookup` target plus four new targets for the bounded-collection modules (`bounded_index_u32`, `bounded_index_ip`, `outstanding_table`, `ip_state_table`), each running 30 s per push/PR. A new `fuzz-nightly.yml` workflow runs all twelve targets for 30 minutes nightly with a persistent corpus cache and auto-opens an issue on any crash. The `oss-fuzz/` directory ships the upstream Dockerfile / build.sh / project.yaml so the project can be registered with Google's OSS-Fuzz infrastructure.

- **Supply-chain posture tightened.** The four optional crypto deps in `varta-vlp` (`chacha20poly1305`, `hkdf`, `sha2`, `zeroize`) are now pinned to **exact** patch versions (`=X.Y.Z`); caret/tilde resolution is no longer permitted. A new `deny.toml` at the repo root configures `cargo-deny` with hard-deny policies on yanked crates, RUSTSEC advisories, license drift outside the OSI-permissive set, multiple-versions, wildcards, and unknown sources. CI runs `cargo deny check` (pinned to `cargo-deny 0.19.6`) as a dedicated `supply-chain` job, and every existing `cargo build / test / clippy / run / miri` invocation in `ci.yml` now passes `--locked` — the lockfile in `main` is the only one that builds. See `book/src/architecture/supply-chain.md` for the policy and dep-bump procedure.
- **Fork-safety is now structurally enforced on `Varta::beat`.** Previously, a `fork(2)` followed by `beat()` in the child would cause catastrophic AEAD nonce reuse on the secure-UDP transport (the child inherited `iv_session_salt` / `iv_prefix_index` / `iv_counter` from its parent). `Varta` now snapshots `std::process::id()` at `connect()` time and, on PID mismatch, invokes `BeatTransport::reconnect()` *before* the frame is built — re-reading OS entropy into a fresh session salt and resetting the prefix/counter state. The recovery is silent (the caller sees `BeatOutcome::Sent`) and observable via `Varta::fork_recoveries() -> u64` (suggested Prometheus name: `varta_client_fork_recoveries_total`). The observer's existing `(SocketAddr, iv_prefix)` per-sender state machine accepts the new prefix as a fresh session transparently — no wire-format change required.
- **`install_panic_handler_secure_udp` is now fork-safe.** The cached 8-byte `iv_random` would, under fork, collide with the parent's panic-frame nonce under the same key. The installer now snapshots `install_pid` and, inside the panic hook, re-runs the entropy chain (`getrandom`/`getentropy` → `/dev/urandom`) when the PID has changed. The strict variant fails closed (skips the secure frame, still chains to the previous hook) when no entropy source is reachable; the `accept-degraded-entropy` variant falls back to `fallback_iv_random` per the documented degraded-entropy policy.

### Removed (BREAKING)

- **Shell-mode recovery permanently removed.** The `unsafe-shell-recovery`
  Cargo feature, `RecoveryMode::Shell`, `--recovery-cmd`, `--recovery-cmd-file`,
  and `--i-accept-shell-risk` have been removed from all build profiles. No
  build of `varta-watch` will ever invoke `/bin/sh` for recovery; the
  `/bin/sh` literal no longer appears in any binary. **Migration:** replace
  `--recovery-cmd "<template>"` with `--recovery-exec /path/to/program` (the
  observer appends the stalled pid as the final argument). Replace
  `--recovery-cmd-file <path>` with `--recovery-exec-file <path>`. Shell
  logic can be moved into a thin wrapper script invoked via `--recovery-exec`.
  Passing the removed flags at startup now produces an immediate hard error
  with a migration hint. See
  `book/src/architecture/recovery-shell-removal.md` for the full migration
  guide.

### Added
- Comprehensive community governance documentation (`CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`).
- Dual-licensing (MIT OR Apache-2.0).
- Professional README with status badges and example index.
- Rich metadata in `Cargo.toml` for all crates.
- GitHub Issue and PR templates.
- Project roadmap.
- `compile_fail` doctest regression in `varta-vlp` pinning `Key: !Clone` (E0277 trait-bound failure).
- `varta_vlp::crypto::BearerToken` — `!Clone + ZeroizeOnDrop` newtype container for the Prometheus `/metrics` bearer secret. Lives alongside `Key` so the same audited `zeroize` dep covers both secrets; `varta-watch` carries no registry deps of its own.
- `compile_fail` doctest regression in `varta-vlp` pinning `BearerToken: !Clone` (E0277 trait-bound failure).
- Architecture note in `book/src/architecture/peer-authentication.md` documenting the panic-hook `Box`-on-process-exit residual and why it is accepted.
- `varta-watch` on Linux now installs signal handlers via the `rt_sigaction(2)` syscall **directly** (`core::arch::asm!` for x86_64 and aarch64) instead of the libc `sigaction(3)` wrapper. The wrapper in both glibc and musl unconditionally substitutes its own `__restore_rt` for any caller-supplied `sa_restorer`, so the previous code was implicitly dependent on libc to make signal-return work; the new path passes the kernel ABI struct (`KernelSigAction`, 32 B on x86_64 with `sa_restorer`, 24 B on aarch64 without) directly to the kernel. On x86_64 the action installs our own `__NR_rt_sigreturn` trampoline (`varta_signal_restorer`, `core::arch::global_asm!`, in its own `.text.varta_signal_restorer` section with signal-frame CFI) and sets `SA_RESTORER`. A debug-build readback round-trip asserts the kernel preserved exactly what we installed — including the trampoline pointer, which would FAIL under any libc-wrapper path because the wrapper strips it. macOS and FreeBSD continue to use the libc `sigaction(3)` wrapper (they have no `sa_restorer` ABI to worry about). New regression tests in `crates/varta-watch/tests/signal_handler.rs`: `linux_restorer_is_ours` (x86_64), `linux_aarch64_direct_syscall_roundtrips` (aarch64), `restorer_symbol_is_addressable` (x86_64). Other Linux architectures fail to compile with an explicit `compile_error!` until a `KernelSigAction` arm is added.

### Changed (breaking)
- `PromExporter::bind` and `PromExporter::bind_with_rate_limit` now accept
  `varta_vlp::crypto::BearerToken` instead of `[u8; 32]`; `Config::load_prom_token`
  returns `BearerToken` accordingly. `BearerToken` is `!Clone + ZeroizeOnDrop` — secret
  bytes are zeroed on drop and cannot be silently duplicated. The `prometheus-exporter`
  feature on `varta-watch` now activates `varta-vlp/crypto` to bring in the type.
  Workspace-internal breaking change (varta-watch is not a published library dep; only
  varta-tests and fuzz targets are affected).
- `varta-vlp` 0.1.0 → 0.2.0: `varta_vlp::crypto::Key` no longer implements `Clone`. Symmetric key material must not be silently duplicated; producing a second `Key` now requires `Key::from_bytes(*existing.as_bytes())`, which is grep-able, audit-visible, and forces the caller to acknowledge the duplication. The previous derive defeated the `ZeroizeOnDrop` guarantee whenever a clone was leaked into a closure (e.g. `Box<dyn Fn>`), shared across threads, or forgotten via `mem::forget` / `Box::leak`. No production callers in this workspace; the change surfaces only in test code that previously cloned `Key` for fixture vectors.

## [0.2.0] - 2026-05-13

### Added
- **UDP Transport**: Support for networked agents via `varta-client/udp`.
- **Secure UDP**: AEAD-authenticated transport (ChaCha20-Poly1305) for high-assurance networked clusters.
- **Panic Handler**: Optional feature to automatically emit a `Critical` beat when a Rust thread panics.
- **Miri Audits**: CI integration for strict provenance and UB detection.
- **Fuzzing**: Continuous fuzzing of protocol decoding and encryption roundtrips.

### Changed
- Refactored `varta-watch` to support multiple listener backends (UDS, UDP, Secure UDP).

## [0.1.0] - 2026-04-15

### Added
- Initial release of the Varta Lifeline Protocol (VLP).
- Base UDS implementation for local agents.
- `varta-watch` observer with Prometheus exporter.
- Zero-allocation steady-state beat path.
