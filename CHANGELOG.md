# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
