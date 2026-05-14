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
- Architecture note in `book/src/architecture/peer-authentication.md` documenting the panic-hook `Box`-on-process-exit residual and why it is accepted.
- `SECURITY:` audit comment on `Config::load_prom_token` flagging the bare `[u8; 32]` token type for a follow-up `BearerToken` newtype hardening.

### Changed (breaking)
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
