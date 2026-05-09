# Varta Project Roadmap

This roadmap outlines the path from Varta's current state to a "High-Assurance" v1.0.0 release suitable for safety-critical deployments.

## Phase 1: Foundation (Current - v0.2.x) :white_check_mark:
Focus on protocol stability, local/network transport, and security audits.
- [x] VLP Protocol Definition (32-byte frames).
- [x] Zero-allocation UDS/UDP transport.
- [x] AEAD encryption for networked agents.
- [x] Fuzzing and Miri integration in CI.
- [x] Initial Prometheus exporter.

## Phase 2: Observability & Resilience (v0.3 - v0.5)
Enhancing the observer and providing more "industrial" features.
- [ ] **Structured Logging**: full `json-log` support across all crates.
- [ ] **Tamper-Evident Logs**: SHA-256 hash chaining for recovery audits.
- [ ] **mdBook Documentation**: A comprehensive "Varta Book" explaining protocol internals.
- [ ] **Crates.io Publication**: Formal release of production-ready crates.

## Phase 3: Compliance & Integration (v0.6 - v0.9)
Preparing for formal certification standards (IEC 62304, ISO 26262).
- [ ] **Static Analysis**: Integrate `cargo-geiger` and custom safety-profile audits.
- [ ] **Multi-Language SDKs**: C/C++ bindings for legacy embedded systems.
- [ ] **Hardware Watchdog Integration**: Native drivers for Linux `watchdogd` and platform-specific hardware timers.
- [ ] **Self-Diagnostic Suite**: Integrated tests for observer clock drift and jitter.

## Phase 4: High-Assurance v1.0
The stable, safety-certified release.
- [ ] **Formal Verification**: TLA+ or Kani proofs for core state machines.
- [ ] **Third-Party Security Audit**: Formal cryptographic and code audit by a specialized firm.
- [ ] **ABI Freeze**: Finalize the VLP wire format for long-term compatibility.
- [ ] **v1.0.0 Release**: LTS support for critical infrastructure.
