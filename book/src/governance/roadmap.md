# Varta Project Roadmap

This roadmap outlines the path from Varta's current state to a
"High-Assurance" v1.0.0 release suitable for safety-critical
deployments.

## Phase 1: Foundation (v0.1.x – v0.2.x) ✅

Protocol stability, local + network transport, security baseline.

- [x] VLP base-frame protocol (32-byte frames, v0.2 frozen).
- [x] Zero-allocation UDS/UDP transport.
- [x] AEAD-encrypted networked agents (`secure-udp` feature,
  ChaCha20-Poly1305, shared-key + master-key forms).
- [x] Fuzzing and Miri integration in CI.
- [x] Prometheus exporter with bearer-token auth and per-IP rate
  limiting.
- [x] Single-threaded poll loop, non-blocking recovery spawn, async
  reap with optional kill-after deadline.
- [x] PID-namespace gating on Linux.
- [x] Class-A safety-critical structural excision
  (`prometheus-exporter`, `compile-time-config` features) with CI
  strings-audit enforcement.
- [x] Kani symbolic verification of `Frame::decode` (nightly job).
- [x] Multi-language verifier-grade reference implementations
  (Python, C, Go) with shared JSON test vectors.

## Phase 2: Observability, Adoption, & Resilience (v0.2 – v0.3) ✅ / 🟡

Industrial features and turnkey adoption paths.

- [x] **Structured logging.** `json-log` feature (default in
  `varta-watch`).
- [x] **Tamper-evident audit chain.** SHA-256 hash chaining for recovery
  audit log (`audit-chain` feature; depends on `varta-vlp/crypto`).
- [x] **mdBook documentation** (this book, published at
  [varta.sh](https://varta.sh)).
- [x] **Official Python client** (`pip install varta`, PyPI Trusted
  Publisher).
- [x] **Container image + Helm chart** (multi-arch, cosign-signed, SLSA
  L3 provenance, published to GHCR).
- [x] **Observability bundle** — Prometheus alert rules, recording
  rules, Grafana dashboard, k8s ServiceMonitor / PodMonitor examples.
- [x] **One-paste installer** (`curl … | sh` with cosign + systemd
  unit).
- [ ] **Crates.io publication** of `varta-vlp`, `varta-client`, and
  `varta-watch`.

## Phase 3: Compliance & Integration (v0.4 – v0.9)

Preparing for formal certification standards (IEC 62304 Class C,
ISO 26262, DO-178C).

- [ ] **`cargo-geiger`** and custom safety-profile auditing in CI.
- [x] **Additional language clients** — Go, JVM, Node, and .NET.
- [ ] **C bindings** for legacy embedded systems.
- [x] **Hardware-watchdog integration** — `--hw-watchdog` flag wires
  the in-process watchdog to `/dev/watchdog{,N}` and systemd
  `WATCHDOG=1`.
- [ ] **Self-diagnostic suite** — packaged smoke tests for observer
  clock drift, scrape latency, and audit-log integrity that operators
  can run against a deployed instance.

## Phase 4: High-Assurance v1.0

The stable, safety-certified release.

- [ ] **Formal verification expansion** — Kani harnesses beyond
  `Frame::decode` (recovery state machine, debounce window, tracker
  eviction).
- [ ] **Third-party security audit** — formal cryptographic and code
  audit by a specialist firm.
- [ ] **ABI freeze** — finalise wire format, `BeatOutcome` taxonomy,
  and CLI argv for long-term compatibility.
- [ ] **v1.0.0 release** — LTS support for critical infrastructure.
