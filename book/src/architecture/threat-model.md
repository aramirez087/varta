# Varta Threat Model

This document outlines the formal threat model for the Varta health monitoring protocol. Varta is designed for high-assurance, zero-overhead health signalling in distributed systems and local IPC.

## 1. Scope and Assets

### Scope
The scope of this threat model includes:
- **varta-vlp**: The 32-byte wire protocol and its cryptographic primitives.
- **varta-client**: The agent library integrated into application processes.
- **varta-watch**: The observer daemon that tracks agent health and triggers recovery.
- **Transports**: Unix Domain Sockets (UDS) and User Datagram Protocol (UDP).

### Assets
1. **Agent Liveness State**: The true health status of an agent process.
2. **Recovery Commands**: The ability to execute privileged operations (e.g., `systemctl restart`) based on agent health.
3. **Master/Session Keys**: Cryptographic material used to secure UDP heartbeats.
4. **Metrics Data**: Operational visibility provided via the Prometheus `/metrics` endpoint.
5. **System Availability**: The continued operation of the observer itself.

---

## 2. Trust Boundaries

Varta operates across several trust boundaries:

| Boundary | Description |
| --- | --- |
| **Agent / Observer (Local)** | Communication over UDS on the same host. Trust is rooted in the Kernel (PID/UID attestation). |
| **Agent / Observer (Network)** | Communication over UDP (Plain or Secure). Trust is rooted in Cryptography (AEAD) or Network Segmentation. |
| **Observer / Metrics Scraper** | Communication over HTTP. Trust is rooted in Bearer Token authentication. |
| **Observer / System** | The interface where the observer executes recovery commands or writes audit logs. |

---

## 3. Threat Analysis (STRIDE)

### S: Spoofing (Impersonating an Agent)
- **Threat**: An attacker process sends forged heartbeats for a target PID to hide a stall or trigger a false recovery.
- **Mitigation (UDS)**: **Kernel PID Attestation**. The observer uses `SO_PASSCRED` (Linux), `LOCAL_PEERTOKEN` (macOS), or `SCM_CREDS` (BSD) to verify the sender's real PID.
- **Mitigation (Secure UDP)**: **ChaCha20-Poly1305 AEAD**. Every frame is cryptographically signed. Master-key mode derives per-agent keys from PIDs to prevent cross-agent spoofing.
- **Mitigation (Network)**: UDP heartbeats are tagged `NetworkUnverified` and are **ineligible** for recovery commands by default.

### T: Tampering (Modifying Heartbeats)
- **Threat**: An attacker modifies a heartbeat in transit to change its status (e.g., changing `Ok` to `Critical`).
- **Mitigation (Wire)**: **CRC-32C Integrity**. Every frame includes a CRC-32C trailer to catch bit flips and in-process corruption.
- **Mitigation (Secure UDP)**: **Poly1305 MAC**. Any modification to an encrypted frame causes a decryption failure, and the frame is dropped.

### R: Repudiation (Audit Log Evasion)
- **Threat**: A recovery action occurs, but there is no record of why or which agent triggered it.
- **Mitigation**: **Opt-in Recovery Auditing**. When `--recovery-audit-file <PATH>` is configured, all recovery actions — including refusals, kills, and reaps — are logged to a structured TSV with kernel-attested PIDs where available. The `audit-chain` feature adds SHA-256 hash chaining for tamper evidence. Without the flag, recovery actions are visible only via the Prometheus `varta_recovery_outcomes_total` / `varta_recovery_refused_total` counters. For high-assurance deployments the audit file is **strongly recommended** and is required for IEC 62304 / DO-178C-grade installations.

### I: Information Disclosure (Leaking Secrets)
- **Threat**: Cryptographic keys or Prometheus tokens are leaked via environment variables or insecure file permissions.
- **Mitigation**: **Secret-File Hardening**. Varta refuses to load keys from environment variables. Key files must be owned by the observer UID and have `0600` permissions.
- **Mitigation (Memory)**: **Zero-on-Drop**. The `Key` type zeros its memory before being released. Panic hooks use a single-owner `Box` to minimize secret lifetime.

### D: Denial of Service (Exhausting Observer Resources)
- **Threat**: An attacker floods the observer with connection requests or malformed frames to prevent it from monitoring legitimate agents.
- **Mitigation (Metrics)**: **Multi-layer DoS Protection**. Rate limiting per source IP, connection budgets, and constant-time token comparison for the `/metrics` endpoint.
- **Mitigation (Wire)**: **Zero-Allocation Hot Path**. The observer processes frames without allocating on the steady-state path, preventing heap exhaustion.

### E: Elevation of Privilege (Exploiting Recovery)
- **Threat**: An attacker triggers a recovery command that executes an arbitrary shell script or targets a process outside its namespace.
- **Mitigation**: **Exec-Only Recovery**. Shell-mode recovery is removed. Commands are executed directly via `execvp(2)` with no shell interpolation.
- **Mitigation (Namespace)**: **Linux PID Namespace Gating**. The observer verifies that the agent belongs to the same PID namespace before permitting recovery.
- **Mitigation (Environment)**: **Isolated Recovery Environment**. Recovery children run with a sanitized, minimal environment to prevent `LD_PRELOAD` or `PATH` attacks.

---

## 4. Security Boundaries & Mitigations Summary

### The "Kernel-First" Trust Model
For local IPC, Varta trusts the kernel over the wire format. A frame's `pid` field is only used if the kernel attests that the sending process actually owns that PID.

### Cryptographic Identity (Secure UDP)
For network communication, Varta uses a 256-bit key-based identity.
- **Forward Secrecy**: Deliberately not provided. A one-way unauthenticated-receiver heartbeat protocol has no handshake in which to negotiate ephemeral keys; adding a DH ratchet would require multi-round-trip session establishment, which contradicts Varta's connectionless beat-and-forget model. Key rotation via `--accepted-key-file` (multiple accepted keys, time-bounded rollover) is the recommended mitigation; see [Peer Authentication](peer-authentication.md) for the full key-loading model and rotation procedure.
- **Replay Protection**: Enforced via monotonic IV counters per sender.

### Recovery Safety Gates
Recovery is the most privileged action Varta performs. It is guarded by:
1. **Origin Gating**: Recovery is disabled for `NetworkUnverified` (UDP) sources unless explicitly enabled with verbose CLI flags.
2. **Platform Gating**: On platforms without kernel PID attestation (e.g., OpenBSD), recovery is disabled.
3. **Execution Safety**: Commands are never passed to a shell.

---

## 5. Residual Risks

1. **Compromised UID (Local)**: If an attacker gains the same UID as the observer, they can read the secret keys and potentially bypass socket-mode permissions.
2. **Master Key Leak**: A leak of the master key allows an attacker to derive all agent keys and spoof any agent on the network.
3. **Clock Skew (UDP)**: Varta uses monotonic timestamps, but significant clock drift or resets on the agent side can lead to rejected heartbeats or false stall detections.
4. **Namespace Mapping**: In complex container environments, PID 1 in a container may map to a different host PID. `varta-watch` provides PID-namespace gating via its own `--allow-cross-namespace-agents` and `--strict-namespace-check` flags. For multi-container recovery the observer container typically needs the runtime's host-PID share (e.g. Docker/podman `--pid=host`, Kubernetes `hostPID: true`) so that recovery targets and the observed PID namespace agree; otherwise namespace mismatches cause beats and recovery to be refused. See [Namespacing](namespaces.md).
5. **No Forward Secrecy**: As a one-way protocol, Varta does not provide forward secrecy. If a key is compromised, all past traffic encrypted with that key can be decrypted if captured.
