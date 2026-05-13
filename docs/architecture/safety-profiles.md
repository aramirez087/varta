# Safety Profiles

`varta-watch` ships with a **two-layer gate** for every structurally-dangerous
capability: a **compile-time Cargo feature** that must be explicitly enabled,
AND a **runtime flag** that must be passed by the operator.  Neither layer
alone is sufficient; both must be active.

This document defines what "production-safe" means for Varta and how to verify
a binary before deploying it to a safety-critical environment.

---

## Production-safe build

A production-safe `varta-watch` binary is built with **default features only**:

```sh
cargo build -p varta-watch --release
```

No `--features` argument is needed or wanted.  Default features are empty.

### What is absent from a production-safe build

| Dangerous capability | Cargo feature | Runtime flag |
|---|---|---|
| Plaintext (unauthenticated) UDP listener | `unsafe-plaintext-udp` | `--i-accept-plaintext-udp` |
| Shell-mode recovery (`/bin/sh -c`) | `unsafe-shell-recovery` | `--i-accept-shell-risk` |

Without the compile-time feature, the code path is **not linked** into the
binary.  A misconfigured deployment cannot accidentally enable the dangerous
path at runtime.

### Verification recipe

```sh
cargo build -p varta-watch --release
strings target/release/varta-watch | grep -F "/bin/sh" && echo "FAIL" || echo "OK"
```

The `strings` check is belt-and-suspenders: because the dangerous code is
`#[cfg(feature = ...)]`-gated at the source level, the literal string is never
even parsed by the compiler, so it cannot appear in the binary.

---

## Unsafe features

### `unsafe-plaintext-udp`

Compiles in the plaintext `UdpListener` transport.  Any device with network
access to the bound port can inject heartbeats, suppress stall detection, or
trigger false recovery commands.

```toml
# varta-watch/Cargo.toml
[features]
unsafe-plaintext-udp = ["udp-core"]
```

Even with this feature, the listener **will not bind** unless
`--i-accept-plaintext-udp` is also passed at runtime.

### `unsafe-shell-recovery`

Compiles in the `RecoveryMode::Shell` variant, which passes the recovery
template to the system shell (`sh -c`).  A template-injection vector can
execute arbitrary commands with the observer's authority.

```toml
[features]
unsafe-shell-recovery = []
```

Even with this feature, shell-mode recovery **will not activate** unless
`--i-accept-shell-risk` is also passed at runtime.

---

## Recommended transport for recovery

Always use `--recovery-exec` instead of `--recovery-cmd` for production
deployments.  `--recovery-exec` invokes the program directly via `execvp(2)`
with no shell involved; shell metacharacters have no effect.

---

## Cross-references

- [Observer liveness](observer-liveness.md) — defending against `varta-watch`
  itself crashing or hanging
- [Peer authentication](peer-authentication.md) — kernel-level PID attestation
  and transport trust classification
