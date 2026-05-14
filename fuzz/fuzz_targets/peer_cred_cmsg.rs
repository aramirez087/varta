#![no_main]

//! Fuzz the kernel-supplied ancillary-data walker.
//!
//! `peer_cred::cmsg::find_credential::<LinuxCmsg>` consumes the bytes the
//! kernel writes into `msg_control` after `recvmsg(2)` and extracts the
//! peer's `(pid, uid)` from any `SCM_CREDENTIALS` cmsg present. The walker
//! must:
//!
//! 1. **Never panic** on arbitrary input — kernel bytes are technically
//!    trusted at runtime (the kernel always writes well-formed cmsg
//!    sequences), but the Rust-side parser is the only thing between us
//!    and pointer-arithmetic UB. Treating the walker as adversarial-input-
//!    safe is a defence-in-depth property.
//! 2. **Always terminate** — corrupt `cmsg_len` values must not produce
//!    infinite iteration. The walker clamps the per-step advance to at
//!    least `cmsg_hdr_size` and uses `saturating_add` to defend against
//!    `usize` overflow.
//! 3. **Never return spurious credentials** — a `Some((pid, uid))` must
//!    only come from a cmsg whose declared `(level, type)` is
//!    `(SOL_SOCKET, SCM_CREDENTIALS)` and whose `cmsg_len` is at least
//!    `cmsg_hdr_size + sizeof::<ucred>()`.
//!
//! Property 3 is structurally enforced by the walker; the fuzz target
//! verifies properties 1 and 2 simply by running.

use libfuzzer_sys::fuzz_target;

#[cfg(target_os = "linux")]
fuzz_target!(|data: &[u8]| {
    let _ = varta_watch::peer_cred::fuzz_entry::find_credential_linux(data);
});

// On non-Linux fuzzing hosts (rare; cargo-fuzz is Linux-first), the entry
// point doesn't exist — provide a no-op shim so the binary still links.
#[cfg(not(target_os = "linux"))]
fuzz_target!(|_data: &[u8]| {});
