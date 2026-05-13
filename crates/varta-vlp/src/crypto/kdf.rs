//! HKDF-SHA256 key derivation for VLP secure transports.
//!
//! Derives per-agent and per-epoch keys from a single master key using
//! HKDF-SHA256 (RFC 5869). This provides per-agent identity isolation
//! without requiring individual pre-shared keys or key exchange protocols.
//!
//! # Key hierarchy
//!
//! ```text
//! master_key ──► agent_key (pid=1) ──► epoch_key (epoch=0)
//!            ├── agent_key (pid=2) ──► epoch_key (epoch=0)
//!            ├── agent_key (pid=3) ──► epoch_key (epoch=0)
//!            │         ...
//!            └── agent_key (pid=N)
//! ```
//!
//! # Migration note
//!
//! This KDF replaced a ChaCha20-PRF construction in the same release that
//! migrated all primitives to RustCrypto. The info strings are versioned
//! (`-v1`) so that a future migration can derive distinct keys without
//! colliding with this generation. Any existing master-key deployment
//! must re-key on upgrade.
//!
//! # Security properties
//!
//! * **Per-agent isolation**: Compromise of one agent's derived key does
//!   not reveal other agents' keys or the master key.
//! * **Deterministic**: Same master + agent_id always produces the same
//!   agent_key, so the observer can derive keys on demand.
//! * **Standard primitive**: HKDF-SHA256 is NIST-recommended and
//!   externally audited via the RustCrypto crate ecosystem.
//! * **No forward secrecy**: An epoch key can decrypt past epochs if the
//!   agent key is compromised. True forward secrecy requires ephemeral
//!   key exchange (e.g. X25519), which is incompatible with the
//!   connectionless, one-way heartbeat model.

use hkdf::Hkdf;
use sha2::Sha256;

use super::Key;

/// Derive a per-agent 256-bit key from a master key and agent identity.
///
/// Uses HKDF-SHA256 with the agent PID encoded in the info string.
/// The same `(master, agent_id)` pair always produces the same output.
///
/// # Security
///
/// Different agent IDs produce independent uniformly-distributed output
/// keys. The info-string domain separator (`varta-agent-v1`) ensures
/// no key overlap with epoch derivation.
pub fn derive_agent_key(master: &Key, agent_id: u32) -> Key {
    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    // info = "varta-agent-v1\0" (15 bytes) || agent_id LE (4 bytes)
    let mut info = [0u8; 19];
    info[..15].copy_from_slice(b"varta-agent-v1\0");
    info[15..].copy_from_slice(&agent_id.to_le_bytes());
    let mut okm = [0u8; 32];
    match hk.expand(&info, &mut okm) {
        Ok(()) => {}
        // `hkdf::InvalidLength` fires only when `okm.len() > 255 * 32 = 8160`
        // bytes (HKDF-SHA256's expansion limit). `okm` is a fixed `[u8; 32]`.
        // Unreachable by construction.
        Err(_) => unreachable!("32-byte HKDF-SHA256 expand is infallible"),
    }
    Key::from_bytes(okm)
}

/// Derive an epoch-scoped 256-bit key from an agent key.
///
/// Uses HKDF-SHA256 with the epoch number encoded in the info string.
/// Epoch keys provide time-bounded key rotation: the observer can
/// discard old epoch keys while retaining the ability to accept
/// future epochs from the same agent.
///
/// # Pigeonhole
///
/// Epoch is a 64-bit value. At one epoch per hour, this provides
/// ~2^44 epochs (~2 trillion years) before wraparound. Typical
/// deployments use Unix timestamps truncated to hourly granularity.
pub fn derive_epoch_key(agent_key: &Key, epoch: u64) -> Key {
    let hk = Hkdf::<Sha256>::new(None, agent_key.as_bytes());
    // info = "varta-epoch-v1\0" (15 bytes) || epoch LE (8 bytes)
    let mut info = [0u8; 23];
    info[..15].copy_from_slice(b"varta-epoch-v1\0");
    info[15..].copy_from_slice(&epoch.to_le_bytes());
    let mut okm = [0u8; 32];
    match hk.expand(&info, &mut okm) {
        Ok(()) => {}
        // Same reasoning as `derive_agent_key`: `okm` is a fixed `[u8; 32]`,
        // far below HKDF-SHA256's 8160-byte expansion limit. Unreachable.
        Err(_) => unreachable!("32-byte HKDF-SHA256 expand is infallible"),
    }
    Key::from_bytes(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_agent_key_deterministic() {
        let master = Key::from_bytes([0x42; 32]);
        let k1 = derive_agent_key(&master, 1);
        let k2 = derive_agent_key(&master, 1);
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_agent_key_different_pids_produce_different_keys() {
        let master = Key::from_bytes([0x42; 32]);
        let k1 = derive_agent_key(&master, 1);
        let k2 = derive_agent_key(&master, 2);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_agent_key_different_masters_produce_different_keys() {
        let m1 = Key::from_bytes([0x42; 32]);
        let m2 = Key::from_bytes([0x43; 32]);
        let k1 = derive_agent_key(&m1, 1);
        let k2 = derive_agent_key(&m2, 1);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_epoch_key_deterministic() {
        let agent = Key::from_bytes([0xab; 32]);
        let e1 = derive_epoch_key(&agent, 0);
        let e2 = derive_epoch_key(&agent, 0);
        assert_eq!(e1.as_bytes(), e2.as_bytes());
    }

    #[test]
    fn derive_epoch_key_different_epochs_produce_different_keys() {
        let agent = Key::from_bytes([0xab; 32]);
        let e1 = derive_epoch_key(&agent, 0);
        let e2 = derive_epoch_key(&agent, 1);
        assert_ne!(e1.as_bytes(), e2.as_bytes());
    }

    #[test]
    fn key_hierarchy_is_one_way() {
        let master = Key::from_bytes([0x42; 32]);
        let agent_key = derive_agent_key(&master, 7);
        let epoch_key = derive_epoch_key(&agent_key, 0);

        assert_ne!(epoch_key.as_bytes(), agent_key.as_bytes());
        assert_ne!(epoch_key.as_bytes(), master.as_bytes());
        assert_ne!(agent_key.as_bytes(), master.as_bytes());
    }

    #[test]
    fn agent_key_and_epoch_key_have_different_domains() {
        // Derive an agent key. Then derive what looks like an "epoch key"
        // but using the agent ID as the epoch — domain separation via the
        // distinct info strings must produce different keys.
        let master = Key::from_bytes([0x42; 32]);
        let agent_key = derive_agent_key(&master, 1000);
        let fake_epoch = derive_epoch_key(&master, 1000);
        assert_ne!(agent_key.as_bytes(), fake_epoch.as_bytes());
    }
}
