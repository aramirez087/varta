//! ChaCha20-based key derivation for VLP secure transports.
//!
//! Derives per-agent and per-epoch keys from a single master key using
//! ChaCha20 as a PRF. This provides per-agent identity isolation without
//! requiring individual pre-shared keys or key exchange protocols.
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
//! Each derivation step uses `chacha20_block(key, counter=0, nonce)` and
//! takes the first 32 bytes as the output key. The nonce encodes the
//! derivation context (agent PID or epoch number) to ensure domain
//! separation between different agents and epochs.
//!
//! # Security properties
//!
//! * **Per-agent isolation**: Compromise of one agent's derived key does
//!   not reveal other agents' keys or the master key (one-way PRF).
//! * **Deterministic**: Same master + agent_id always produces the same
//!   agent_key, so the observer can derive keys on demand.
//! * **No forward secrecy**: An epoch key can decrypt past epochs if the
//!   agent key is compromised. True forward secrecy requires ephemeral
//!   key exchange (e.g. X25519), which is incompatible with the
//!   connectionless, one-way heartbeat model.
//!
//! # Usage
//!
//! Agent side (client):
//! ```ignore
//! let master = Key::from_env("VARTA_MASTER_KEY")?;
//! let agent_key = kdf::derive_agent_key(&master, std::process::id());
//! let transport = SecureUdpTransport::connect(addr, agent_key)?;
//! ```
//!
//! Observer side (watch):
//! ```ignore
//! let master = Key::from_file("/etc/varta/master.key")?;
//! let listener = SecureUdpListener::with_master_key(addr, master)?;
//! ```

use super::chacha20::chacha20_block;
use super::Key;

/// Domain tag for agent key derivation: `"agnt"` (agent).
const DOMAIN_AGENT: [u8; 4] = [0x61, 0x67, 0x6e, 0x74];

/// Domain tag for epoch key derivation: `"epch"` (epoch).
const DOMAIN_EPOCH: [u8; 4] = [0x65, 0x70, 0x63, 0x68];

/// Derive a per-agent 256-bit key from a master key and agent identity.
///
/// Uses `chacha20_block(master, 0, nonce)` as a PRF where the nonce
/// encodes `domain_tag || agent_id`. The first 32 bytes of the ChaCha20
/// block output form the derived key.
///
/// # Determinism
///
/// The same `(master, agent_id)` pair always produces the same output.
/// This is intentional: the observer derives agent keys on demand from
/// the master key and the PID encoded in the VLP frame.
///
/// # Security
///
/// ChaCha20 with a fixed counter is a PRF under the standard ChaCha20
/// security assumptions. Different agent IDs produce independent
/// uniformly-distributed output keys (collision probability bounded
/// by the birthday bound for 256-bit keys).
pub fn derive_agent_key(master: &Key, agent_id: u32) -> Key {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&DOMAIN_AGENT);
    nonce[4..8].copy_from_slice(&agent_id.to_le_bytes());
    // nonce[8..12] is already zero

    let block = chacha20_block(master.as_bytes(), 0, &nonce);
    let mut derived = [0u8; 32];
    derived.copy_from_slice(&block[..32]);
    Key::from_bytes(derived)
}

/// Derive an epoch-scoped 256-bit key from an agent key.
///
/// Uses `chacha20_block(agent_key, 0, nonce)` where the nonce encodes
/// `domain_tag || epoch`. The first 32 bytes form the epoch key.
///
/// Epoch keys provide time-bounded key rotation: the observer can
/// discard old epoch keys while retaining the ability to accept
/// futures epochs from the same agent. This limits the blast radius
/// of a single epoch key compromise.
///
/// # Pigeonhole
///
/// Epoch is a 64-bit value. At one epoch per hour, this provides
/// ~2^44 epochs (~2 trillion years) before wraparound. Typical
/// deployments use Unix timestamps truncated to hourly granularity.
pub fn derive_epoch_key(agent_key: &Key, epoch: u64) -> Key {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&DOMAIN_EPOCH);
    nonce[4..12].copy_from_slice(&epoch.to_le_bytes());

    let block = chacha20_block(agent_key.as_bytes(), 0, &nonce);
    let mut derived = [0u8; 32];
    derived.copy_from_slice(&block[..32]);
    Key::from_bytes(derived)
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

        // The epoch key must be different from both the agent key and master
        assert_ne!(epoch_key.as_bytes(), agent_key.as_bytes());
        assert_ne!(epoch_key.as_bytes(), master.as_bytes());
        assert_ne!(agent_key.as_bytes(), master.as_bytes());
    }

    #[test]
    fn agent_key_and_epoch_key_have_different_domains() {
        // Derive an agent key. Then derive what looks like an "epoch key"
        // but using the agent ID as the epoch — it should produce a
        // different key than the agent key itself, proving domain separation.
        let master = Key::from_bytes([0x42; 32]);
        let agent_key = derive_agent_key(&master, 1000);
        let fake_epoch = derive_epoch_key(&master, 1000);
        assert_ne!(agent_key.as_bytes(), fake_epoch.as_bytes());
    }
}
