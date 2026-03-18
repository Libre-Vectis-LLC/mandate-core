//! KDF chain: canonical CSV → SHA3-512 → Argon2id → age x25519 Identity.
//!
//! Derives a deterministic age identity from a canonical solution CSV,
//! enabling anyone with the correct solution to reproduce the same keypair.

use age::x25519::Identity;
use argon2::{Algorithm, Argon2, Params, Version};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;

use crate::config::KdfConfig;

/// Derive an age x25519 Identity from canonical CSV content using the KDF chain.
///
/// Steps:
/// 1. SHA3-512(csv_bytes) → 64 bytes
/// 2. Argon2id(password=sha3_hash, salt=kdf.salt, params) → 32 bytes
/// 3. age::x25519::Identity::from_secret_bytes(argon2_output)
pub fn derive_identity(csv_bytes: &[u8], kdf: &KdfConfig) -> anyhow::Result<Identity> {
    // Step 1: SHA3-512 hash of canonical CSV
    let mut sha3_hash = Sha3_512::digest(csv_bytes).to_vec();

    // Step 2: Argon2id KDF
    let m_cost_kib = kdf
        .m_cost_mib
        .checked_mul(1024)
        .ok_or_else(|| anyhow::anyhow!("m_cost_mib overflow when converting to KiB"))?;

    let params = Params::new(m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(&sha3_hash, kdf.salt.as_bytes(), &mut output)
        .map_err(|e| anyhow::anyhow!("Argon2id hashing failed: {e}"))?;

    // Zeroize intermediate material
    sha3_hash.zeroize();

    // Step 3: Create age identity from derived bytes
    let identity = Identity::from_secret_bytes(output);
    output.zeroize();

    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny KDF params for fast testing (1 MiB, 1 iteration, 1 lane).
    fn test_kdf_config() -> KdfConfig {
        KdfConfig {
            salt: "test-salt".into(),
            m_cost_mib: 1,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn test_derive_identity_deterministic() {
        let csv = b"Alice,opt-a\nBob,opt-b";
        let kdf = test_kdf_config();

        let id1 = derive_identity(csv, &kdf).expect("derive_identity should succeed");
        let id2 = derive_identity(csv, &kdf).expect("derive_identity should succeed");

        assert_eq!(
            id1.to_public().to_string(),
            id2.to_public().to_string(),
            "same input must produce same identity"
        );
    }

    /// Golden vector test: fixed CSV + tiny KDF params → known age1... pubkey.
    ///
    /// If this test breaks, the KDF chain output has changed — which means
    /// existing bounty challenges would become unverifiable.
    #[test]
    fn test_golden_vector() {
        // Fixed 3-entry CSV, already sorted by pubkey_bs58 (AAA < BBB < CCC)
        let csv = b"Alice,opt-b\nZara,opt-a\nMika,opt-c";
        let kdf = KdfConfig {
            salt: "test-salt".into(),
            m_cost_mib: 1,
            t_cost: 1,
            p_cost: 1,
        };

        let identity = derive_identity(csv, &kdf).expect("derive_identity should succeed");
        let pubkey = identity.to_public().to_string();

        // Hardcoded expected value — DO NOT CHANGE without bumping challenge version
        assert_eq!(
            pubkey, "age12xxh4679z7ypv4f9nl6cag0u6eyu8xhe7gnyjf7m6uwspxhs83fqhgyp7p",
            "golden vector mismatch — KDF chain output has changed"
        );
    }

    /// Second golden vector with different CSV content.
    #[test]
    fn test_golden_vector_2_entries() {
        let csv = b"Alice,opt-a\nBob,opt-b";
        let kdf = test_kdf_config();

        let identity = derive_identity(csv, &kdf).expect("derive_identity should succeed");
        let pubkey = identity.to_public().to_string();

        assert_eq!(
            pubkey, "age1d69tnll2p4uy2g72sgd3vnlcercq3xqk9mxdkj0kmfdgc0wzfv7qaq6ysk",
            "golden vector 2 mismatch — KDF chain output has changed"
        );
    }

    #[test]
    fn test_derive_identity_different_input_different_output() {
        let kdf = test_kdf_config();

        let id1 = derive_identity(b"Alice,opt-a\nBob,opt-b", &kdf)
            .expect("derive_identity should succeed");
        let id2 = derive_identity(b"Alice,opt-a\nBob,opt-c", &kdf)
            .expect("derive_identity should succeed");

        assert_ne!(
            id1.to_public().to_string(),
            id2.to_public().to_string(),
            "different input must produce different identity"
        );
    }

    #[test]
    fn test_derive_identity_different_salt_different_output() {
        let csv = b"Alice,opt-a\nBob,opt-b";

        let kdf1 = test_kdf_config();
        let mut kdf2 = test_kdf_config();
        kdf2.salt = "other-salt".into();

        let id1 = derive_identity(csv, &kdf1).expect("derive_identity should succeed");
        let id2 = derive_identity(csv, &kdf2).expect("derive_identity should succeed");

        assert_ne!(
            id1.to_public().to_string(),
            id2.to_public().to_string(),
            "different salt must produce different identity"
        );
    }
}
