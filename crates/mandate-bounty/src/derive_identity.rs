//! KDF chain: canonical CSV → SHA3-512 → Argon2id → age x25519 Identity.
//!
//! Derives a deterministic age identity from a canonical solution CSV,
//! enabling anyone with the correct solution to reproduce the same keypair.

use age::x25519::Identity;
use argon2::{Algorithm, Argon2, Params, Version};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroize;

use crate::config::KdfConfig;

/// Normalize participant-submitted CSV bytes before hashing.
///
/// This strips an optional UTF-8 BOM, rewrites all line endings to LF,
/// and removes trailing empty lines so equivalent text produces the same KDF.
pub fn normalize_csv_bytes(csv_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(csv_bytes)
        .map_err(|e| anyhow::anyhow!("CSV file is not valid UTF-8: {e}"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    Ok(normalized.trim_end_matches('\n').as_bytes().to_vec())
}

/// Derive an age x25519 Identity from canonical CSV content using the KDF chain.
///
/// Steps:
/// 1. SHA3-512(csv_bytes) → 64 bytes
/// 2. Argon2id(password=sha3_hash, salt=kdf.salt, params) → 32 bytes
/// 3. age::x25519::Identity::from_secret_bytes(argon2_output)
pub fn derive_identity(csv_bytes: &[u8], kdf: &KdfConfig) -> anyhow::Result<Identity> {
    let mut normalized_csv = normalize_csv_bytes(csv_bytes)?;

    // Step 1: SHA3-512 hash of canonical CSV
    let mut sha3_hash = Sha3_512::digest(&normalized_csv).to_vec();

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
    normalized_csv.zeroize();
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
        let csv = b"Alice,Option A\nBob,Option B";
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
        let csv = b"Alice,Option B\nZara,Option A\nMika,Option C";
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
            pubkey, "age14lnqc7580yn083a38f3l8lln23dh4g09r8sp7yxwy0x3ges3gy8qdqfsa5",
            "golden vector mismatch — KDF chain output has changed"
        );
    }

    /// Second golden vector with different CSV content.
    #[test]
    fn test_golden_vector_2_entries() {
        let csv = b"Alice,Option A\nBob,Option B";
        let kdf = test_kdf_config();

        let identity = derive_identity(csv, &kdf).expect("derive_identity should succeed");
        let pubkey = identity.to_public().to_string();

        assert_eq!(
            pubkey, "age1syekeesakee7hxu5ckdpg4ne9j2kqhxpmpkp08d65s7wt3djteuqjqfcat",
            "golden vector 2 mismatch — KDF chain output has changed"
        );
    }

    #[test]
    fn test_derive_identity_different_input_different_output() {
        let kdf = test_kdf_config();

        let id1 = derive_identity(b"Alice,Option A\nBob,Option B", &kdf)
            .expect("derive_identity should succeed");
        let id2 = derive_identity(b"Alice,Option A\nBob,Option C", &kdf)
            .expect("derive_identity should succeed");

        assert_ne!(
            id1.to_public().to_string(),
            id2.to_public().to_string(),
            "different input must produce different identity"
        );
    }

    #[test]
    fn test_derive_identity_different_salt_different_output() {
        let csv = b"Alice,Option A\nBob,Option B";

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

    #[test]
    fn test_normalize_csv_bytes_removes_bom_and_crlf() {
        let normalized = normalize_csv_bytes(b"\xEF\xBB\xBFAlice,Option A\r\nBob,Option B\r\n\r\n")
            .expect("normalize");
        assert_eq!(normalized, b"Alice,Option A\nBob,Option B");
    }
}
