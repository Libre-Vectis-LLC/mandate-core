//! Registry-ring cross-validation.
//!
//! Compares the set of Nazgul master public keys from a voter registry
//! (parsed from XLSX) against the ring member public keys declared in a
//! [`PollBundle`](crate::bundle::PollBundle). Optionally validates that
//! every registry key can be successfully derived into a poll-specific
//! signing key using the HKDF derivation path.

use std::collections::BTreeSet;

use thiserror::Error;

use crate::derivation::{self, DerivationError};
use crate::registry::RegistryEntry;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during cross-validation.
#[derive(Debug, Error)]
pub enum CrossValidationError {
    /// A registry entry's master public key failed derivation.
    #[error("derivation failed for registry entry {voter_info:?}: {source}")]
    Derivation {
        voter_info: String,
        #[source]
        source: DerivationError,
    },
}

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Outcome of cross-validating registry entries against ring member keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossValidationResult {
    /// Number of master public keys present in both registry and ring.
    pub matched: usize,

    /// Master public keys that appear in the ring but NOT in the registry
    /// (bs58-encoded).
    pub extra_in_ring: Vec<String>,

    /// Registry entries whose master public key appears in the registry but
    /// NOT in the ring.
    pub missing_from_ring: Vec<RegistryEntry>,
}

impl CrossValidationResult {
    /// Returns `true` when registry and ring are perfectly aligned.
    pub fn is_perfect_match(&self) -> bool {
        self.extra_in_ring.is_empty() && self.missing_from_ring.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Cross-validate a voter registry against a poll bundle's ring member keys.
///
/// The function performs two checks:
///
/// 1. **Set comparison** — compares registry master public keys against
///    `ring_member_pubs` to find matched, extra, and missing members.
///
/// 2. **Derivation integrity** — verifies that every registry entry's master
///    key can be successfully derived into a poll-specific signing key using
///    the provided HKDF derivation path parameters. This catches corrupt or
///    invalid public keys early.
///
/// # Arguments
///
/// * `registry` — parsed voter registry entries.
/// * `ring_member_pubs` — bs58-encoded Nazgul master public keys from the
///   bundle.
/// * `org_id` — organization identifier (ULID string) for derivation.
/// * `poll_ulid` — poll identifier string for derivation.
/// * `poll_ring_hash` — 32-byte ring hash for derivation.
///
/// # Errors
///
/// Returns [`CrossValidationError::Derivation`] if any registry entry's
/// master public key cannot be derived (invalid bs58 or invalid curve point).
pub fn cross_validate(
    registry: &[RegistryEntry],
    ring_member_pubs: &[String],
    org_id: &str,
    poll_ulid: &str,
    poll_ring_hash: &[u8; 32],
) -> Result<CrossValidationResult, CrossValidationError> {
    // --- Derivation integrity check ---
    // Verify every registry master key is cryptographically valid by
    // attempting the HKDF derivation. We collect the bs58 strings for the
    // set comparison below.
    let registry_keys: BTreeSet<&str> = registry
        .iter()
        .map(|entry| entry.master_pub_bs58.as_str())
        .collect();

    // Attempt derivation for all registry keys (validates they are valid
    // Ristretto points and the org_id is a proper ULID).
    if !registry.is_empty() {
        let master_strs: Vec<&str> = registry
            .iter()
            .map(|e| e.master_pub_bs58.as_str())
            .collect();

        derivation::derive_poll_ring(&master_strs, org_id, poll_ring_hash, poll_ulid).map_err(
            |source| {
                // Find which entry caused the failure from the index encoded
                // in the DerivationError variants.
                let idx = derivation_error_index(&source);
                let voter_info = registry
                    .get(idx)
                    .map(|e| e.voter_info.clone())
                    .unwrap_or_else(|| format!("<index {idx}>"));
                CrossValidationError::Derivation { voter_info, source }
            },
        )?;
    }

    // --- Set comparison ---
    let ring_keys: BTreeSet<&str> = ring_member_pubs.iter().map(String::as_str).collect();

    let matched = registry_keys.intersection(&ring_keys).count();

    let extra_in_ring: Vec<String> = ring_keys
        .difference(&registry_keys)
        .map(|k| (*k).to_owned())
        .collect();

    let missing_from_ring: Vec<RegistryEntry> = registry
        .iter()
        .filter(|entry| !ring_keys.contains(entry.master_pub_bs58.as_str()))
        .cloned()
        .collect();

    Ok(CrossValidationResult {
        matched,
        extra_in_ring,
        missing_from_ring,
    })
}

/// Extract the index from a [`DerivationError`] variant.
fn derivation_error_index(err: &DerivationError) -> usize {
    match err {
        DerivationError::InvalidBs58 { index, .. }
        | DerivationError::InvalidPointLength { index, .. }
        | DerivationError::DecompressionFailed { index } => *index,
        // InvalidOrgId is not index-specific; attribute to first entry.
        DerivationError::InvalidOrgId(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mandate_core::key_manager::KeyManager;

    /// Standard test mnemonic (24-word).
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const TEST_ORG_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const TEST_POLL_ULID: &str = "01JTEST_POLL";
    const TEST_RING_HASH: [u8; 32] = [0x11u8; 32];

    fn master_pub_bs58(km: &KeyManager) -> String {
        let master = km.derive_nazgul_master_keypair();
        let compressed = master.0.public().compress();
        bs58::encode(compressed.as_bytes()).into_string()
    }

    fn make_entry(name: &str, key: &str) -> RegistryEntry {
        RegistryEntry {
            voter_info: name.to_owned(),
            master_pub_bs58: key.to_owned(),
        }
    }

    /// Two distinct key managers producing different master keys.
    fn two_key_managers() -> (KeyManager, KeyManager) {
        let km1 = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid mnemonic");
        let km2 = KeyManager::from_mnemonic(TEST_MNEMONIC, Some("other")).expect("valid mnemonic");
        (km1, km2)
    }

    // -----------------------------------------------------------------------
    // Test: perfect match
    // -----------------------------------------------------------------------

    #[test]
    fn test_perfect_match() {
        let (km1, km2) = two_key_managers();
        let pub1 = master_pub_bs58(&km1);
        let pub2 = master_pub_bs58(&km2);

        let registry = vec![make_entry("Alice", &pub1), make_entry("Bob", &pub2)];
        let ring = vec![pub1.clone(), pub2.clone()];

        let result = cross_validate(
            &registry,
            &ring,
            TEST_ORG_ID,
            TEST_POLL_ULID,
            &TEST_RING_HASH,
        )
        .expect("cross-validation should succeed");

        assert_eq!(result.matched, 2);
        assert!(result.extra_in_ring.is_empty());
        assert!(result.missing_from_ring.is_empty());
        assert!(result.is_perfect_match());
    }

    // -----------------------------------------------------------------------
    // Test: extra member in ring (not in registry)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extra_member_in_ring() {
        let (km1, km2) = two_key_managers();
        let pub1 = master_pub_bs58(&km1);
        let pub2 = master_pub_bs58(&km2);

        // Registry only has Alice
        let registry = vec![make_entry("Alice", &pub1)];
        // Ring has both Alice and Bob
        let ring = vec![pub1.clone(), pub2.clone()];

        let result = cross_validate(
            &registry,
            &ring,
            TEST_ORG_ID,
            TEST_POLL_ULID,
            &TEST_RING_HASH,
        )
        .expect("cross-validation should succeed");

        assert_eq!(result.matched, 1);
        assert_eq!(result.extra_in_ring.len(), 1);
        assert_eq!(result.extra_in_ring[0], pub2);
        assert!(result.missing_from_ring.is_empty());
        assert!(!result.is_perfect_match());
    }

    // -----------------------------------------------------------------------
    // Test: missing member (in registry but not in ring)
    // -----------------------------------------------------------------------

    #[test]
    fn test_missing_member_from_ring() {
        let (km1, km2) = two_key_managers();
        let pub1 = master_pub_bs58(&km1);
        let pub2 = master_pub_bs58(&km2);

        // Registry has both Alice and Bob
        let registry = vec![make_entry("Alice", &pub1), make_entry("Bob", &pub2)];
        // Ring only has Alice
        let ring = vec![pub1.clone()];

        let result = cross_validate(
            &registry,
            &ring,
            TEST_ORG_ID,
            TEST_POLL_ULID,
            &TEST_RING_HASH,
        )
        .expect("cross-validation should succeed");

        assert_eq!(result.matched, 1);
        assert!(result.extra_in_ring.is_empty());
        assert_eq!(result.missing_from_ring.len(), 1);
        assert_eq!(result.missing_from_ring[0].voter_info, "Bob");
        assert_eq!(result.missing_from_ring[0].master_pub_bs58, pub2);
        assert!(!result.is_perfect_match());
    }

    // -----------------------------------------------------------------------
    // Test: empty inputs
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_registry_and_ring() {
        let result = cross_validate(&[], &[], TEST_ORG_ID, TEST_POLL_ULID, &TEST_RING_HASH)
            .expect("empty inputs should succeed");

        assert_eq!(result.matched, 0);
        assert!(result.extra_in_ring.is_empty());
        assert!(result.missing_from_ring.is_empty());
        assert!(result.is_perfect_match());
    }

    #[test]
    fn test_empty_registry_with_ring_members() {
        let (km1, _) = two_key_managers();
        let pub1 = master_pub_bs58(&km1);

        let ring = vec![pub1.clone()];

        let result = cross_validate(&[], &ring, TEST_ORG_ID, TEST_POLL_ULID, &TEST_RING_HASH)
            .expect("should succeed");

        assert_eq!(result.matched, 0);
        assert_eq!(result.extra_in_ring.len(), 1);
        assert!(result.missing_from_ring.is_empty());
        assert!(!result.is_perfect_match());
    }

    // -----------------------------------------------------------------------
    // Test: derivation failure (invalid key in registry)
    // -----------------------------------------------------------------------

    #[test]
    fn test_derivation_failure_for_invalid_registry_key() {
        let registry = vec![make_entry("BadActor", "not-valid-bs58!!!")];
        let ring = vec!["not-valid-bs58!!!".to_owned()];

        let err = cross_validate(
            &registry,
            &ring,
            TEST_ORG_ID,
            TEST_POLL_ULID,
            &TEST_RING_HASH,
        )
        .unwrap_err();

        assert!(
            matches!(
                err,
                CrossValidationError::Derivation {
                    ref voter_info,
                    ..
                } if voter_info == "BadActor"
            ),
            "expected Derivation error for BadActor, got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Boundary: duplicate keys in ring (set comparison deduplicates)
    // -----------------------------------------------------------------------

    #[test]
    fn test_duplicate_ring_members_counted_once() {
        let (km1, _) = two_key_managers();
        let pub1 = master_pub_bs58(&km1);

        let registry = vec![make_entry("Alice", &pub1)];
        // Ring has the same key twice
        let ring = vec![pub1.clone(), pub1.clone()];

        let result = cross_validate(
            &registry,
            &ring,
            TEST_ORG_ID,
            TEST_POLL_ULID,
            &TEST_RING_HASH,
        )
        .expect("should succeed");

        // BTreeSet deduplicates, so ring has effectively 1 unique key
        assert_eq!(result.matched, 1);
        assert!(result.extra_in_ring.is_empty());
        assert!(result.missing_from_ring.is_empty());
        assert!(result.is_perfect_match());
    }

    // -----------------------------------------------------------------------
    // Boundary: empty ring with non-empty registry
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_ring_with_registry() {
        let (km1, _) = two_key_managers();
        let pub1 = master_pub_bs58(&km1);

        let registry = vec![make_entry("Alice", &pub1)];
        let ring: Vec<String> = Vec::new();

        let result = cross_validate(
            &registry,
            &ring,
            TEST_ORG_ID,
            TEST_POLL_ULID,
            &TEST_RING_HASH,
        )
        .expect("should succeed");

        assert_eq!(result.matched, 0);
        assert!(result.extra_in_ring.is_empty());
        assert_eq!(result.missing_from_ring.len(), 1);
        assert_eq!(result.missing_from_ring[0].voter_info, "Alice");
        assert!(!result.is_perfect_match());
    }

    // -----------------------------------------------------------------------
    // Boundary: large registry and ring, perfect match
    // -----------------------------------------------------------------------

    #[test]
    fn test_large_perfect_match() {
        // Use multiple key managers with different passphrases to generate
        // distinct keys. We'll use passphrases "0", "1", "2", etc.
        let count = 5;
        let mut registry = Vec::new();
        let mut ring = Vec::new();

        for i in 0..count {
            let passphrase = format!("{i}");
            let passphrase_opt = if i == 0 {
                None
            } else {
                Some(passphrase.as_str())
            };
            let km =
                KeyManager::from_mnemonic(TEST_MNEMONIC, passphrase_opt).expect("valid mnemonic");
            let pub_key = master_pub_bs58(&km);
            registry.push(make_entry(&format!("Voter-{i}"), &pub_key));
            ring.push(pub_key);
        }

        let result = cross_validate(
            &registry,
            &ring,
            TEST_ORG_ID,
            TEST_POLL_ULID,
            &TEST_RING_HASH,
        )
        .expect("should succeed");

        assert_eq!(result.matched, count);
        assert!(result.is_perfect_match());
    }
}
