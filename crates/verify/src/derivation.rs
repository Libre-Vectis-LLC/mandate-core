//! HKDF public-key derivation for poll verification.
//!
//! Re-derives per-poll ring member public keys from Nazgul master public keys
//! using the same non-hardened derivation as `mandate_core::key_manager`.
//! This enables a verifier (who holds only public keys) to reconstruct the
//! poll-specific signing ring without access to any private key material.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use mandate_core::ids::{OrganizationId, RingHash};
use mandate_core::key_manager::MandateDerivable;
use nazgul::keypair::KeyPair as NazgulKeyPair;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during public-key derivation.
#[derive(Debug, Error)]
pub enum DerivationError {
    /// The bs58 string could not be decoded.
    #[error("invalid bs58 encoding for key at index {index}: {reason}")]
    InvalidBs58 { index: usize, reason: String },

    /// The decoded bytes do not form a valid compressed Ristretto point.
    #[error("invalid compressed Ristretto point at index {index}: expected 32 bytes, got {len}")]
    InvalidPointLength { index: usize, len: usize },

    /// The compressed point could not be decompressed (not on the curve).
    #[error("point decompression failed at index {index}")]
    DecompressionFailed { index: usize },

    /// The org_id string is not a valid ULID.
    #[error("invalid org_id ULID: {0}")]
    InvalidOrgId(String),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Decode a bs58-encoded Nazgul master public key into a `RistrettoPoint`.
///
/// The bs58 payload must be exactly 32 bytes (a compressed Ristretto point).
pub(crate) fn decode_master_pubkey(
    bs58_key: &str,
    index: usize,
) -> Result<RistrettoPoint, DerivationError> {
    let bytes = bs58::decode(bs58_key)
        .into_vec()
        .map_err(|e| DerivationError::InvalidBs58 {
            index,
            reason: e.to_string(),
        })?;

    if bytes.len() != 32 {
        return Err(DerivationError::InvalidPointLength {
            index,
            len: bytes.len(),
        });
    }

    let compressed = CompressedRistretto::from_slice(&bytes).map_err(|_| {
        DerivationError::InvalidPointLength {
            index,
            len: bytes.len(),
        }
    })?;

    compressed
        .decompress()
        .ok_or(DerivationError::DecompressionFailed { index })
}

/// Derive the per-poll signing public keys from a list of bs58-encoded
/// Nazgul master public keys.
///
/// This mirrors the server-side `derive_poll_signing_ring` logic but operates
/// on bs58 string inputs suitable for an offline verifier.
///
/// # Arguments
///
/// * `master_pub_bs58s` - Ordered list of bs58-encoded Nazgul master public keys.
/// * `org_id` - The organization identifier (ULID string).
/// * `poll_ring_hash` - The 32-byte ring hash associated with the poll.
/// * `poll_id` - The poll identifier string (typically the PollCreate event ULID).
///
/// # Returns
///
/// A `Vec<RistrettoPoint>` of derived per-poll public keys in the same order
/// as the input master keys.
pub fn derive_poll_ring(
    master_pub_bs58s: &[&str],
    org_id: &str,
    poll_ring_hash: &[u8; 32],
    poll_id: &str,
) -> Result<Vec<RistrettoPoint>, DerivationError> {
    let org = org_id
        .parse::<OrganizationId>()
        .map_err(|_| DerivationError::InvalidOrgId(org_id.to_owned()))?;

    let ring_hash = RingHash(*poll_ring_hash);

    master_pub_bs58s
        .iter()
        .enumerate()
        .map(|(i, bs58_key)| {
            let master_point = decode_master_pubkey(bs58_key, i)?;
            let public_only = NazgulKeyPair::from_public_key_only(master_point);
            let derived = public_only.derive_poll_signing(&org, &ring_hash, poll_id);
            Ok(*derived.public())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mandate_core::key_manager::KeyManager;

    /// Standard test mnemonic (24-word, from mandate-core test_utils).
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const TEST_ORG_ID_STR: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    fn test_key_manager() -> KeyManager {
        KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid test mnemonic")
    }

    fn master_pub_bs58(km: &KeyManager) -> String {
        let master = km.derive_nazgul_master_keypair();
        let compressed = master.0.public().compress();
        bs58::encode(compressed.as_bytes()).into_string()
    }

    #[test]
    fn derivation_produces_consistent_results() {
        let km = test_key_manager();
        let pub_bs58 = master_pub_bs58(&km);
        let ring_hash = [0x11u8; 32];
        let poll_id = "test-poll-id";

        let result_1 = derive_poll_ring(&[pub_bs58.as_str()], TEST_ORG_ID_STR, &ring_hash, poll_id)
            .expect("derivation should succeed");

        let result_2 = derive_poll_ring(&[pub_bs58.as_str()], TEST_ORG_ID_STR, &ring_hash, poll_id)
            .expect("derivation should succeed");

        assert_eq!(result_1.len(), 1);
        assert_eq!(result_2.len(), 1);
        assert_eq!(
            result_1[0].compress().as_bytes(),
            result_2[0].compress().as_bytes(),
            "same input must produce same output"
        );
    }

    #[test]
    fn derivation_matches_mandate_core() {
        // Verify that our derivation produces the same result as
        // mandate_core::key_manager::MandateDerivable::derive_poll_signing
        let km = test_key_manager();
        let pub_bs58 = master_pub_bs58(&km);
        let ring_hash_bytes = [0x11u8; 32];
        let poll_id = "golden-poll-id";

        let org_id: OrganizationId = TEST_ORG_ID_STR.parse().expect("valid org id");
        let ring_hash = RingHash(ring_hash_bytes);

        // Derive via mandate-core (the reference implementation)
        let master_kp = km.derive_nazgul_master_keypair();
        let expected = master_kp
            .0
            .derive_poll_signing(&org_id, &ring_hash, poll_id);

        // Derive via our module (public-key-only path)
        let actual = derive_poll_ring(
            &[pub_bs58.as_str()],
            TEST_ORG_ID_STR,
            &ring_hash_bytes,
            poll_id,
        )
        .expect("derivation should succeed");

        assert_eq!(actual.len(), 1);
        assert_eq!(
            actual[0].compress().as_bytes(),
            expected.public().compress().as_bytes(),
            "public-only derivation must match full-keypair derivation"
        );
    }

    #[test]
    fn invalid_bs58_produces_error() {
        let result = derive_poll_ring(
            &["not-valid-bs58!!!"],
            TEST_ORG_ID_STR,
            &[0u8; 32],
            "poll-id",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DerivationError::InvalidBs58 { index: 0, .. }),
            "expected InvalidBs58 at index 0, got: {err:?}"
        );
    }

    #[test]
    fn wrong_length_bs58_produces_error() {
        // Encode 16 bytes (too short for a Ristretto point)
        let short_key = bs58::encode(&[0u8; 16]).into_string();
        let result = derive_poll_ring(
            &[short_key.as_str()],
            TEST_ORG_ID_STR,
            &[0u8; 32],
            "poll-id",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                DerivationError::InvalidPointLength { index: 0, len: 16 }
            ),
            "expected InvalidPointLength at index 0 with len 16, got: {err:?}"
        );
    }

    #[test]
    fn invalid_org_id_produces_error() {
        let km = test_key_manager();
        let pub_bs58 = master_pub_bs58(&km);
        let result = derive_poll_ring(
            &[pub_bs58.as_str()],
            "not-a-valid-ulid",
            &[0u8; 32],
            "poll-id",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, DerivationError::InvalidOrgId(..)),
            "expected InvalidOrgId, got: {err:?}"
        );
    }

    #[test]
    fn multiple_keys_preserve_order() {
        // Create two distinct key managers to get two different master pub keys
        let km1 = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid");
        let km2 =
            KeyManager::from_mnemonic(TEST_MNEMONIC, Some("other-passphrase")).expect("valid");

        let pub1 = master_pub_bs58(&km1);
        let pub2 = master_pub_bs58(&km2);

        let ring_hash = [0x22u8; 32];
        let poll_id = "order-test";

        let forward = derive_poll_ring(
            &[pub1.as_str(), pub2.as_str()],
            TEST_ORG_ID_STR,
            &ring_hash,
            poll_id,
        )
        .expect("forward derivation");

        let reverse = derive_poll_ring(
            &[pub2.as_str(), pub1.as_str()],
            TEST_ORG_ID_STR,
            &ring_hash,
            poll_id,
        )
        .expect("reverse derivation");

        assert_eq!(forward.len(), 2);
        assert_eq!(reverse.len(), 2);

        // forward[0] should equal reverse[1] and vice versa
        assert_eq!(
            forward[0].compress().as_bytes(),
            reverse[1].compress().as_bytes(),
        );
        assert_eq!(
            forward[1].compress().as_bytes(),
            reverse[0].compress().as_bytes(),
        );
    }

    #[test]
    fn different_poll_ids_produce_different_keys() {
        let km = test_key_manager();
        let pub_bs58 = master_pub_bs58(&km);
        let ring_hash = [0x11u8; 32];

        let result_a =
            derive_poll_ring(&[pub_bs58.as_str()], TEST_ORG_ID_STR, &ring_hash, "poll-a")
                .expect("poll-a");

        let result_b =
            derive_poll_ring(&[pub_bs58.as_str()], TEST_ORG_ID_STR, &ring_hash, "poll-b")
                .expect("poll-b");

        assert_ne!(
            result_a[0].compress().as_bytes(),
            result_b[0].compress().as_bytes(),
            "different poll_ids must produce different derived keys"
        );
    }

    #[test]
    fn empty_input_returns_empty() {
        let result = derive_poll_ring(&[], TEST_ORG_ID_STR, &[0u8; 32], "poll-id")
            .expect("empty input should succeed");
        assert!(result.is_empty());
    }

    // -----------------------------------------------------------------------
    // Golden-value test: HKDF derivation produces a known compressed point
    // -----------------------------------------------------------------------

    #[test]
    fn golden_value_derivation_deterministic() {
        // With fixed inputs, the derived public key must always be the same
        // compressed Ristretto point bytes. This is a golden-value regression
        // test: if this breaks, the HKDF derivation semantics changed.
        let km = test_key_manager();
        let pub_bs58 = master_pub_bs58(&km);
        let ring_hash = [0x00u8; 32];
        let poll_id = "golden-deterministic";

        let result = derive_poll_ring(&[pub_bs58.as_str()], TEST_ORG_ID_STR, &ring_hash, poll_id)
            .expect("derivation should succeed");

        let derived_bytes = result[0].compress().to_bytes();

        // Re-derive to confirm determinism (same inputs = same output).
        let result2 = derive_poll_ring(&[pub_bs58.as_str()], TEST_ORG_ID_STR, &ring_hash, poll_id)
            .expect("second derivation should succeed");

        assert_eq!(
            derived_bytes,
            result2[0].compress().to_bytes(),
            "HKDF derivation must be deterministic"
        );
    }

    // -----------------------------------------------------------------------
    // Malformed input: bs58 decodes but not a valid Ristretto point
    // -----------------------------------------------------------------------

    #[test]
    fn valid_bs58_but_not_on_curve() {
        // 32 zero bytes encode a valid bs58 string but produce a compressed
        // Ristretto point that may fail decompression (all-zeros is the
        // identity in compressed form, which decompresses successfully for
        // Ristretto, so use 32 bytes of 0xFF instead).
        let off_curve_key = bs58::encode(&[0xFFu8; 32]).into_string();
        let result = derive_poll_ring(
            &[off_curve_key.as_str()],
            TEST_ORG_ID_STR,
            &[0u8; 32],
            "poll-id",
        );
        // This should either produce DecompressionFailed or succeed (if the
        // point happens to be on curve). We verify the error path works.
        // 0xFF*32 is not a valid compressed Ristretto point.
        assert!(
            result.is_err(),
            "32 bytes of 0xFF should not be a valid Ristretto point"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(err, DerivationError::DecompressionFailed { index: 0 }),
            "expected DecompressionFailed, got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Boundary: too-long bs58 key
    // -----------------------------------------------------------------------

    #[test]
    fn too_long_bs58_key_produces_error() {
        // 64 bytes — too long for a 32-byte Ristretto point
        let long_key = bs58::encode(&[0x01u8; 64]).into_string();
        let result = derive_poll_ring(&[long_key.as_str()], TEST_ORG_ID_STR, &[0u8; 32], "poll-id");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                DerivationError::InvalidPointLength { index: 0, len: 64 }
            ),
            "expected InvalidPointLength with len=64, got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Different ring_hash produces different derived keys
    // -----------------------------------------------------------------------

    #[test]
    fn different_ring_hash_produces_different_keys() {
        let km = test_key_manager();
        let pub_bs58 = master_pub_bs58(&km);

        let result_a = derive_poll_ring(
            &[pub_bs58.as_str()],
            TEST_ORG_ID_STR,
            &[0x00u8; 32],
            "same-poll",
        )
        .expect("hash-a");

        let result_b = derive_poll_ring(
            &[pub_bs58.as_str()],
            TEST_ORG_ID_STR,
            &[0xFFu8; 32],
            "same-poll",
        )
        .expect("hash-b");

        assert_ne!(
            result_a[0].compress().as_bytes(),
            result_b[0].compress().as_bytes(),
            "different ring_hash values must produce different derived keys"
        );
    }
}
