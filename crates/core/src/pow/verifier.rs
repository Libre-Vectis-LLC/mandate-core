//! POW verifier service.

use std::time::{SystemTime, UNIX_EPOCH};

use moka::future::Cache;
use sha3::{Digest, Sha3_256};
use thiserror::Error;

use super::types::{PowParams, PowSubmission, PowVerifyResult};

/// POW verification errors.
#[derive(Debug, Error)]
pub enum PowVerifyError {
    /// POW submission expired (outside time window).
    #[error("POW expired: timestamp {timestamp} is outside valid window")]
    Expired { timestamp: u64 },

    /// POW already used (replay attack detected).
    #[error("POW replay detected: nonce already used")]
    ReplayDetected,

    /// Failed to deserialize proof bundle.
    #[error("Failed to deserialize proof bundle: {0}")]
    DeserializationFailed(String),

    /// Insufficient proofs in bundle.
    #[error("Insufficient proofs: expected {expected}, got {actual}")]
    InsufficientProofs { expected: usize, actual: usize },

    /// Proof verification failed.
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid difficulty bits.
    #[error("Invalid difficulty: expected {expected} bits, got {actual} bits")]
    InvalidDifficulty { expected: u32, actual: u32 },

    /// rspow error.
    #[error("rspow error: {0}")]
    RspowError(String),
}

/// Composite key for POW replay detection: `[proof_bundle_hash (32) || client_nonce (32)]`.
///
/// Using both components prevents attacks where:
/// - Same proof_bundle is reused with different client_nonce values
/// - Same client_nonce is reused with different proof_bundle (though unlikely valid)
type ReplayKey = [u8; 64];

/// POW verifier using rspow near-stateless protocol.
///
/// Maintains a replay cache to prevent reuse of POW submissions.
/// The cache key combines proof_bundle hash and client_nonce to ensure
/// each unique (proof, nonce) pair can only be used once.
pub struct PowVerifier {
    /// Replay cache: maps (proof_bundle_hash || client_nonce) to timestamp.
    replay_cache: Cache<ReplayKey, u64>,
    /// Secondary cache: tracks proof_bundle hashes to prevent reuse with any nonce.
    proof_bundle_cache: Cache<[u8; 32], u64>,
}

impl PowVerifier {
    /// Creates a new POW verifier.
    ///
    /// # Arguments
    ///
    /// * `cache_capacity` - Maximum number of entries to keep in replay cache.
    /// * `cache_ttl_secs` - Time-to-live for cache entries in seconds.
    pub fn new(cache_capacity: u64, cache_ttl_secs: u64) -> Self {
        let replay_cache = Cache::builder()
            .max_capacity(cache_capacity)
            .time_to_live(std::time::Duration::from_secs(cache_ttl_secs))
            .build();

        // Separate cache for proof_bundle hashes to prevent bundle reuse attacks.
        // This cache tracks which proof bundles have been used, regardless of nonce.
        let proof_bundle_cache = Cache::builder()
            .max_capacity(cache_capacity)
            .time_to_live(std::time::Duration::from_secs(cache_ttl_secs))
            .build();

        Self {
            replay_cache,
            proof_bundle_cache,
        }
    }

    /// Computes SHA3-256 hash of proof bundle for replay detection.
    fn hash_proof_bundle(proof_bundle: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(proof_bundle);
        hasher.finalize().into()
    }

    /// Creates a composite replay key from proof_bundle hash and client_nonce.
    fn make_replay_key(proof_bundle_hash: &[u8; 32], client_nonce: &[u8; 32]) -> ReplayKey {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(proof_bundle_hash);
        key[32..].copy_from_slice(client_nonce);
        key
    }

    /// Verifies a POW submission.
    ///
    /// # Arguments
    ///
    /// * `submission` - The POW submission from the client.
    /// * `params` - The POW parameters that were sent to the client.
    ///
    /// # Returns
    ///
    /// Returns `Ok(PowVerifyResult)` if verification succeeds, or a `PowVerifyError` if it fails.
    pub async fn verify_submission(
        &self,
        submission: &PowSubmission,
        params: &PowParams,
    ) -> Result<PowVerifyResult, PowVerifyError> {
        // Check timestamp validity (within time window)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        let time_diff = current_time.abs_diff(submission.timestamp);

        if time_diff > params.time_window_secs {
            return Err(PowVerifyError::Expired {
                timestamp: submission.timestamp,
            });
        }

        // Compute proof_bundle hash for replay detection
        let proof_bundle_hash = Self::hash_proof_bundle(&submission.proof_bundle);

        // Check if this proof_bundle has been used before (with ANY nonce)
        // This is the critical fix: prevents reusing the same proof with different nonces
        if self
            .proof_bundle_cache
            .get(&proof_bundle_hash)
            .await
            .is_some()
        {
            return Err(PowVerifyError::ReplayDetected);
        }

        // Also check composite key for paranoia (belt + suspenders)
        let replay_key = Self::make_replay_key(&proof_bundle_hash, &submission.client_nonce);
        if self.replay_cache.get(&replay_key).await.is_some() {
            return Err(PowVerifyError::ReplayDetected);
        }

        // Deserialize proof bundle from rspow
        let bundle: rspow::ProofBundle = bincode::deserialize(&submission.proof_bundle)
            .map_err(|e| PowVerifyError::DeserializationFailed(e.to_string()))?;

        // Check proof count
        if bundle.proofs.len() < params.required_proofs {
            return Err(PowVerifyError::InsufficientProofs {
                expected: params.required_proofs,
                actual: bundle.proofs.len(),
            });
        }

        // Verify difficulty bits
        if bundle.config.bits != params.bits {
            return Err(PowVerifyError::InvalidDifficulty {
                expected: params.bits,
                actual: bundle.config.bits,
            });
        }

        // Verify the entire bundle using rspow's verify_strict method
        bundle
            .verify_strict(params.bits, params.required_proofs)
            .map_err(|e| PowVerifyError::VerificationFailed(e.to_string()))?;

        let proofs_verified = bundle.proofs.len();

        // All proofs verified successfully, add to both replay caches:
        // 1. proof_bundle_hash cache - prevents this proof from being reused with any nonce
        self.proof_bundle_cache
            .insert(proof_bundle_hash, submission.timestamp)
            .await;
        // 2. composite key cache - belt + suspenders
        self.replay_cache
            .insert(replay_key, submission.timestamp)
            .await;

        Ok(PowVerifyResult::success(proofs_verified))
    }

    /// Clears all replay caches (for testing purposes).
    #[cfg(test)]
    pub async fn clear_cache(&self) {
        self.replay_cache.invalidate_all();
        self.proof_bundle_cache.invalidate_all();
        // Wait for invalidation to propagate
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_verifier_creation() {
        let verifier = PowVerifier::new(10000, 300);
        assert_eq!(verifier.replay_cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn test_expired_submission() {
        let verifier = PowVerifier::new(10000, 300);
        let params = PowParams::new(7, 1, 60);

        // Submission from 2 hours ago
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 7200;

        let submission = PowSubmission::new(old_timestamp, [1u8; 32], vec![]);

        let result = verifier.verify_submission(&submission, &params).await;
        assert!(matches!(result, Err(PowVerifyError::Expired { .. })));
    }

    #[tokio::test]
    async fn test_replay_detection_via_proof_bundle() {
        let verifier = PowVerifier::new(10000, 300);
        let proof_bundle = vec![1u8, 2, 3, 4]; // Dummy proof bundle
        let proof_bundle_hash = PowVerifier::hash_proof_bundle(&proof_bundle);

        // Insert proof_bundle hash into cache (simulates previously used proof)
        verifier
            .proof_bundle_cache
            .insert(proof_bundle_hash, 1234567890)
            .await;

        let params = PowParams::new(7, 1, 60);
        let submission = PowSubmission::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            [42u8; 32], // Different nonce, but same proof_bundle should be rejected
            proof_bundle,
        );

        let result = verifier.verify_submission(&submission, &params).await;
        assert!(matches!(result, Err(PowVerifyError::ReplayDetected)));
    }

    #[tokio::test]
    async fn test_replay_detection_via_composite_key() {
        let verifier = PowVerifier::new(10000, 300);
        let proof_bundle = vec![5u8, 6, 7, 8]; // Dummy proof bundle
        let nonce = [42u8; 32];
        let proof_bundle_hash = PowVerifier::hash_proof_bundle(&proof_bundle);
        let replay_key = PowVerifier::make_replay_key(&proof_bundle_hash, &nonce);

        // Insert composite key into replay cache
        verifier.replay_cache.insert(replay_key, 1234567890).await;

        let params = PowParams::new(7, 1, 60);
        let submission = PowSubmission::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce,
            proof_bundle,
        );

        let result = verifier.verify_submission(&submission, &params).await;
        assert!(matches!(result, Err(PowVerifyError::ReplayDetected)));
    }
}
