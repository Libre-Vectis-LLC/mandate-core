//! POW verifier service.

use std::time::{SystemTime, UNIX_EPOCH};

use moka::future::Cache;
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

/// POW verifier using rspow near-stateless protocol.
///
/// Maintains a replay cache to prevent reuse of POW submissions.
pub struct PowVerifier {
    /// Replay cache: maps client_nonce to timestamp when it was used.
    replay_cache: Cache<[u8; 32], u64>,
}

impl PowVerifier {
    /// Creates a new POW verifier.
    ///
    /// # Arguments
    ///
    /// * `cache_capacity` - Maximum number of nonces to keep in replay cache.
    /// * `cache_ttl_secs` - Time-to-live for cache entries in seconds.
    pub fn new(cache_capacity: u64, cache_ttl_secs: u64) -> Self {
        let replay_cache = Cache::builder()
            .max_capacity(cache_capacity)
            .time_to_live(std::time::Duration::from_secs(cache_ttl_secs))
            .build();

        Self { replay_cache }
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

        // Check for replay attack
        if self
            .replay_cache
            .get(&submission.client_nonce)
            .await
            .is_some()
        {
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

        // All proofs verified successfully, add nonce to replay cache
        self.replay_cache
            .insert(submission.client_nonce, submission.timestamp)
            .await;

        Ok(PowVerifyResult::success(proofs_verified))
    }

    /// Clears the replay cache (for testing purposes).
    #[cfg(test)]
    pub async fn clear_cache(&self) {
        self.replay_cache.invalidate_all();
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
    async fn test_replay_detection() {
        let verifier = PowVerifier::new(10000, 300);
        let nonce = [42u8; 32];

        // Insert nonce into cache
        verifier.replay_cache.insert(nonce, 1234567890).await;

        let params = PowParams::new(7, 1, 60);
        let submission = PowSubmission::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce,
            vec![],
        );

        let result = verifier.verify_submission(&submission, &params).await;
        assert!(matches!(result, Err(PowVerifyError::ReplayDetected)));
    }
}
