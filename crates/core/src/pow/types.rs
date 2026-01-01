//! POW type definitions.

use serde::{Deserialize, Serialize};

/// POW parameters sent to client.
///
/// The client must compute `required_proofs` valid proofs with the specified `bits` difficulty
/// and submit them within `time_window_secs`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PowParams {
    /// Difficulty bits per proof (typically fixed at 7).
    pub bits: u32,
    /// Number of proofs required in the bundle.
    pub required_proofs: usize,
    /// Time window in seconds for the POW to be valid.
    pub time_window_secs: u64,
}

/// POW submission from client.
///
/// Contains the client's nonce, timestamp, and serialized rspow ProofBundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowSubmission {
    /// Unix timestamp when the POW was computed.
    pub timestamp: u64,
    /// Client-generated random nonce (32 bytes).
    pub client_nonce: [u8; 32],
    /// Serialized rspow ProofBundle (use rspow's serialization).
    pub proof_bundle: Vec<u8>,
}

/// POW verification result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PowVerifyResult {
    /// Whether the POW submission is valid.
    pub valid: bool,
    /// Number of proofs successfully verified in the bundle.
    pub proofs_verified: usize,
}

impl PowParams {
    /// Creates new POW parameters.
    pub fn new(bits: u32, required_proofs: usize, time_window_secs: u64) -> Self {
        Self {
            bits,
            required_proofs,
            time_window_secs,
        }
    }
}

impl PowSubmission {
    /// Creates a new POW submission.
    pub fn new(timestamp: u64, client_nonce: [u8; 32], proof_bundle: Vec<u8>) -> Self {
        Self {
            timestamp,
            client_nonce,
            proof_bundle,
        }
    }
}

impl PowVerifyResult {
    /// Creates a successful verification result.
    pub fn success(proofs_verified: usize) -> Self {
        Self {
            valid: true,
            proofs_verified,
        }
    }

    /// Creates a failed verification result.
    pub fn failure(proofs_verified: usize) -> Self {
        Self {
            valid: false,
            proofs_verified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_params_creation() {
        let params = PowParams::new(7, 100, 60);
        assert_eq!(params.bits, 7);
        assert_eq!(params.required_proofs, 100);
        assert_eq!(params.time_window_secs, 60);
    }

    #[test]
    fn test_pow_submission_creation() {
        let nonce = [42u8; 32];
        let bundle = vec![1, 2, 3, 4];
        let submission = PowSubmission::new(1234567890, nonce, bundle.clone());
        assert_eq!(submission.timestamp, 1234567890);
        assert_eq!(submission.client_nonce, nonce);
        assert_eq!(submission.proof_bundle, bundle);
    }

    #[test]
    fn test_pow_verify_result() {
        let success = PowVerifyResult::success(100);
        assert!(success.valid);
        assert_eq!(success.proofs_verified, 100);

        let failure = PowVerifyResult::failure(50);
        assert!(!failure.valid);
        assert_eq!(failure.proofs_verified, 50);
    }
}
