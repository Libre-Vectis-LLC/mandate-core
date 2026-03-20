//! POW verifier service.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bincode::Options;
use blake3::Hasher as Blake3Hasher;
use moka::future::Cache;
use rspow::near_stateless::prf::DeterministicNonceProvider;
use rspow::near_stateless::{
    MokaReplayCache, NearStatelessVerifier, Submission as NsSubmission, SystemTimeProvider,
    VerifierConfig,
};
use rspow::ProofBundle;
use sha3::{Digest, Sha3_256};
use thiserror::Error;

use super::types::{PowIssuedParams, PowParams, PowSubmission, PowVerifyResult};

type NsVerifier =
    NearStatelessVerifier<ContextBoundNonceProvider, MokaReplayCache, SystemTimeProvider>;

/// POW verification errors.
#[derive(Debug, Error)]
pub enum PowVerifyError {
    /// System clock is invalid for UNIX timestamp conversion.
    #[error("invalid system clock: {0}")]
    InvalidSystemClock(String),

    /// POW submission expired (outside time window).
    #[error("POW expired: timestamp {timestamp} is outside valid window")]
    Expired { timestamp: u64 },

    /// POW already used (replay attack detected).
    #[error("POW replay detected: nonce already used")]
    ReplayDetected,

    /// Failed to deserialize proof bundle.
    #[error("failed to deserialize proof bundle: {0}")]
    DeserializationFailed(String),

    /// Proof bundle exceeds verifier size limit.
    #[error("proof bundle too large: {actual_bytes} bytes exceeds {max_bytes} bytes")]
    ProofBundleTooLarge {
        max_bytes: usize,
        actual_bytes: usize,
    },

    /// Insufficient proofs in bundle.
    #[error("insufficient proofs: expected {expected}, got {actual}")]
    InsufficientProofs { expected: usize, actual: usize },

    /// Proof verification failed.
    #[error("proof verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid difficulty bits.
    #[error("invalid difficulty: expected {expected} bits, got {actual} bits")]
    InvalidDifficulty { expected: u32, actual: u32 },

    /// rspow error.
    #[error("rspow error: {0}")]
    RspowError(String),
}

/// Composite key for the legacy replay cache: `[proof_bundle_hash (32) || client_nonce (32)]`.
type ReplayKey = [u8; 64];

/// Upper bound for serialized rspow proof bundle payload.
const MAX_PROOF_BUNDLE_BYTES: usize = 1024 * 1024;
const DEFAULT_SERVER_SECRET_TAG: &[u8] = b"mandate:pow:server-secret:v1";
const CONTEXT_BOUND_NONCE_TAG: &[u8] = b"mandate:pow:nonce:v2";
const SERVER_SECRET_ENV: &str = "MANDATE_POW_SERVER_SECRET_HEX";
const ENVIRONMENT_ENV: &str = "MANDATE_POW_ENVIRONMENT";
const LEGACY_FALLBACK_ENV: &str = "MANDATE_POW_USE_LEGACY_FALLBACK";

#[derive(Debug, Clone)]
struct ContextBoundNonceProvider {
    organization_id: Arc<str>,
    difficulty_version: u64,
}

impl ContextBoundNonceProvider {
    fn new(organization_id: &str, difficulty_version: u64) -> Self {
        Self {
            organization_id: Arc::<str>::from(organization_id),
            difficulty_version,
        }
    }
}

impl DeterministicNonceProvider for ContextBoundNonceProvider {
    fn derive(&self, secret: [u8; 32], ts: u64) -> [u8; 32] {
        let mut hasher = Blake3Hasher::new_keyed(&secret);
        hasher.update(CONTEXT_BOUND_NONCE_TAG);
        hasher.update(&ts.to_le_bytes());
        hasher.update(self.organization_id.as_bytes());
        hasher.update(&self.difficulty_version.to_le_bytes());
        hasher.finalize().into()
    }
}

/// POW verifier using rspow's near-stateless protocol.
///
/// The near-stateless path is the default. The legacy dual-cache verifier is
/// retained as an env-switched fallback during migration.
pub struct PowVerifier {
    near_stateless_replay_cache: Arc<MokaReplayCache>,
    time_provider: Arc<SystemTimeProvider>,
    server_secret: [u8; 32],
    use_legacy_fallback: bool,
    // Legacy replay state kept for the transitional fallback path.
    replay_cache: Cache<ReplayKey, u64>,
    proof_bundle_cache: Cache<[u8; 32], u64>,
}

impl PowVerifier {
    /// Creates a new POW verifier.
    ///
    /// The verifier loads `MANDATE_POW_SERVER_SECRET_HEX` when available.
    /// Otherwise it only allows the deterministic baked-in secret in
    /// `development` or `test` environments.
    pub fn new(cache_capacity: u64, cache_ttl_secs: u64) -> Self {
        Self::with_server_secret(
            cache_capacity,
            cache_ttl_secs,
            Self::resolve_server_secret(
                Self::load_server_secret_from_env(),
                Self::pow_environment().as_deref(),
            ),
        )
    }

    /// Creates a new POW verifier with an explicit shared server secret.
    pub fn with_server_secret(
        cache_capacity: u64,
        cache_ttl_secs: u64,
        server_secret: [u8; 32],
    ) -> Self {
        let replay_cache = Cache::builder()
            .max_capacity(cache_capacity)
            .time_to_live(Duration::from_secs(cache_ttl_secs))
            .build();
        let proof_bundle_cache = Cache::builder()
            .max_capacity(cache_capacity)
            .time_to_live(Duration::from_secs(cache_ttl_secs))
            .build();

        Self {
            near_stateless_replay_cache: Arc::new(MokaReplayCache::new(cache_capacity)),
            time_provider: Arc::new(SystemTimeProvider),
            server_secret,
            use_legacy_fallback: Self::env_flag(LEGACY_FALLBACK_ENV),
            replay_cache,
            proof_bundle_cache,
        }
    }

    fn env_flag(key: &str) -> bool {
        std::env::var(key)
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn load_server_secret_from_env() -> Option<[u8; 32]> {
        let value = std::env::var(SERVER_SECRET_ENV).ok()?;
        let decoded = hex::decode(value).ok()?;
        decoded.as_slice().try_into().ok()
    }

    fn pow_environment() -> Option<String> {
        std::env::var(ENVIRONMENT_ENV).ok().or_else(|| {
            // debug_assertions is true for all test/debug builds (cargo test, nextest),
            // false for release builds (production). This is the most reliable heuristic.
            if cfg!(debug_assertions) {
                Some("test".to_string())
            } else {
                None
            }
        })
    }

    fn resolve_server_secret(
        server_secret: Option<[u8; 32]>,
        environment: Option<&str>,
    ) -> [u8; 32] {
        if let Some(server_secret) = server_secret {
            return server_secret;
        }

        if matches!(
            environment,
            Some(environment)
                if environment.eq_ignore_ascii_case("development")
                    || environment.eq_ignore_ascii_case("test")
        ) {
            return Self::default_server_secret();
        }

        panic!("{SERVER_SECRET_ENV} must be set when {ENVIRONMENT_ENV} is not development/test");
    }

    fn default_server_secret() -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(DEFAULT_SERVER_SECRET_TAG);
        hasher.finalize().into()
    }

    fn verifier_config(params: &PowParams) -> Result<VerifierConfig, PowVerifyError> {
        let config = VerifierConfig {
            time_window: Duration::from_secs(params.time_window_secs),
            min_difficulty: params.bits,
            min_required_proofs: params.required_proofs,
        };
        config
            .validate()
            .map_err(|err| PowVerifyError::RspowError(err.to_string()))?;
        Ok(config)
    }

    fn build_near_stateless_verifier(
        &self,
        params: &PowParams,
        organization_id: &str,
        difficulty_version: u64,
    ) -> Result<NsVerifier, PowVerifyError> {
        NearStatelessVerifier::new(
            Self::verifier_config(params)?,
            self.server_secret,
            Arc::new(ContextBoundNonceProvider::new(
                organization_id,
                difficulty_version,
            )),
            self.near_stateless_replay_cache.clone(),
            self.time_provider.clone(),
        )
        .map_err(|err| PowVerifyError::RspowError(err.to_string()))
    }

    fn deserialize_proof_bundle(submission: &PowSubmission) -> Result<ProofBundle, PowVerifyError> {
        if submission.proof_bundle.len() > MAX_PROOF_BUNDLE_BYTES {
            return Err(PowVerifyError::ProofBundleTooLarge {
                max_bytes: MAX_PROOF_BUNDLE_BYTES,
                actual_bytes: submission.proof_bundle.len(),
            });
        }

        bincode::DefaultOptions::new()
            .with_limit(MAX_PROOF_BUNDLE_BYTES as u64)
            .deserialize(&submission.proof_bundle)
            .map_err(|err| PowVerifyError::DeserializationFailed(err.to_string()))
    }

    /// Derive the deterministic nonce for a previously issued timestamp.
    pub fn deterministic_nonce_for_timestamp(
        &self,
        timestamp: u64,
        organization_id: &str,
        difficulty_version: u64,
    ) -> [u8; 32] {
        ContextBoundNonceProvider::new(organization_id, difficulty_version)
            .derive(self.server_secret, timestamp)
    }

    /// Create the concrete challenge parameters to return to a client.
    pub fn issue_params(
        &self,
        params: &PowParams,
        organization_id: &str,
        difficulty_version: u64,
    ) -> Result<PowIssuedParams, PowVerifyError> {
        let solve_params = self
            .build_near_stateless_verifier(params, organization_id, difficulty_version)?
            .issue_params();
        Ok(PowIssuedParams::from_params(
            params,
            organization_id,
            difficulty_version,
            solve_params.deterministic_nonce,
            solve_params.timestamp,
        ))
    }

    /// Verifies a POW submission.
    pub async fn verify_submission(
        &self,
        submission: &PowSubmission,
        params: &PowParams,
        organization_id: &str,
        difficulty_version: u64,
    ) -> Result<PowVerifyResult, PowVerifyError> {
        if self.use_legacy_fallback {
            // TODO: remove the legacy dual-cache verifier once all supported
            // deployments have migrated to rspow near-stateless verification.
            return self
                .verify_submission_legacy(submission, params, organization_id, difficulty_version)
                .await;
        }

        let bundle = Self::deserialize_proof_bundle(submission)?;
        let proofs_verified = bundle.proofs.len();

        if proofs_verified < params.required_proofs {
            return Err(PowVerifyError::InsufficientProofs {
                expected: params.required_proofs,
                actual: proofs_verified,
            });
        }

        if bundle.config.bits != params.bits {
            return Err(PowVerifyError::InvalidDifficulty {
                expected: params.bits,
                actual: bundle.config.bits,
            });
        }

        let ns_submission = NsSubmission {
            timestamp: submission.timestamp,
            client_nonce: submission.client_nonce,
            proof_bundle: bundle,
        };

        match self
            .build_near_stateless_verifier(params, organization_id, difficulty_version)?
            .verify_submission(&ns_submission)
        {
            Ok(()) => Ok(PowVerifyResult::success(proofs_verified)),
            Err(rspow::near_stateless::NsError::StaleTimestamp)
            | Err(rspow::near_stateless::NsError::FutureTimestamp) => {
                Err(PowVerifyError::Expired {
                    timestamp: submission.timestamp,
                })
            }
            Err(rspow::near_stateless::NsError::Replay) => Err(PowVerifyError::ReplayDetected),
            Err(rspow::near_stateless::NsError::MasterChallengeMismatch) => Err(
                PowVerifyError::VerificationFailed("master challenge mismatch".to_string()),
            ),
            Err(rspow::near_stateless::NsError::Verify(err)) => {
                Err(PowVerifyError::VerificationFailed(err.to_string()))
            }
            Err(rspow::near_stateless::NsError::InvalidConfig(err)) => {
                Err(PowVerifyError::RspowError(err))
            }
            Err(rspow::near_stateless::NsError::Cache(err)) => {
                Err(PowVerifyError::RspowError(err.to_string()))
            }
        }
    }

    fn hash_proof_bundle(proof_bundle: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(proof_bundle);
        hasher.finalize().into()
    }

    fn make_replay_key(proof_bundle_hash: &[u8; 32], client_nonce: &[u8; 32]) -> ReplayKey {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(proof_bundle_hash);
        key[32..].copy_from_slice(client_nonce);
        key
    }

    async fn verify_submission_legacy(
        &self,
        submission: &PowSubmission,
        params: &PowParams,
        organization_id: &str,
        difficulty_version: u64,
    ) -> Result<PowVerifyResult, PowVerifyError> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PowVerifyError::InvalidSystemClock(e.to_string()))?
            .as_secs();

        let time_diff = current_time.abs_diff(submission.timestamp);
        if time_diff > params.time_window_secs {
            return Err(PowVerifyError::Expired {
                timestamp: submission.timestamp,
            });
        }

        let proof_bundle_hash = Self::hash_proof_bundle(&submission.proof_bundle);
        if self
            .proof_bundle_cache
            .get(&proof_bundle_hash)
            .await
            .is_some()
        {
            return Err(PowVerifyError::ReplayDetected);
        }

        let replay_key = Self::make_replay_key(&proof_bundle_hash, &submission.client_nonce);
        if self.replay_cache.get(&replay_key).await.is_some() {
            return Err(PowVerifyError::ReplayDetected);
        }

        let bundle = Self::deserialize_proof_bundle(submission)?;
        if bundle.proofs.len() < params.required_proofs {
            return Err(PowVerifyError::InsufficientProofs {
                expected: params.required_proofs,
                actual: bundle.proofs.len(),
            });
        }
        if bundle.config.bits != params.bits {
            return Err(PowVerifyError::InvalidDifficulty {
                expected: params.bits,
                actual: bundle.config.bits,
            });
        }

        let expected_deterministic_nonce = self.deterministic_nonce_for_timestamp(
            submission.timestamp,
            organization_id,
            difficulty_version,
        );
        let expected_master_challenge = rspow::near_stateless::derive_master_challenge(
            expected_deterministic_nonce,
            submission.client_nonce,
        );
        if bundle.master_challenge != expected_master_challenge {
            return Err(PowVerifyError::VerificationFailed(
                "master challenge mismatch".to_string(),
            ));
        }

        bundle
            .verify_strict(params.bits, params.required_proofs)
            .map_err(|err| PowVerifyError::VerificationFailed(err.to_string()))?;

        let proofs_verified = bundle.proofs.len();
        self.proof_bundle_cache
            .insert(proof_bundle_hash, submission.timestamp)
            .await;
        self.replay_cache
            .insert(replay_key, submission.timestamp)
            .await;

        Ok(PowVerifyResult::success(proofs_verified))
    }

    #[cfg(test)]
    pub async fn clear_cache(&self) {
        self.replay_cache.invalidate_all();
        self.proof_bundle_cache.invalidate_all();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    use rspow::equix::EquixEngineBuilder;
    use rspow::near_stateless::derive_master_challenge;
    use rspow::pow::PowEngine;

    use super::*;

    const TEST_ORG_ALPHA: &str = "org-alpha";
    const TEST_ORG_BETA: &str = "org-beta";
    const TEST_DIFFICULTY_VERSION: u64 = 7;

    fn build_submission(
        verifier: &PowVerifier,
        issued: &PowIssuedParams,
        client_nonce: [u8; 32],
    ) -> PowSubmission {
        let progress = Arc::new(AtomicU64::new(0));
        let mut engine = EquixEngineBuilder::default()
            .bits(issued.bits)
            .threads(1)
            .required_proofs(issued.required_proofs)
            .progress(progress)
            .build_validated()
            .expect("engine should build");

        let master = derive_master_challenge(issued.deterministic_nonce, client_nonce);
        let bundle = engine.solve_bundle(master).expect("solve should succeed");
        let serialized = bincode::DefaultOptions::new()
            .serialize(&bundle)
            .expect("serialize bundle");
        let _ = verifier;

        PowSubmission::new(issued.timestamp, client_nonce, serialized)
    }

    #[tokio::test]
    async fn test_verifier_creation() {
        let verifier = PowVerifier::new(10_000, 300);
        let issued = verifier
            .issue_params(
                &PowParams::new(1, 1, 60),
                TEST_ORG_ALPHA,
                TEST_DIFFICULTY_VERSION,
            )
            .expect("issue params");
        assert!(issued.timestamp > 0);
        assert_ne!(issued.deterministic_nonce, [0u8; 32]);
        assert_eq!(issued.organization_id, TEST_ORG_ALPHA);
        assert_eq!(issued.difficulty_version, TEST_DIFFICULTY_VERSION);
    }

    #[tokio::test]
    async fn test_issue_params_matches_deterministic_nonce_derivation() {
        let verifier = PowVerifier::with_server_secret(10_000, 300, [7u8; 32]);
        let issued = verifier
            .issue_params(
                &PowParams::new(1, 1, 60),
                TEST_ORG_ALPHA,
                TEST_DIFFICULTY_VERSION,
            )
            .expect("issue params");
        assert_eq!(
            issued.deterministic_nonce,
            verifier.deterministic_nonce_for_timestamp(
                issued.timestamp,
                TEST_ORG_ALPHA,
                TEST_DIFFICULTY_VERSION,
            )
        );
    }

    #[tokio::test]
    async fn test_expired_submission() {
        let verifier = PowVerifier::with_server_secret(10_000, 300, [6u8; 32]);
        let params = PowParams::new(1, 1, 60);
        let issued = verifier
            .issue_params(&params, TEST_ORG_ALPHA, TEST_DIFFICULTY_VERSION)
            .expect("issue params");
        let mut submission = build_submission(&verifier, &issued, [1u8; 32]);
        submission.timestamp = submission.timestamp.saturating_sub(7_200);

        let result = verifier
            .verify_submission(
                &submission,
                &params,
                TEST_ORG_ALPHA,
                TEST_DIFFICULTY_VERSION,
            )
            .await;
        assert!(matches!(result, Err(PowVerifyError::Expired { .. })));
    }

    #[tokio::test]
    async fn test_rejects_oversized_proof_bundle() {
        let verifier = PowVerifier::new(10_000, 300);
        let params = PowParams::new(7, 1, 60);
        let submission = PowSubmission::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            [7u8; 32],
            vec![0u8; MAX_PROOF_BUNDLE_BYTES + 1],
        );

        let result = verifier
            .verify_submission(
                &submission,
                &params,
                TEST_ORG_ALPHA,
                TEST_DIFFICULTY_VERSION,
            )
            .await;
        assert!(matches!(
            result,
            Err(PowVerifyError::ProofBundleTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn test_round_trip_verification_uses_near_stateless_binding() {
        let verifier = PowVerifier::with_server_secret(10_000, 300, [9u8; 32]);
        let params = PowParams::new(1, 1, 60);
        let issued = verifier
            .issue_params(&params, TEST_ORG_ALPHA, TEST_DIFFICULTY_VERSION)
            .expect("issue params");
        let submission = build_submission(&verifier, &issued, [11u8; 32]);

        let result = verifier
            .verify_submission(
                &submission,
                &params,
                TEST_ORG_ALPHA,
                TEST_DIFFICULTY_VERSION,
            )
            .await
            .expect("verification should succeed");
        assert!(result.valid);
        assert_eq!(result.proofs_verified, 1);
    }

    #[tokio::test]
    async fn test_replay_detection_uses_near_stateless_cache() {
        let verifier = PowVerifier::with_server_secret(10_000, 300, [3u8; 32]);
        let params = PowParams::new(1, 1, 60);
        let issued = verifier
            .issue_params(&params, TEST_ORG_ALPHA, TEST_DIFFICULTY_VERSION)
            .expect("issue params");
        let submission = build_submission(&verifier, &issued, [5u8; 32]);

        verifier
            .verify_submission(
                &submission,
                &params,
                TEST_ORG_ALPHA,
                TEST_DIFFICULTY_VERSION,
            )
            .await
            .expect("first verification should succeed");

        let result = verifier
            .verify_submission(
                &submission,
                &params,
                TEST_ORG_ALPHA,
                TEST_DIFFICULTY_VERSION,
            )
            .await;
        assert!(matches!(result, Err(PowVerifyError::ReplayDetected)));
    }

    #[tokio::test]
    async fn test_master_challenge_mismatch_is_rejected() {
        let verifier = PowVerifier::with_server_secret(10_000, 300, [2u8; 32]);
        let params = PowParams::new(1, 1, 60);
        let issued = verifier
            .issue_params(&params, TEST_ORG_ALPHA, TEST_DIFFICULTY_VERSION)
            .expect("issue params");

        let mut submission = build_submission(&verifier, &issued, [8u8; 32]);
        submission.client_nonce = [9u8; 32];

        let result = verifier
            .verify_submission(
                &submission,
                &params,
                TEST_ORG_ALPHA,
                TEST_DIFFICULTY_VERSION,
            )
            .await;
        assert!(matches!(result, Err(PowVerifyError::VerificationFailed(_))));
    }

    #[tokio::test]
    async fn test_proof_is_not_reusable_across_organizations() {
        let verifier = PowVerifier::with_server_secret(10_000, 300, [4u8; 32]);
        let params = PowParams::new(1, 1, 60);
        let issued = verifier
            .issue_params(&params, TEST_ORG_ALPHA, TEST_DIFFICULTY_VERSION)
            .expect("issue params");
        let submission = build_submission(&verifier, &issued, [10u8; 32]);

        let result = verifier
            .verify_submission(&submission, &params, TEST_ORG_BETA, TEST_DIFFICULTY_VERSION)
            .await;
        assert!(matches!(result, Err(PowVerifyError::VerificationFailed(_))));
    }

    #[tokio::test]
    async fn test_proof_is_not_reusable_across_difficulty_versions() {
        let verifier = PowVerifier::with_server_secret(10_000, 300, [5u8; 32]);
        let params = PowParams::new(1, 1, 60);
        let issued = verifier
            .issue_params(&params, TEST_ORG_ALPHA, TEST_DIFFICULTY_VERSION)
            .expect("issue params");
        let submission = build_submission(&verifier, &issued, [12u8; 32]);

        let result = verifier
            .verify_submission(
                &submission,
                &params,
                TEST_ORG_ALPHA,
                TEST_DIFFICULTY_VERSION + 1,
            )
            .await;
        assert!(matches!(result, Err(PowVerifyError::VerificationFailed(_))));
    }

    #[test]
    #[should_panic(expected = "MANDATE_POW_SERVER_SECRET_HEX must be set")]
    fn test_default_secret_panics_outside_development_and_test() {
        let _ = PowVerifier::resolve_server_secret(None, Some("production"));
    }
}
