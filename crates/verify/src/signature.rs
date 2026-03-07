//! Adaptive empirical auto-tuning parallel BLSAG ring signature verification.
//!
//! Provides [`verify_all_signatures`] which automatically selects the optimal
//! parallelism level for batch signature verification by running a calibration
//! phase on a small sample of the input. All calibration work counts toward
//! the final results (zero waste).
//!
//! The verification itself is abstracted behind [`SignatureVerifier`] so that
//! real BLSAG verification and mock/test implementations can be swapped freely.
//!
//! Adaptive calibration logic (candidate-level selection, item distribution,
//! benchmarking) lives in [`crate::calibration`].

use rayon::prelude::*;
use thiserror::Error;

use crate::calibration::verify_with_calibration;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from parallel batch verification.
#[derive(Debug, Error)]
pub enum BatchVerifyError {
    /// A verifier-specific error occurred for one or more items.
    #[error("verification error at index {index}: {message}")]
    VerifierError {
        /// Index of the item that caused the error.
        index: usize,
        /// Human-readable error description.
        message: String,
    },

    /// Failed to build a Rayon thread pool.
    #[error("thread pool build error: {0}")]
    ThreadPoolBuild(#[from] rayon::ThreadPoolBuildError),
}

// ---------------------------------------------------------------------------
// Verifier trait (mockable)
// ---------------------------------------------------------------------------

/// Abstracts single-item signature verification.
///
/// Implementations must be `Send + Sync` so items can be verified in parallel
/// across Rayon worker threads.
pub trait SignatureVerifier: Send + Sync {
    /// Verify a single item, returning `true` if the signature is valid.
    ///
    /// The `index` is the position in the original batch — useful for error
    /// reporting.
    fn verify_one(&self, index: usize, item: &VerifyItem) -> Result<bool, BatchVerifyError>;
}

// ---------------------------------------------------------------------------
// Input / Output types
// ---------------------------------------------------------------------------

/// One item to verify.
///
/// This is intentionally opaque — the actual signature bytes, ring, and message
/// are stored inside so that different [`SignatureVerifier`] implementations
/// can interpret them freely.
#[derive(Clone, Debug)]
pub struct VerifyItem {
    /// Opaque identifier for the item (e.g. vote event ULID).
    pub id: String,
    /// Signature bytes (encoding is verifier-specific).
    pub signature_bytes: Vec<u8>,
    /// The signed message bytes.
    pub message: Vec<u8>,
    /// Ring member public keys (bs58-encoded).
    pub ring_pubkeys_bs58: Vec<String>,
}

/// Result of verifying one item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteCheck {
    /// The item's identifier (copied from [`VerifyItem::id`]).
    pub id: String,
    /// Whether the signature is valid.
    pub valid: bool,
    /// Optional error message if verification encountered an error
    /// (as opposed to a clean `false`).
    pub error: Option<String>,
    /// KeyImage in bs58 encoding (for voter self-audit).
    pub key_image_bs58: String,
    /// The option the voter selected.
    pub chosen_option: String,
    /// Whether this vote has been revoked by a VoteRevocation event.
    /// Revoked votes are excluded from the tally.
    pub revoked: bool,
}

/// Options controlling the batch verification strategy.
#[derive(Clone, Debug, Default)]
pub struct VerifyOptions {
    /// If `Some(n)`, force exactly `n` threads (skip calibration).
    /// If `None`, use adaptive auto-tuning.
    pub parallelism: Option<usize>,
}

// ---------------------------------------------------------------------------
// Adaptive auto-tuning engine
// ---------------------------------------------------------------------------

/// Verify a batch of signatures with adaptive parallelism.
///
/// # Strategy
///
/// 1. **Explicit override** — if `opts.parallelism` is `Some(n)`, use a Rayon
///    thread pool with `n` threads directly.
/// 2. **Small batch** — if `items.len() <= 2 * nproc`, use Rayon's global
///    thread pool (default parallelism).
/// 3. **Calibration** — take ~10 % of items, split them across candidate
///    parallelism levels `[1, 2, 4, 8, ..., nproc]`, measure throughput,
///    pick the best level, then verify the remaining items at that level.
///    All calibration results are included in the final output (zero waste).
///
/// # Errors
///
/// Returns [`BatchVerifyError::ThreadPoolBuild`] if Rayon cannot create a
/// thread pool with the requested size.
pub fn verify_all_signatures(
    verifier: &dyn SignatureVerifier,
    items: &[VerifyItem],
    opts: &VerifyOptions,
) -> Result<Vec<VoteCheck>, BatchVerifyError> {
    if items.is_empty() {
        return Ok(Vec::new());
    }

    let nproc = num_cpus::get().max(1);

    match opts.parallelism {
        // --- Path 1: explicit override ---
        Some(threads) => verify_with_threads(verifier, items, threads.max(1)),

        // --- Path 2 & 3: auto ---
        None => {
            if items.len() <= 2 * nproc {
                // Small batch — Rayon global pool is fine.
                verify_with_global_pool(verifier, items)
            } else {
                // Large batch — run calibration.
                verify_with_calibration(verifier, items, nproc)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internal: verify with a fixed thread count
// ---------------------------------------------------------------------------

/// Build a scoped Rayon pool with `threads` threads and verify all items.
fn verify_with_threads(
    verifier: &dyn SignatureVerifier,
    items: &[VerifyItem],
    threads: usize,
) -> Result<Vec<VoteCheck>, BatchVerifyError> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()?;

    pool.install(|| verify_parallel(verifier, items))
}

/// Verify items using Rayon's global thread pool.
fn verify_with_global_pool(
    verifier: &dyn SignatureVerifier,
    items: &[VerifyItem],
) -> Result<Vec<VoteCheck>, BatchVerifyError> {
    verify_parallel(verifier, items)
}

/// Core parallel verification: map each item through the verifier.
fn verify_parallel(
    verifier: &dyn SignatureVerifier,
    items: &[VerifyItem],
) -> Result<Vec<VoteCheck>, BatchVerifyError> {
    items
        .par_iter()
        .enumerate()
        .map(|(idx, item)| {
            match verifier.verify_one(idx, item) {
                Ok(valid) => Ok(VoteCheck {
                    id: item.id.clone(),
                    valid,
                    error: None,
                    key_image_bs58: String::new(),
                    chosen_option: String::new(),
                    revoked: false,
                }),
                Err(e) => {
                    // Record the error but don't abort the whole batch.
                    Ok(VoteCheck {
                        id: item.id.clone(),
                        valid: false,
                        error: Some(e.to_string()),
                        key_image_bs58: String::new(),
                        chosen_option: String::new(),
                        revoked: false,
                    })
                }
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -----------------------------------------------------------------------
    // Mock verifier (pub(crate) for reuse in calibration tests)
    // -----------------------------------------------------------------------

    /// A mock verifier that always returns `valid = true` and counts calls.
    pub(crate) struct AlwaysValidVerifier {
        call_count: AtomicUsize,
    }

    impl AlwaysValidVerifier {
        pub(crate) fn new() -> Self {
            Self {
                call_count: AtomicUsize::new(0),
            }
        }

        pub(crate) fn calls(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    impl SignatureVerifier for AlwaysValidVerifier {
        fn verify_one(&self, _index: usize, _item: &VerifyItem) -> Result<bool, BatchVerifyError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }
    }

    /// A mock verifier that returns `false` for items whose id starts with "bad".
    struct SelectiveVerifier;

    impl SignatureVerifier for SelectiveVerifier {
        fn verify_one(&self, _index: usize, item: &VerifyItem) -> Result<bool, BatchVerifyError> {
            Ok(!item.id.starts_with("bad"))
        }
    }

    /// A mock verifier that returns an error for items whose id starts with "err".
    struct ErrorVerifier;

    impl SignatureVerifier for ErrorVerifier {
        fn verify_one(&self, index: usize, item: &VerifyItem) -> Result<bool, BatchVerifyError> {
            if item.id.starts_with("err") {
                Err(BatchVerifyError::VerifierError {
                    index,
                    message: format!("simulated error for {}", item.id),
                })
            } else {
                Ok(true)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Helpers (pub(crate) for reuse in calibration tests)
    // -----------------------------------------------------------------------

    fn make_item(id: &str) -> VerifyItem {
        VerifyItem {
            id: id.to_owned(),
            signature_bytes: vec![0xAB],
            message: vec![0x01, 0x02],
            ring_pubkeys_bs58: vec!["fakepub".to_owned()],
        }
    }

    pub(crate) fn make_items(count: usize) -> Vec<VerifyItem> {
        (0..count)
            .map(|i| make_item(&format!("vote-{i}")))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Test: empty input
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_input() {
        let verifier = AlwaysValidVerifier::new();
        let results = verify_all_signatures(&verifier, &[], &VerifyOptions::default())
            .expect("should succeed");
        assert!(results.is_empty());
        assert_eq!(verifier.calls(), 0);
    }

    // -----------------------------------------------------------------------
    // Test: explicit parallelism override
    // -----------------------------------------------------------------------

    #[test]
    fn test_explicit_parallelism() {
        let verifier = AlwaysValidVerifier::new();
        let items = make_items(10);
        let opts = VerifyOptions {
            parallelism: Some(2),
        };

        let results = verify_all_signatures(&verifier, &items, &opts).expect("should succeed");

        assert_eq!(results.len(), 10);
        assert!(results.iter().all(|r| r.valid));
        assert!(results.iter().all(|r| r.error.is_none()));
        assert_eq!(verifier.calls(), 10);
    }

    // -----------------------------------------------------------------------
    // Test: explicit parallelism of 1 (sequential)
    // -----------------------------------------------------------------------

    #[test]
    fn test_explicit_single_thread() {
        let verifier = AlwaysValidVerifier::new();
        let items = make_items(5);
        let opts = VerifyOptions {
            parallelism: Some(1),
        };

        let results = verify_all_signatures(&verifier, &items, &opts).expect("should succeed");

        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|r| r.valid));
        assert_eq!(verifier.calls(), 5);
    }

    // -----------------------------------------------------------------------
    // Test: small batch (direct Rayon path)
    // -----------------------------------------------------------------------

    #[test]
    fn test_small_batch_uses_global_pool() {
        let verifier = AlwaysValidVerifier::new();
        // Small enough to skip calibration: <= 2 * nproc
        let nproc = num_cpus::get();
        let count = nproc; // always <= 2*nproc
        let items = make_items(count);
        let opts = VerifyOptions::default();

        let results = verify_all_signatures(&verifier, &items, &opts).expect("should succeed");

        assert_eq!(results.len(), count);
        assert!(results.iter().all(|r| r.valid));
        assert_eq!(verifier.calls(), count);
    }

    // -----------------------------------------------------------------------
    // Test: large batch triggers calibration, all items verified (zero waste)
    // -----------------------------------------------------------------------

    #[test]
    fn test_calibration_zero_waste() {
        let verifier = AlwaysValidVerifier::new();
        let nproc = num_cpus::get();
        // Make sure we exceed the 2*nproc threshold.
        let count = (2 * nproc) + 50;
        let items = make_items(count);
        let opts = VerifyOptions::default();

        let results = verify_all_signatures(&verifier, &items, &opts).expect("should succeed");

        // Every single item must appear in results.
        assert_eq!(results.len(), count, "all items must be in the output");
        assert_eq!(
            verifier.calls(),
            count,
            "verifier must be called exactly once per item"
        );

        // Check that all item IDs are present (calibration items are NOT re-verified).
        let result_ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        for i in 0..count {
            let expected_id = format!("vote-{i}");
            assert!(
                result_ids.contains(&expected_id.as_str()),
                "missing result for {expected_id}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test: selective verification (mix of valid and invalid)
    // -----------------------------------------------------------------------

    #[test]
    fn test_selective_verification() {
        let verifier = SelectiveVerifier;
        let items = vec![
            make_item("good-1"),
            make_item("bad-1"),
            make_item("good-2"),
            make_item("bad-2"),
            make_item("good-3"),
        ];
        let opts = VerifyOptions {
            parallelism: Some(2),
        };

        let results = verify_all_signatures(&verifier, &items, &opts).expect("should succeed");

        assert_eq!(results.len(), 5);

        let good_count = results.iter().filter(|r| r.valid).count();
        let bad_count = results.iter().filter(|r| !r.valid).count();
        assert_eq!(good_count, 3);
        assert_eq!(bad_count, 2);

        // Verify specific items.
        for r in &results {
            if r.id.starts_with("bad") {
                assert!(!r.valid, "{} should be invalid", r.id);
            } else {
                assert!(r.valid, "{} should be valid", r.id);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test: verifier errors are captured, not propagated
    // -----------------------------------------------------------------------

    #[test]
    fn test_verifier_errors_captured() {
        let verifier = ErrorVerifier;
        let items = vec![
            make_item("ok-1"),
            make_item("err-1"),
            make_item("ok-2"),
            make_item("err-2"),
        ];
        let opts = VerifyOptions {
            parallelism: Some(1),
        };

        let results = verify_all_signatures(&verifier, &items, &opts).expect("should succeed");

        assert_eq!(results.len(), 4);

        for r in &results {
            if r.id.starts_with("err") {
                assert!(!r.valid, "{} should be invalid", r.id);
                assert!(r.error.is_some(), "{} should have an error message", r.id);
                assert!(
                    r.error
                        .as_ref()
                        .is_some_and(|e| e.contains("simulated error")),
                    "error should contain 'simulated error'"
                );
            } else {
                assert!(r.valid, "{} should be valid", r.id);
                assert!(r.error.is_none(), "{} should not have an error", r.id);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test: parallelism = Some(0) is clamped to 1
    // -----------------------------------------------------------------------

    #[test]
    fn test_parallelism_zero_clamped() {
        let verifier = AlwaysValidVerifier::new();
        let items = make_items(3);
        let opts = VerifyOptions {
            parallelism: Some(0),
        };

        let results = verify_all_signatures(&verifier, &items, &opts).expect("should succeed");

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.valid));
    }

    // -----------------------------------------------------------------------
    // Test: VoteCheck equality
    // -----------------------------------------------------------------------

    #[test]
    fn test_vote_check_equality() {
        let a = VoteCheck {
            id: "v1".into(),
            valid: true,
            error: None,
            key_image_bs58: String::new(),
            chosen_option: String::new(),
            revoked: false,
        };
        let b = VoteCheck {
            id: "v1".into(),
            valid: true,
            error: None,
            key_image_bs58: String::new(),
            chosen_option: String::new(),
            revoked: false,
        };
        let c = VoteCheck {
            id: "v1".into(),
            valid: false,
            error: None,
            key_image_bs58: String::new(),
            chosen_option: String::new(),
            revoked: false,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // -----------------------------------------------------------------------
    // Test: VerifyOptions default
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_options_default() {
        let opts = VerifyOptions::default();
        assert!(opts.parallelism.is_none());
    }

    // -----------------------------------------------------------------------
    // Test: single item batch
    // -----------------------------------------------------------------------

    #[test]
    fn test_single_item() {
        let verifier = AlwaysValidVerifier::new();
        let items = vec![make_item("solo-vote")];
        let opts = VerifyOptions {
            parallelism: Some(1),
        };

        let results = verify_all_signatures(&verifier, &items, &opts).expect("should succeed");
        assert_eq!(results.len(), 1);
        assert!(results[0].valid);
        assert_eq!(results[0].id, "solo-vote");
        assert_eq!(verifier.calls(), 1);
    }

    // -----------------------------------------------------------------------
    // Test: all items produce errors (none valid)
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_errors() {
        let verifier = ErrorVerifier;
        let items = vec![make_item("err-1"), make_item("err-2"), make_item("err-3")];
        let opts = VerifyOptions {
            parallelism: Some(1),
        };

        let results = verify_all_signatures(&verifier, &items, &opts).expect("should succeed");
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| !r.valid));
        assert!(results.iter().all(|r| r.error.is_some()));
    }

    // -----------------------------------------------------------------------
    // Test: VerifyItem fields preserved in VoteCheck
    // -----------------------------------------------------------------------

    #[test]
    fn test_item_id_preserved_in_check() {
        let verifier = AlwaysValidVerifier::new();
        let items = vec![make_item("unique-id-abc"), make_item("unique-id-xyz")];
        let opts = VerifyOptions {
            parallelism: Some(1),
        };

        let results = verify_all_signatures(&verifier, &items, &opts).expect("should succeed");
        let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"unique-id-abc"));
        assert!(ids.contains(&"unique-id-xyz"));
    }
}
