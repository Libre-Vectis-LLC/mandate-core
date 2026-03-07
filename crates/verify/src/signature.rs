//! Adaptive empirical auto-tuning parallel BLSAG ring signature verification.
//!
//! Provides [`verify_all_signatures`] which automatically selects the optimal
//! parallelism level for batch signature verification by running a calibration
//! phase on a small sample of the input. All calibration work counts toward
//! the final results (zero waste).
//!
//! The verification itself is abstracted behind [`SignatureVerifier`] so that
//! real BLSAG verification and mock/test implementations can be swapped freely.

use std::time::Instant;

use rayon::prelude::*;
use thiserror::Error;

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
                }),
                Err(e) => {
                    // Record the error but don't abort the whole batch.
                    Ok(VoteCheck {
                        id: item.id.clone(),
                        valid: false,
                        error: Some(e.to_string()),
                    })
                }
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Internal: calibration-based adaptive tuning
// ---------------------------------------------------------------------------

/// Candidate parallelism levels: powers of two up to `nproc`.
fn candidate_levels(nproc: usize) -> Vec<usize> {
    let mut levels = Vec::new();
    let mut level = 1;
    while level <= nproc {
        levels.push(level);
        // Avoid infinite loop when level is already at max.
        if level == nproc {
            break;
        }
        level *= 2;
        if level > nproc {
            // Always include nproc itself as the final candidate.
            levels.push(nproc);
        }
    }
    levels
}

/// Run calibration on ~10% of items, pick the best parallelism, then verify
/// the rest. All calibration results are preserved.
fn verify_with_calibration(
    verifier: &dyn SignatureVerifier,
    items: &[VerifyItem],
    nproc: usize,
) -> Result<Vec<VoteCheck>, BatchVerifyError> {
    let levels = candidate_levels(nproc);

    // Calibration sample: ~10% of items, minimum = number of candidate levels
    // so that every level gets at least one item.
    let sample_size = (items.len() / 10).max(levels.len()).min(items.len());

    let calibration_items = &items[..sample_size];
    let remaining_items = &items[sample_size..];

    // Distribute calibration items across levels as evenly as possible.
    let per_level = distribute_items(calibration_items.len(), levels.len());

    // Pre-allocate results buffer. Index order matches the original `items` slice.
    let mut all_results: Vec<VoteCheck> = Vec::with_capacity(items.len());

    let mut best_level = nproc;
    let mut best_throughput: f64 = 0.0;
    let mut offset = 0;

    for (level_idx, &thread_count) in levels.iter().enumerate() {
        let count = per_level[level_idx];
        if count == 0 {
            continue;
        }
        let chunk = &calibration_items[offset..offset + count];
        // We need to pass the correct absolute indices so verifier errors
        // reference the right position in the original `items` array.
        let chunk_with_offsets: Vec<(usize, &VerifyItem)> = chunk
            .iter()
            .enumerate()
            .map(|(i, item)| (offset + i, item))
            .collect();

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build()?;

        let start = Instant::now();
        let chunk_results: Vec<VoteCheck> = pool.install(|| {
            chunk_with_offsets
                .par_iter()
                .map(
                    |(abs_idx, item)| match verifier.verify_one(*abs_idx, item) {
                        Ok(valid) => VoteCheck {
                            id: item.id.clone(),
                            valid,
                            error: None,
                        },
                        Err(e) => VoteCheck {
                            id: item.id.clone(),
                            valid: false,
                            error: Some(e.to_string()),
                        },
                    },
                )
                .collect()
        });
        let elapsed = start.elapsed();

        let throughput = if elapsed.as_secs_f64() > 0.0 {
            count as f64 / elapsed.as_secs_f64()
        } else {
            // Instant verification — treat as very high throughput.
            f64::MAX
        };

        if throughput > best_throughput {
            best_throughput = throughput;
            best_level = thread_count;
        }

        all_results.extend(chunk_results);
        offset += count;
    }

    // Verify remaining items with the best parallelism level.
    if !remaining_items.is_empty() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(best_level)
            .build()?;

        let base_offset = sample_size;
        let remaining_results: Vec<VoteCheck> = pool.install(|| {
            remaining_items
                .par_iter()
                .enumerate()
                .map(|(i, item)| {
                    let abs_idx = base_offset + i;
                    match verifier.verify_one(abs_idx, item) {
                        Ok(valid) => VoteCheck {
                            id: item.id.clone(),
                            valid,
                            error: None,
                        },
                        Err(e) => VoteCheck {
                            id: item.id.clone(),
                            valid: false,
                            error: Some(e.to_string()),
                        },
                    }
                })
                .collect()
        });

        all_results.extend(remaining_results);
    }

    Ok(all_results)
}

/// Distribute `total` items across `buckets` as evenly as possible.
///
/// Returns a vector of length `buckets` where the sum equals `total`.
fn distribute_items(total: usize, buckets: usize) -> Vec<usize> {
    if buckets == 0 {
        return Vec::new();
    }
    let base = total / buckets;
    let remainder = total % buckets;
    (0..buckets)
        .map(|i| if i < remainder { base + 1 } else { base })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -----------------------------------------------------------------------
    // Mock verifier
    // -----------------------------------------------------------------------

    /// A mock verifier that always returns `valid = true` and counts calls.
    struct AlwaysValidVerifier {
        call_count: AtomicUsize,
    }

    impl AlwaysValidVerifier {
        fn new() -> Self {
            Self {
                call_count: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
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
    // Helpers
    // -----------------------------------------------------------------------

    fn make_item(id: &str) -> VerifyItem {
        VerifyItem {
            id: id.to_owned(),
            signature_bytes: vec![0xAB],
            message: vec![0x01, 0x02],
            ring_pubkeys_bs58: vec!["fakepub".to_owned()],
        }
    }

    fn make_items(count: usize) -> Vec<VerifyItem> {
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
                        .map_or(false, |e| e.contains("simulated error")),
                    "error should contain 'simulated error'"
                );
            } else {
                assert!(r.valid, "{} should be valid", r.id);
                assert!(r.error.is_none(), "{} should not have an error", r.id);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test: candidate_levels generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_candidate_levels_power_of_two_nproc() {
        // nproc = 8 → [1, 2, 4, 8]
        let levels = candidate_levels(8);
        assert_eq!(levels, vec![1, 2, 4, 8]);
    }

    #[test]
    fn test_candidate_levels_non_power_of_two_nproc() {
        // nproc = 6 → [1, 2, 4, 6]
        let levels = candidate_levels(6);
        assert_eq!(levels, vec![1, 2, 4, 6]);
    }

    #[test]
    fn test_candidate_levels_single_cpu() {
        let levels = candidate_levels(1);
        assert_eq!(levels, vec![1]);
    }

    #[test]
    fn test_candidate_levels_two_cpus() {
        let levels = candidate_levels(2);
        assert_eq!(levels, vec![1, 2]);
    }

    #[test]
    fn test_candidate_levels_three_cpus() {
        // nproc = 3 → [1, 2, 3]
        let levels = candidate_levels(3);
        assert_eq!(levels, vec![1, 2, 3]);
    }

    // -----------------------------------------------------------------------
    // Test: distribute_items
    // -----------------------------------------------------------------------

    #[test]
    fn test_distribute_even() {
        assert_eq!(distribute_items(10, 5), vec![2, 2, 2, 2, 2]);
    }

    #[test]
    fn test_distribute_uneven() {
        // 7 items across 3 buckets → [3, 2, 2]
        assert_eq!(distribute_items(7, 3), vec![3, 2, 2]);
    }

    #[test]
    fn test_distribute_fewer_items_than_buckets() {
        // 2 items across 5 buckets → [1, 1, 0, 0, 0]
        assert_eq!(distribute_items(2, 5), vec![1, 1, 0, 0, 0]);
    }

    #[test]
    fn test_distribute_zero_items() {
        assert_eq!(distribute_items(0, 3), vec![0, 0, 0]);
    }

    #[test]
    fn test_distribute_zero_buckets() {
        assert_eq!(distribute_items(10, 0), Vec::<usize>::new());
    }

    // -----------------------------------------------------------------------
    // Test: large calibration batch preserves order of calibration + remaining
    // -----------------------------------------------------------------------

    #[test]
    fn test_calibration_results_precede_remaining() {
        let verifier = AlwaysValidVerifier::new();
        let nproc = num_cpus::get();
        let count = (2 * nproc) + 100;
        let items = make_items(count);
        let opts = VerifyOptions::default();

        let results = verify_all_signatures(&verifier, &items, &opts).expect("should succeed");

        assert_eq!(results.len(), count);

        // The first `sample_size` results come from calibration, then the rest.
        // Since calibration preserves insertion order per level and remaining
        // items are appended, the total count must match.
        assert_eq!(verifier.calls(), count);
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
        };
        let b = VoteCheck {
            id: "v1".into(),
            valid: true,
            error: None,
        };
        let c = VoteCheck {
            id: "v1".into(),
            valid: false,
            error: None,
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
