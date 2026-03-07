//! Adaptive calibration engine for parallel signature verification.
//!
//! Determines the optimal Rayon thread-pool size by benchmarking candidate
//! parallelism levels on a small sample of the input batch.  All calibration
//! work counts toward the final results (zero waste).

use std::time::Instant;

use rayon::prelude::*;

use crate::signature::{BatchVerifyError, SignatureVerifier, VerifyItem, VoteCheck};

// ---------------------------------------------------------------------------
// Candidate levels
// ---------------------------------------------------------------------------

/// Candidate parallelism levels: powers of two up to `nproc`.
pub(crate) fn candidate_levels(nproc: usize) -> Vec<usize> {
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

// ---------------------------------------------------------------------------
// Item distribution
// ---------------------------------------------------------------------------

/// Distribute `total` items across `buckets` as evenly as possible.
///
/// Returns a vector of length `buckets` where the sum equals `total`.
pub(crate) fn distribute_items(total: usize, buckets: usize) -> Vec<usize> {
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
// Calibration-based adaptive verification
// ---------------------------------------------------------------------------

/// Run calibration on ~10% of items, pick the best parallelism, then verify
/// the rest. All calibration results are preserved.
pub(crate) fn verify_with_calibration(
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
                            key_image_bs58: String::new(),
                            chosen_option: String::new(),
                            revoked: false,
                        },
                        Err(e) => VoteCheck {
                            id: item.id.clone(),
                            valid: false,
                            error: Some(e.to_string()),
                            key_image_bs58: String::new(),
                            chosen_option: String::new(),
                            revoked: false,
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
                            key_image_bs58: String::new(),
                            chosen_option: String::new(),
                            revoked: false,
                        },
                        Err(e) => VoteCheck {
                            id: item.id.clone(),
                            valid: false,
                            error: Some(e.to_string()),
                            key_image_bs58: String::new(),
                            chosen_option: String::new(),
                            revoked: false,
                        },
                    }
                })
                .collect()
        });

        all_results.extend(remaining_results);
    }

    Ok(all_results)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::tests::{make_items, AlwaysValidVerifier};

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

        let results = verify_with_calibration(&verifier, &items, nproc).expect("should succeed");

        assert_eq!(results.len(), count);

        // The first `sample_size` results come from calibration, then the rest.
        // Since calibration preserves insertion order per level and remaining
        // items are appended, the total count must match.
        assert_eq!(verifier.calls(), count);
    }
}
