//! Anti-temporal-correlation shuffle.
//!
//! Securely shuffles vote records before output to prevent
//! de-anonymization via timestamp correlation with network traffic.
//! This is a critical privacy measure adopted after adversarial review.

use rand::seq::SliceRandom;
use rand::thread_rng;

/// Shuffle a mutable slice in place using a cryptographically secure RNG.
///
/// This prevents temporal correlation attacks where an adversary matches
/// vote submission timestamps (from network traffic analysis) to the
/// chronological order of votes in the verification report.
pub fn secure_shuffle<T>(items: &mut [T]) {
    let mut rng = thread_rng();
    items.shuffle(&mut rng);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shuffle_changes_order() {
        // With 20 items, the probability of shuffle producing the original
        // order is 1/20! ≈ 4e-19. Running 5 trials makes false failure
        // astronomically unlikely.
        let original: Vec<u32> = (0..20).collect();
        let mut found_different = false;

        for _ in 0..5 {
            let mut shuffled = original.clone();
            secure_shuffle(&mut shuffled);
            if shuffled != original {
                found_different = true;
                break;
            }
        }

        assert!(
            found_different,
            "shuffle should produce a different order (5 trials with 20 items)"
        );
    }

    #[test]
    fn test_shuffle_preserves_elements() {
        let mut items: Vec<u32> = (0..100).collect();
        let original = items.clone();
        secure_shuffle(&mut items);

        // Same elements, possibly different order.
        let mut sorted = items.clone();
        sorted.sort();
        assert_eq!(sorted, original);
    }

    #[test]
    fn test_shuffle_empty() {
        let mut items: Vec<u32> = Vec::new();
        secure_shuffle(&mut items); // Should not panic.
        assert!(items.is_empty());
    }

    #[test]
    fn test_shuffle_single_element() {
        let mut items = vec![42u32];
        secure_shuffle(&mut items);
        assert_eq!(items, vec![42]);
    }

    #[test]
    fn test_shuffle_two_elements() {
        // With 2 items, P(same order) = 0.5 per trial.
        // 20 trials: P(all same) = 0.5^20 ≈ 1e-6.
        let original = vec![1u32, 2];
        let mut found_different = false;

        for _ in 0..20 {
            let mut shuffled = original.clone();
            secure_shuffle(&mut shuffled);
            if shuffled != original {
                found_different = true;
                break;
            }
        }

        assert!(found_different, "two-element shuffle should swap sometimes");
    }
}
