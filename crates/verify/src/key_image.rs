//! KeyImage uniqueness checker.
//!
//! Detects double-voting by checking that all KeyImages in a set of votes
//! are unique.

use std::collections::HashSet;

/// Result of a KeyImage uniqueness check.
#[derive(Debug, Clone)]
pub struct KeyImageCheck {
    /// Total number of KeyImages inspected.
    pub total: usize,
    /// Number of unique KeyImages.
    pub unique: usize,
    /// Duplicate KeyImages (bs58-encoded), if any.
    pub duplicates: Vec<String>,
}

impl KeyImageCheck {
    /// Returns `true` if all KeyImages are unique (no double voting).
    pub fn all_unique(&self) -> bool {
        self.duplicates.is_empty()
    }
}

/// Check that all KeyImages in `key_images_bs58` are unique.
///
/// Returns a [`KeyImageCheck`] with duplicate details if any are found.
pub fn check_key_image_uniqueness(key_images_bs58: &[String]) -> KeyImageCheck {
    let mut seen = HashSet::with_capacity(key_images_bs58.len());
    let mut duplicates = Vec::new();

    for ki in key_images_bs58 {
        if !seen.insert(ki.as_str()) {
            // Only add to duplicates list once per duplicate value.
            if !duplicates.contains(ki) {
                duplicates.push(ki.clone());
            }
        }
    }

    KeyImageCheck {
        total: key_images_bs58.len(),
        unique: seen.len(),
        duplicates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_unique() {
        let keys = vec![
            "abc123".to_string(),
            "def456".to_string(),
            "ghi789".to_string(),
        ];
        let result = check_key_image_uniqueness(&keys);
        assert!(result.all_unique());
        assert_eq!(result.total, 3);
        assert_eq!(result.unique, 3);
        assert!(result.duplicates.is_empty());
    }

    #[test]
    fn test_with_duplicates() {
        let keys = vec![
            "abc123".to_string(),
            "def456".to_string(),
            "abc123".to_string(), // duplicate
            "ghi789".to_string(),
            "def456".to_string(), // duplicate
        ];
        let result = check_key_image_uniqueness(&keys);
        assert!(!result.all_unique());
        assert_eq!(result.total, 5);
        assert_eq!(result.unique, 3);
        assert_eq!(result.duplicates.len(), 2);
        assert!(result.duplicates.contains(&"abc123".to_string()));
        assert!(result.duplicates.contains(&"def456".to_string()));
    }

    #[test]
    fn test_empty_input() {
        let keys: Vec<String> = Vec::new();
        let result = check_key_image_uniqueness(&keys);
        assert!(result.all_unique());
        assert_eq!(result.total, 0);
        assert_eq!(result.unique, 0);
    }

    #[test]
    fn test_single_key() {
        let keys = vec!["only_one".to_string()];
        let result = check_key_image_uniqueness(&keys);
        assert!(result.all_unique());
        assert_eq!(result.total, 1);
        assert_eq!(result.unique, 1);
    }

    #[test]
    fn test_all_same() {
        let keys = vec!["same".to_string(), "same".to_string(), "same".to_string()];
        let result = check_key_image_uniqueness(&keys);
        assert!(!result.all_unique());
        assert_eq!(result.total, 3);
        assert_eq!(result.unique, 1);
        assert_eq!(result.duplicates, vec!["same".to_string()]);
    }

    // -----------------------------------------------------------------------
    // Boundary: large set of unique keys
    // -----------------------------------------------------------------------

    #[test]
    fn test_large_unique_set() {
        let keys: Vec<String> = (0..1000).map(|i| format!("ki-{i:06}")).collect();
        let result = check_key_image_uniqueness(&keys);
        assert!(result.all_unique());
        assert_eq!(result.total, 1000);
        assert_eq!(result.unique, 1000);
    }

    // -----------------------------------------------------------------------
    // Edge: triple duplicate only listed once
    // -----------------------------------------------------------------------

    #[test]
    fn test_triple_duplicate_listed_once() {
        let keys = vec![
            "abc".to_string(),
            "abc".to_string(),
            "abc".to_string(),
            "def".to_string(),
        ];
        let result = check_key_image_uniqueness(&keys);
        assert!(!result.all_unique());
        assert_eq!(result.duplicates.len(), 1);
        assert_eq!(result.duplicates[0], "abc");
        assert_eq!(result.unique, 2); // "abc" and "def"
        assert_eq!(result.total, 4);
    }

    // -----------------------------------------------------------------------
    // Edge: two distinct duplicates
    // -----------------------------------------------------------------------

    #[test]
    fn test_two_keys_alternating() {
        let keys = vec![
            "a".to_string(),
            "b".to_string(),
            "a".to_string(),
            "b".to_string(),
        ];
        let result = check_key_image_uniqueness(&keys);
        assert!(!result.all_unique());
        assert_eq!(result.total, 4);
        assert_eq!(result.unique, 2);
        assert_eq!(result.duplicates.len(), 2);
    }
}
