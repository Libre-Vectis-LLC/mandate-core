//! Bounty challenge configuration types and validation.
//!
//! Parses and validates TOML configuration for CTF-style bounty challenges
//! that prove anonymous poll integrity.

use std::collections::HashSet;
use std::path::Path;

use serde::Deserialize;
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced by config or name-list validation.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("option count sum ({sum}) does not match voters.total ({total})")]
    CountMismatch { sum: u32, total: u32 },

    #[error("at least 2 poll options required, got {count}")]
    TooFewOptions { count: usize },

    #[error("duplicate option id: {id}")]
    DuplicateOptionId { id: String },

    #[error("unsupported normalization: {value} (only \"NFC\" is supported)")]
    UnsupportedNormalization { value: String },

    #[error("unsupported config version: {version} (only version 1 is supported)")]
    UnsupportedVersion { version: u32 },

    #[error("KDF parameter {param} must be > 0")]
    ZeroKdfParam { param: &'static str },

    #[error("name at index {index} is not NFC-normalized")]
    NotNfcNormalized { index: usize },

    #[error("expected {expected} names, got {actual}")]
    NameCountMismatch { expected: u32, actual: usize },

    #[error("duplicate NFC-normalized name at index {index}: {name}")]
    DuplicateName { index: usize, name: String },

    #[error("name at index {index} is empty")]
    EmptyName { index: usize },

    #[error("name at index {index} contains forbidden character: {description}")]
    ForbiddenCharacter {
        index: usize,
        description: &'static str,
    },
}

// ---------------------------------------------------------------------------
// Config structs
// ---------------------------------------------------------------------------

/// Top-level bounty challenge configuration.
#[derive(Debug, Deserialize)]
pub struct BountyConfig {
    pub challenge: ChallengeConfig,
    pub poll: PollConfig,
    pub voters: VotersConfig,
    pub kdf: KdfConfig,
    pub bounty: BountyRewardConfig,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeConfig {
    pub version: u32,
}

#[derive(Debug, Deserialize)]
pub struct PollConfig {
    pub org_id: String,
    pub poll_ulid: String,
    pub title_zh: String,
    pub title_en: String,
    pub options: Vec<OptionConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OptionConfig {
    pub id: String,
    pub text_zh: String,
    pub text_en: String,
    pub count: u32,
}

#[derive(Debug, Deserialize)]
pub struct VotersConfig {
    pub total: u32,
    pub names_file: String,
    pub normalization: String,
}

#[derive(Debug, Deserialize)]
pub struct KdfConfig {
    pub salt: String,
    pub m_cost_mib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Deserialize)]
pub struct BountyRewardConfig {
    pub total_usdc: u32,
    pub instant_usdc: u32,
    pub report_usdc: u32,
    pub challenge_days: u32,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl BountyConfig {
    /// Load and validate a config from a TOML file path.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config file {}: {e}", path.display()))?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("failed to parse config TOML: {e}"))?;
        config
            .validate()
            .map_err(|e| anyhow::anyhow!("config validation failed: {e}"))?;
        Ok(config)
    }

    /// Validate internal consistency of the configuration.
    pub fn validate(&self) -> Result<(), ValidationError> {
        // 0. Version check
        if self.challenge.version != 1 {
            return Err(ValidationError::UnsupportedVersion {
                version: self.challenge.version,
            });
        }

        // 0b. KDF sanity
        if self.kdf.m_cost_mib == 0 {
            return Err(ValidationError::ZeroKdfParam {
                param: "m_cost_mib",
            });
        }
        if self.kdf.t_cost == 0 {
            return Err(ValidationError::ZeroKdfParam { param: "t_cost" });
        }
        if self.kdf.p_cost == 0 {
            return Err(ValidationError::ZeroKdfParam { param: "p_cost" });
        }

        // 1. At least 2 options
        if self.poll.options.len() < 2 {
            return Err(ValidationError::TooFewOptions {
                count: self.poll.options.len(),
            });
        }

        // 2. All option IDs unique
        let mut seen_ids = HashSet::with_capacity(self.poll.options.len());
        for opt in &self.poll.options {
            if !seen_ids.insert(&opt.id) {
                return Err(ValidationError::DuplicateOptionId { id: opt.id.clone() });
            }
        }

        // 3. Sum of option counts == voters.total
        let sum: u32 = self.poll.options.iter().map(|o| o.count).sum();
        if sum != self.voters.total {
            return Err(ValidationError::CountMismatch {
                sum,
                total: self.voters.total,
            });
        }

        // 4. Normalization must be "NFC"
        if self.voters.normalization != "NFC" {
            return Err(ValidationError::UnsupportedNormalization {
                value: self.voters.normalization.clone(),
            });
        }

        Ok(())
    }

    /// Validate a list of voter names against the config constraints.
    pub fn validate_names(&self, names: &[String]) -> Result<(), ValidationError> {
        // 1. Count must match
        if names.len() != self.voters.total as usize {
            return Err(ValidationError::NameCountMismatch {
                expected: self.voters.total,
                actual: names.len(),
            });
        }

        let mut seen = HashSet::with_capacity(names.len());

        for (i, name) in names.iter().enumerate() {
            // 2. No empty names
            if name.is_empty() {
                return Err(ValidationError::EmptyName { index: i });
            }

            // 3. No forbidden characters
            if name.contains(',') {
                return Err(ValidationError::ForbiddenCharacter {
                    index: i,
                    description: "comma",
                });
            }
            if name.contains('\n') || name.contains('\r') {
                return Err(ValidationError::ForbiddenCharacter {
                    index: i,
                    description: "newline",
                });
            }
            if name.chars().any(|c| c.is_control()) {
                return Err(ValidationError::ForbiddenCharacter {
                    index: i,
                    description: "control character",
                });
            }

            // 4. Must already be NFC-normalized
            let normalized: String = name.nfc().collect();
            if normalized != *name {
                return Err(ValidationError::NotNfcNormalized { index: i });
            }

            // 5. NFC-unique
            if !seen.insert(normalized.clone()) {
                return Err(ValidationError::DuplicateName {
                    index: i,
                    name: normalized,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse the bundled fixture config.
    fn load_fixture_config() -> BountyConfig {
        let toml_str = include_str!("../fixtures/bounty.toml");
        toml::from_str(toml_str).expect("fixture bounty.toml should parse")
    }

    /// Helper: load the 10-voter test fixture.
    fn load_fixture_names() -> Vec<String> {
        let raw = include_str!("../fixtures/test-voters-10.txt");
        raw.lines().map(|l| l.to_owned()).collect()
    }

    /// Helper: build a minimal valid config for mutation tests.
    fn minimal_config() -> BountyConfig {
        toml::from_str(include_str!("../fixtures/bounty.toml"))
            .expect("fixture bounty.toml should parse")
    }

    #[test]
    fn test_parse_valid_config() {
        let cfg = load_fixture_config();
        assert!(cfg.validate().is_ok(), "fixture config should be valid");
    }

    #[test]
    fn test_count_mismatch() {
        let mut cfg = minimal_config();
        // Sabotage: set total to a wrong value
        cfg.voters.total = 999;
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(err, ValidationError::CountMismatch { .. }),
            "expected CountMismatch, got {err:?}"
        );
    }

    #[test]
    fn test_duplicate_option_ids() {
        let mut cfg = minimal_config();
        // Make second option's id equal to first
        cfg.poll.options[1].id = cfg.poll.options[0].id.clone();
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(err, ValidationError::DuplicateOptionId { .. }),
            "expected DuplicateOptionId, got {err:?}"
        );
    }

    #[test]
    fn test_too_few_options() {
        let mut cfg = minimal_config();
        // Keep only one option, adjust total to match
        let single = cfg.poll.options[0].clone();
        cfg.poll.options = vec![single];
        cfg.voters.total = cfg.poll.options[0].count;
        let err = cfg.validate().unwrap_err();
        assert!(
            matches!(err, ValidationError::TooFewOptions { count: 1 }),
            "expected TooFewOptions, got {err:?}"
        );
    }

    #[test]
    fn test_valid_names() {
        let cfg = load_fixture_config();
        let names = load_fixture_names();
        // The fixture has total=1000 but test file has 10 names;
        // build a config with matching total for this test.
        let mut cfg = cfg;
        cfg.voters.total = names.len() as u32;
        assert!(
            cfg.validate_names(&names).is_ok(),
            "fixture names should be valid"
        );
    }

    #[test]
    fn test_name_with_comma() {
        let mut cfg = minimal_config();
        let names = vec!["Alice,Bob".to_owned(), "Carol".to_owned()];
        cfg.voters.total = 2;
        let err = cfg.validate_names(&names).unwrap_err();
        assert!(
            matches!(
                err,
                ValidationError::ForbiddenCharacter {
                    description: "comma",
                    ..
                }
            ),
            "expected ForbiddenCharacter(comma), got {err:?}"
        );
    }

    #[test]
    fn test_name_with_newline() {
        let mut cfg = minimal_config();
        let names = vec!["Alice\nBob".to_owned(), "Carol".to_owned()];
        cfg.voters.total = 2;
        let err = cfg.validate_names(&names).unwrap_err();
        assert!(
            matches!(
                err,
                ValidationError::ForbiddenCharacter {
                    description: "newline",
                    ..
                }
            ),
            "expected ForbiddenCharacter(newline), got {err:?}"
        );
    }

    #[test]
    fn test_name_with_control() {
        let mut cfg = minimal_config();
        let names = vec!["Alice\x00Bob".to_owned(), "Carol".to_owned()];
        cfg.voters.total = 2;
        let err = cfg.validate_names(&names).unwrap_err();
        assert!(
            matches!(err, ValidationError::ForbiddenCharacter { .. }),
            "expected ForbiddenCharacter(control), got {err:?}"
        );
    }

    #[test]
    fn test_empty_name() {
        let mut cfg = minimal_config();
        let names = vec!["Alice".to_owned(), String::new()];
        cfg.voters.total = 2;
        let err = cfg.validate_names(&names).unwrap_err();
        assert!(
            matches!(err, ValidationError::EmptyName { index: 1 }),
            "expected EmptyName at index 1, got {err:?}"
        );
    }

    #[test]
    fn test_duplicate_names_nfc() {
        let mut cfg = minimal_config();
        // Two identical NFC names — should be detected as duplicates
        let names = vec!["caf\u{00e9}".to_owned(), "caf\u{00e9}".to_owned()];
        cfg.voters.total = 2;
        let err = cfg.validate_names(&names).unwrap_err();
        assert!(
            matches!(err, ValidationError::DuplicateName { index: 1, .. }),
            "expected DuplicateName at index 1, got {err:?}"
        );
    }

    #[test]
    fn test_not_nfc_normalized() {
        let mut cfg = minimal_config();
        // NFD form: U+0065 U+0301 — not NFC-normalized, should be rejected
        let names = vec!["Alice".to_owned(), "cafe\u{0301}".to_owned()];
        cfg.voters.total = 2;
        let err = cfg.validate_names(&names).unwrap_err();
        assert!(
            matches!(err, ValidationError::NotNfcNormalized { index: 1 }),
            "expected NotNfcNormalized at index 1, got {err:?}"
        );
    }
}
