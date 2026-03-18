//! Solution bundle types for bounty challenge secrets.
//!
//! Contains the operator-only secret data: the full solution mapping
//! and voter private keys. All structs zeroize on drop to prevent
//! secret material from lingering in memory.

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::canonical_csv::CsvEntry;

/// The complete solution bundle (secret, operator-only).
///
/// Contains the mapping of pubkeys to names/options plus the voter
/// private keys needed to construct ring signatures.
///
/// **Security**: No `Debug` derive — prevents accidental logging of secrets.
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct SolutionBundle {
    pub version: u32,
    pub solution: Vec<SolutionEntry>,
    pub voter_private_keys: Vec<VoterPrivateKey>,
}

/// A single solution entry mapping a voter to their poll choice.
#[derive(Serialize, Deserialize, Clone, ZeroizeOnDrop)]
pub struct SolutionEntry {
    /// Base58-encoded nazgul public key.
    pub pubkey_bs58: String,
    /// Voter display name (NFC-normalized).
    pub name: String,
    /// The poll option id this voter selected.
    pub option: String,
}

/// A voter's private key material.
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct VoterPrivateKey {
    /// Base58-encoded nazgul public key (for correlation with `SolutionEntry`).
    pub pubkey_bs58: String,
    /// Base58-encoded scalar (secret key).
    pub scalar_bs58: String,
}

impl SolutionBundle {
    /// Convert solution entries into canonical CSV entries.
    pub fn to_csv_entries(&self) -> Vec<CsvEntry> {
        self.solution
            .iter()
            .map(|entry| CsvEntry {
                name: entry.name.clone(),
                option: entry.option.clone(),
                pubkey_bs58: entry.pubkey_bs58.clone(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_csv::serialize_canonical_csv;

    #[test]
    fn test_solution_bundle_to_csv_entries() {
        let bundle = SolutionBundle {
            version: 1,
            solution: vec![
                SolutionEntry {
                    pubkey_bs58: "BBB".into(),
                    name: "Bob".into(),
                    option: "opt-a".into(),
                },
                SolutionEntry {
                    pubkey_bs58: "AAA".into(),
                    name: "Alice".into(),
                    option: "opt-b".into(),
                },
            ],
            voter_private_keys: vec![],
        };

        let entries = bundle.to_csv_entries();
        let csv = serialize_canonical_csv(&entries);
        // Sorted by pubkey_bs58: AAA first, then BBB
        assert_eq!(csv, "Alice,opt-b\nBob,opt-a");
    }

    #[test]
    fn test_solution_bundle_json_roundtrip() {
        let bundle = SolutionBundle {
            version: 1,
            solution: vec![SolutionEntry {
                pubkey_bs58: "ABC123".into(),
                name: "Test".into(),
                option: "opt-x".into(),
            }],
            voter_private_keys: vec![VoterPrivateKey {
                pubkey_bs58: "ABC123".into(),
                scalar_bs58: "SECRET".into(),
            }],
        };

        let json = serde_json::to_string(&bundle).expect("serialize");
        let restored: SolutionBundle = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.version, 1);
        assert_eq!(restored.solution.len(), 1);
        assert_eq!(restored.solution[0].name, "Test");
        assert_eq!(restored.voter_private_keys.len(), 1);
        assert_eq!(restored.voter_private_keys[0].scalar_bs58, "SECRET");
    }
}
