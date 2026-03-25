//! Canonical CSV serialization for bounty challenge solutions.
//!
//! The canonical format ensures deterministic output regardless of input order,
//! enabling reproducible KDF derivation from the same logical solution.

use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Debug, PartialEq, Eq)]
/// A single entry in the canonical CSV.
pub struct CsvEntry {
    /// Voter display name (will be NFC-normalized on output).
    pub name: String,
    /// The poll option this voter selected.
    pub option: String,
    /// Base58-encoded public key, used only for deterministic sort order.
    pub pubkey_bs58: String,
}

/// Serialize solution entries to canonical CSV format.
///
/// Entries are sorted by `pubkey_bs58` in lexicographic (string) order.
/// Each line is `"{name},{option}"` with LF line endings, no trailing newline.
/// Names and option text are NFC-normalized before output.
pub fn serialize_canonical_csv(entries: &[CsvEntry]) -> String {
    let mut sorted: Vec<&CsvEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.pubkey_bs58.cmp(&b.pubkey_bs58));

    let lines: Vec<String> = sorted
        .iter()
        .map(|e| {
            let nfc_name: String = e.name.nfc().collect();
            let nfc_option: String = e.option.nfc().collect();
            format!("{},{}", nfc_name, nfc_option)
        })
        .collect();

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sorted_output_is_deterministic() {
        let entries_a = vec![
            CsvEntry {
                name: "Zara".into(),
                option: "Option A".into(),
                pubkey_bs58: "BBB".into(),
            },
            CsvEntry {
                name: "Alice".into(),
                option: "Option B".into(),
                pubkey_bs58: "AAA".into(),
            },
            CsvEntry {
                name: "Mika".into(),
                option: "Option C".into(),
                pubkey_bs58: "CCC".into(),
            },
        ];

        // Same entries in different input order
        let entries_b = vec![
            CsvEntry {
                name: "Mika".into(),
                option: "Option C".into(),
                pubkey_bs58: "CCC".into(),
            },
            CsvEntry {
                name: "Alice".into(),
                option: "Option B".into(),
                pubkey_bs58: "AAA".into(),
            },
            CsvEntry {
                name: "Zara".into(),
                option: "Option A".into(),
                pubkey_bs58: "BBB".into(),
            },
        ];

        let csv_a = serialize_canonical_csv(&entries_a);
        let csv_b = serialize_canonical_csv(&entries_b);

        assert_eq!(
            csv_a, csv_b,
            "different input order must produce identical output"
        );
        assert_eq!(csv_a, "Alice,Option B\nZara,Option A\nMika,Option C");
    }

    #[test]
    fn test_nfc_normalization_applied() {
        // NFD: U+0065 + U+0301 = 'e' + combining acute
        // NFC: U+00E9 = 'é'
        let entries = vec![CsvEntry {
            name: "caf\u{0065}\u{0301}".into(), // NFD form
            option: "Option X".into(),
            pubkey_bs58: "AAA".into(),
        }];

        let csv = serialize_canonical_csv(&entries);
        assert_eq!(csv, "caf\u{00e9},Option X", "name should be NFC-normalized");
    }

    #[test]
    fn test_no_trailing_newline() {
        let entries = vec![
            CsvEntry {
                name: "A".into(),
                option: "x".into(),
                pubkey_bs58: "1".into(),
            },
            CsvEntry {
                name: "B".into(),
                option: "y".into(),
                pubkey_bs58: "2".into(),
            },
        ];

        let csv = serialize_canonical_csv(&entries);
        assert!(!csv.ends_with('\n'), "must not have trailing newline");
    }

    #[test]
    fn test_single_entry() {
        let entries = vec![CsvEntry {
            name: "Solo".into(),
            option: "only".into(),
            pubkey_bs58: "X".into(),
        }];
        let csv = serialize_canonical_csv(&entries);
        assert_eq!(csv, "Solo,only");
    }

    #[test]
    fn test_empty_entries() {
        let entries: Vec<CsvEntry> = vec![];
        let csv = serialize_canonical_csv(&entries);
        assert_eq!(csv, "");
    }
}
