//! Voter registry XLSX parser.
//!
//! Reads a `.xlsx` workbook and extracts two columns per row:
//! - **voter info** (name / identifier string)
//! - **Nazgul master public key** (bs58-encoded string)
//!
//! Column detection is automatic: the parser scans the first row for
//! well-known header names and maps them to the two required fields.

use std::path::Path;

use calamine::{open_workbook, Data, DataType as _, Reader, Xlsx, XlsxError};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur while parsing a voter registry workbook.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// The workbook could not be opened or read.
    #[error("failed to open workbook: {0}")]
    Open(#[from] XlsxError),

    /// The workbook contains no worksheets.
    #[error("workbook contains no worksheets")]
    NoSheets,

    /// A required column header could not be found in the first row.
    #[error("missing column: {0}")]
    MissingColumn(&'static str),

    /// A row is missing an expected cell value.
    #[error("row {row}: empty {field} cell")]
    EmptyCell { row: usize, field: &'static str },
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single entry from the voter registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    /// Human-readable voter identifier (name, ID number, etc.).
    pub voter_info: String,
    /// bs58-encoded Nazgul master public key.
    pub master_pub_bs58: String,
}

// ---------------------------------------------------------------------------
// Header detection
// ---------------------------------------------------------------------------

/// Well-known header names (lowercased) that map to the *voter info* column.
const VOTER_INFO_HEADERS: &[&str] = &[
    "voter",
    "name",
    "info",
    "voter_info",
    "voter info",
    "voter_name",
    "voter name",
    "identifier",
];

/// Well-known header names (lowercased) that map to the *public key* column.
const PUBKEY_HEADERS: &[&str] = &[
    "public_key",
    "public key",
    "pubkey",
    "pub_key",
    "nazgul",
    "nazgul_pub",
    "nazgul pub",
    "master_pub",
    "master pub",
    "master_public_key",
    "master public key",
    "key",
];

/// Locate the column index for a set of candidate header names.
///
/// `headers` is the first row of the worksheet. The function returns the
/// 0-based column index of the first cell whose lowercased, trimmed text
/// matches any of the `candidates`.
fn find_column(headers: &[Data], candidates: &[&str]) -> Option<usize> {
    headers.iter().position(|cell| {
        let text = cell.to_string().trim().to_lowercase();
        candidates.iter().any(|c| text == *c)
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a voter registry from a `.xlsx` file at `path`.
///
/// The first worksheet is used. The first row must contain headers that the
/// parser can map to the two required columns (voter info and public key).
/// Subsequent rows are parsed into [`RegistryEntry`] values.
///
/// Empty rows (both cells blank) are silently skipped.
pub fn parse_registry(path: &Path) -> Result<Vec<RegistryEntry>, RegistryError> {
    let mut workbook: Xlsx<_> = open_workbook(path)?;

    let sheet_name = workbook
        .sheet_names()
        .first()
        .ok_or(RegistryError::NoSheets)?
        .clone();

    let range = workbook.worksheet_range(&sheet_name)?;

    let mut rows = range.rows();

    // --- header row ---
    let header_row = match rows.next() {
        Some(r) => r,
        // Completely empty sheet -- return empty vec, not an error.
        None => return Ok(Vec::new()),
    };

    let voter_col = find_column(header_row, VOTER_INFO_HEADERS)
        .ok_or(RegistryError::MissingColumn("voter info"))?;

    let key_col = find_column(header_row, PUBKEY_HEADERS)
        .ok_or(RegistryError::MissingColumn("public key"))?;

    // --- data rows ---
    let mut entries = Vec::new();
    for (idx, row) in rows.enumerate() {
        let voter_cell = row.get(voter_col);
        let key_cell = row.get(key_col);

        // Skip entirely blank rows.
        let voter_text = cell_to_string(voter_cell);
        let key_text = cell_to_string(key_cell);

        if voter_text.is_empty() && key_text.is_empty() {
            continue;
        }

        if voter_text.is_empty() {
            return Err(RegistryError::EmptyCell {
                row: idx + 2, // 1-indexed, +1 for header
                field: "voter info",
            });
        }
        if key_text.is_empty() {
            return Err(RegistryError::EmptyCell {
                row: idx + 2,
                field: "public key",
            });
        }

        entries.push(RegistryEntry {
            voter_info: voter_text,
            master_pub_bs58: key_text,
        });
    }

    Ok(entries)
}

/// Extract a trimmed string from an optional cell value.
fn cell_to_string(cell: Option<&Data>) -> String {
    match cell {
        Some(dt) if !dt.is_empty() => dt.to_string().trim().to_owned(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rust_xlsxwriter::Workbook;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    /// Helper: write a workbook to a temporary file and return the handle.
    fn write_temp_xlsx(wb: &mut Workbook) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().expect("failed to create temp file");
        let buf = wb.save_to_buffer().expect("failed to save workbook");
        tmp.write_all(&buf).expect("failed to write xlsx");
        tmp.flush().expect("flush failed");
        tmp
    }

    #[test]
    fn test_parse_normal_registry() {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        // Headers
        ws.write_string(0, 0, "Name").unwrap();
        ws.write_string(0, 1, "Public_Key").unwrap();
        // Data rows
        ws.write_string(1, 0, "Alice").unwrap();
        ws.write_string(1, 1, "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")
            .unwrap();
        ws.write_string(2, 0, "Bob").unwrap();
        ws.write_string(2, 1, "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
            .unwrap();

        let tmp = write_temp_xlsx(&mut wb);

        let entries = parse_registry(tmp.path()).expect("parse should succeed");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].voter_info, "Alice");
        assert_eq!(
            entries[0].master_pub_bs58,
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        );
        assert_eq!(entries[1].voter_info, "Bob");
        assert_eq!(
            entries[1].master_pub_bs58,
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
        );
    }

    #[test]
    fn test_missing_voter_column() {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "UnknownColumn").unwrap();
        ws.write_string(0, 1, "Pubkey").unwrap();

        let tmp = write_temp_xlsx(&mut wb);

        let err = parse_registry(tmp.path()).unwrap_err();
        assert!(
            matches!(err, RegistryError::MissingColumn("voter info")),
            "expected MissingColumn(voter info), got: {err:?}"
        );
    }

    #[test]
    fn test_missing_key_column() {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "Voter").unwrap();
        ws.write_string(0, 1, "SomeOtherColumn").unwrap();

        let tmp = write_temp_xlsx(&mut wb);

        let err = parse_registry(tmp.path()).unwrap_err();
        assert!(
            matches!(err, RegistryError::MissingColumn("public key")),
            "expected MissingColumn(public key), got: {err:?}"
        );
    }

    #[test]
    fn test_empty_workbook() {
        let mut wb = Workbook::new();
        let _ws = wb.add_worksheet();

        let tmp = write_temp_xlsx(&mut wb);

        let entries = parse_registry(tmp.path()).expect("empty workbook should return Ok");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_header_only_workbook() {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "Voter").unwrap();
        ws.write_string(0, 1, "Key").unwrap();

        let tmp = write_temp_xlsx(&mut wb);

        let entries = parse_registry(tmp.path()).expect("header-only should return Ok");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_blank_rows_are_skipped() {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "Voter Info").unwrap();
        ws.write_string(0, 1, "Nazgul").unwrap();
        // Row 1: data
        ws.write_string(1, 0, "Charlie").unwrap();
        ws.write_string(1, 1, "abc123").unwrap();
        // Row 2: blank (skipped)
        // Row 3: data
        ws.write_string(3, 0, "Dave").unwrap();
        ws.write_string(3, 1, "def456").unwrap();

        let tmp = write_temp_xlsx(&mut wb);

        let entries = parse_registry(tmp.path()).expect("parse should succeed");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].voter_info, "Charlie");
        assert_eq!(entries[1].voter_info, "Dave");
    }

    #[test]
    fn test_case_insensitive_headers() {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "VOTER_NAME").unwrap();
        ws.write_string(0, 1, "MASTER_PUBLIC_KEY").unwrap();
        ws.write_string(1, 0, "Eve").unwrap();
        ws.write_string(1, 1, "key123").unwrap();

        let tmp = write_temp_xlsx(&mut wb);

        let entries = parse_registry(tmp.path()).expect("case-insensitive headers should work");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].voter_info, "Eve");
    }

    #[test]
    fn test_empty_cell_error() {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "Name").unwrap();
        ws.write_string(0, 1, "Key").unwrap();
        ws.write_string(1, 0, "Frank").unwrap();
        // Missing key cell on purpose

        let tmp = write_temp_xlsx(&mut wb);

        let err = parse_registry(tmp.path()).unwrap_err();
        assert!(
            matches!(
                err,
                RegistryError::EmptyCell {
                    row: 2,
                    field: "public key"
                }
            ),
            "expected EmptyCell for public key at row 2, got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Edge case: very long voter info strings
    // -----------------------------------------------------------------------

    #[test]
    fn test_very_long_voter_info() {
        let long_name = "A".repeat(10_000);
        let long_key = "B".repeat(5_000);

        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "Voter").unwrap();
        ws.write_string(0, 1, "Key").unwrap();
        ws.write_string(1, 0, &long_name).unwrap();
        ws.write_string(1, 1, &long_key).unwrap();

        let tmp = write_temp_xlsx(&mut wb);

        let entries = parse_registry(tmp.path()).expect("long strings should parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].voter_info.len(), 10_000);
        assert_eq!(entries[0].master_pub_bs58.len(), 5_000);
    }

    // -----------------------------------------------------------------------
    // Edge case: Unicode in voter info
    // -----------------------------------------------------------------------

    #[test]
    fn test_unicode_voter_info() {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "Voter Name").unwrap();
        ws.write_string(0, 1, "Pubkey").unwrap();
        ws.write_string(1, 0, "\u{5f20}\u{4e09} / \u{5f35}\u{4e09}")
            .unwrap();
        ws.write_string(1, 1, "abc123key").unwrap();
        ws.write_string(2, 0, "Ελληνικά Ωμέγα").unwrap();
        ws.write_string(2, 1, "def456key").unwrap();
        ws.write_string(3, 0, "\u{65e5}\u{672c}\u{8a9e}テスト 🗳️")
            .unwrap();
        ws.write_string(3, 1, "ghi789key").unwrap();

        let tmp = write_temp_xlsx(&mut wb);

        let entries = parse_registry(tmp.path()).expect("unicode should parse");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].voter_info, "\u{5f20}\u{4e09} / \u{5f35}\u{4e09}");
        assert_eq!(entries[1].voter_info, "Ελληνικά Ωμέγα");
        assert!(entries[2]
            .voter_info
            .contains("\u{65e5}\u{672c}\u{8a9e}テスト"));
    }

    // -----------------------------------------------------------------------
    // Edge case: extra columns are ignored
    // -----------------------------------------------------------------------

    #[test]
    fn test_extra_columns_ignored() {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "Name").unwrap();
        ws.write_string(0, 1, "Public_Key").unwrap();
        ws.write_string(0, 2, "Email").unwrap();
        ws.write_string(0, 3, "Phone").unwrap();
        ws.write_string(1, 0, "Alice").unwrap();
        ws.write_string(1, 1, "key123").unwrap();
        ws.write_string(1, 2, "alice@example.com").unwrap();
        ws.write_string(1, 3, "+1234567890").unwrap();

        let tmp = write_temp_xlsx(&mut wb);

        let entries = parse_registry(tmp.path()).expect("extra columns should be ignored");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].voter_info, "Alice");
        assert_eq!(entries[0].master_pub_bs58, "key123");
    }

    // -----------------------------------------------------------------------
    // Edge case: missing voter info cell (key present, voter empty)
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_voter_info_error() {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "Name").unwrap();
        ws.write_string(0, 1, "Key").unwrap();
        // Row 1: key present, voter missing
        ws.write_string(1, 1, "somekey").unwrap();

        let tmp = write_temp_xlsx(&mut wb);

        let err = parse_registry(tmp.path()).unwrap_err();
        assert!(
            matches!(
                err,
                RegistryError::EmptyCell {
                    row: 2,
                    field: "voter info"
                }
            ),
            "expected EmptyCell for voter info at row 2, got: {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Edge case: columns in non-standard order
    // -----------------------------------------------------------------------

    #[test]
    fn test_reversed_column_order() {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        // Put key column first, voter column second
        ws.write_string(0, 0, "Pubkey").unwrap();
        ws.write_string(0, 1, "Voter").unwrap();
        ws.write_string(1, 0, "mykey123").unwrap();
        ws.write_string(1, 1, "Alice").unwrap();

        let tmp = write_temp_xlsx(&mut wb);

        let entries = parse_registry(tmp.path()).expect("reversed columns should work");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].voter_info, "Alice");
        assert_eq!(entries[0].master_pub_bs58, "mykey123");
    }
}
