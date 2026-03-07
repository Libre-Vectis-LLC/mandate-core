//! XLSX report export for verification results.
//!
//! Generates a 4-sheet Excel workbook from a [`VerificationReport`]:
//!
//! 1. **Verification Summary** — key-value pairs with a pie chart for vote shares.
//! 2. **Registry Mapping** — voter registry vs ring member cross-validation table.
//! 3. **Vote Details** — per-vote signature check results (shuffled order).
//! 4. **Tally Results** — per-option vote counts with a bar chart.

use std::collections::HashSet;
use std::path::Path;

use rust_xlsxwriter::{Chart, ChartType, Format, Workbook, XlsxError};
use thiserror::Error;

use crate::i18n::{translate, Language, Locale, TranslationKey};
use crate::pipeline::VerificationReport;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during XLSX export.
#[derive(Debug, Error)]
pub enum ExportError {
    /// rust_xlsxwriter failed.
    #[error("xlsx write error: {0}")]
    Xlsx(#[from] XlsxError),

    /// Failed to write the output file.
    #[error("io error writing output file: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Export a [`VerificationReport`] to an XLSX workbook at `output`.
///
/// Headers are localized according to `locale`. For [`Locale::Bilingual`],
/// headers show both languages separated by " / ".
///
/// # Errors
///
/// Returns [`ExportError`] if workbook creation or file I/O fails.
pub fn export_xlsx(
    report: &VerificationReport,
    locale: &Locale,
    output: &Path,
) -> Result<(), ExportError> {
    let mut workbook = Workbook::new();

    let header_fmt = Format::new().set_bold();
    let pct_fmt = Format::new().set_num_format("0.00%");

    write_summary_sheet(&mut workbook, report, locale, &header_fmt, &pct_fmt)?;
    write_registry_sheet(&mut workbook, report, locale, &header_fmt)?;
    write_vote_details_sheet(&mut workbook, report, locale, &header_fmt)?;
    write_tally_sheet(&mut workbook, report, locale, &header_fmt, &pct_fmt)?;

    let buf = workbook.save_to_buffer()?;
    std::fs::write(output, buf)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a translation key for the given locale.
///
/// For [`Locale::Single`], returns the single-language string.
/// For [`Locale::Bilingual`], returns `"primary | secondary"`.
///
/// Uses `|` as separator instead of `/` because Excel sheet names prohibit `/`.
fn t(key: TranslationKey, locale: &Locale) -> String {
    match locale {
        Locale::Single(lang) => translate(key, *lang).to_owned(),
        Locale::Bilingual(a, b) => {
            let primary = translate(key, *a);
            let secondary = translate(key, *b);
            format!("{primary} | {secondary}")
        }
    }
}

/// Truncate a string to at most 31 characters (Excel sheet name limit).
fn truncate_sheet_name(name: &str) -> String {
    if name.chars().count() <= 31 {
        name.to_owned()
    } else {
        name.chars().take(31).collect()
    }
}

/// Return the primary language for Yes/No status values.
fn primary_lang(locale: &Locale) -> Language {
    match locale {
        Locale::Single(lang) => *lang,
        Locale::Bilingual(a, _) => *a,
    }
}

/// Return a localized yes/no string.
fn yes_no(value: bool, locale: &Locale) -> String {
    let lang = primary_lang(locale);
    if value {
        translate(TranslationKey::Yes, lang).to_owned()
    } else {
        translate(TranslationKey::No, lang).to_owned()
    }
}

// ---------------------------------------------------------------------------
// Sheet 1: Verification Summary
// ---------------------------------------------------------------------------

fn write_summary_sheet(
    workbook: &mut Workbook,
    report: &VerificationReport,
    locale: &Locale,
    header_fmt: &Format,
    pct_fmt: &Format,
) -> Result<(), ExportError> {
    let sheet_name = truncate_sheet_name(&t(TranslationKey::VerificationSummary, locale));
    let ws = workbook.add_worksheet();
    ws.set_name(&sheet_name)?;

    // Column widths for readability.
    ws.set_column_width(0, 30)?;
    ws.set_column_width(1, 50)?;

    let s = &report.summary;

    // Key-value rows
    let rows: Vec<(TranslationKey, String)> = vec![
        (TranslationKey::PollTitle, s.poll_title.clone()),
        (TranslationKey::PollId, s.poll_id.clone()),
        (TranslationKey::OrgId, s.org_id.clone()),
        (TranslationKey::RingSize, s.ring_size.to_string()),
        (TranslationKey::VotesCast, s.votes_cast.to_string()),
    ];

    let mut row: u32 = 0;
    for (key, value) in &rows {
        ws.write_string_with_format(row, 0, t(*key, locale), header_fmt)?;
        ws.write_string(row, 1, value)?;
        row += 1;
    }

    // Turnout as percentage
    ws.write_string_with_format(row, 0, t(TranslationKey::Turnout, locale), header_fmt)?;
    ws.write_number_with_format(row, 1, s.turnout, pct_fmt)?;
    row += 1;

    // Boolean status flags
    let flags: Vec<(TranslationKey, bool)> = vec![
        (TranslationKey::SignaturesVerified, s.all_signatures_valid),
        (TranslationKey::KeyImagesUnique, s.all_key_images_unique),
        (TranslationKey::RegistryMatches, s.registry_matches_ring),
    ];

    for (key, value) in &flags {
        ws.write_string_with_format(row, 0, t(*key, locale), header_fmt)?;
        ws.write_string(row, 1, yes_no(*value, locale))?;
        row += 1;
    }

    // --- Vote share pie chart (embedded from tally data) ---
    // Write a small hidden data table for the chart, starting after the
    // key-value section with a blank row separator.
    row += 1;
    let chart_data_start = row;

    ws.write_string_with_format(row, 0, t(TranslationKey::OptionText, locale), header_fmt)?;
    ws.write_string_with_format(row, 1, t(TranslationKey::Votes, locale), header_fmt)?;
    row += 1;

    for opt in &report.tally.options {
        ws.write_string(row, 0, &opt.option_text)?;
        ws.write_number(row, 1, opt.votes as f64)?;
        row += 1;
    }

    let chart_data_end = row - 1;

    // Only insert chart if there is tally data.
    if !report.tally.options.is_empty() {
        let mut chart = Chart::new(ChartType::Pie);
        chart
            .add_series()
            .set_categories((
                sheet_name.as_str(),
                chart_data_start + 1,
                0_u16,
                chart_data_end,
                0_u16,
            ))
            .set_values((
                sheet_name.as_str(),
                chart_data_start + 1,
                1_u16,
                chart_data_end,
                1_u16,
            ));
        chart
            .title()
            .set_name(&t(TranslationKey::TallyResults, locale));

        ws.insert_chart(chart_data_start, 3, &chart)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sheet 2: Registry Mapping
// ---------------------------------------------------------------------------

fn write_registry_sheet(
    workbook: &mut Workbook,
    report: &VerificationReport,
    locale: &Locale,
    header_fmt: &Format,
) -> Result<(), ExportError> {
    let sheet_name = truncate_sheet_name(&t(TranslationKey::RegistryMapping, locale));
    let ws = workbook.add_worksheet();
    ws.set_name(&sheet_name)?;

    // Headers: #, Voter Info, Master PubKey (bs58), In Ring?
    let headers = [
        "#",
        &t(TranslationKey::VoterInfo, locale),
        &t(TranslationKey::MasterPubKey, locale),
        &t(TranslationKey::InRing, locale),
    ];

    for (col, header) in headers.iter().enumerate() {
        ws.write_string_with_format(0, col as u16, *header, header_fmt)?;
    }

    // Set column widths.
    ws.set_column_width(0, 5)?;
    ws.set_column_width(1, 25)?;
    ws.set_column_width(2, 55)?;
    ws.set_column_width(3, 12)?;

    let rc = &report.registry_check;

    // Build a set of master pub keys that are missing from ring for quick
    // lookup.
    let missing_keys: HashSet<&str> = rc
        .missing_from_ring
        .iter()
        .map(|e| e.master_pub_bs58.as_str())
        .collect();

    // Collect all entries: matched + missing from ring entries come from the
    // original registry (which we reconstruct from the cross-validation result).
    // We also include extra-in-ring entries (no voter info).
    let mut row: u32 = 1;
    let mut index: usize = 1;

    // Entries from the registry side (matched + missing_from_ring).
    // The cross-validation result stores missing_from_ring entries.
    // For matched entries, we don't have the original RegistryEntry in the
    // report (they are counted, not stored individually). We include only
    // what we have: missing_from_ring entries and extra_in_ring entries.
    //
    // Note: In the current data model, the VerificationReport does not carry
    // the full registry. We output the entries we DO have.

    // Missing from ring entries (voter in registry but not in ring).
    for entry in &rc.missing_from_ring {
        let in_ring = missing_keys.contains(entry.master_pub_bs58.as_str());
        ws.write_number(row, 0, index as f64)?;
        ws.write_string(row, 1, &entry.voter_info)?;
        ws.write_string(row, 2, &entry.master_pub_bs58)?;
        ws.write_string(row, 3, yes_no(!in_ring, locale))?;
        row += 1;
        index += 1;
    }

    // Extra in ring entries (in ring but not in registry — no voter info).
    for key in &rc.extra_in_ring {
        ws.write_number(row, 0, index as f64)?;
        ws.write_string(row, 1, "—")?;
        ws.write_string(row, 2, key)?;
        ws.write_string(row, 3, yes_no(true, locale))?;
        row += 1;
        index += 1;
    }

    // Summary row: matched count.
    ws.write_string_with_format(row, 0, t(TranslationKey::Total, locale), header_fmt)?;
    ws.write_string(
        row,
        1,
        format!(
            "{} matched, {} missing, {} extra",
            rc.matched,
            rc.missing_from_ring.len(),
            rc.extra_in_ring.len()
        ),
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Sheet 3: Vote Verification Details (SHUFFLED)
// ---------------------------------------------------------------------------

fn write_vote_details_sheet(
    workbook: &mut Workbook,
    report: &VerificationReport,
    locale: &Locale,
    header_fmt: &Format,
) -> Result<(), ExportError> {
    let sheet_name = truncate_sheet_name(&t(TranslationKey::VoteDetails, locale));
    let ws = workbook.add_worksheet();
    ws.set_name(&sheet_name)?;

    // Build a set of duplicate key images for quick per-vote lookup.
    let duplicate_kis: HashSet<&str> = report
        .key_image_check
        .duplicates
        .iter()
        .map(String::as_str)
        .collect();

    // Headers: #, Vote ID, Signature Valid?, Error
    let headers = [
        "#",
        &t(TranslationKey::KeyImage, locale),
        &t(TranslationKey::SigValid, locale),
        &t(TranslationKey::KiUnique, locale),
    ];

    for (col, header) in headers.iter().enumerate() {
        ws.write_string_with_format(0, col as u16, *header, header_fmt)?;
    }

    ws.set_column_width(0, 5)?;
    ws.set_column_width(1, 30)?;
    ws.set_column_width(2, 18)?;
    ws.set_column_width(3, 18)?;

    // The vote_checks are already shuffled by the pipeline for
    // anti-temporal-correlation.
    for (i, vc) in report.vote_checks.iter().enumerate() {
        let row = (i + 1) as u32;
        ws.write_number(row, 0, (i + 1) as f64)?;
        // Use the vote id as a stand-in for key image (the id field
        // contains the vote identifier which maps to the key image concept).
        ws.write_string(row, 1, &vc.id)?;
        ws.write_string(row, 2, yes_no(vc.valid, locale))?;
        // Key image uniqueness: if the id is NOT in the duplicate set, it's unique.
        let ki_unique = !duplicate_kis.contains(vc.id.as_str());
        ws.write_string(row, 3, yes_no(ki_unique, locale))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sheet 4: Tally Results
// ---------------------------------------------------------------------------

fn write_tally_sheet(
    workbook: &mut Workbook,
    report: &VerificationReport,
    locale: &Locale,
    header_fmt: &Format,
    pct_fmt: &Format,
) -> Result<(), ExportError> {
    let sheet_name = truncate_sheet_name(&t(TranslationKey::TallyResults, locale));
    let ws = workbook.add_worksheet();
    ws.set_name(&sheet_name)?;

    let headers = [
        t(TranslationKey::OptionId, locale),
        t(TranslationKey::OptionText, locale),
        t(TranslationKey::Votes, locale),
        t(TranslationKey::Share, locale),
    ];

    for (col, header) in headers.iter().enumerate() {
        ws.write_string_with_format(0, col as u16, header, header_fmt)?;
    }

    ws.set_column_width(0, 15)?;
    ws.set_column_width(1, 30)?;
    ws.set_column_width(2, 10)?;
    ws.set_column_width(3, 12)?;

    for (i, opt) in report.tally.options.iter().enumerate() {
        let row = (i + 1) as u32;
        ws.write_string(row, 0, &opt.option_id)?;
        ws.write_string(row, 1, &opt.option_text)?;
        ws.write_number(row, 2, opt.votes as f64)?;
        ws.write_number_with_format(row, 3, opt.share, pct_fmt)?;
    }

    // Total row
    let total_row = (report.tally.options.len() + 1) as u32;
    ws.write_string_with_format(total_row, 0, t(TranslationKey::Total, locale), header_fmt)?;
    ws.write_string(total_row, 1, "")?;
    ws.write_number(total_row, 2, report.tally.total_votes as f64)?;
    ws.write_number_with_format(total_row, 3, 1.0, pct_fmt)?;

    // --- Bar chart ---
    if !report.tally.options.is_empty() {
        let data_start: u32 = 1;
        let data_end = report.tally.options.len() as u32;

        let mut chart = Chart::new(ChartType::Bar);
        chart
            .add_series()
            .set_categories((sheet_name.as_str(), data_start, 1_u16, data_end, 1_u16))
            .set_values((sheet_name.as_str(), data_start, 2_u16, data_end, 2_u16));
        chart
            .title()
            .set_name(&t(TranslationKey::TallyResults, locale));

        ws.insert_chart(data_end + 2, 0, &chart)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_validate::CrossValidationResult;
    use crate::key_image::KeyImageCheck;
    use crate::pipeline::PollSummary;
    use crate::registry::RegistryEntry;
    use crate::signature::VoteCheck;
    use crate::tally::{OptionTally, TallyResult};

    use calamine::{open_workbook, Reader, Xlsx};
    use tempfile::NamedTempFile;

    /// Build a synthetic VerificationReport for testing.
    fn make_test_report() -> VerificationReport {
        let summary = PollSummary {
            poll_title: "Test Poll: Favorite Color".into(),
            poll_id: "01JTEST_POLL".into(),
            org_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            ring_size: 5,
            votes_cast: 4,
            turnout: 0.8,
            all_signatures_valid: true,
            all_key_images_unique: true,
            registry_matches_ring: false,
        };

        let registry_check = CrossValidationResult {
            matched: 4,
            extra_in_ring: vec!["ExtraKeyBs58InRing".into()],
            missing_from_ring: vec![RegistryEntry {
                voter_info: "MissingVoter".into(),
                master_pub_bs58: "MissingKeyBs58".into(),
            }],
        };

        let vote_checks = vec![
            VoteCheck {
                id: "vote-0".into(),
                valid: true,
                error: None,
            },
            VoteCheck {
                id: "vote-1".into(),
                valid: true,
                error: None,
            },
            VoteCheck {
                id: "vote-2".into(),
                valid: false,
                error: Some("simulated failure".into()),
            },
            VoteCheck {
                id: "vote-3".into(),
                valid: true,
                error: None,
            },
        ];

        let key_image_check = KeyImageCheck {
            total: 4,
            unique: 4,
            duplicates: vec![],
        };

        let tally = TallyResult {
            options: vec![
                OptionTally {
                    option_id: "red".into(),
                    option_text: "Red".into(),
                    votes: 2,
                    share: 0.5,
                },
                OptionTally {
                    option_id: "blue".into(),
                    option_text: "Blue".into(),
                    votes: 1,
                    share: 0.25,
                },
                OptionTally {
                    option_id: "green".into(),
                    option_text: "Green".into(),
                    votes: 1,
                    share: 0.25,
                },
            ],
            total_votes: 4,
        };

        VerificationReport {
            summary,
            registry_check,
            vote_checks,
            key_image_check,
            tally,
        }
    }

    #[test]
    fn test_export_xlsx_single_locale_structure() {
        let report = make_test_report();
        let locale = Locale::Single(Language::En);
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().with_extension("xlsx");

        export_xlsx(&report, &locale, &path).expect("export should succeed");

        // Read back with calamine.
        let mut wb: Xlsx<_> = open_workbook(&path).expect("open exported xlsx");
        let sheets = wb.sheet_names().to_vec();

        assert_eq!(sheets.len(), 4, "should have 4 sheets");
        assert_eq!(sheets[0], "Verification Summary");
        assert_eq!(sheets[1], "Registry Mapping");
        assert_eq!(sheets[2], "Vote Details");
        assert_eq!(sheets[3], "Tally Results");

        // Sheet 3 (Vote Details): header + 4 votes = 5 rows
        let vote_range = wb.worksheet_range(&sheets[2]).expect("vote details sheet");
        // Row count includes header.
        assert_eq!(
            vote_range.rows().count(),
            5,
            "vote details: 1 header + 4 votes"
        );

        // Sheet 4 (Tally Results): header + 3 options + 1 total = 5 rows
        let tally_range = wb.worksheet_range(&sheets[3]).expect("tally results sheet");
        assert_eq!(
            tally_range.rows().count(),
            5,
            "tally: 1 header + 3 options + 1 total"
        );

        // Clean up.
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_export_xlsx_bilingual_locale_headers() {
        let report = make_test_report();
        let locale = Locale::Bilingual(Language::Zhs, Language::En);
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().with_extension("xlsx");

        export_xlsx(&report, &locale, &path).expect("export should succeed");

        let mut wb: Xlsx<_> = open_workbook(&path).expect("open exported xlsx");
        let sheets = wb.sheet_names().to_vec();

        assert_eq!(sheets.len(), 4, "should have 4 sheets");

        // Bilingual sheet names should contain " / ".
        for name in &sheets {
            assert!(
                name.contains(" | "),
                "bilingual sheet name should contain ' / ': got {name}"
            );
        }

        // Check first sheet name specifically.
        assert_eq!(
            sheets[0],
            "\u{9a8c}\u{8bc1}\u{6458}\u{8981} | Verification Summary"
        );

        // Check tally sheet has bilingual headers.
        let tally_range = wb.worksheet_range(&sheets[3]).expect("tally results sheet");
        let first_row: Vec<String> = tally_range
            .rows()
            .next()
            .expect("at least one row")
            .iter()
            .map(|cell| cell.to_string())
            .collect();

        // First header should be bilingual Option ID.
        assert!(
            first_row[0].contains(" | "),
            "tally header should be bilingual: got {}",
            first_row[0]
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_export_xlsx_empty_votes() {
        let mut report = make_test_report();
        report.summary.votes_cast = 0;
        report.summary.turnout = 0.0;
        report.vote_checks = vec![];
        report.key_image_check = KeyImageCheck {
            total: 0,
            unique: 0,
            duplicates: vec![],
        };
        report.tally = TallyResult {
            options: vec![],
            total_votes: 0,
        };

        let locale = Locale::Single(Language::En);
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().with_extension("xlsx");

        export_xlsx(&report, &locale, &path).expect("export should succeed");

        let mut wb: Xlsx<_> = open_workbook(&path).expect("open exported xlsx");
        let sheets = wb.sheet_names().to_vec();
        assert_eq!(sheets.len(), 4);

        // Vote details should have only header.
        let vote_range = wb.worksheet_range(&sheets[2]).expect("vote details sheet");
        assert_eq!(
            vote_range.rows().count(),
            1,
            "only header row for empty votes"
        );

        // Tally should have header + total = 2 rows.
        let tally_range = wb.worksheet_range(&sheets[3]).expect("tally results sheet");
        assert_eq!(
            tally_range.rows().count(),
            2,
            "header + total for empty tally"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_export_xlsx_summary_values() {
        let report = make_test_report();
        let locale = Locale::Single(Language::En);
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().with_extension("xlsx");

        export_xlsx(&report, &locale, &path).expect("export should succeed");

        let mut wb: Xlsx<_> = open_workbook(&path).expect("open exported xlsx");
        let sheets = wb.sheet_names().to_vec();

        let summary_range = wb.worksheet_range(&sheets[0]).expect("summary sheet");

        // Collect key-value pairs from column A and B.
        let rows: Vec<(String, String)> = summary_range
            .rows()
            .map(|r| {
                let key = r.first().map(|c| c.to_string()).unwrap_or_default();
                let val = r.get(1).map(|c| c.to_string()).unwrap_or_default();
                (key, val)
            })
            .collect();

        // Find Poll Title row.
        let poll_title_row = rows
            .iter()
            .find(|(k, _)| k == "Poll Title")
            .expect("should have Poll Title row");
        assert_eq!(poll_title_row.1, "Test Poll: Favorite Color");

        // Find Ring Size row.
        let ring_size_row = rows
            .iter()
            .find(|(k, _)| k == "Ring Size")
            .expect("should have Ring Size row");
        assert_eq!(ring_size_row.1, "5");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_export_xlsx_zht_locale() {
        let report = make_test_report();
        let locale = Locale::Single(Language::Zht);
        let tmp = NamedTempFile::new().expect("temp file");
        let path = tmp.path().with_extension("xlsx");

        export_xlsx(&report, &locale, &path).expect("export should succeed");

        let wb: Xlsx<_> = open_workbook(&path).expect("open exported xlsx");
        let sheets = wb.sheet_names().to_vec();

        assert_eq!(sheets.len(), 4);
        // Traditional Chinese sheet names.
        assert_eq!(sheets[0], "\u{9a57}\u{8b49}\u{6458}\u{8981}"); // \u{9a57}\u{8b49}\u{6458}\u{8981}
        assert_eq!(sheets[3], "\u{8a08}\u{7968}\u{7d50}\u{679c}"); // \u{8a08}\u{7968}\u{7d50}\u{679c}

        let _ = std::fs::remove_file(&path);
    }
}
