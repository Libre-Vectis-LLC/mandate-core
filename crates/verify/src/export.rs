//! XLSX report export for verification results.
//!
//! Generates a 5-sheet Excel workbook from a [`VerificationReport`]:
//!
//! 1. **Verification Summary** — key-value overview of poll integrity checks.
//! 2. **Registry Mapping** — voter registry member listing.
//! 3. **Tally Results** — per-option vote counts including non-voters.
//! 4. **Vote Audit** — per-vote key image + choice for voter self-verification.
//! 5. **Charts** — pie chart and bar chart referencing tally data.

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
    let tally_sheet_name = write_tally_sheet(&mut workbook, report, locale, &header_fmt, &pct_fmt)?;
    write_vote_audit_sheet(&mut workbook, report, locale, &header_fmt)?;
    write_charts_sheet(
        &mut workbook,
        report,
        locale,
        &header_fmt,
        &tally_sheet_name,
    )?;

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

    // Headers: #, Voter Info, Master PubKey (bs58)
    let headers = [
        "#",
        &t(TranslationKey::VoterInfo, locale),
        &t(TranslationKey::MasterPubKey, locale),
    ];

    for (col, header) in headers.iter().enumerate() {
        ws.write_string_with_format(0, col as u16, *header, header_fmt)?;
    }

    ws.set_column_width(0, 5)?;
    ws.set_column_width(1, 25)?;
    ws.set_column_width(2, 55)?;

    // Registry and ring are guaranteed to match (CLI enforces this),
    // so we only list matched_entries.
    let rc = &report.registry_check;
    for (i, entry) in rc.matched_entries.iter().enumerate() {
        let row = (i + 1) as u32;
        ws.write_number(row, 0, (i + 1) as f64)?;
        ws.write_string(row, 1, &entry.voter_info)?;
        ws.write_string(row, 2, &entry.master_pub_bs58)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sheet 3: Tally Results
// ---------------------------------------------------------------------------

fn write_tally_sheet(
    workbook: &mut Workbook,
    report: &VerificationReport,
    locale: &Locale,
    header_fmt: &Format,
    pct_fmt: &Format,
) -> Result<String, ExportError> {
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

    let ring_size = report.summary.ring_size;

    for (i, opt) in report.tally.options.iter().enumerate() {
        let row = (i + 1) as u32;
        ws.write_string(row, 0, &opt.option_id)?;
        ws.write_string(row, 1, &opt.option_text)?;
        ws.write_number(row, 2, opt.votes as f64)?;
        // Share relative to ring size (not just votes cast).
        let share = if ring_size > 0 {
            opt.votes as f64 / ring_size as f64
        } else {
            0.0
        };
        ws.write_number_with_format(row, 3, share, pct_fmt)?;
    }

    // "Not Voted" row — ring members who did not cast any vote.
    let not_voted = ring_size.saturating_sub(report.tally.total_votes);
    let nv_row = (report.tally.options.len() + 1) as u32;
    ws.write_string(nv_row, 0, "\u{2014}")?;
    ws.write_string(nv_row, 1, t(TranslationKey::NotVoted, locale))?;
    ws.write_number(nv_row, 2, not_voted as f64)?;
    let nv_share = if ring_size > 0 {
        not_voted as f64 / ring_size as f64
    } else {
        0.0
    };
    ws.write_number_with_format(nv_row, 3, nv_share, pct_fmt)?;

    // Total row
    let total_row = nv_row + 1;
    ws.write_string_with_format(total_row, 0, t(TranslationKey::Total, locale), header_fmt)?;
    ws.write_string(total_row, 1, "")?;
    ws.write_number(total_row, 2, ring_size as f64)?;
    ws.write_number_with_format(total_row, 3, 1.0, pct_fmt)?;

    Ok(sheet_name)
}

// ---------------------------------------------------------------------------
// Sheet 4: Vote Audit (Key Image + Vote Choice per vote)
// ---------------------------------------------------------------------------

fn write_vote_audit_sheet(
    workbook: &mut Workbook,
    report: &VerificationReport,
    locale: &Locale,
    header_fmt: &Format,
) -> Result<(), ExportError> {
    let sheet_name = truncate_sheet_name(&t(TranslationKey::VoteAudit, locale));
    let ws = workbook.add_worksheet();
    ws.set_name(&sheet_name)?;

    let headers = [
        t(TranslationKey::KeyImageBs58, locale),
        t(TranslationKey::VoteChoice, locale),
    ];

    for (col, header) in headers.iter().enumerate() {
        ws.write_string_with_format(0, col as u16, header, header_fmt)?;
    }

    ws.set_column_width(0, 55)?;
    ws.set_column_width(1, 30)?;

    for (i, vc) in report.vote_checks.iter().enumerate() {
        let row = (i + 1) as u32;
        ws.write_string(row, 0, &vc.key_image_bs58)?;
        ws.write_string(row, 1, &vc.chosen_option)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sheet 5: Charts (Pie + Bar, referencing Tally Results data)
// ---------------------------------------------------------------------------

fn write_charts_sheet(
    workbook: &mut Workbook,
    report: &VerificationReport,
    locale: &Locale,
    _header_fmt: &Format,
    tally_sheet_name: &str,
) -> Result<(), ExportError> {
    let sheet_name = truncate_sheet_name(&t(TranslationKey::Charts, locale));
    let ws = workbook.add_worksheet();
    ws.set_name(&sheet_name)?;

    if report.tally.options.is_empty() {
        return Ok(());
    }

    let data_start: u32 = 1;
    // Include options + "Not Voted" row.
    let data_end = (report.tally.options.len() + 1) as u32;

    // Pie chart — vote share
    let mut pie = Chart::new(ChartType::Pie);
    pie.add_series()
        .set_categories((tally_sheet_name, data_start, 1_u16, data_end, 1_u16))
        .set_values((tally_sheet_name, data_start, 2_u16, data_end, 2_u16));
    pie.title()
        .set_name(&t(TranslationKey::TallyResults, locale));

    ws.insert_chart(0, 0, &pie)?;

    // Bar chart — vote counts
    let mut bar = Chart::new(ChartType::Bar);
    bar.add_series()
        .set_categories((tally_sheet_name, data_start, 1_u16, data_end, 1_u16))
        .set_values((tally_sheet_name, data_start, 2_u16, data_end, 2_u16));
    bar.title()
        .set_name(&t(TranslationKey::TallyResults, locale));

    ws.insert_chart(16, 0, &bar)?;

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
            registry_matches_ring: true,
        };

        let registry_check = CrossValidationResult {
            matched: 5,
            matched_entries: vec![
                RegistryEntry {
                    voter_info: "Alice".into(),
                    master_pub_bs58: "AliceKeyBs58".into(),
                },
                RegistryEntry {
                    voter_info: "Bob".into(),
                    master_pub_bs58: "BobKeyBs58".into(),
                },
                RegistryEntry {
                    voter_info: "Carol".into(),
                    master_pub_bs58: "CarolKeyBs58".into(),
                },
                RegistryEntry {
                    voter_info: "Dave".into(),
                    master_pub_bs58: "DaveKeyBs58".into(),
                },
                RegistryEntry {
                    voter_info: "Eve".into(),
                    master_pub_bs58: "EveKeyBs58".into(),
                },
            ],
            extra_in_ring: vec![],
            missing_from_ring: vec![],
        };

        let vote_checks = vec![
            VoteCheck {
                id: "vote-0".into(),
                valid: true,
                error: None,
                key_image_bs58: "ki_AAAA".into(),
                chosen_option: "Red".into(),
            },
            VoteCheck {
                id: "vote-1".into(),
                valid: true,
                error: None,
                key_image_bs58: "ki_BBBB".into(),
                chosen_option: "Blue".into(),
            },
            VoteCheck {
                id: "vote-2".into(),
                valid: false,
                error: Some("simulated failure".into()),
                key_image_bs58: "ki_CCCC".into(),
                chosen_option: "Red".into(),
            },
            VoteCheck {
                id: "vote-3".into(),
                valid: true,
                error: None,
                key_image_bs58: "ki_DDDD".into(),
                chosen_option: "Green".into(),
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

        assert_eq!(sheets.len(), 5, "should have 5 sheets");
        assert_eq!(sheets[0], "Verification Summary");
        assert_eq!(sheets[1], "Registry Mapping");
        assert_eq!(sheets[2], "Tally Results");
        assert_eq!(sheets[3], "Vote Audit");
        assert_eq!(sheets[4], "Charts");

        // Tally Results: header + 3 options + 1 not-voted + 1 total = 6 rows
        let tally_range = wb.worksheet_range(&sheets[2]).expect("tally results sheet");
        assert_eq!(
            tally_range.rows().count(),
            6,
            "tally: 1 header + 3 options + 1 not-voted + 1 total"
        );

        // Vote Audit: header + 4 votes = 5 rows
        let audit_range = wb.worksheet_range(&sheets[3]).expect("vote audit sheet");
        assert_eq!(
            audit_range.rows().count(),
            5,
            "vote audit: 1 header + 4 votes"
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

        assert_eq!(sheets.len(), 5, "should have 5 sheets");

        // Bilingual sheet names should contain " | ".
        for name in &sheets {
            assert!(
                name.contains(" | "),
                "bilingual sheet name should contain ' | ': got {name}"
            );
        }

        // Check first sheet name specifically.
        assert_eq!(
            sheets[0],
            "\u{9a8c}\u{8bc1}\u{6458}\u{8981} | Verification Summary"
        );

        // Check tally sheet has bilingual headers.
        let tally_range = wb.worksheet_range(&sheets[2]).expect("tally results sheet");
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
        assert_eq!(sheets.len(), 5);

        // Tally should have header + not-voted + total = 3 rows.
        let tally_range = wb.worksheet_range(&sheets[2]).expect("tally results sheet");
        assert_eq!(
            tally_range.rows().count(),
            3,
            "header + not-voted + total for empty tally"
        );

        // Vote Audit should have header only (no votes).
        let audit_range = wb.worksheet_range(&sheets[3]).expect("vote audit sheet");
        assert_eq!(
            audit_range.rows().count(),
            1,
            "vote audit: header only for empty votes"
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

        assert_eq!(sheets.len(), 5);
        // Traditional Chinese sheet names.
        assert_eq!(sheets[0], "\u{9a57}\u{8b49}\u{6458}\u{8981}");
        assert_eq!(sheets[2], "\u{8a08}\u{7968}\u{7d50}\u{679c}");
        assert_eq!(sheets[3], "\u{6295}\u{7968}\u{5be9}\u{8a08}");

        let _ = std::fs::remove_file(&path);
    }
}
