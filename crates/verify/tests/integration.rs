//! End-to-end integration tests for the mandate-verify crate.
//!
//! Each test exercises the full verification workflow:
//! 1. Build a synthetic voter registry XLSX (rust_xlsxwriter)
//! 2. Build a synthetic PollBundle and serialize to bytes
//! 3. Call `verify_poll(VerifyInput::FromFiles { .. }, VerifyOptions { .. })`
//! 4. Assert the VerificationReport is complete and consistent
//! 5. Call `export_xlsx()` to produce a report workbook
//! 6. Read back the exported XLSX with calamine and verify structure

use std::io::Write as _;

use calamine::{open_workbook, Reader, Xlsx};
use mandate_core::key_manager::KeyManager;
use mandate_verify::bundle::PollBundle;
use mandate_verify::export::{export_xlsx, ExportError};
use mandate_verify::i18n::{Language, Locale};
use mandate_verify::pipeline::{VerificationReport, VerifyError};
use mandate_verify::{verify_poll, VerifyInput, VerifyOptions};
use rust_xlsxwriter::Workbook;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Standard 24-word test mnemonic (BIP-39 "abandon" series).
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const TEST_ORG_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const TEST_POLL_ULID: &str = "01JTEST_POLL";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Derive the bs58-encoded Nazgul master public key from a KeyManager.
fn master_pub_bs58(km: &KeyManager) -> String {
    let master = km.derive_nazgul_master_keypair();
    let compressed = master.0.public().compress();
    bs58::encode(compressed.as_bytes()).into_string()
}

/// Generate `count` distinct KeyManagers (and their bs58 master public keys)
/// by varying the passphrase.
fn generate_voters(count: usize) -> Vec<(KeyManager, String)> {
    (0..count)
        .map(|i| {
            let passphrase = format!("{i}");
            let passphrase_opt = if i == 0 {
                None
            } else {
                Some(passphrase.as_str())
            };
            let km =
                KeyManager::from_mnemonic(TEST_MNEMONIC, passphrase_opt).expect("valid mnemonic");
            let pub_key = master_pub_bs58(&km);
            (km, pub_key)
        })
        .collect()
}

/// Write a voter registry XLSX to a temp file.
///
/// The workbook has columns "Name" and "Public_Key" with one row per voter.
fn write_registry_xlsx(voters: &[(String, String)]) -> NamedTempFile {
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "Name").unwrap();
    ws.write_string(0, 1, "Public_Key").unwrap();

    for (row, (name, pubkey)) in voters.iter().enumerate() {
        let r = (row + 1) as u32;
        ws.write_string(r, 0, name).unwrap();
        ws.write_string(r, 1, pubkey).unwrap();
    }

    let mut tmp = NamedTempFile::new().expect("temp file");
    let buf = wb.save_to_buffer().expect("save workbook");
    tmp.write_all(&buf).expect("write xlsx");
    tmp.flush().expect("flush");
    tmp
}

/// Build a synthetic PollBundle and write it to a temp file.
fn write_bundle(ring_member_pubs: Vec<String>, vote_count: usize) -> NamedTempFile {
    write_bundle_with_revocations(ring_member_pubs, vote_count, Vec::new())
}

/// Build a synthetic PollBundle with revocation events and write it to a temp file.
fn write_bundle_with_revocations(
    ring_member_pubs: Vec<String>,
    vote_count: usize,
    revocation_events_raw: Vec<Vec<u8>>,
) -> NamedTempFile {
    let bundle = PollBundle {
        poll_event_raw: vec![0x01, 0x02, 0x03],
        vote_events_raw: (0..vote_count).map(|i| vec![i as u8]).collect(),
        ring_member_pubs,
        org_id: TEST_ORG_ID.into(),
        poll_ulid: TEST_POLL_ULID.into(),
        poll_key_hex: "deadbeef".into(),
        poll_title: String::new(),
        option_definitions: Vec::new(),
        revocation_events_raw,
    };
    let bytes = bundle.to_bytes();
    let mut tmp = NamedTempFile::new().expect("temp file");
    tmp.write_all(&bytes).expect("write bundle");
    tmp.flush().expect("flush");
    tmp
}

/// Run the full verification pipeline and return the report.
fn run_pipeline(
    registry_file: &NamedTempFile,
    bundle_file: &NamedTempFile,
) -> Result<VerificationReport, VerifyError> {
    let input = VerifyInput::FromFiles {
        registry_xlsx: registry_file.path().to_path_buf(),
        bundle_bin: bundle_file.path().to_path_buf(),
    };
    let opts = VerifyOptions { parallelism: None };
    verify_poll(input, opts)
}

/// Export a verification report to XLSX and return the temp file path.
fn export_report(
    report: &VerificationReport,
    locale: &Locale,
) -> Result<std::path::PathBuf, ExportError> {
    let tmp = NamedTempFile::new().expect("temp file");
    let path = tmp.path().with_extension("xlsx");
    export_xlsx(report, locale, &path)?;
    Ok(path)
}

/// Expected English sheet names for the exported XLSX.
const EXPECTED_EN_SHEETS: [&str; 6] = [
    "Verification Summary",
    "Registry Mapping",
    "Tally Results",
    "Vote Audit",
    "Revocation Audit",
    "Charts",
];

// =========================================================================
// Test 1: Happy path — 5 voters, 4 votes cast, 2 options
// =========================================================================

#[test]
fn test_e2e_happy_path_5_voters_4_votes() {
    // --- Setup: 5 distinct voters ---
    let voters = generate_voters(5);
    let pub_keys: Vec<String> = voters.iter().map(|(_, pk)| pk.clone()).collect();
    let registry_rows: Vec<(String, String)> = voters
        .iter()
        .enumerate()
        .map(|(i, (_, pk))| (format!("Voter-{i}"), pk.clone()))
        .collect();

    let registry_file = write_registry_xlsx(&registry_rows);
    let bundle_file = write_bundle(pub_keys.clone(), 4);

    // --- Step 1: Run verification pipeline ---
    let report = run_pipeline(&registry_file, &bundle_file).expect("pipeline should succeed");

    // --- Step 2: Verify report summary ---
    assert_eq!(report.summary.poll_id, TEST_POLL_ULID);
    assert_eq!(report.summary.org_id, TEST_ORG_ID);
    assert_eq!(report.summary.ring_size, 5);
    assert_eq!(report.summary.votes_cast, 4);
    assert!(
        (report.summary.turnout - 0.8).abs() < f64::EPSILON,
        "turnout should be 0.8 (80%), got {}",
        report.summary.turnout
    );
    assert!(report.summary.all_signatures_valid);
    assert!(report.summary.all_key_images_unique);
    assert!(report.summary.registry_matches_ring);

    // --- Step 3: Verify cross-validation ---
    assert!(report.registry_check.is_perfect_match());
    assert_eq!(report.registry_check.matched, 5);
    assert!(report.registry_check.extra_in_ring.is_empty());
    assert!(report.registry_check.missing_from_ring.is_empty());

    // --- Step 4: Verify vote checks ---
    assert_eq!(report.vote_checks.len(), 4);
    assert!(report.vote_checks.iter().all(|vc| vc.valid));
    assert!(report.vote_checks.iter().all(|vc| vc.error.is_none()));

    // --- Step 5: Verify key image check ---
    assert!(report.key_image_check.all_unique());
    assert_eq!(report.key_image_check.total, 4);
    assert_eq!(report.key_image_check.unique, 4);

    // --- Step 6: Verify tally ---
    assert_eq!(report.tally.total_votes, 4);
    // With 4 votes cycling through 2 options (i%2): option-0 gets 2, option-1 gets 2
    assert_eq!(report.tally.options.len(), 2);
    let total_share: f64 = report.tally.options.iter().map(|o| o.share).sum();
    assert!(
        (total_share - 1.0).abs() < 1e-10,
        "shares should sum to 1.0, got {total_share}"
    );

    // --- Step 7: Export to XLSX and verify structure ---
    let locale = Locale::Single(Language::En);
    let xlsx_path = export_report(&report, &locale).expect("export should succeed");

    let mut wb: Xlsx<_> = open_workbook(&xlsx_path).expect("open exported xlsx");
    let sheets = wb.sheet_names().to_vec();

    assert_eq!(sheets.len(), 6, "exported workbook should have 6 sheets");
    for (i, expected) in EXPECTED_EN_SHEETS.iter().enumerate() {
        assert_eq!(sheets[i], *expected, "sheet {i} name mismatch");
    }

    // Vote Audit sheet: header + 4 votes = 5 rows
    let audit_range = wb.worksheet_range("Vote Audit").expect("vote audit sheet");
    assert_eq!(
        audit_range.rows().count(),
        5,
        "vote audit: 1 header + 4 votes"
    );

    // Tally Results sheet: header + 2 options + 1 not-voted + 1 total = 5 rows
    let tally_range = wb
        .worksheet_range("Tally Results")
        .expect("tally results sheet");
    assert_eq!(
        tally_range.rows().count(),
        5,
        "tally: 1 header + 2 options + 1 not-voted + 1 total"
    );

    // Summary sheet: verify poll_id appears in the data
    let summary_range = wb
        .worksheet_range("Verification Summary")
        .expect("summary sheet");
    let all_values: Vec<String> = summary_range
        .rows()
        .flat_map(|r| r.iter().map(|c| c.to_string()))
        .collect();
    assert!(
        all_values.iter().any(|v| v.contains(TEST_POLL_ULID)),
        "summary sheet should contain the poll ULID"
    );

    let _ = std::fs::remove_file(&xlsx_path);
}

// =========================================================================
// Test 2: Edge case — 1 voter, 1 vote
// =========================================================================

#[test]
fn test_e2e_single_voter_single_vote() {
    let voters = generate_voters(1);
    let pub_keys: Vec<String> = voters.iter().map(|(_, pk)| pk.clone()).collect();
    let registry_rows: Vec<(String, String)> =
        vec![("Solo-Voter".to_string(), pub_keys[0].clone())];

    let registry_file = write_registry_xlsx(&registry_rows);
    let bundle_file = write_bundle(pub_keys.clone(), 1);

    // --- Verify pipeline ---
    let report = run_pipeline(&registry_file, &bundle_file).expect("pipeline should succeed");

    assert_eq!(report.summary.ring_size, 1);
    assert_eq!(report.summary.votes_cast, 1);
    assert!(
        (report.summary.turnout - 1.0).abs() < f64::EPSILON,
        "turnout should be 100%, got {}",
        report.summary.turnout
    );
    assert!(report.summary.all_signatures_valid);
    assert!(report.summary.all_key_images_unique);
    assert!(report.summary.registry_matches_ring);
    assert!(report.registry_check.is_perfect_match());
    assert_eq!(report.vote_checks.len(), 1);
    assert!(report.vote_checks[0].valid);
    assert_eq!(report.tally.total_votes, 1);
    assert_eq!(report.tally.options.len(), 1);
    assert!((report.tally.options[0].share - 1.0).abs() < f64::EPSILON);

    // --- Export and verify ---
    let locale = Locale::Single(Language::En);
    let xlsx_path = export_report(&report, &locale).expect("export should succeed");

    let mut wb: Xlsx<_> = open_workbook(&xlsx_path).expect("open exported xlsx");
    let sheets = wb.sheet_names().to_vec();
    assert_eq!(sheets.len(), 6);
    for (i, expected) in EXPECTED_EN_SHEETS.iter().enumerate() {
        assert_eq!(sheets[i], *expected);
    }

    // Tally: header + 1 option + 1 not-voted + 1 total = 4 rows
    let tally_range = wb
        .worksheet_range("Tally Results")
        .expect("tally results sheet");
    assert_eq!(tally_range.rows().count(), 4);

    // Vote Audit: header + 1 vote = 2 rows
    let audit_range = wb.worksheet_range("Vote Audit").expect("vote audit sheet");
    assert_eq!(audit_range.rows().count(), 2);

    let _ = std::fs::remove_file(&xlsx_path);
}

// =========================================================================
// Test 3: Edge case — 10 voters, 0 votes
// =========================================================================

#[test]
fn test_e2e_ten_voters_zero_votes() {
    let voters = generate_voters(10);
    let pub_keys: Vec<String> = voters.iter().map(|(_, pk)| pk.clone()).collect();
    let registry_rows: Vec<(String, String)> = voters
        .iter()
        .enumerate()
        .map(|(i, (_, pk))| (format!("Voter-{i}"), pk.clone()))
        .collect();

    let registry_file = write_registry_xlsx(&registry_rows);
    let bundle_file = write_bundle(pub_keys.clone(), 0);

    // --- Verify pipeline ---
    let report = run_pipeline(&registry_file, &bundle_file).expect("pipeline should succeed");

    assert_eq!(report.summary.ring_size, 10);
    assert_eq!(report.summary.votes_cast, 0);
    assert!(
        (report.summary.turnout - 0.0).abs() < f64::EPSILON,
        "turnout should be 0%, got {}",
        report.summary.turnout
    );
    assert!(report.summary.all_signatures_valid);
    assert!(report.summary.all_key_images_unique);
    assert!(report.summary.registry_matches_ring);
    assert!(report.registry_check.is_perfect_match());
    assert_eq!(report.registry_check.matched, 10);
    assert!(report.vote_checks.is_empty());
    assert_eq!(report.tally.total_votes, 0);
    assert!(report.tally.options.is_empty());

    // --- Export and verify ---
    let locale = Locale::Single(Language::En);
    let xlsx_path = export_report(&report, &locale).expect("export should succeed");

    let mut wb: Xlsx<_> = open_workbook(&xlsx_path).expect("open exported xlsx");
    let sheets = wb.sheet_names().to_vec();
    assert_eq!(sheets.len(), 6);
    for (i, expected) in EXPECTED_EN_SHEETS.iter().enumerate() {
        assert_eq!(sheets[i], *expected);
    }

    // Tally: header + not-voted + total = 3 rows (no options)
    let tally_range = wb
        .worksheet_range("Tally Results")
        .expect("tally results sheet");
    assert_eq!(
        tally_range.rows().count(),
        3,
        "tally should have header + not-voted + total row only"
    );

    // Vote Audit: header only (no votes)
    let audit_range = wb.worksheet_range("Vote Audit").expect("vote audit sheet");
    assert_eq!(
        audit_range.rows().count(),
        1,
        "vote audit: header only for zero votes"
    );

    let _ = std::fs::remove_file(&xlsx_path);
}

// =========================================================================
// Test 4: Bilingual export preserves 5-sheet structure
// =========================================================================

#[test]
fn test_e2e_bilingual_export() {
    let voters = generate_voters(3);
    let pub_keys: Vec<String> = voters.iter().map(|(_, pk)| pk.clone()).collect();
    let registry_rows: Vec<(String, String)> = voters
        .iter()
        .enumerate()
        .map(|(i, (_, pk))| (format!("Voter-{i}"), pk.clone()))
        .collect();

    let registry_file = write_registry_xlsx(&registry_rows);
    let bundle_file = write_bundle(pub_keys.clone(), 2);

    let report = run_pipeline(&registry_file, &bundle_file).expect("pipeline should succeed");

    // Export with bilingual locale (Simplified Chinese + English)
    let locale = Locale::Bilingual(Language::Zhs, Language::En);
    let xlsx_path = export_report(&report, &locale).expect("bilingual export should succeed");

    let wb: Xlsx<_> = open_workbook(&xlsx_path).expect("open exported xlsx");
    let sheets = wb.sheet_names().to_vec();

    assert_eq!(sheets.len(), 6, "bilingual export should have 6 sheets");

    // All sheet names should contain " | " separator for bilingual
    // (uses "|" instead of "/" because Excel sheet names prohibit "/")
    for name in &sheets {
        assert!(
            name.contains(" | "),
            "bilingual sheet name should contain ' | ': got {name}"
        );
    }

    let _ = std::fs::remove_file(&xlsx_path);
}

// =========================================================================
// Test 5: Vote revocation — 5 voters, 4 votes, 1 revocation → tally shows 3
// =========================================================================

#[test]
fn test_e2e_vote_revocation_5_voters_4_votes_1_revocation() {
    // --- Setup: 5 distinct voters ---
    let voters = generate_voters(5);
    let pub_keys: Vec<String> = voters.iter().map(|(_, pk)| pk.clone()).collect();
    let registry_rows: Vec<(String, String)> = voters
        .iter()
        .enumerate()
        .map(|(i, (_, pk))| (format!("Voter-{i}"), pk.clone()))
        .collect();

    let registry_file = write_registry_xlsx(&registry_rows);

    // The pipeline assigns key images as "placeholder-ki-{i}" for vote index i.
    // We revoke the vote at index 1 by targeting its key image.
    let revocation_target = "placeholder-ki-1";
    let revocations = vec![revocation_target.as_bytes().to_vec()];
    let bundle_file = write_bundle_with_revocations(pub_keys.clone(), 4, revocations);

    // --- Step 1: Run verification pipeline ---
    let report = run_pipeline(&registry_file, &bundle_file).expect("pipeline should succeed");

    // --- Step 2: Verify summary ---
    assert_eq!(report.summary.ring_size, 5);
    assert_eq!(report.summary.votes_cast, 4);
    assert_eq!(report.summary.revocations_count, 1);
    assert_eq!(report.summary.valid_revocations, 1);
    assert!(report.summary.all_signatures_valid);
    assert!(report.summary.all_key_images_unique);
    assert!(report.summary.registry_matches_ring);

    // --- Step 3: Verify vote checks — one should be revoked ---
    assert_eq!(report.vote_checks.len(), 4);
    let revoked_count = report.vote_checks.iter().filter(|vc| vc.revoked).count();
    assert_eq!(revoked_count, 1, "exactly one vote should be revoked");

    // The revoked vote should have key_image_bs58 == "placeholder-ki-1"
    let revoked_vote = report
        .vote_checks
        .iter()
        .find(|vc| vc.revoked)
        .expect("should have a revoked vote");
    assert_eq!(revoked_vote.key_image_bs58, "placeholder-ki-1");

    // --- Step 4: Verify revocation checks ---
    assert_eq!(report.revocation_checks.len(), 1);
    assert!(report.revocation_checks[0].valid);
    assert_eq!(
        report.revocation_checks[0].original_vote_key_image_bs58,
        "placeholder-ki-1"
    );
    assert!(report.revocation_checks[0].error.is_none());

    // --- Step 5: Verify tally excludes revoked vote ---
    // 4 votes - 1 revoked = 3 active votes in the tally
    assert_eq!(
        report.tally.total_votes, 3,
        "tally should count only non-revoked votes"
    );

    // --- Step 6: Export and verify XLSX structure ---
    let locale = Locale::Single(Language::En);
    let xlsx_path = export_report(&report, &locale).expect("export should succeed");

    let mut wb: Xlsx<_> = open_workbook(&xlsx_path).expect("open exported xlsx");
    let sheets = wb.sheet_names().to_vec();

    assert_eq!(sheets.len(), 6, "exported workbook should have 6 sheets");
    for (i, expected) in EXPECTED_EN_SHEETS.iter().enumerate() {
        assert_eq!(sheets[i], *expected, "sheet {i} name mismatch");
    }

    // Vote Audit sheet: header + 4 votes = 5 rows, with "Revoked" column
    let audit_range = wb.worksheet_range("Vote Audit").expect("vote audit sheet");
    assert_eq!(
        audit_range.rows().count(),
        5,
        "vote audit: 1 header + 4 votes"
    );
    // Verify the header has 3 columns (Key Image, Vote Choice, Revoked)
    let audit_header: Vec<String> = audit_range
        .rows()
        .next()
        .expect("at least one row")
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(audit_header.len(), 3, "vote audit should have 3 columns");
    assert_eq!(audit_header[2], "Revoked");

    // Revocation Audit sheet: header + 1 revocation = 2 rows
    let revoc_range = wb
        .worksheet_range("Revocation Audit")
        .expect("revocation audit sheet");
    assert_eq!(
        revoc_range.rows().count(),
        2,
        "revocation audit: 1 header + 1 revocation"
    );
    // Verify the header columns
    let revoc_header: Vec<String> = revoc_range
        .rows()
        .next()
        .expect("at least one row")
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(
        revoc_header.len(),
        3,
        "revocation audit should have 3 columns"
    );
    assert_eq!(revoc_header[0], "Key Image (bs58)");
    assert_eq!(revoc_header[1], "Revocation Status");
    assert_eq!(revoc_header[2], "Signature Valid");

    let _ = std::fs::remove_file(&xlsx_path);
}
