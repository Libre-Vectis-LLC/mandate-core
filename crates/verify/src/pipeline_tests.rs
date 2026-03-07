use super::*;
use mandate_core::key_manager::KeyManager;
use rust_xlsxwriter::Workbook;
use std::io::Write as _;
use tempfile::NamedTempFile;

/// Standard test mnemonic (24-word).
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const TEST_ORG_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const TEST_POLL_ULID: &str = "01JTEST_POLL";

fn master_pub_bs58(km: &KeyManager) -> String {
    let master = km.derive_nazgul_master_keypair();
    let compressed = master.0.public().compress();
    bs58::encode(compressed.as_bytes()).into_string()
}

/// Helper: write a workbook to a temporary file.
fn write_temp_xlsx(wb: &mut Workbook) -> NamedTempFile {
    let mut tmp = NamedTempFile::new().expect("failed to create temp file");
    let buf = wb.save_to_buffer().expect("failed to save workbook");
    tmp.write_all(&buf).expect("failed to write xlsx");
    tmp.flush().expect("flush failed");
    tmp
}

/// Helper: build a synthetic PollBundle and write it to a temp file.
fn write_temp_bundle(ring_member_pubs: Vec<String>, vote_count: usize) -> NamedTempFile {
    let bundle = PollBundle {
        poll_event_raw: vec![0x01, 0x02, 0x03],
        vote_events_raw: (0..vote_count).map(|i| vec![i as u8]).collect(),
        ring_member_pubs,
        org_id: TEST_ORG_ID.into(),
        poll_ulid: TEST_POLL_ULID.into(),
        poll_key_hex: "deadbeef".into(),
        poll_title: String::new(),
        option_definitions: Vec::new(),
        revocation_events_raw: Vec::new(),
    };

    let bytes = bundle.to_bytes();
    let mut tmp = NamedTempFile::new().expect("failed to create temp file");
    tmp.write_all(&bytes).expect("failed to write bundle");
    tmp.flush().expect("flush failed");
    tmp
}

/// Two distinct key managers producing different master keys.
fn two_key_managers() -> (KeyManager, KeyManager) {
    let km1 = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid mnemonic");
    let km2 = KeyManager::from_mnemonic(TEST_MNEMONIC, Some("other")).expect("valid mnemonic");
    (km1, km2)
}

#[test]
fn test_happy_path_pipeline() {
    let (km1, km2) = two_key_managers();
    let pub1 = master_pub_bs58(&km1);
    let pub2 = master_pub_bs58(&km2);

    // Build synthetic registry XLSX
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "Name").unwrap();
    ws.write_string(0, 1, "Public_Key").unwrap();
    ws.write_string(1, 0, "Alice").unwrap();
    ws.write_string(1, 1, &pub1).unwrap();
    ws.write_string(2, 0, "Bob").unwrap();
    ws.write_string(2, 1, &pub2).unwrap();
    let xlsx_file = write_temp_xlsx(&mut wb);

    // Build synthetic bundle (2 members, 3 votes)
    let bundle_file = write_temp_bundle(vec![pub1.clone(), pub2.clone()], 3);

    let input = VerifyInput::FromFiles {
        registry_xlsx: xlsx_file.path().to_path_buf(),
        bundle_bin: bundle_file.path().to_path_buf(),
    };
    let opts = VerifyOptions {
        parallelism: Some(1),
    };

    let report = verify_poll(input, opts).expect("pipeline should succeed");

    // --- Verify summary ---
    assert_eq!(report.summary.poll_id, TEST_POLL_ULID);
    assert_eq!(report.summary.org_id, TEST_ORG_ID);
    assert_eq!(report.summary.ring_size, 2);
    assert_eq!(report.summary.votes_cast, 3);
    assert!((report.summary.turnout - 1.5).abs() < f64::EPSILON);
    assert!(report.summary.all_signatures_valid);
    assert!(report.summary.all_key_images_unique);
    assert!(report.summary.registry_matches_ring);

    // --- Verify registry check ---
    assert!(report.registry_check.is_perfect_match());
    assert_eq!(report.registry_check.matched, 2);

    // --- Verify vote checks ---
    assert_eq!(report.vote_checks.len(), 3);
    assert!(report.vote_checks.iter().all(|vc| vc.valid));

    // --- Verify key image check ---
    assert!(report.key_image_check.all_unique());
    assert_eq!(report.key_image_check.total, 3);

    // --- Verify tally ---
    assert_eq!(report.tally.total_votes, 3);
    // With 3 votes cycling through 2 options: option-0 gets 2 votes,
    // option-1 gets 1 vote.
    assert_eq!(report.tally.options.len(), 2);
}

#[test]
fn test_empty_votes_pipeline() {
    let (km1, km2) = two_key_managers();
    let pub1 = master_pub_bs58(&km1);
    let pub2 = master_pub_bs58(&km2);

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "Name").unwrap();
    ws.write_string(0, 1, "Public_Key").unwrap();
    ws.write_string(1, 0, "Alice").unwrap();
    ws.write_string(1, 1, &pub1).unwrap();
    ws.write_string(2, 0, "Bob").unwrap();
    ws.write_string(2, 1, &pub2).unwrap();
    let xlsx_file = write_temp_xlsx(&mut wb);

    let bundle_file = write_temp_bundle(vec![pub1.clone(), pub2.clone()], 0);

    let input = VerifyInput::FromFiles {
        registry_xlsx: xlsx_file.path().to_path_buf(),
        bundle_bin: bundle_file.path().to_path_buf(),
    };
    let opts = VerifyOptions {
        parallelism: Some(1),
    };

    let report = verify_poll(input, opts).expect("pipeline should succeed");

    assert_eq!(report.summary.votes_cast, 0);
    assert!((report.summary.turnout - 0.0).abs() < f64::EPSILON);
    assert!(report.vote_checks.is_empty());
    assert_eq!(report.tally.total_votes, 0);
}

#[test]
fn test_single_member_pipeline() {
    let km1 = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid mnemonic");
    let pub1 = master_pub_bs58(&km1);

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "Name").unwrap();
    ws.write_string(0, 1, "Public_Key").unwrap();
    ws.write_string(1, 0, "Alice").unwrap();
    ws.write_string(1, 1, &pub1).unwrap();
    let xlsx_file = write_temp_xlsx(&mut wb);

    let bundle_file = write_temp_bundle(vec![pub1.clone()], 1);

    let input = VerifyInput::FromFiles {
        registry_xlsx: xlsx_file.path().to_path_buf(),
        bundle_bin: bundle_file.path().to_path_buf(),
    };
    let opts = VerifyOptions {
        parallelism: Some(1),
    };

    let report = verify_poll(input, opts).expect("pipeline should succeed");

    assert_eq!(report.summary.ring_size, 1);
    assert_eq!(report.summary.votes_cast, 1);
    assert!((report.summary.turnout - 1.0).abs() < f64::EPSILON);
    assert!(report.summary.registry_matches_ring);
}

#[test]
fn test_mismatched_registry_ring() {
    let (km1, km2) = two_key_managers();
    let pub1 = master_pub_bs58(&km1);
    let pub2 = master_pub_bs58(&km2);

    // Registry has only Alice, but ring has both Alice and Bob
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "Name").unwrap();
    ws.write_string(0, 1, "Public_Key").unwrap();
    ws.write_string(1, 0, "Alice").unwrap();
    ws.write_string(1, 1, &pub1).unwrap();
    let xlsx_file = write_temp_xlsx(&mut wb);

    let bundle_file = write_temp_bundle(vec![pub1.clone(), pub2.clone()], 2);

    let input = VerifyInput::FromFiles {
        registry_xlsx: xlsx_file.path().to_path_buf(),
        bundle_bin: bundle_file.path().to_path_buf(),
    };
    let opts = VerifyOptions {
        parallelism: Some(1),
    };

    let report = verify_poll(input, opts).expect("pipeline should succeed");

    // Registry does NOT match ring
    assert!(!report.summary.registry_matches_ring);
    assert!(!report.registry_check.is_perfect_match());
    assert_eq!(report.registry_check.matched, 1);
    assert_eq!(report.registry_check.extra_in_ring.len(), 1);
}

#[test]
fn test_bundle_io_error() {
    let km1 = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid mnemonic");
    let pub1 = master_pub_bs58(&km1);

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "Name").unwrap();
    ws.write_string(0, 1, "Public_Key").unwrap();
    ws.write_string(1, 0, "Alice").unwrap();
    ws.write_string(1, 1, &pub1).unwrap();
    let xlsx_file = write_temp_xlsx(&mut wb);

    let input = VerifyInput::FromFiles {
        registry_xlsx: xlsx_file.path().to_path_buf(),
        bundle_bin: PathBuf::from("/nonexistent/path/bundle.bin"),
    };
    let opts = VerifyOptions {
        parallelism: Some(1),
    };

    let err = verify_poll(input, opts).unwrap_err();
    assert!(
        matches!(err, VerifyError::BundleIo(_)),
        "expected BundleIo error, got: {err:?}"
    );
}

// -----------------------------------------------------------------------
// Boundary: all members voted (100% turnout)
// -----------------------------------------------------------------------

#[test]
fn test_full_turnout_pipeline() {
    let (km1, km2) = two_key_managers();
    let pub1 = master_pub_bs58(&km1);
    let pub2 = master_pub_bs58(&km2);

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "Name").unwrap();
    ws.write_string(0, 1, "Public_Key").unwrap();
    ws.write_string(1, 0, "Alice").unwrap();
    ws.write_string(1, 1, &pub1).unwrap();
    ws.write_string(2, 0, "Bob").unwrap();
    ws.write_string(2, 1, &pub2).unwrap();
    let xlsx_file = write_temp_xlsx(&mut wb);

    // 2 members, 2 votes = 100% turnout
    let bundle_file = write_temp_bundle(vec![pub1.clone(), pub2.clone()], 2);

    let input = VerifyInput::FromFiles {
        registry_xlsx: xlsx_file.path().to_path_buf(),
        bundle_bin: bundle_file.path().to_path_buf(),
    };
    let opts = VerifyOptions {
        parallelism: Some(1),
    };

    let report = verify_poll(input, opts).expect("pipeline should succeed");
    assert_eq!(report.summary.ring_size, 2);
    assert_eq!(report.summary.votes_cast, 2);
    assert!(
        (report.summary.turnout - 1.0).abs() < f64::EPSILON,
        "expected 100% turnout, got {}",
        report.summary.turnout
    );
}

// -----------------------------------------------------------------------
// Boundary: corrupted bundle bytes (valid file but bad protobuf)
// -----------------------------------------------------------------------

#[test]
fn test_corrupted_bundle_file() {
    let km1 = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid mnemonic");
    let pub1 = master_pub_bs58(&km1);

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "Name").unwrap();
    ws.write_string(0, 1, "Public_Key").unwrap();
    ws.write_string(1, 0, "Alice").unwrap();
    ws.write_string(1, 1, &pub1).unwrap();
    let xlsx_file = write_temp_xlsx(&mut wb);

    // Write garbage bytes as the bundle file
    let mut tmp = NamedTempFile::new().expect("failed to create temp file");
    tmp.write_all(&[0xFF; 100]).expect("write garbage");
    tmp.flush().expect("flush");

    let input = VerifyInput::FromFiles {
        registry_xlsx: xlsx_file.path().to_path_buf(),
        bundle_bin: tmp.path().to_path_buf(),
    };
    let opts = VerifyOptions {
        parallelism: Some(1),
    };

    let err = verify_poll(input, opts).unwrap_err();
    assert!(
        matches!(err, VerifyError::Bundle(_)),
        "expected Bundle error for corrupted bytes, got: {err:?}"
    );
}

// -----------------------------------------------------------------------
// Boundary: empty registry with ring members (pipeline succeeds)
// -----------------------------------------------------------------------

#[test]
fn test_empty_registry_pipeline() {
    let km1 = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid mnemonic");
    let pub1 = master_pub_bs58(&km1);

    // Empty registry (header-only)
    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "Name").unwrap();
    ws.write_string(0, 1, "Public_Key").unwrap();
    let xlsx_file = write_temp_xlsx(&mut wb);

    let bundle_file = write_temp_bundle(vec![pub1.clone()], 1);

    let input = VerifyInput::FromFiles {
        registry_xlsx: xlsx_file.path().to_path_buf(),
        bundle_bin: bundle_file.path().to_path_buf(),
    };
    let opts = VerifyOptions {
        parallelism: Some(1),
    };

    let report = verify_poll(input, opts).expect("pipeline should succeed");

    // Registry doesn't match ring (registry is empty, ring has 1 member)
    assert!(!report.summary.registry_matches_ring);
    assert_eq!(report.registry_check.matched, 0);
    assert_eq!(report.registry_check.extra_in_ring.len(), 1);
}

// -----------------------------------------------------------------------
// Boundary: turnout > 100% (more votes than members)
// -----------------------------------------------------------------------

#[test]
fn test_over_100_percent_turnout() {
    let km1 = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid mnemonic");
    let pub1 = master_pub_bs58(&km1);

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "Name").unwrap();
    ws.write_string(0, 1, "Public_Key").unwrap();
    ws.write_string(1, 0, "Alice").unwrap();
    ws.write_string(1, 1, &pub1).unwrap();
    let xlsx_file = write_temp_xlsx(&mut wb);

    // 1 member but 5 votes
    let bundle_file = write_temp_bundle(vec![pub1.clone()], 5);

    let input = VerifyInput::FromFiles {
        registry_xlsx: xlsx_file.path().to_path_buf(),
        bundle_bin: bundle_file.path().to_path_buf(),
    };
    let opts = VerifyOptions {
        parallelism: Some(1),
    };

    let report = verify_poll(input, opts).expect("pipeline should succeed");
    assert_eq!(report.summary.ring_size, 1);
    assert_eq!(report.summary.votes_cast, 5);
    assert!(
        (report.summary.turnout - 5.0).abs() < f64::EPSILON,
        "turnout should be 5.0 (500%), got {}",
        report.summary.turnout
    );
}
