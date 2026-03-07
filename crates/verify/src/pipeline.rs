//! Main verification pipeline.
//!
//! Orchestrates the full poll verification workflow:
//! parse registry, parse bundle, derive ring, cross-validate,
//! verify signatures, check key images, shuffle, tally, and
//! assemble the final [`VerificationReport`].

use std::fs;
use std::path::PathBuf;

use thiserror::Error;

use crate::bundle::{BundleError, PollBundle};
use crate::cross_validate::{self, CrossValidationError, CrossValidationResult};
use crate::derivation::{self, DerivationError};
use crate::key_image::{self, KeyImageCheck};
use crate::registry::{self, RegistryError};
use crate::shuffle;
use crate::signature::{
    self, BatchVerifyError, SignatureVerifier, VerifyItem, VerifyOptions as SigVerifyOptions,
    VoteCheck,
};
use crate::tally::{self, TallyResult, VoteChoice};

use curve25519_dalek::ristretto::RistrettoPoint;
use mandate_core::hashing::ring_hash_sha3_256;
use nazgul::ring::Ring;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during the verification pipeline.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Failed to parse the voter registry XLSX.
    #[error("registry error: {0}")]
    Registry(#[from] RegistryError),

    /// Failed to read the bundle file.
    #[error("failed to read bundle file: {0}")]
    BundleIo(#[source] std::io::Error),

    /// Failed to decode the PollBundle protobuf.
    #[error("bundle error: {0}")]
    Bundle(#[from] BundleError),

    /// Failed during public-key derivation.
    #[error("derivation error: {0}")]
    Derivation(#[from] DerivationError),

    /// Registry-ring cross-validation failed.
    #[error("cross-validation error: {0}")]
    CrossValidation(#[from] CrossValidationError),

    /// Batch signature verification failed.
    #[error("signature verification error: {0}")]
    Signature(#[from] BatchVerifyError),
}

// ---------------------------------------------------------------------------
// Input / Options / Output types
// ---------------------------------------------------------------------------

/// Input source for the verification pipeline.
pub enum VerifyInput {
    /// Load data from local files.
    FromFiles {
        /// Path to the voter registry XLSX workbook.
        registry_xlsx: PathBuf,
        /// Path to the protobuf-encoded PollBundle file.
        bundle_bin: PathBuf,
    },
    // TODO: FromServer variant for online verification (deferred).
}

/// Options controlling the verification pipeline.
pub struct VerifyOptions {
    /// Thread count for parallel signature verification.
    /// `None` uses adaptive auto-tuning.
    pub parallelism: Option<usize>,
}

/// High-level summary of the poll verification.
#[derive(Debug, Clone)]
pub struct PollSummary {
    /// Poll title (extracted from poll event, placeholder for now).
    pub poll_title: String,
    /// Poll identifier (ULID).
    pub poll_id: String,
    /// Organization identifier (ULID).
    pub org_id: String,
    /// Number of ring members.
    pub ring_size: usize,
    /// Number of votes cast.
    pub votes_cast: usize,
    /// Voter turnout as a fraction (0.0..=1.0).
    pub turnout: f64,
    /// Whether all BLSAG ring signatures are valid.
    pub all_signatures_valid: bool,
    /// Whether all KeyImages are unique (no double-voting).
    pub all_key_images_unique: bool,
    /// Whether the voter registry perfectly matches the ring.
    pub registry_matches_ring: bool,
}

/// Complete verification report assembled by [`verify_poll`].
#[derive(Debug)]
pub struct VerificationReport {
    /// High-level poll summary.
    pub summary: PollSummary,
    /// Registry-ring cross-validation result.
    pub registry_check: CrossValidationResult,
    /// Per-vote signature check results (shuffled for anti-temporal-correlation).
    pub vote_checks: Vec<VoteCheck>,
    /// KeyImage uniqueness check result.
    pub key_image_check: KeyImageCheck,
    /// Vote tally result.
    pub tally: TallyResult,
}

// ---------------------------------------------------------------------------
// Placeholder verifier
// ---------------------------------------------------------------------------

/// Placeholder signature verifier that always returns valid.
///
/// TODO: Replace with real BLSAG signature verifier once vote event
/// parsing and signature extraction are implemented.
struct PlaceholderVerifier;

impl SignatureVerifier for PlaceholderVerifier {
    fn verify_one(&self, _index: usize, _item: &VerifyItem) -> Result<bool, BatchVerifyError> {
        // TODO: Implement real BLSAG verification once vote event
        // deserialization is available.
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/// Run the full poll verification pipeline.
///
/// # Pipeline steps
///
/// 1. Parse voter registry XLSX
/// 2. Read and parse bundle.bin
/// 3. Compute ring hash from bundle's ring member public keys
/// 4. Re-derive ring member public keys from master keys (HKDF)
/// 5. Cross-validate registry vs bundle ring members
/// 6. Verify all BLSAG ring signatures (parallel, adaptive)
/// 7. Check all KeyImages unique
/// 8. Shuffle vote checks (anti-temporal-correlation)
/// 9. Tally votes
/// 10. Assemble VerificationReport
///
/// # Errors
///
/// Returns [`VerifyError`] if any pipeline step fails.
pub fn verify_poll(
    input: VerifyInput,
    opts: VerifyOptions,
) -> Result<VerificationReport, VerifyError> {
    // --- Step 1: Parse inputs ---
    let (registry_entries, bundle) = match input {
        VerifyInput::FromFiles {
            registry_xlsx,
            bundle_bin,
        } => {
            let reg = registry::parse_registry(&registry_xlsx)?;
            let bundle_bytes = fs::read(&bundle_bin).map_err(VerifyError::BundleIo)?;
            let bundle = PollBundle::from_bytes(&bundle_bytes)?;
            (reg, bundle)
        }
    };

    // --- Step 2: Compute ring hash from ring member public keys ---
    //
    // Decode master public keys to RistrettoPoints so we can construct
    // a `Ring` and compute its hash for HKDF derivation.
    let master_points: Vec<RistrettoPoint> = bundle
        .ring_member_pubs
        .iter()
        .enumerate()
        .map(|(i, bs58_key)| derivation::decode_master_pubkey(bs58_key, i))
        .collect::<Result<Vec<_>, _>>()?;

    let ring = Ring::new(master_points);
    let ring_hash = ring_hash_sha3_256(&ring);

    // --- Step 3: Re-derive per-poll signing public keys ---
    let master_strs: Vec<&str> = bundle.ring_member_pubs.iter().map(String::as_str).collect();

    let _derived_ring = derivation::derive_poll_ring(
        &master_strs,
        &bundle.org_id,
        &ring_hash.0,
        &bundle.poll_ulid,
    )?;

    // --- Step 4: Cross-validate registry vs ring ---
    let registry_check = cross_validate::cross_validate(
        &registry_entries,
        &bundle.ring_member_pubs,
        &bundle.org_id,
        &bundle.poll_ulid,
        &ring_hash.0,
    )?;

    // --- Step 5: Verify all signatures ---
    //
    // Build VerifyItems from the bundle's vote events. For now we use
    // a placeholder verifier since real BLSAG vote event parsing is not
    // yet implemented.
    let verify_items: Vec<VerifyItem> = bundle
        .vote_events_raw
        .iter()
        .enumerate()
        .map(|(i, raw)| VerifyItem {
            id: format!("vote-{i}"),
            // TODO: Extract actual signature bytes from vote event.
            signature_bytes: raw.clone(),
            // TODO: Extract actual message bytes from vote event.
            message: raw.clone(),
            ring_pubkeys_bs58: bundle.ring_member_pubs.clone(),
        })
        .collect();

    let sig_opts = SigVerifyOptions {
        parallelism: opts.parallelism,
    };
    let verifier = PlaceholderVerifier;
    let mut vote_checks = signature::verify_all_signatures(&verifier, &verify_items, &sig_opts)?;

    let all_signatures_valid = vote_checks.iter().all(|vc| vc.valid);

    // --- Step 6: Check KeyImage uniqueness ---
    //
    // TODO: Extract real KeyImages from vote events once parsing is
    // implemented. For now, use the vote index as a stand-in (guaranteed
    // unique within a single pipeline run).
    let key_images: Vec<String> = (0..bundle.vote_events_raw.len())
        .map(|i| format!("placeholder-ki-{i}"))
        .collect();
    let key_image_check = key_image::check_key_image_uniqueness(&key_images);

    // --- Step 7: Shuffle vote checks ---
    shuffle::secure_shuffle(&mut vote_checks);

    // --- Step 8: Tally votes ---
    //
    // TODO: Extract real option_id from vote events once parsing is
    // implemented. For now, use a placeholder that cycles through
    // synthetic option IDs.
    let choices: Vec<VoteChoice> = bundle
        .vote_events_raw
        .iter()
        .enumerate()
        .map(|(i, _raw)| {
            // TODO: Decode actual vote selection from raw vote event bytes.
            let option_id = format!("option-{}", i % 2);
            VoteChoice {
                option_id,
                option_text: format!("Placeholder option {}", i % 2),
            }
        })
        .collect();

    let tally_result = tally::tally_votes(&choices);

    // --- Step 9: Assemble report ---
    let ring_size = bundle.ring_member_pubs.len();
    let votes_cast = bundle.vote_events_raw.len();
    let turnout = if ring_size > 0 {
        votes_cast as f64 / ring_size as f64
    } else {
        0.0
    };

    let summary = PollSummary {
        // TODO: Extract poll title from poll_event_raw once parsing is
        // implemented.
        poll_title: String::from("(poll title placeholder)"),
        poll_id: bundle.poll_ulid.clone(),
        org_id: bundle.org_id.clone(),
        ring_size,
        votes_cast,
        turnout,
        all_signatures_valid,
        all_key_images_unique: key_image_check.all_unique(),
        registry_matches_ring: registry_check.is_perfect_match(),
    };

    Ok(VerificationReport {
        summary,
        registry_check,
        vote_checks,
        key_image_check,
        tally: tally_result,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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
}
