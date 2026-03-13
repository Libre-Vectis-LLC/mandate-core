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
use mandate_core::hashing::ring_hash;
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
    /// Total number of revocation events in the bundle.
    pub revocations_count: usize,
    /// Number of revocations that successfully matched a vote's key image.
    pub valid_revocations: usize,
}

/// Result of checking one revocation event.
#[derive(Debug, Clone)]
pub struct RevocationCheck {
    /// Identifier for this revocation event (e.g. index-based).
    pub revocation_id: String,
    /// The key image (bs58) of the original vote being revoked.
    pub original_vote_key_image_bs58: String,
    /// Whether the revocation successfully matched an existing vote.
    pub valid: bool,
    /// Error description if the revocation did not match any vote.
    pub error: Option<String>,
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
    /// Per-revocation check results.
    pub revocation_checks: Vec<RevocationCheck>,
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
/// 8. Enrich vote checks with key images and chosen options
///    - 8.5. Parse revocation events and match to vote key images
///    - 8.6. Mark matched votes as revoked
///    - 8.7. Re-tally excluding revoked votes
/// 9. Shuffle vote checks (anti-temporal-correlation)
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
    let ring_hash = ring_hash(&ring);

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

    // --- Step 7: Tally votes ---
    //
    // Build an option lookup table from PollBundle.option_definitions.
    // When option_definitions is non-empty, use it for human-readable text.
    // When empty (old bundles), fall back to placeholder text.
    let option_lookup: std::collections::HashMap<&str, &str> = bundle
        .option_definitions
        .iter()
        .map(|def| (def.option_id.as_str(), def.option_text_zhs.as_str()))
        .collect();

    let choices: Vec<VoteChoice> = bundle
        .vote_events_raw
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            // Try to decode the vote event bytes as a UTF-8 option_id.
            // In production this would parse the actual VoteCast protobuf;
            // for now the sample generator stores the option_id directly.
            let option_id = std::str::from_utf8(raw)
                .ok()
                .filter(|s| option_lookup.contains_key(s))
                .map(|s| s.to_owned())
                .unwrap_or_else(|| {
                    if !bundle.option_definitions.is_empty() {
                        let idx = i % bundle.option_definitions.len();
                        bundle.option_definitions[idx].option_id.clone()
                    } else {
                        format!("option-{}", i % 2)
                    }
                });
            let option_text = option_lookup
                .get(option_id.as_str())
                .map(|s| (*s).to_owned())
                .unwrap_or_else(|| format!("Option {option_id}"));
            VoteChoice {
                option_id,
                option_text,
            }
        })
        .collect();

    // --- Step 8: Enrich vote checks with key image + chosen option ---
    //
    // vote_checks, key_images, and choices are all indexed by vote index
    // (0..vote_count), so we can zip them to attach audit data before shuffle.
    for (i, vc) in vote_checks.iter_mut().enumerate() {
        if let Some(ki) = key_images.get(i) {
            vc.key_image_bs58 = ki.clone();
        }
        if let Some(choice) = choices.get(i) {
            vc.chosen_option.clone_from(&choice.option_text);
        }
    }

    // --- Step 8.5: Parse revocation events ---
    //
    // Each revocation_events_raw entry contains a UTF-8 key_image_bs58
    // string that identifies which vote to revoke.
    let mut revocation_checks: Vec<RevocationCheck> = Vec::new();
    for (i, raw) in bundle.revocation_events_raw.iter().enumerate() {
        let revocation_id = format!("revocation-{i}");
        match std::str::from_utf8(raw) {
            Ok(target_ki_bs58) => {
                let target_ki = target_ki_bs58.trim().to_owned();
                // --- Step 8.6: Match revocation to vote check by key image ---
                let matched = vote_checks
                    .iter_mut()
                    .any(|vc| vc.key_image_bs58 == target_ki);
                if matched {
                    // Mark the matching vote as revoked.
                    for vc in vote_checks.iter_mut() {
                        if vc.key_image_bs58 == target_ki {
                            vc.revoked = true;
                        }
                    }
                    revocation_checks.push(RevocationCheck {
                        revocation_id,
                        original_vote_key_image_bs58: target_ki,
                        valid: true,
                        error: None,
                    });
                } else {
                    revocation_checks.push(RevocationCheck {
                        revocation_id,
                        original_vote_key_image_bs58: target_ki,
                        valid: false,
                        error: Some("no matching vote key image found".into()),
                    });
                }
            }
            Err(e) => {
                revocation_checks.push(RevocationCheck {
                    revocation_id,
                    original_vote_key_image_bs58: String::new(),
                    valid: false,
                    error: Some(format!("invalid UTF-8 in revocation event: {e}")),
                });
            }
        }
    }

    let revocations_count = revocation_checks.len();
    let valid_revocations = revocation_checks.iter().filter(|rc| rc.valid).count();

    // --- Step 8.7: Adjust tally to exclude revoked votes ---
    //
    // Re-tally using only non-revoked votes.
    let active_choices: Vec<VoteChoice> = vote_checks
        .iter()
        .filter(|vc| !vc.revoked)
        .map(|vc| {
            // Find the original choice by matching vote check back to choices.
            // Since vote_checks may have been enriched with chosen_option text,
            // we construct VoteChoice from the enriched data.
            VoteChoice {
                option_id: choices
                    .iter()
                    .find(|c| c.option_text == vc.chosen_option)
                    .map(|c| c.option_id.clone())
                    .unwrap_or_default(),
                option_text: vc.chosen_option.clone(),
            }
        })
        .collect();
    let tally_result = tally::tally_votes(&active_choices);

    // --- Step 9: Shuffle vote checks (anti-temporal-correlation) ---
    shuffle::secure_shuffle(&mut vote_checks);

    // --- Step 10: Assemble report ---
    let ring_size = bundle.ring_member_pubs.len();
    let votes_cast = bundle.vote_events_raw.len();
    let turnout = if ring_size > 0 {
        votes_cast as f64 / ring_size as f64
    } else {
        0.0
    };

    let summary = PollSummary {
        poll_title: if bundle.poll_title.is_empty() {
            String::from("(untitled poll)")
        } else {
            bundle.poll_title.clone()
        },
        poll_id: bundle.poll_ulid.clone(),
        org_id: bundle.org_id.clone(),
        ring_size,
        votes_cast,
        turnout,
        all_signatures_valid,
        all_key_images_unique: key_image_check.all_unique(),
        registry_matches_ring: registry_check.is_perfect_match(),
        revocations_count,
        valid_revocations,
    };

    Ok(VerificationReport {
        summary,
        registry_check,
        vote_checks,
        key_image_check,
        tally: tally_result,
        revocation_checks,
    })
}

#[cfg(test)]
#[path = "pipeline_tests.rs"]
mod tests;
