//! Generate public challenge artifacts from a SolutionBundle.
//!
//! Reads a [`SolutionBundle`] and bounty config, then produces:
//! - `voters.xlsx` — voter name + public key registry
//! - `poll-bundle.bin` — PollBundle protobuf with real BLSAG signatures
//! - `results.json` — aggregate vote tally
//! - `encrypted_secret.rage` — age-encrypted bounty secret placeholder
//! - `manifest.json` — hashes plus KDF / expected-age-key metadata

mod artifacts;
mod events;

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use crate::config::BountyConfig;
use crate::manifest;
use crate::solution_bundle::SolutionBundle;

/// Generate all public challenge artifacts into `output_dir`.
///
/// If `secret_plaintext` is `Some`, that content is encrypted as the bounty
/// secret. Otherwise a default reverse-prompt placeholder is used.
///
/// The caller must ensure `output_dir` exists (or this function creates it).
pub fn generate_artifacts(
    config: &BountyConfig,
    bundle: &SolutionBundle,
    output_dir: &Path,
    secret_plaintext: Option<&[u8]>,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(output_dir)?;

    // 1. Build voter registry (name → pubkey, sorted by pubkey).
    let voters_path = output_dir.join("voters.xlsx");
    artifacts::generate_voters_xlsx(bundle, &voters_path)?;
    eprintln!("  voters.xlsx");

    // 2. Build PollBundle with real BLSAG signatures.
    let bundle_path = output_dir.join("poll-bundle.bin");
    events::generate_poll_bundle(config, bundle, &bundle_path)?;
    eprintln!("  poll-bundle.bin");

    // 3. Generate results.json (aggregate vote tally).
    let results_path = output_dir.join("results.json");
    artifacts::generate_results_json(config, bundle, &results_path)?;
    eprintln!("  results.json");

    // 4. Derive the expected age recipient once and reuse it for encryption
    // and manifest metadata.
    let solution_identity = artifacts::derive_solution_identity(config, bundle)?;
    let expected_age_pubkey = solution_identity.to_public().to_string();

    // 5. Generate encrypted_secret.rage.
    let encrypted_path = output_dir.join("encrypted_secret.rage");
    artifacts::generate_encrypted_secret(
        &solution_identity.to_public(),
        &encrypted_path,
        secret_plaintext,
    )?;
    eprintln!("  encrypted_secret.rage");

    // 6. Generate manifest.json (hashes + KDF metadata + expected age key).
    let manifest_path = output_dir.join("manifest.json");
    let artifact_names = [
        "voters.xlsx",
        "poll-bundle.bin",
        "results.json",
        "encrypted_secret.rage",
    ];
    let git_commit = resolve_git_commit().unwrap_or_else(|err| {
        eprintln!("  warning: failed to resolve git commit: {err}");
        "UNKNOWN".to_owned()
    });
    let manifest_doc = manifest::build_manifest(
        output_dir,
        &artifact_names,
        expected_age_pubkey,
        git_commit,
        &config.kdf,
    )?;
    manifest::write_manifest(&manifest_doc, &manifest_path)?;
    eprintln!("  manifest.json");

    // Summary
    let total_votes: u32 = config.poll.options.iter().map(|o| o.count).sum();
    let mut tally: HashMap<&str, u32> = HashMap::new();
    for opt in &config.poll.options {
        tally.insert(&opt.id, opt.count);
    }
    eprintln!();
    eprintln!("Artifacts generated in {}", output_dir.display());
    eprintln!("  Total voters: {}", config.voters.total);
    eprintln!("  Total votes:  {total_votes}");
    for opt in &config.poll.options {
        eprintln!("    {}: {}", opt.id, opt.count);
    }

    Ok(())
}

fn resolve_git_commit() -> anyhow::Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| anyhow::anyhow!("git rev-parse failed: {e}"))?;

    anyhow::ensure!(
        output.status.success(),
        "git rev-parse exited with {}",
        output.status
    );

    let commit = String::from_utf8(output.stdout)
        .map_err(|e| anyhow::anyhow!("git rev-parse output was not UTF-8: {e}"))?;
    let commit = commit.trim().to_owned();
    anyhow::ensure!(
        !commit.is_empty(),
        "git rev-parse returned an empty commit hash"
    );
    Ok(commit)
}
