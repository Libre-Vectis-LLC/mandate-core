//! Generate public challenge artifacts from a SolutionBundle.
//!
//! Reads a [`SolutionBundle`] and bounty config, then produces:
//! - `voters.xlsx` — voter name + public key registry
//! - `poll-bundle.bin` — PollBundle protobuf with real BLSAG signatures
//! - `results.json` — aggregate vote tally
//! - `encrypted_secret.rage` — age-encrypted bounty secret placeholder
//! - `RULES.md` — challenge rules with KDF params
//! - `manifest.json` — SHA-256 hashes of all artifacts

mod artifacts;
mod events;
pub(crate) mod manifest;

use std::collections::HashMap;
use std::path::Path;

use crate::config::BountyConfig;
use crate::solution_bundle::SolutionBundle;

/// Generate all public challenge artifacts into `output_dir`.
///
/// The caller must ensure `output_dir` exists (or this function creates it).
pub fn generate_artifacts(
    config: &BountyConfig,
    bundle: &SolutionBundle,
    output_dir: &Path,
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

    // 4. Generate encrypted_secret.rage.
    let encrypted_path = output_dir.join("encrypted_secret.rage");
    artifacts::generate_encrypted_secret(config, bundle, &encrypted_path)?;
    eprintln!("  encrypted_secret.rage");

    // 5. Generate RULES.md.
    let rules_path = output_dir.join("RULES.md");
    artifacts::generate_rules_md(config, bundle, &rules_path)?;
    eprintln!("  RULES.md");

    // 6. Generate manifest.json (SHA-256 hashes of all other artifacts).
    let manifest_path = output_dir.join("manifest.json");
    let artifact_names = [
        "voters.xlsx",
        "poll-bundle.bin",
        "results.json",
        "encrypted_secret.rage",
        "RULES.md",
    ];
    manifest::generate_manifest(output_dir, &artifact_names, &manifest_path)?;
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
