//! mandate-bounty CLI — CTF bounty challenge tool for anonymous poll integrity.
//!
//! Provides commands for generating, verifying, and auditing bounty challenge
//! artifacts that prove anonymous poll integrity.

use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// mandate-bounty: CTF bounty challenge tool for Mandate anonymous voting
/// protocol.
#[derive(Parser)]
#[command(name = "mandate-bounty", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate the canonical solution (operator-only).
    ///
    /// Reads the challenge config and produces the solution JSON containing
    /// voter-to-identity mappings and vote assignments. Output goes to stdout
    /// for piping to encryption.
    GenerateSolution {
        /// Path to the bounty challenge TOML config.
        #[arg(long)]
        config: PathBuf,

        /// Deterministic seed for testing (uses StdRng instead of OsRng).
        #[arg(long)]
        seed: Option<u64>,

        /// Allow writing secret material to a terminal (unsafe, for debugging).
        #[arg(long)]
        force_tty: bool,
    },

    /// Generate the public challenge artifacts.
    ///
    /// Produces the encrypted poll bundle and voter list that participants
    /// use to attempt de-anonymization.
    Generate {
        /// Path to the bounty challenge TOML config.
        #[arg(long)]
        config: PathBuf,

        /// Directory to write generated artifacts into.
        #[arg(long)]
        output_dir: PathBuf,

        /// File containing the bounty secret plaintext to encrypt.
        ///
        /// Use process substitution to pipe from age decryption:
        ///   --secret-file <(age -d bounty-secret.age)
        ///
        /// If omitted, a default reverse-prompt placeholder is used.
        #[arg(long)]
        secret_file: Option<PathBuf>,
    },

    /// Verify a submitted solution against the challenge artifacts.
    ///
    /// Checks whether a participant's CSV correctly maps voters to their
    /// anonymous identities and votes.
    VerifySolution {
        /// Path to the submitted solution CSV.
        #[arg(long)]
        csv: PathBuf,

        /// Path to the public voter registry workbook.
        #[arg(long)]
        voters: PathBuf,

        /// Path to the age-encrypted bounty secret.
        #[arg(long)]
        encrypted: PathBuf,

        /// Path to manifest.json from the public challenge artifacts.
        #[arg(long)]
        manifest: PathBuf,
    },

    /// Audit the generated artifacts for correctness.
    ///
    /// Performs integrity checks on all files in the artifacts directory.
    AuditArtifacts {
        /// Directory containing the challenge artifacts.
        #[arg(long)]
        dir: PathBuf,
    },

    /// Derive the age identity from a solution CSV (via stdin).
    ///
    /// Runs only the KDF chain (CSV → SHA3-512 → Argon2id → age Identity)
    /// and outputs the derived `age1...` public key to stdout.
    DeriveIdentity {
        /// Path to the public voter registry workbook.
        #[arg(long)]
        voters: PathBuf,

        /// Path to manifest.json from the public challenge artifacts.
        #[arg(long)]
        manifest: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::GenerateSolution {
            config,
            seed,
            force_tty,
        } => cmd_generate_solution(&config, seed, force_tty),
        Command::Generate {
            config,
            output_dir,
            secret_file,
        } => cmd_generate(&config, &output_dir, secret_file.as_deref()),
        Command::VerifySolution {
            csv,
            voters,
            encrypted,
            manifest,
        } => cmd_verify_solution(&csv, &voters, &encrypted, &manifest),
        Command::AuditArtifacts { dir } => cmd_audit_artifacts(&dir),
        Command::DeriveIdentity { voters, manifest } => cmd_derive_identity(&voters, &manifest),
    }
}

// ---------------------------------------------------------------------------
// generate-solution
// ---------------------------------------------------------------------------

fn cmd_generate_solution(
    config_path: &std::path::Path,
    seed: Option<u64>,
    force_tty: bool,
) -> Result<()> {
    use mandate_bounty::config::{load_names, BountyConfig};
    use mandate_bounty::generate_solution::generate_solution;

    // TTY protection: refuse to dump secrets to a terminal.
    if std::io::stdout().is_terminal() && !force_tty {
        anyhow::bail!(
            "refusing to write secret material to terminal; \
             pipe to a file or encrypt (use --force-tty to override)"
        );
    }

    // Load and validate config.
    let config = BountyConfig::load(config_path)?;

    // Resolve names file relative to config directory.
    let config_dir = config_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path has no parent directory"))?;
    let names = load_names(&config.voters.names_file, config_dir)?;
    config
        .validate_names(&names)
        .map_err(|e| anyhow::anyhow!("name validation failed: {e}"))?;

    // Generate the solution bundle.
    let bundle = if let Some(s) = seed {
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(s);
        generate_solution(&config, &names, &mut rng)?
    } else {
        let mut rng = rand::rngs::OsRng;
        generate_solution(&config, &names, &mut rng)?
    };

    // Serialize to JSON on stdout.
    serde_json::to_writer(std::io::stdout().lock(), &bundle)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

fn cmd_generate(
    config_path: &std::path::Path,
    output_dir: &std::path::Path,
    secret_file: Option<&std::path::Path>,
) -> Result<()> {
    use std::io::Read as _;

    use mandate_bounty::config::BountyConfig;
    use mandate_bounty::generate::generate_artifacts;
    use mandate_bounty::solution_bundle::SolutionBundle;

    // Load and validate config.
    let config = BountyConfig::load(config_path)?;

    // Read custom secret plaintext if provided.
    let secret_plaintext = if let Some(path) = secret_file {
        eprintln!("Reading bounty secret from {}...", path.display());
        let content = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read secret file {}: {e}", path.display()))?;
        anyhow::ensure!(!content.is_empty(), "secret file is empty");
        Some(content)
    } else {
        None
    };

    // Read SolutionBundle JSON from stdin.
    eprintln!("Reading solution bundle from stdin...");
    let mut stdin_buf = String::new();
    std::io::stdin().lock().read_to_string(&mut stdin_buf)?;
    let bundle: SolutionBundle = serde_json::from_str(&stdin_buf)
        .map_err(|e| anyhow::anyhow!("failed to parse solution bundle from stdin: {e}"))?;

    anyhow::ensure!(
        bundle.version == 1,
        "unsupported solution bundle version: {}",
        bundle.version
    );
    anyhow::ensure!(
        bundle.solution.len() == config.voters.total as usize,
        "solution entry count ({}) does not match config voters.total ({})",
        bundle.solution.len(),
        config.voters.total
    );

    eprintln!("Generating artifacts...");
    generate_artifacts(&config, &bundle, output_dir, secret_plaintext.as_deref())?;

    Ok(())
}

// ---------------------------------------------------------------------------
// verify-solution
// ---------------------------------------------------------------------------

fn cmd_verify_solution(
    csv_path: &std::path::Path,
    voters_path: &std::path::Path,
    encrypted_path: &std::path::Path,
    manifest_path: &std::path::Path,
) -> Result<()> {
    use mandate_bounty::manifest::load_manifest;
    use mandate_bounty::verify::verify_solution;

    let manifest = load_manifest(manifest_path)?;

    eprintln!("Verifying solution...");
    eprintln!("  CSV:       {}", csv_path.display());
    eprintln!("  Voters:    {}", voters_path.display());
    eprintln!("  Encrypted: {}", encrypted_path.display());
    eprintln!("  Manifest:  {}", manifest_path.display());
    eprintln!("  KDF salt:  {}", manifest.kdf.salt);

    match verify_solution(csv_path, voters_path, encrypted_path, &manifest) {
        Ok(outcome) => {
            eprintln!("Verification PASSED — decryption succeeded.");
            if outcome.was_reordered {
                eprintln!("  Input CSV was reordered into canonical pubkey order via voters.xlsx.");
            }
            eprintln!("  Derived key matches manifest: {}", outcome.derived_pubkey);
            // Write decrypted content to stdout.
            let text = String::from_utf8_lossy(&outcome.plaintext);
            println!("{text}");
            Ok(())
        }
        Err(e) => {
            eprintln!("Verification FAILED.");
            Err(e)
        }
    }
}

// ---------------------------------------------------------------------------
// audit-artifacts
// ---------------------------------------------------------------------------

fn cmd_audit_artifacts(dir: &std::path::Path) -> Result<()> {
    use mandate_bounty::audit::audit_artifacts;

    eprintln!("Auditing artifacts in {}...", dir.display());

    let results = audit_artifacts(dir)?;

    let mut all_passed = true;
    for check in &results {
        let status = if check.passed { "PASS" } else { "FAIL" };
        eprintln!("  [{status}] {}", check.name);
        if !check.passed {
            eprintln!("    expected: {}", check.expected);
            eprintln!("    actual:   {}", check.actual);
            all_passed = false;
        }
    }

    if all_passed {
        eprintln!("All {} artifacts passed integrity check.", results.len());
        Ok(())
    } else {
        let failed: Vec<&str> = results
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name.as_str())
            .collect();
        anyhow::bail!("artifact integrity check failed for: {}", failed.join(", "))
    }
}

// ---------------------------------------------------------------------------
// derive-identity
// ---------------------------------------------------------------------------

fn cmd_derive_identity(
    voters_path: &std::path::Path,
    manifest_path: &std::path::Path,
) -> Result<()> {
    use std::io::Read as _;

    use mandate_bounty::derive_identity::derive_identity;
    use mandate_bounty::manifest::load_manifest;
    use mandate_bounty::verify::canonicalize_solution_csv_bytes;

    let manifest = load_manifest(manifest_path)?;

    // Read CSV from stdin.
    eprintln!("Reading CSV from stdin...");
    let mut csv_buf = Vec::new();
    std::io::stdin().lock().read_to_end(&mut csv_buf)?;

    anyhow::ensure!(!csv_buf.is_empty(), "stdin is empty — provide CSV content");

    let canonicalized = canonicalize_solution_csv_bytes(&csv_buf, voters_path)?;
    if canonicalized.was_reordered {
        eprintln!("Reordered input into canonical pubkey order via voters.xlsx.");
    }

    eprintln!("Running KDF chain (this may take a while)...");
    let identity = derive_identity(&canonicalized.bytes, &manifest.kdf.to_config()?)?;
    let pubkey = identity.to_public().to_string();

    if pubkey == manifest.expected_age_pubkey {
        eprintln!("Derived public key matches manifest expected_age_pubkey.");
    } else {
        eprintln!(
            "Derived public key does not match manifest expected_age_pubkey (expected {}).",
            manifest.expected_age_pubkey
        );
    }

    println!("{pubkey}");

    Ok(())
}
