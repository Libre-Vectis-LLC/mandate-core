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
    },

    /// Verify a submitted solution against the challenge artifacts.
    ///
    /// Checks whether a participant's CSV correctly maps voters to their
    /// anonymous identities and votes.
    VerifySolution {
        /// Path to the submitted solution CSV.
        #[arg(long)]
        csv: PathBuf,

        /// Path to the voter names file.
        #[arg(long)]
        voters: PathBuf,

        /// Path to the encrypted poll bundle.
        #[arg(long)]
        encrypted: PathBuf,

        /// Path to the bounty challenge TOML config.
        #[arg(long)]
        config: PathBuf,
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
        /// Path to the bounty challenge TOML config.
        #[arg(long)]
        config: PathBuf,
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
            config: _,
            output_dir: _,
        } => {
            anyhow::bail!("generate: not yet implemented")
        }
        Command::VerifySolution {
            csv: _,
            voters: _,
            encrypted: _,
            config: _,
        } => {
            anyhow::bail!("verify-solution: not yet implemented")
        }
        Command::AuditArtifacts { dir: _ } => {
            anyhow::bail!("audit-artifacts: not yet implemented")
        }
        Command::DeriveIdentity { config: _ } => {
            anyhow::bail!("derive-identity: not yet implemented")
        }
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
