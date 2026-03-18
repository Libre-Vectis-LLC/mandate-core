//! mandate-bounty CLI — CTF bounty challenge tool for anonymous poll integrity.
//!
//! Provides commands for generating, verifying, and auditing bounty challenge
//! artifacts that prove anonymous poll integrity.

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
    /// Reads the challenge config and produces the solution CSV containing
    /// voter-to-identity mappings and vote assignments.
    GenerateSolution {
        /// Path to the bounty challenge TOML config.
        #[arg(long)]
        config: PathBuf,
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
        Command::GenerateSolution { config: _ } => {
            anyhow::bail!("generate-solution: not yet implemented")
        }
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
