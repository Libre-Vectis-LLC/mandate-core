//! mandate-verify CLI — independent poll verification tool.
//!
//! Thin CLI shell over the `mandate-verify` library. Supports two modes:
//! - **Offline**: `--registry` + `--bundle` (local files)
//! - **Online**: `--server` + `--poll-id` + `--poll-key` (gRPC fetch — stub)

use std::path::PathBuf;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use mandate_verify::export::{export_xlsx, ExportError};
use mandate_verify::i18n::Locale;
use mandate_verify::{verify_poll, VerifyInput, VerifyOptions};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// mandate-verify: independent poll verification tool for Mandate anonymous
/// voting protocol.
#[derive(Parser)]
#[command(name = "mandate-verify", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a quick hardware benchmark to determine optimal verification
    /// concurrency and save the result as a HardwareProfile.
    ///
    /// The profile is saved to `$XDG_DATA_HOME/mandate/benchmark-results.json`
    /// (or `~/.local/share/mandate/benchmark-results.json`). Subsequent
    /// `mandate-verify poll` runs will use this profile to skip runtime
    /// calibration.
    Tune,

    /// Prepare a vote revocation request for a poll.
    ///
    /// This constructs and displays a revocation intent. The actual submission
    /// to the server (via gRPC through Edge) is not yet implemented.
    Revoke {
        /// Poll ID (ULID) of the poll whose vote to revoke.
        #[arg(long)]
        poll_id: String,

        /// bs58-encoded key image identifying the vote to revoke.
        #[arg(long)]
        key_image: String,

        /// Optional reason for the revocation (plaintext, will be encrypted
        /// by the client before submission).
        #[arg(long)]
        reason: Option<String>,
    },

    /// Verify a poll and export a verification report.
    Poll {
        // ----- Offline mode inputs -----
        /// Path to voter registry XLSX workbook.
        #[arg(long)]
        registry: PathBuf,

        /// Path to PollBundle binary file (offline mode).
        #[arg(long, group = "source")]
        bundle: Option<PathBuf>,

        // ----- Online mode inputs (stub) -----
        /// gRPC server URL (online mode, e.g. grpc://edge:8080).
        #[arg(long, group = "source")]
        server: Option<String>,

        /// Poll ID (ULID) to fetch from server (requires --server).
        #[arg(long, requires = "server")]
        poll_id: Option<String>,

        /// Hex-encoded poll key for decryption (requires --server).
        #[arg(long, requires = "server")]
        poll_key: Option<String>,

        // ----- Common options -----
        /// Output path for the verification report XLSX.
        #[arg(long, default_value = "report.xlsx")]
        output: PathBuf,

        /// Report locale: single language (e.g. "en", "zhs") or
        /// bilingual (e.g. "zhs+en", "zht+en").
        #[arg(long, default_value = "zhs+en")]
        locale: String,

        /// Number of threads for parallel signature verification.
        /// Defaults to adaptive auto-tuning.
        #[arg(long)]
        parallelism: Option<usize>,
    },
}

// ---------------------------------------------------------------------------
// Progress helpers
// ---------------------------------------------------------------------------

/// Create a styled spinner with the given message.
fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg} [{elapsed_precise}]")
            .expect("valid template")
            .tick_chars("/|\\- "),
    );
    pb.set_message(msg.to_owned());
    pb.enable_steady_tick(std::time::Duration::from_millis(120));
    pb
}

/// Finish a spinner with a success message.
fn finish_spinner(pb: &ProgressBar, msg: &str) {
    pb.finish_with_message(msg.to_owned());
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Tune => run_tune(),
        Command::Revoke {
            poll_id,
            key_image,
            reason,
        } => run_revoke(&poll_id, &key_image, reason.as_deref()),
        Command::Poll {
            registry,
            bundle,
            server,
            poll_id,
            poll_key,
            output,
            locale,
            parallelism,
        } => run_poll(PollArgs {
            registry,
            bundle,
            server,
            poll_id,
            poll_key,
            output,
            locale,
            parallelism,
        }),
    }
}

/// Run the hardware tuning benchmark.
///
/// Generates synthetic verification workloads, tests concurrency levels,
/// and saves the optimal configuration as a `HardwareProfile`.
fn run_tune() -> Result<()> {
    println!();
    println!("  Hardware Tuning Benchmark");
    println!("  ========================");
    println!();

    let sp = spinner("Running benchmark...");

    let profile = mandate_verify::quick_tune(Some(&|msg| {
        sp.set_message(msg.to_owned());
    }))
    .context("tuning benchmark failed")?;

    finish_spinner(&sp, "Benchmark complete.");

    println!();
    println!("  Hardware:           {}", profile.hardware_fingerprint);
    println!("  Optimal concurrency: {}", profile.optimal_concurrency);
    if let Some(path) = mandate_verify::HardwareProfile::default_path() {
        println!("  Profile saved to:   {}", path.display());
    }
    println!();
    println!(
        "  Future `mandate-verify poll` runs will use this profile \
         to skip runtime calibration."
    );

    Ok(())
}

/// Stub implementation for vote revocation.
///
/// Validates arguments and prints an informational message.
/// Actual gRPC submission will be added when online mode is built.
fn run_revoke(poll_id: &str, key_image: &str, reason: Option<&str>) -> Result<()> {
    // Basic validation: poll_id should look like a ULID (26 chars, alphanumeric).
    if poll_id.len() != 26 || !poll_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("invalid poll ID: expected a 26-character ULID, got {poll_id:?}");
    }

    // Basic validation: key_image should be non-empty and look like bs58
    // (alphanumeric, no 0/O/I/l which bs58 excludes).
    if key_image.is_empty() {
        bail!("invalid key image: must be non-empty bs58 string");
    }
    if key_image
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() || matches!(c, '0' | 'O' | 'I' | 'l'))
    {
        bail!(
            "invalid key image: contains characters outside the bs58 alphabet \
             (must be alphanumeric excluding 0, O, I, l)"
        );
    }

    println!();
    println!(
        "  Vote revocation request prepared for poll {}, key image {}",
        poll_id, key_image
    );
    if let Some(r) = reason {
        println!("  Reason: {r}");
    }
    println!();
    println!("  Submit via Edge/Server endpoint (online mode not yet implemented)");

    Ok(())
}

struct PollArgs {
    registry: PathBuf,
    bundle: Option<PathBuf>,
    server: Option<String>,
    poll_id: Option<String>,
    poll_key: Option<String>,
    output: PathBuf,
    locale: String,
    parallelism: Option<usize>,
}

fn run_poll(args: PollArgs) -> Result<()> {
    // ---- Determine mode ----
    let input = if let Some(bundle_path) = args.bundle {
        // Offline mode
        VerifyInput::FromFiles {
            registry_xlsx: args.registry,
            bundle_bin: bundle_path,
        }
    } else if let Some(_server) = args.server {
        // Online mode (stub)
        let _poll_id = args
            .poll_id
            .context("--poll-id is required with --server")?;
        let _poll_key = args
            .poll_key
            .context("--poll-key is required with --server")?;
        bail!(
            "Online mode is not yet implemented.\n\
             Use offline mode with --bundle instead:\n  \
             mandate-verify poll --registry voters.xlsx --bundle poll-bundle.bin"
        );
    } else {
        bail!(
            "Either --bundle (offline) or --server (online) must be provided.\n\
             Example:\n  \
             mandate-verify poll --registry voters.xlsx --bundle poll-bundle.bin --output report.xlsx"
        );
    };

    // ---- Parse locale ----
    let locale =
        Locale::parse(&args.locale).map_err(|e| anyhow::anyhow!("invalid --locale value: {e}"))?;

    let opts = VerifyOptions {
        parallelism: args.parallelism,
    };

    // ---- Run pipeline with progress indicators ----
    let wall_start = Instant::now();

    let sp = spinner("Verifying poll (registry + bundle + signatures)...");
    let report = verify_poll(input, opts).context("verification pipeline failed")?;
    finish_spinner(&sp, "Verification complete.");

    // Hard-error on any integrity failure — refuse to produce a report
    // for inconsistent or invalid data (anti-tampering measure).
    if !report.summary.registry_matches_ring {
        let rc = &report.registry_check;
        bail!(
            "registry/ring mismatch: {} matched, {} missing from ring, {} extra in ring. \
             The bundle may be corrupted or tampered with.",
            rc.matched,
            rc.missing_from_ring.len(),
            rc.extra_in_ring.len()
        );
    }
    if !report.summary.all_signatures_valid {
        let invalid = report.vote_checks.iter().filter(|vc| !vc.valid).count();
        bail!(
            "signature verification failed: {invalid} of {} votes have invalid signatures. \
             The bundle may be corrupted or tampered with.",
            report.summary.votes_cast
        );
    }
    if !report.summary.all_key_images_unique {
        bail!(
            "duplicate key images detected: {:?}. \
             Double-voting detected — the bundle is invalid.",
            report.key_image_check.duplicates
        );
    }

    let sp = spinner("Exporting report...");
    export_xlsx(&report, &locale, &args.output).map_err(|e: ExportError| anyhow::anyhow!(e))?;
    finish_spinner(&sp, "Report exported.");

    let elapsed = wall_start.elapsed();

    // ---- Print summary ----
    println!();
    println!("  Poll ID:            {}", report.summary.poll_id);
    println!("  Organization ID:    {}", report.summary.org_id);
    println!("  Ring size:          {}", report.summary.ring_size);
    println!("  Votes cast:         {}", report.summary.votes_cast);
    println!(
        "  Turnout:            {:.1}%",
        report.summary.turnout * 100.0
    );
    println!(
        "  Signatures valid:   {}",
        if report.summary.all_signatures_valid {
            "YES"
        } else {
            "NO"
        }
    );
    println!(
        "  Key images unique:  {}",
        if report.summary.all_key_images_unique {
            "YES"
        } else {
            "NO"
        }
    );
    println!(
        "  Registry matches:   {}",
        if report.summary.registry_matches_ring {
            "YES"
        } else {
            "NO"
        }
    );
    println!();
    println!("  Report written to:  {}", args.output.display());
    println!("  Wall time:          {:.2}s", elapsed.as_secs_f64());

    Ok(())
}
