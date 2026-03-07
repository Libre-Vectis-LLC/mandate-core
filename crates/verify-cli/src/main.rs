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
