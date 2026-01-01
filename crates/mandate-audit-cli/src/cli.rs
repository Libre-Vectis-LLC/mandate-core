use clap::{ArgGroup, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "mandate-audit-cli",
    version,
    about = "Audit tooling for Mandate event verification and poll export"
)]
pub struct Cli {
    /// Edge gRPC endpoint for Event/Ring services.
    #[arg(
        long,
        env = "MANDATE_EDGE_URL",
        default_value = "http://127.0.0.1:48080"
    )]
    pub edge_url: String,
    /// Optional public gRPC endpoint (bypasses edge cache when needed).
    #[arg(long, env = "MANDATE_PUBLIC_URL")]
    pub public_url: Option<String>,
    /// API token for group access.
    #[arg(long, env = "MANDATE_API_TOKEN")]
    pub api_token: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Stream all events and verify signature, chain, and vote key images.
    VerifyEvents {
        /// Group ID (ULID).
        #[arg(long)]
        group_id: String,
        /// Start sequence number (exclusive). Use -1 for full history.
        #[arg(long, default_value_t = -1)]
        start_seq: i64,
        /// Maximum events per stream page.
        #[arg(long, default_value_t = 200)]
        limit: u32,
        /// Optional JSON report output path.
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Export a poll event + vote events + poll key for external audit.
    #[command(group(
        ArgGroup::new("poll_selector")
            .required(true)
            .args(["poll_id", "poll_event_ulid"])
    ))]
    ExportPollBundle {
        /// Group ID (ULID).
        #[arg(long)]
        group_id: String,
        /// Poll ID (from PollCreate payload).
        #[arg(long)]
        poll_id: Option<String>,
        /// Poll event ULID (from event metadata).
        #[arg(long)]
        poll_event_ulid: Option<String>,
        /// Group shared secret K_shared (hex, 32 bytes).
        #[arg(long)]
        k_shared_hex: String,
        /// Output directory for bundle files.
        #[arg(long)]
        output_dir: PathBuf,
        /// Maximum events per stream page.
        #[arg(long, default_value_t = 200)]
        limit: u32,
    },
}
