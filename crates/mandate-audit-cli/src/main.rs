use anyhow::{Context, Result};
use clap::Parser;

mod cli;
mod client;
mod poll_bundle;
mod ring_cache;
mod verify;

use cli::{Cli, Command};
use client::AuditClient;
use poll_bundle::{export_poll_bundle, PollBundleOptions};
use verify::verify_events;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut client = AuditClient::new(cli.edge_url, cli.public_url, cli.api_token);

    match cli.command {
        Command::VerifyEvents {
            group_id,
            start_seq,
            limit,
            report,
        } => {
            let report_data = verify_events(&mut client, &group_id, start_seq, limit)
                .await
                .context("verify events")?;
            let json = serde_json::to_string_pretty(&report_data).context("serialize report")?;
            if let Some(path) = report {
                std::fs::write(&path, json).with_context(|| format!("write {:?}", path))?;
            } else {
                println!("{}", json);
            }
        }
        Command::ExportPollBundle {
            group_id,
            poll_id,
            poll_event_ulid,
            k_shared_hex,
            output_dir,
            limit,
        } => {
            let options = PollBundleOptions {
                group_id,
                poll_id,
                poll_event_ulid,
                k_shared_hex,
                output_dir,
                limit,
            };
            let manifest = export_poll_bundle(&mut client, options)
                .await
                .context("export poll bundle")?;
            let json = serde_json::to_string_pretty(&manifest).context("serialize manifest")?;
            println!("{}", json);
        }
    }

    Ok(())
}
