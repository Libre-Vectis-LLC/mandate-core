//! Generate sample verification data (6 voters, 4 votes).
//!
//! Outputs two files that can be fed directly to `mandate-verify`:
//!
//! ```bash
//! cargo run -p mandate-verify --example generate_sample
//! mandate-verify poll \
//!     --registry  target/sample-verification/voters.xlsx \
//!     --bundle    target/sample-verification/poll-bundle.bin \
//!     --output    target/sample-verification/report.xlsx
//! ```

use std::fs;
use std::io::Write as _;
use std::path::Path;

use mandate_core::key_manager::KeyManager;
use mandate_verify::bundle::PollBundle;
use rust_xlsxwriter::Workbook;

/// Standard 24-word test mnemonic (BIP-39 "abandon" series).
const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

const ORG_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const POLL_ULID: &str = "01JTEST0POLL0DEMO00000VOTE";

const VOTER_NAMES: [&str; 6] = ["Alice", "Bob", "Carol", "Dave", "Eve", "Frank"];

/// Number of votes to cast (< 6 to show partial turnout).
const VOTES_CAST: usize = 4;

/// Poll options.
const OPTIONS: [&str; 3] = ["Approve", "Reject", "Abstain"];

fn main() {
    let out_dir = Path::new("target/sample-verification");
    fs::create_dir_all(out_dir).expect("create output directory");

    // ---- Generate 6 distinct voters ----
    let voters: Vec<(String, String)> = VOTER_NAMES
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let passphrase = if i == 0 {
                None
            } else {
                Some(format!("voter-{i}"))
            };
            let km = KeyManager::from_mnemonic(TEST_MNEMONIC, passphrase.as_deref())
                .expect("valid mnemonic");
            let master = km.derive_nazgul_master_keypair();
            let pub_bs58 = bs58::encode(master.0.public().compress().as_bytes()).into_string();
            (name.to_string(), pub_bs58)
        })
        .collect();

    // ---- Write voter registry XLSX ----
    let registry_path = out_dir.join("voters.xlsx");
    {
        let mut wb = Workbook::new();
        let ws = wb.add_worksheet();
        ws.write_string(0, 0, "Name").unwrap();
        ws.write_string(0, 1, "Public_Key").unwrap();

        for (row, (name, pubkey)) in voters.iter().enumerate() {
            let r = (row + 1) as u32;
            ws.write_string(r, 0, name).unwrap();
            ws.write_string(r, 1, pubkey).unwrap();
        }

        wb.save(&registry_path).expect("save registry XLSX");
    }
    println!("Registry:  {}", registry_path.display());

    // ---- Build PollBundle ----
    let ring_member_pubs: Vec<String> = voters.iter().map(|(_, pk)| pk.clone()).collect();

    // Simulate vote events: each vote picks an option round-robin.
    let vote_events_raw: Vec<Vec<u8>> = (0..VOTES_CAST)
        .map(|i| {
            let option = OPTIONS[i % OPTIONS.len()];
            // Placeholder: in production this would be an encrypted+signed
            // protobuf VoteCast event. Here we just store the option text
            // as raw bytes so the bundle is non-empty.
            option.as_bytes().to_vec()
        })
        .collect();

    let bundle = PollBundle {
        poll_event_raw: b"sample-poll-create-event".to_vec(),
        vote_events_raw,
        ring_member_pubs,
        org_id: ORG_ID.into(),
        poll_ulid: POLL_ULID.into(),
        poll_key_hex: "cafebabe01234567".into(),
    };

    let bundle_path = out_dir.join("poll-bundle.bin");
    {
        let bytes = bundle.to_bytes();
        let mut f = fs::File::create(&bundle_path).expect("create bundle file");
        f.write_all(&bytes).expect("write bundle");
    }
    println!("Bundle:    {}", bundle_path.display());

    // ---- Summary ----
    println!();
    println!("Sample data generated:");
    println!("  Voters:      {}", voters.len());
    println!("  Ring size:   {}", voters.len());
    println!("  Votes cast:  {VOTES_CAST}");
    println!(
        "  Turnout:     {:.1}%",
        VOTES_CAST as f64 / voters.len() as f64 * 100.0
    );
    println!("  Options:     {OPTIONS:?}");
    println!();
    println!("Voter registry:");
    for (i, (name, pk)) in voters.iter().enumerate() {
        let short_key = if pk.len() > 16 {
            format!("{}...{}", &pk[..8], &pk[pk.len() - 8..])
        } else {
            pk.clone()
        };
        println!("  {:>2}. {:<8} key={short_key}", i + 1, name);
    }
    println!();
    println!("To verify, run:");
    println!("  mandate-verify poll \\");
    println!("    --registry  {} \\", registry_path.display());
    println!("    --bundle    {} \\", bundle_path.display());
    println!("    --output    {}", out_dir.join("report.xlsx").display());
}
