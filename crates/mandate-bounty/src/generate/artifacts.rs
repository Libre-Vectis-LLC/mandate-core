//! Non-cryptographic artifact generation (XLSX, results, rules, encrypted secret).

use std::io::Write as _;
use std::path::Path;

use crate::canonical_csv::serialize_canonical_csv;
use crate::config::BountyConfig;
use crate::derive_identity::derive_identity;
use crate::solution_bundle::SolutionBundle;

// ---------------------------------------------------------------------------
// voters.xlsx
// ---------------------------------------------------------------------------

/// Generate the voter registry XLSX with columns: Name, Public_Key.
///
/// Rows are sorted by Public_Key (bs58 lexicographic order).
pub fn generate_voters_xlsx(bundle: &SolutionBundle, output: &Path) -> anyhow::Result<()> {
    use rust_xlsxwriter::Workbook;

    // Sort by pubkey for deterministic output.
    let mut entries: Vec<(&str, &str)> = bundle
        .solution
        .iter()
        .map(|e| (e.name.as_str(), e.pubkey_bs58.as_str()))
        .collect();
    entries.sort_by_key(|(_, pk)| *pk);

    let mut wb = Workbook::new();
    let ws = wb.add_worksheet();
    ws.write_string(0, 0, "Name")
        .map_err(|e| anyhow::anyhow!("xlsx write header: {e}"))?;
    ws.write_string(0, 1, "Public_Key")
        .map_err(|e| anyhow::anyhow!("xlsx write header: {e}"))?;

    for (row, (name, pubkey)) in entries.iter().enumerate() {
        let r = (row + 1) as u32;
        ws.write_string(r, 0, *name)
            .map_err(|e| anyhow::anyhow!("xlsx write name row {r}: {e}"))?;
        ws.write_string(r, 1, *pubkey)
            .map_err(|e| anyhow::anyhow!("xlsx write pubkey row {r}: {e}"))?;
    }

    wb.save(output)
        .map_err(|e| anyhow::anyhow!("xlsx save: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// results.json
// ---------------------------------------------------------------------------

/// Generate aggregate vote tally as JSON.
pub fn generate_results_json(
    config: &BountyConfig,
    _bundle: &SolutionBundle,
    output: &Path,
) -> anyhow::Result<()> {
    let total_votes: u32 = config.poll.options.iter().map(|o| o.count).sum();

    let mut results = serde_json::Map::new();
    for opt in &config.poll.options {
        results.insert(opt.id.clone(), serde_json::Value::from(opt.count));
    }

    let doc = serde_json::json!({
        "poll_id": config.poll.poll_ulid,
        "total_votes": total_votes,
        "results": results,
    });

    let json = serde_json::to_string_pretty(&doc)?;
    std::fs::write(output, json.as_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// encrypted_secret.rage
// ---------------------------------------------------------------------------

/// Generate the age-encrypted bounty secret.
///
/// Derives the age public key from the canonical CSV via the KDF chain,
/// then encrypts the secret with that key. If `custom_plaintext` is provided,
/// it is used as-is; otherwise a default reverse-prompt is used.
pub fn generate_encrypted_secret(
    config: &BountyConfig,
    bundle: &SolutionBundle,
    output: &Path,
    custom_plaintext: Option<&[u8]>,
) -> anyhow::Result<()> {
    // Derive the age identity from the canonical CSV.
    let csv_entries = bundle.to_csv_entries();
    let csv_text = serialize_canonical_csv(&csv_entries);
    let identity = derive_identity(csv_text.as_bytes(), &config.kdf)?;
    let recipient = identity.to_public();

    let default_plaintext = b"BOUNTY_SECRET_PLACEHOLDER";
    let plaintext = custom_plaintext.unwrap_or(default_plaintext);

    let recipients = [Box::new(recipient) as Box<dyn age::Recipient>];
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
        .expect("at least one recipient provided");

    let mut ciphertext = Vec::new();
    {
        let mut writer = encryptor
            .wrap_output(&mut ciphertext)
            .map_err(|e| anyhow::anyhow!("age wrap_output failed: {e}"))?;
        writer.write_all(plaintext)?;
        writer
            .finish()
            .map_err(|e| anyhow::anyhow!("age finish failed: {e}"))?;
    }

    std::fs::write(output, &ciphertext)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// RULES.md
// ---------------------------------------------------------------------------

/// Generate the RULES.md challenge description.
pub fn generate_rules_md(
    config: &BountyConfig,
    bundle: &SolutionBundle,
    output: &Path,
) -> anyhow::Result<()> {
    // Derive the public key for display in rules.
    let csv_entries = bundle.to_csv_entries();
    let csv_text = serialize_canonical_csv(&csv_entries);
    let identity = derive_identity(csv_text.as_bytes(), &config.kdf)?;
    let pubkey = identity.to_public().to_string();

    let rules = format!(
        r#"# Mandate Anonymous Voting Bounty Challenge

## Objective

De-anonymize the ring-signature-based anonymous poll by mapping each voter
to their public key and vote choice.

## Artifacts

| File | Description |
|------|-------------|
| `voters.xlsx` | Voter name + public key registry |
| `poll-bundle.bin` | PollBundle protobuf (PollCreate + VoteCast events with real BLSAG signatures) |
| `results.json` | Aggregate vote tally |
| `encrypted_secret.rage` | Age-encrypted bounty secret |
| `manifest.json` | SHA-256 hashes of all artifacts |

## Solution Format

Submit a CSV file with one line per voter, sorted by public key (bs58 lexicographic):

```
<name>,<option_id>
```

- Names must be NFC-normalized Unicode.
- No header row.
- LF line endings, no trailing newline.

## KDF Chain

The correct solution CSV is transformed into an age identity via:

1. `SHA3-512(csv_bytes)` -> 64 bytes
2. `Argon2id(password=sha3_hash, salt="{salt}", m_cost={m_cost_mib}MiB, t_cost={t_cost}, p_cost={p_cost})` -> 32 bytes
3. `age::x25519::Identity::from_secret_bytes(argon2_output)`

### Parameters

- **Salt**: `{salt}`
- **Memory cost**: {m_cost_mib} MiB
- **Time cost**: {t_cost} iterations
- **Parallelism**: {p_cost} lanes

### Expected Public Key

```
{pubkey}
```

If your derived public key matches the above, you can decrypt `encrypted_secret.rage`.

## Bounty

- **Total**: {total_usdc} USDC
- **Instant reward**: {instant_usdc} USDC (first correct submission)
- **Report reward**: {report_usdc} USDC (write-up describing the attack)
- **Challenge period**: {challenge_days} days

## Verification

```bash
mandate-bounty verify-solution \
    --csv <your-solution.csv> \
    --voters voters.xlsx \
    --encrypted encrypted_secret.rage \
    --config <bounty.toml>
```
"#,
        salt = config.kdf.salt,
        m_cost_mib = config.kdf.m_cost_mib,
        t_cost = config.kdf.t_cost,
        p_cost = config.kdf.p_cost,
        pubkey = pubkey,
        total_usdc = config.bounty.total_usdc,
        instant_usdc = config.bounty.instant_usdc,
        report_usdc = config.bounty.report_usdc,
        challenge_days = config.bounty.challenge_days,
    );

    std::fs::write(output, rules.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solution_bundle::{SolutionEntry, VoterPrivateKey};

    fn test_bundle() -> SolutionBundle {
        SolutionBundle {
            version: 1,
            solution: vec![
                SolutionEntry {
                    pubkey_bs58: "BBB".into(),
                    name: "Bob".into(),
                    option: "opt-a".into(),
                },
                SolutionEntry {
                    pubkey_bs58: "AAA".into(),
                    name: "Alice".into(),
                    option: "opt-b".into(),
                },
            ],
            voter_private_keys: vec![
                VoterPrivateKey {
                    pubkey_bs58: "BBB".into(),
                    scalar_bs58: "SCALAR_BOB".into(),
                },
                VoterPrivateKey {
                    pubkey_bs58: "AAA".into(),
                    scalar_bs58: "SCALAR_ALICE".into(),
                },
            ],
        }
    }

    fn test_config() -> BountyConfig {
        toml::from_str(include_str!("../../fixtures/bounty.toml")).expect("fixture config")
    }

    #[test]
    fn test_generate_voters_xlsx() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("voters.xlsx");
        let bundle = test_bundle();
        generate_voters_xlsx(&bundle, &path).expect("generate xlsx");
        assert!(path.exists());
        assert!(std::fs::metadata(&path).expect("meta").len() > 0);
    }

    #[test]
    fn test_generate_results_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("results.json");
        let config = test_config();
        let bundle = test_bundle();
        generate_results_json(&config, &bundle, &path).expect("generate results");

        let content = std::fs::read_to_string(&path).expect("read results");
        let doc: serde_json::Value = serde_json::from_str(&content).expect("parse json");
        assert_eq!(doc["poll_id"], config.poll.poll_ulid);
        assert!(doc["total_votes"].as_u64().is_some());
        assert!(doc["results"].is_object());
    }
}
