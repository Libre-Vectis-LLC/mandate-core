//! Solution verification: canonicalize a candidate CSV and decrypt the secret.
//!
//! The verification flow uses `voters.xlsx` to enforce exact voter-set
//! consistency and canonical pubkey ordering before running the KDF chain.

use std::collections::{HashMap, HashSet};
use std::io::Read as _;
use std::path::Path;

use mandate_verify::registry::{parse_registry, RegistryEntry};
use unicode_normalization::UnicodeNormalization;

use crate::canonical_csv::{serialize_canonical_csv, CsvEntry};
use crate::derive_identity::{derive_identity, normalize_csv_bytes};
use crate::manifest::ChallengeManifest;

/// Maximum allowed CSV file size (10 MB).
const MAX_CSV_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum allowed line count in the CSV.
const MAX_CSV_LINES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalizedCsv {
    pub bytes: Vec<u8>,
    pub was_reordered: bool,
}

#[derive(Debug)]
pub struct VerificationOutcome {
    pub plaintext: Vec<u8>,
    pub derived_pubkey: String,
    pub was_reordered: bool,
}

/// Canonicalize a participant-submitted CSV file using the public voter registry.
pub fn canonicalize_solution_csv_file(
    csv_path: &Path,
    voters_path: &Path,
) -> anyhow::Result<CanonicalizedCsv> {
    let csv_bytes = read_csv_bytes(csv_path)?;
    canonicalize_solution_csv_bytes(&csv_bytes, voters_path)
}

/// Canonicalize participant-submitted CSV bytes using the public voter registry.
pub fn canonicalize_solution_csv_bytes(
    csv_bytes: &[u8],
    voters_path: &Path,
) -> anyhow::Result<CanonicalizedCsv> {
    let registry = parse_registry(voters_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to parse voters registry {}: {e}",
            voters_path.display()
        )
    })?;
    canonicalize_solution_with_registry(csv_bytes, &registry)
}

/// Verify a candidate solution CSV by canonicalizing it, deriving the expected
/// age identity from `manifest.json`, and decrypting the secret artifact.
pub fn verify_solution(
    csv_path: &Path,
    voters_path: &Path,
    encrypted_path: &Path,
    manifest: &ChallengeManifest,
) -> anyhow::Result<VerificationOutcome> {
    let canonicalized = canonicalize_solution_csv_file(csv_path, voters_path)?;
    let kdf = manifest.kdf.to_config()?;

    let identity = derive_identity(&canonicalized.bytes, &kdf)?;
    let derived_pubkey = identity.to_public().to_string();
    anyhow::ensure!(
        derived_pubkey == manifest.expected_age_pubkey,
        "derived public key does not match manifest expected_age_pubkey: got {}, expected {}",
        derived_pubkey,
        manifest.expected_age_pubkey
    );

    let ciphertext = std::fs::read(encrypted_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read encrypted file {}: {e}",
            encrypted_path.display()
        )
    })?;

    let decryptor = age::Decryptor::new(&ciphertext[..])
        .map_err(|e| anyhow::anyhow!("failed to parse age ciphertext: {e}"))?;

    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| anyhow::anyhow!("decryption failed despite matching manifest key: {e}"))?;

    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;

    Ok(VerificationOutcome {
        plaintext,
        derived_pubkey,
        was_reordered: canonicalized.was_reordered,
    })
}

fn canonicalize_solution_with_registry(
    csv_bytes: &[u8],
    registry: &[RegistryEntry],
) -> anyhow::Result<CanonicalizedCsv> {
    let normalized_bytes = normalize_csv_bytes(csv_bytes)?;
    let normalized_text = String::from_utf8(normalized_bytes)
        .map_err(|e| anyhow::anyhow!("normalized CSV is not valid UTF-8: {e}"))?;

    let lines: Vec<&str> = if normalized_text.is_empty() {
        Vec::new()
    } else {
        normalized_text.split('\n').collect()
    };

    anyhow::ensure!(!lines.is_empty(), "CSV is empty");
    anyhow::ensure!(
        lines.len() <= MAX_CSV_LINES,
        "CSV has too many lines: {} (max {})",
        lines.len(),
        MAX_CSV_LINES
    );

    let mut registry_by_name = HashMap::with_capacity(registry.len());
    let mut registry_pubkeys = HashSet::with_capacity(registry.len());
    for (idx, entry) in registry.iter().enumerate() {
        let normalized_name: String = entry.voter_info.nfc().collect();
        anyhow::ensure!(
            !normalized_name.is_empty(),
            "voters.xlsx row {} has empty voter name",
            idx + 2
        );
        anyhow::ensure!(
            registry_by_name
                .insert(normalized_name.clone(), entry.master_pub_bs58.clone())
                .is_none(),
            "duplicate NFC-normalized voter name in voters.xlsx: {:?}",
            normalized_name
        );
        anyhow::ensure!(
            registry_pubkeys.insert(entry.master_pub_bs58.clone()),
            "duplicate public key in voters.xlsx: {}",
            entry.master_pub_bs58
        );
    }

    let mut submitted_names = HashSet::with_capacity(lines.len());
    let mut original_pubkey_order = Vec::with_capacity(lines.len());
    let mut csv_entries = Vec::with_capacity(lines.len());

    for (i, line) in lines.iter().enumerate() {
        anyhow::ensure!(!line.is_empty(), "CSV line {} is empty", i + 1);

        let comma_count = line.chars().filter(|&c| c == ',').count();
        anyhow::ensure!(
            comma_count == 1,
            "CSV line {} has {} commas (expected exactly 1): {:?}",
            i + 1,
            comma_count,
            line
        );

        let (name_raw, option_raw) = line
            .split_once(',')
            .ok_or_else(|| anyhow::anyhow!("CSV line {} is missing a comma", i + 1))?;

        let name: String = name_raw.nfc().collect();
        let option: String = option_raw.nfc().collect();

        anyhow::ensure!(!name.is_empty(), "CSV line {} has empty name field", i + 1);
        anyhow::ensure!(
            !option.is_empty(),
            "CSV line {} has empty option field",
            i + 1
        );
        anyhow::ensure!(
            submitted_names.insert(name.clone()),
            "duplicate voter name in CSV: {:?}",
            name
        );

        let pubkey_bs58 = registry_by_name
            .remove(&name)
            .ok_or_else(|| anyhow::anyhow!("CSV voter {:?} not found in voters.xlsx", name))?;

        original_pubkey_order.push(pubkey_bs58.clone());
        csv_entries.push(CsvEntry {
            name,
            option,
            pubkey_bs58,
        });
    }

    anyhow::ensure!(
        registry_by_name.is_empty(),
        "CSV is missing voters present in voters.xlsx ({} unmatched)",
        registry_by_name.len()
    );

    let mut sorted_pubkeys = original_pubkey_order.clone();
    sorted_pubkeys.sort();
    let was_reordered = original_pubkey_order != sorted_pubkeys;

    let canonical_csv = serialize_canonical_csv(&csv_entries);
    Ok(CanonicalizedCsv {
        bytes: canonical_csv.into_bytes(),
        was_reordered,
    })
}

fn read_csv_bytes(path: &Path) -> anyhow::Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("failed to stat CSV file {}: {e}", path.display()))?;

    anyhow::ensure!(
        metadata.len() <= MAX_CSV_SIZE,
        "CSV file too large: {} bytes (max {} bytes)",
        metadata.len(),
        MAX_CSV_SIZE
    );

    std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read CSV file {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Write as _;

    use rust_xlsxwriter::Workbook;

    use super::*;
    use crate::manifest::{ChallengeManifest, DocumentationLinks, ManifestKdf, MANIFEST_VERSION};

    /// Tiny KDF params for fast testing.
    fn test_kdf() -> crate::config::KdfConfig {
        crate::config::KdfConfig {
            salt: "test-salt".into(),
            m_cost_mib: 1,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn write_registry(path: &Path, rows: &[(&str, &str)]) {
        let mut workbook = Workbook::new();
        let sheet = workbook.add_worksheet();
        sheet.write_string(0, 0, "Name").expect("header");
        sheet.write_string(0, 1, "Public_Key").expect("header");
        for (row, (name, pubkey)) in rows.iter().enumerate() {
            let row = (row + 1) as u32;
            sheet.write_string(row, 0, *name).expect("name");
            sheet.write_string(row, 1, *pubkey).expect("pubkey");
        }
        workbook.save(path).expect("save xlsx");
    }

    fn manifest_for(csv_text: &str, kdf: &crate::config::KdfConfig) -> ChallengeManifest {
        let identity = derive_identity(csv_text.as_bytes(), kdf).expect("derive identity");
        ChallengeManifest {
            version: MANIFEST_VERSION,
            git_commit: "test-commit".into(),
            expected_age_pubkey: identity.to_public().to_string(),
            kdf: ManifestKdf::from(kdf),
            documentation: DocumentationLinks {
                challenger_guide: "bounty-challenger.zh.md".into(),
            },
            artifacts: BTreeMap::new(),
        }
    }

    fn encrypt_with_csv(
        csv_text: &str,
        kdf: &crate::config::KdfConfig,
        plaintext: &[u8],
        out: &Path,
    ) {
        let identity = derive_identity(csv_text.as_bytes(), kdf).expect("derive identity");
        let recipient = identity.to_public();

        let recipients = [Box::new(recipient) as Box<dyn age::Recipient>];
        let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
            .expect("encryptor");

        let mut ciphertext = Vec::new();
        {
            let mut writer = encryptor.wrap_output(&mut ciphertext).expect("wrap_output");
            writer.write_all(plaintext).expect("write plaintext");
            writer.finish().expect("finish");
        }

        std::fs::write(out, &ciphertext).expect("write encrypted file");
    }

    #[test]
    fn test_roundtrip_verify_with_registry_reordering_and_normalization() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kdf = test_kdf();
        let voters_path = dir.path().join("voters.xlsx");
        write_registry(&voters_path, &[("Alice", "AAA"), ("Bob", "BBB")]);

        let canonical_csv = "Alice,Option B\nBob,Option A";
        let manifest = manifest_for(canonical_csv, &kdf);

        let encrypted_path = dir.path().join("encrypted_secret.rage");
        encrypt_with_csv(canonical_csv, &kdf, b"BOUNTY_SECRET_42", &encrypted_path);

        let csv_path = dir.path().join("solution.csv");
        std::fs::write(
            &csv_path,
            b"\xEF\xBB\xBFBob,Option A\r\nAlice,Option B\r\n\r\n",
        )
        .expect("write csv");

        let outcome =
            verify_solution(&csv_path, &voters_path, &encrypted_path, &manifest).expect("verify");
        assert_eq!(outcome.plaintext, b"BOUNTY_SECRET_42");
        assert!(outcome.was_reordered, "input order should be canonicalized");
        assert_eq!(outcome.derived_pubkey, manifest.expected_age_pubkey);
    }

    #[test]
    fn test_missing_voter_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let voters_path = dir.path().join("voters.xlsx");
        write_registry(&voters_path, &[("Alice", "AAA"), ("Bob", "BBB")]);

        let result = canonicalize_solution_csv_bytes(b"Alice,Option B\n", &voters_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing voters"), "unexpected error: {err}");
    }

    #[test]
    fn test_unknown_voter_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let voters_path = dir.path().join("voters.xlsx");
        write_registry(&voters_path, &[("Alice", "AAA"), ("Bob", "BBB")]);

        let result =
            canonicalize_solution_csv_bytes(b"Alice,Option B\nMallory,Option A\n", &voters_path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found in voters.xlsx"),
            "unexpected error: {err}"
        );
    }
}
