//! Solution verification: validate a candidate CSV against the encrypted secret.
//!
//! Runs the full KDF chain on a submitted CSV and attempts to decrypt
//! `encrypted_secret.rage`. A successful decryption proves the CSV is the
//! correct solution.

use std::io::Read as _;
use std::path::Path;

use crate::config::KdfConfig;
use crate::derive_identity::derive_identity;

/// Maximum allowed CSV file size (10 MB).
const MAX_CSV_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum allowed line count in the CSV.
const MAX_CSV_LINES: usize = 10_000;

/// Verify a candidate solution CSV by attempting to decrypt the encrypted secret.
///
/// Returns the decrypted plaintext bytes on success. Fails if:
/// - The CSV file exceeds size or line limits
/// - Individual lines are not `name,option` format
/// - The derived identity cannot decrypt the encrypted file
pub fn verify_solution(
    csv_path: &Path,
    encrypted_path: &Path,
    kdf: &KdfConfig,
) -> anyhow::Result<Vec<u8>> {
    // 1. Read and validate CSV
    let csv_bytes = read_and_validate_csv(csv_path)?;

    // 2. Derive age identity via KDF chain
    let identity = derive_identity(&csv_bytes, kdf)?;

    // 3. Read encrypted file
    let ciphertext = std::fs::read(encrypted_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read encrypted file {}: {e}",
            encrypted_path.display()
        )
    })?;

    // 4. Attempt decryption
    let decryptor = age::Decryptor::new(&ciphertext[..])
        .map_err(|e| anyhow::anyhow!("failed to parse age ciphertext: {e}"))?;

    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| anyhow::anyhow!("decryption failed (wrong solution?): {e}"))?;

    let mut plaintext = Vec::new();
    reader.read_to_end(&mut plaintext)?;

    Ok(plaintext)
}

/// Read a CSV file and validate its size, line count, and format.
///
/// Returns the raw file bytes on success.
fn read_and_validate_csv(path: &Path) -> anyhow::Result<Vec<u8>> {
    // Check file size
    let metadata = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("failed to stat CSV file {}: {e}", path.display()))?;

    anyhow::ensure!(
        metadata.len() <= MAX_CSV_SIZE,
        "CSV file too large: {} bytes (max {} bytes)",
        metadata.len(),
        MAX_CSV_SIZE
    );

    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read CSV file {}: {e}", path.display()))?;

    // Validate UTF-8
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| anyhow::anyhow!("CSV file is not valid UTF-8: {e}"))?;

    // Check line count and format
    let lines: Vec<&str> = text.split('\n').collect();

    // Handle trailing newline: if last element is empty from a trailing \n, exclude it
    let effective_lines: Vec<&str> = if lines.last() == Some(&"") {
        lines[..lines.len() - 1].to_vec()
    } else {
        lines
    };

    anyhow::ensure!(
        effective_lines.len() <= MAX_CSV_LINES,
        "CSV has too many lines: {} (max {})",
        effective_lines.len(),
        MAX_CSV_LINES
    );

    // Validate each line is "name,option" format
    for (i, line) in effective_lines.iter().enumerate() {
        anyhow::ensure!(!line.is_empty(), "CSV line {} is empty", i + 1);

        let comma_count = line.chars().filter(|&c| c == ',').count();
        anyhow::ensure!(
            comma_count == 1,
            "CSV line {} has {} commas (expected exactly 1): {:?}",
            i + 1,
            comma_count,
            line
        );

        let parts: Vec<&str> = line.splitn(2, ',').collect();
        anyhow::ensure!(
            !parts[0].is_empty(),
            "CSV line {} has empty name field",
            i + 1
        );
        anyhow::ensure!(
            !parts[1].is_empty(),
            "CSV line {} has empty option field",
            i + 1
        );
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;
    use crate::canonical_csv::{serialize_canonical_csv, CsvEntry};

    /// Tiny KDF params for fast testing.
    fn test_kdf() -> KdfConfig {
        KdfConfig {
            salt: "test-salt".into(),
            m_cost_mib: 1,
            t_cost: 1,
            p_cost: 1,
        }
    }

    /// Helper: encrypt plaintext with a derived identity and write to a file.
    fn encrypt_with_csv(csv_text: &str, kdf: &KdfConfig, plaintext: &[u8], out: &Path) {
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
    fn test_roundtrip_verify() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kdf = test_kdf();

        // Build canonical CSV
        let entries = vec![
            CsvEntry {
                name: "Alice".into(),
                option: "opt-b".into(),
                pubkey_bs58: "AAA".into(),
            },
            CsvEntry {
                name: "Bob".into(),
                option: "opt-a".into(),
                pubkey_bs58: "BBB".into(),
            },
        ];
        let csv_text = serialize_canonical_csv(&entries);

        // Write CSV file
        let csv_path = dir.path().join("solution.csv");
        std::fs::write(&csv_path, csv_text.as_bytes()).expect("write csv");

        // Encrypt a secret
        let secret = b"BOUNTY_SECRET_42";
        let encrypted_path = dir.path().join("encrypted_secret.rage");
        encrypt_with_csv(&csv_text, &kdf, secret, &encrypted_path);

        // Verify
        let result = verify_solution(&csv_path, &encrypted_path, &kdf);
        assert!(result.is_ok(), "verification should succeed: {:?}", result);
        assert_eq!(result.expect("ok"), secret);
    }

    #[test]
    fn test_wrong_solution_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kdf = test_kdf();

        // Correct CSV
        let correct_csv = "Alice,opt-b\nBob,opt-a";

        // Wrong CSV (different option)
        let wrong_csv = "Alice,opt-a\nBob,opt-b";

        // Encrypt with correct CSV
        let encrypted_path = dir.path().join("encrypted_secret.rage");
        encrypt_with_csv(correct_csv, &kdf, b"SECRET", &encrypted_path);

        // Write wrong CSV to file
        let csv_path = dir.path().join("wrong.csv");
        std::fs::write(&csv_path, wrong_csv.as_bytes()).expect("write csv");

        // Verify should fail
        let result = verify_solution(&csv_path, &encrypted_path, &kdf);
        assert!(result.is_err(), "wrong solution should fail verification");
    }

    #[test]
    fn test_csv_too_large() {
        let dir = tempfile::tempdir().expect("tempdir");
        let csv_path = dir.path().join("huge.csv");

        // Create a file just over 10MB
        let line = "Name,opt-a\n";
        let count = (MAX_CSV_SIZE as usize / line.len()) + 1;
        let big = line.repeat(count);
        std::fs::write(&csv_path, big.as_bytes()).expect("write");

        let encrypted_path = dir.path().join("dummy.rage");
        std::fs::write(&encrypted_path, b"dummy").expect("write");

        let result = verify_solution(&csv_path, &encrypted_path, &test_kdf());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("too large"),
            "error should mention size: {err}"
        );
    }

    #[test]
    fn test_csv_bad_format() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Missing comma
        let csv_path = dir.path().join("bad.csv");
        std::fs::write(&csv_path, b"Alice opt-a").expect("write");

        let encrypted_path = dir.path().join("dummy.rage");
        std::fs::write(&encrypted_path, b"dummy").expect("write");

        let result = verify_solution(&csv_path, &encrypted_path, &test_kdf());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("commas"), "error should mention format: {err}");
    }

    #[test]
    fn test_csv_empty_name() {
        let dir = tempfile::tempdir().expect("tempdir");

        let csv_path = dir.path().join("bad.csv");
        std::fs::write(&csv_path, b",opt-a").expect("write");

        let encrypted_path = dir.path().join("dummy.rage");
        std::fs::write(&encrypted_path, b"dummy").expect("write");

        let result = verify_solution(&csv_path, &encrypted_path, &test_kdf());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("empty name"),
            "error should mention empty name: {err}"
        );
    }
}
