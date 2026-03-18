//! Artifact integrity auditing via manifest.json hash verification.
//!
//! Reads the manifest and verifies that every listed artifact's SHA-256
//! hash matches the recorded value.

use std::path::Path;

use sha2::{Digest, Sha256};

/// Result of auditing a single artifact.
#[derive(Debug)]
pub struct ArtifactCheck {
    /// Artifact file name.
    pub name: String,
    /// Whether the hash matched.
    pub passed: bool,
    /// Expected hash from manifest (prefixed with "sha256:").
    pub expected: String,
    /// Actual computed hash (prefixed with "sha256:").
    pub actual: String,
}

/// Audit all artifacts listed in `manifest.json` within `dir`.
///
/// Returns a list of per-artifact check results. The caller decides
/// how to present pass/fail to the user.
pub fn audit_artifacts(dir: &Path) -> anyhow::Result<Vec<ArtifactCheck>> {
    let manifest_path = dir.join("manifest.json");
    let manifest_data = std::fs::read_to_string(&manifest_path)
        .map_err(|e| anyhow::anyhow!("failed to read manifest.json in {}: {e}", dir.display()))?;

    let doc: serde_json::Value = serde_json::from_str(&manifest_data)
        .map_err(|e| anyhow::anyhow!("failed to parse manifest.json: {e}"))?;

    let version = doc
        .get("version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("manifest.json missing or invalid 'version' field"))?;

    anyhow::ensure!(
        version == 1,
        "unsupported manifest version: {version} (only version 1 is supported)"
    );

    let artifacts = doc
        .get("artifacts")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow::anyhow!("manifest.json missing or invalid 'artifacts' field"))?;

    let mut results = Vec::with_capacity(artifacts.len());

    for (name, expected_val) in artifacts {
        let expected = expected_val
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("artifact '{name}' hash is not a string"))?
            .to_owned();

        let artifact_path = dir.join(name);
        let data = std::fs::read(&artifact_path).map_err(|e| {
            anyhow::anyhow!("failed to read artifact {}: {e}", artifact_path.display())
        })?;

        let hash = Sha256::digest(&data);
        let actual = format!("sha256:{}", hex::encode(hash));

        let passed = actual == expected;

        results.push(ArtifactCheck {
            name: name.clone(),
            passed,
            expected,
            actual,
        });
    }

    // Sort by name for deterministic output
    results.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: write files and a manifest, then audit.
    fn setup_artifacts(dir: &Path, files: &[(&str, &[u8])]) {
        for (name, content) in files {
            std::fs::write(dir.join(name), content).expect("write artifact");
        }

        // Generate manifest
        crate::generate::manifest::generate_manifest(
            dir,
            &files.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            &dir.join("manifest.json"),
        )
        .expect("generate manifest");
    }

    #[test]
    fn test_audit_all_pass() {
        let dir = tempfile::tempdir().expect("tempdir");
        setup_artifacts(dir.path(), &[("a.txt", b"hello"), ("b.txt", b"world")]);

        let results = audit_artifacts(dir.path()).expect("audit");
        assert_eq!(results.len(), 2);
        for check in &results {
            assert!(
                check.passed,
                "artifact {} should pass: expected={}, actual={}",
                check.name, check.expected, check.actual
            );
        }
    }

    #[test]
    fn test_audit_tampered_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        setup_artifacts(dir.path(), &[("a.txt", b"hello"), ("b.txt", b"world")]);

        // Tamper with b.txt after manifest was generated
        std::fs::write(dir.path().join("b.txt"), b"TAMPERED").expect("tamper");

        let results = audit_artifacts(dir.path()).expect("audit");
        assert_eq!(results.len(), 2);

        let a = results.iter().find(|c| c.name == "a.txt").expect("a.txt");
        assert!(a.passed, "a.txt should still pass");

        let b = results.iter().find(|c| c.name == "b.txt").expect("b.txt");
        assert!(!b.passed, "b.txt should fail after tampering");
    }

    #[test]
    fn test_audit_missing_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = audit_artifacts(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("manifest.json"),
            "error should mention manifest: {err}"
        );
    }

    #[test]
    fn test_audit_missing_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        setup_artifacts(dir.path(), &[("a.txt", b"hello")]);

        // Delete the artifact but keep the manifest
        std::fs::remove_file(dir.path().join("a.txt")).expect("remove");

        let result = audit_artifacts(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("a.txt"),
            "error should mention missing file: {err}"
        );
    }
}
