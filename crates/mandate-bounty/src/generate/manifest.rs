//! Manifest generation: SHA-256 hashes of all challenge artifacts.

use std::path::Path;

use sha2::{Digest, Sha256};

/// Generate manifest.json containing SHA-256 hashes of specified artifacts.
pub fn generate_manifest(
    artifact_dir: &Path,
    artifact_names: &[&str],
    output: &Path,
) -> anyhow::Result<()> {
    let mut artifacts = serde_json::Map::new();

    for name in artifact_names {
        let path = artifact_dir.join(name);
        let data = std::fs::read(&path)
            .map_err(|e| anyhow::anyhow!("failed to read artifact {}: {e}", path.display()))?;
        let hash = Sha256::digest(&data);
        let hash_hex = format!("sha256:{}", hex::encode(hash));
        artifacts.insert(name.to_string(), serde_json::Value::from(hash_hex));
    }

    let doc = serde_json::json!({
        "version": 1,
        "artifacts": artifacts,
    });

    let json = serde_json::to_string_pretty(&doc)?;
    std::fs::write(output, json.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Create some test files.
        std::fs::write(dir.path().join("a.txt"), b"hello").expect("write");
        std::fs::write(dir.path().join("b.txt"), b"world").expect("write");

        let manifest_path = dir.path().join("manifest.json");
        generate_manifest(dir.path(), &["a.txt", "b.txt"], &manifest_path).expect("manifest");

        let content = std::fs::read_to_string(&manifest_path).expect("read");
        let doc: serde_json::Value = serde_json::from_str(&content).expect("parse");

        assert_eq!(doc["version"], 1);
        let artifacts = doc["artifacts"].as_object().expect("artifacts object");
        assert!(artifacts["a.txt"]
            .as_str()
            .expect("str")
            .starts_with("sha256:"));
        assert!(artifacts["b.txt"]
            .as_str()
            .expect("str")
            .starts_with("sha256:"));

        // Verify deterministic: same file content → same hash.
        let hash_a = artifacts["a.txt"].as_str().expect("str");
        // SHA-256 of "hello" = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            hash_a,
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
