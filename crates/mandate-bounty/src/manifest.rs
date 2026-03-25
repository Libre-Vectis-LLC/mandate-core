//! Public challenge manifest generation and parsing.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::KdfConfig;

pub const MANIFEST_VERSION: u32 = 1;
pub const KDF_ALGORITHM: &str = "csv-sha3-512-argon2id-age-x25519-v1";
pub const CHALLENGER_GUIDE_PATH: &str = "bounty-challenger.zh.md";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeManifest {
    pub version: u32,
    pub git_commit: String,
    pub expected_age_pubkey: String,
    pub kdf: ManifestKdf,
    pub documentation: DocumentationLinks,
    pub artifacts: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestKdf {
    pub algorithm: String,
    pub salt: String,
    pub m_cost_mib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DocumentationLinks {
    pub challenger_guide: String,
}

impl From<&KdfConfig> for ManifestKdf {
    fn from(value: &KdfConfig) -> Self {
        Self {
            algorithm: KDF_ALGORITHM.to_owned(),
            salt: value.salt.clone(),
            m_cost_mib: value.m_cost_mib,
            t_cost: value.t_cost,
            p_cost: value.p_cost,
        }
    }
}

impl ManifestKdf {
    pub fn to_config(&self) -> anyhow::Result<KdfConfig> {
        anyhow::ensure!(
            self.algorithm == KDF_ALGORITHM,
            "unsupported manifest kdf.algorithm: {}",
            self.algorithm
        );
        anyhow::ensure!(self.m_cost_mib > 0, "manifest kdf.m_cost_mib must be > 0");
        anyhow::ensure!(self.t_cost > 0, "manifest kdf.t_cost must be > 0");
        anyhow::ensure!(self.p_cost > 0, "manifest kdf.p_cost must be > 0");
        Ok(KdfConfig {
            salt: self.salt.clone(),
            m_cost_mib: self.m_cost_mib,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
        })
    }
}

pub fn build_manifest(
    artifact_dir: &Path,
    artifact_names: &[&str],
    expected_age_pubkey: String,
    git_commit: String,
    kdf: &KdfConfig,
) -> anyhow::Result<ChallengeManifest> {
    Ok(ChallengeManifest {
        version: MANIFEST_VERSION,
        git_commit,
        expected_age_pubkey,
        kdf: ManifestKdf::from(kdf),
        documentation: DocumentationLinks {
            challenger_guide: CHALLENGER_GUIDE_PATH.to_owned(),
        },
        artifacts: hash_artifacts(artifact_dir, artifact_names)?,
    })
}

pub fn load_manifest(path: &Path) -> anyhow::Result<ChallengeManifest> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read manifest {}: {e}", path.display()))?;
    let manifest: ChallengeManifest = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("invalid manifest JSON: {e}"))?;

    anyhow::ensure!(
        manifest.version == MANIFEST_VERSION,
        "unsupported manifest version: {}",
        manifest.version
    );
    anyhow::ensure!(
        !manifest.expected_age_pubkey.is_empty(),
        "manifest expected_age_pubkey must not be empty"
    );
    anyhow::ensure!(
        !manifest.git_commit.is_empty(),
        "manifest git_commit must not be empty"
    );
    manifest.kdf.to_config()?;

    Ok(manifest)
}

pub fn write_manifest(manifest: &ChallengeManifest, output: &Path) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(manifest)?;
    std::fs::write(output, json.as_bytes())?;
    Ok(())
}

pub fn sha256_prefixed(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("sha256:{}", hex::encode(hash))
}

fn hash_artifacts(
    artifact_dir: &Path,
    artifact_names: &[&str],
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut artifacts = BTreeMap::new();

    for name in artifact_names {
        let path = artifact_dir.join(name);
        let data = std::fs::read(&path)
            .map_err(|e| anyhow::anyhow!("failed to read artifact {}: {e}", path.display()))?;
        artifacts.insert((*name).to_owned(), sha256_prefixed(&data));
    }

    Ok(artifacts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kdf() -> KdfConfig {
        KdfConfig {
            salt: "test-salt".into(),
            m_cost_mib: 1,
            t_cost: 2,
            p_cost: 1,
        }
    }

    #[test]
    fn test_build_manifest_records_hashes_and_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.txt"), b"hello").expect("write");
        std::fs::write(dir.path().join("b.txt"), b"world").expect("write");

        let manifest = build_manifest(
            dir.path(),
            &["a.txt", "b.txt"],
            "age1test".into(),
            "deadbeef".into(),
            &test_kdf(),
        )
        .expect("build manifest");

        assert_eq!(manifest.version, MANIFEST_VERSION);
        assert_eq!(manifest.git_commit, "deadbeef");
        assert_eq!(manifest.expected_age_pubkey, "age1test");
        assert_eq!(manifest.kdf.algorithm, KDF_ALGORITHM);
        assert_eq!(
            manifest.documentation.challenger_guide,
            CHALLENGER_GUIDE_PATH
        );
        assert_eq!(
            manifest.artifacts["a.txt"],
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_write_and_load_manifest_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("manifest.json");
        let manifest = ChallengeManifest {
            version: MANIFEST_VERSION,
            git_commit: "deadbeef".into(),
            expected_age_pubkey: "age1expected".into(),
            kdf: ManifestKdf::from(&test_kdf()),
            documentation: DocumentationLinks {
                challenger_guide: CHALLENGER_GUIDE_PATH.into(),
            },
            artifacts: BTreeMap::from([("demo.bin".into(), "sha256:1234".into())]),
        };

        write_manifest(&manifest, &path).expect("write manifest");
        let loaded = load_manifest(&path).expect("load manifest");
        assert_eq!(loaded, manifest);
    }
}
