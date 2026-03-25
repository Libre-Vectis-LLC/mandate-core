//! Artifact integrity auditing via manifest hash checks plus poll-bundle validation.

use std::collections::BTreeSet;
use std::path::Path;

use curve25519_dalek::ristretto::RistrettoPoint;
use mandate_core::event::{Event, EventType};
use mandate_core::hashing::ring_hash;
use mandate_core::ids::OrganizationId;
use mandate_core::key_manager::manager::derive_poll_signing_ring;
use mandate_verify::bundle::PollBundle;
use nazgul::ring::Ring;
use nazgul::traits::LocalByteConvertible;

use crate::manifest::{load_manifest, sha256_prefixed};

/// Result of auditing a single artifact or validation step.
#[derive(Debug)]
pub struct ArtifactCheck {
    /// Artifact or validation step name.
    pub name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Expected value or invariant.
    pub expected: String,
    /// Actual value or error detail.
    pub actual: String,
}

/// Audit all artifacts listed in `manifest.json` within `dir`.
///
/// In addition to verifying SHA-256 hashes from the manifest, this validates
/// that `poll-bundle.bin` decodes as protobuf and that a deterministic sample
/// of BLSAG signatures verifies successfully.
pub fn audit_artifacts(dir: &Path) -> anyhow::Result<Vec<ArtifactCheck>> {
    let manifest = load_manifest(&dir.join("manifest.json"))?;
    let mut results = Vec::with_capacity(manifest.artifacts.len() + 4);

    for (name, expected) in &manifest.artifacts {
        let artifact_path = dir.join(name);
        let data = std::fs::read(&artifact_path).map_err(|e| {
            anyhow::anyhow!("failed to read artifact {}: {e}", artifact_path.display())
        })?;

        let actual = sha256_prefixed(&data);
        let passed = actual == *expected;

        results.push(ArtifactCheck {
            name: name.clone(),
            passed,
            expected: expected.clone(),
            actual,
        });
    }

    if manifest.artifacts.contains_key("poll-bundle.bin") {
        results.extend(audit_poll_bundle(&dir.join("poll-bundle.bin")));
    }

    results.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(results)
}

fn audit_poll_bundle(path: &Path) -> Vec<ArtifactCheck> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(err) => {
            return vec![fail_check(
                "poll-bundle.bin::protobuf",
                "valid protobuf bundle",
                err.to_string(),
            )];
        }
    };

    match PollBundle::from_bytes(&data) {
        Ok(bundle) => {
            let mut checks = vec![pass_check(
                "poll-bundle.bin::protobuf",
                "valid protobuf bundle",
            )];
            checks.extend(audit_poll_bundle_signatures(&bundle));
            checks
        }
        Err(err) => {
            vec![fail_check(
                "poll-bundle.bin::protobuf",
                "valid protobuf bundle",
                err.to_string(),
            )]
        }
    }
}

fn audit_poll_bundle_signatures(bundle: &PollBundle) -> Vec<ArtifactCheck> {
    match audit_poll_bundle_signatures_inner(bundle) {
        Ok(checks) => checks,
        Err(err) => vec![fail_check(
            "poll-bundle.bin::signature-audit",
            "valid PollCreate and sampled VoteCast signatures",
            err.to_string(),
        )],
    }
}

fn audit_poll_bundle_signatures_inner(bundle: &PollBundle) -> anyhow::Result<Vec<ArtifactCheck>> {
    let master_ring = reconstruct_master_ring(&bundle.ring_member_pubs)?;
    let master_ring_hash = ring_hash(&master_ring);
    let org_id: OrganizationId = bundle
        .org_id
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid org_id in poll bundle: {}", bundle.org_id))?;

    let poll_event: Event = serde_json::from_slice(&bundle.poll_event_raw)
        .map_err(|e| anyhow::anyhow!("failed to parse PollCreate event JSON: {e}"))?;
    let poll_signature = poll_event
        .signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("PollCreate event is missing a signature"))?;
    let poll_signing_bytes = poll_event
        .to_signing_bytes()
        .map_err(|e| anyhow::anyhow!("failed to canonicalize PollCreate signing bytes: {e}"))?;

    let poll_check = match &poll_event.event_type {
        EventType::PollCreate(poll) => {
            anyhow::ensure!(
                poll.ring_hash == master_ring_hash,
                "PollCreate ring hash does not match reconstructed master ring"
            );
            let verified = poll_signature
                .verify(Some(&master_ring), None, &poll_signing_bytes)
                .map_err(|e| anyhow::anyhow!("PollCreate signature verification errored: {e}"))?;
            if verified {
                pass_check(
                    "poll-bundle.bin::poll-create-signature",
                    "valid archival BLSAG signature",
                )
            } else {
                fail_check(
                    "poll-bundle.bin::poll-create-signature",
                    "valid archival BLSAG signature",
                    "signature verification returned false",
                )
            }
        }
        other => fail_check(
            "poll-bundle.bin::poll-create-signature",
            "PollCreate event",
            format!("unexpected event type {}", other.as_str()),
        ),
    };

    let vote_ring =
        derive_poll_signing_ring(&org_id, &master_ring_hash, &bundle.poll_ulid, &master_ring);
    let vote_ring_hash = ring_hash(&vote_ring);

    let mut checks = vec![poll_check];
    for idx in sampled_vote_indices(bundle.vote_events_raw.len()) {
        let event: Event = serde_json::from_slice(&bundle.vote_events_raw[idx]).map_err(|e| {
            anyhow::anyhow!("failed to parse VoteCast event JSON at index {idx}: {e}")
        })?;
        let signature = event
            .signature
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("VoteCast event {idx} is missing a signature"))?;
        let signing_bytes = event
            .to_signing_bytes()
            .map_err(|e| anyhow::anyhow!("failed to canonicalize VoteCast {idx}: {e}"))?;

        let name = format!("poll-bundle.bin::vote-signature[{idx}]");
        let check = match &event.event_type {
            EventType::VoteCast(vote) => {
                anyhow::ensure!(
                    vote.poll_ring_hash == master_ring_hash,
                    "VoteCast {idx} poll_ring_hash does not match reconstructed master ring"
                );
                anyhow::ensure!(
                    vote.ring_hash == vote_ring_hash,
                    "VoteCast {idx} ring_hash does not match reconstructed vote ring"
                );
                let verified = signature
                    .verify(Some(&vote_ring), None, &signing_bytes)
                    .map_err(|e| {
                        anyhow::anyhow!("VoteCast {idx} signature verification errored: {e}")
                    })?;
                if verified {
                    pass_check(&name, "valid compact BLSAG signature")
                } else {
                    fail_check(
                        &name,
                        "valid compact BLSAG signature",
                        "signature verification returned false",
                    )
                }
            }
            other => fail_check(
                &name,
                "VoteCast event",
                format!("unexpected event type {}", other.as_str()),
            ),
        };
        checks.push(check);
    }

    Ok(checks)
}

fn reconstruct_master_ring(public_keys: &[String]) -> anyhow::Result<Ring> {
    let points: anyhow::Result<Vec<RistrettoPoint>> = public_keys
        .iter()
        .enumerate()
        .map(|(idx, pubkey)| {
            RistrettoPoint::from_base58(pubkey.clone())
                .map_err(|e| anyhow::anyhow!("invalid ring member public key at index {idx}: {e}"))
        })
        .collect();
    Ok(Ring::new(points?))
}

fn sampled_vote_indices(len: usize) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }

    let mut indices = BTreeSet::new();
    indices.insert(0);
    indices.insert(len / 2);
    indices.insert(len - 1);
    indices.into_iter().collect()
}

fn pass_check(name: impl Into<String>, expected: impl Into<String>) -> ArtifactCheck {
    let expected = expected.into();
    ArtifactCheck {
        name: name.into(),
        passed: true,
        actual: expected.clone(),
        expected,
    }
}

fn fail_check(
    name: impl Into<String>,
    expected: impl Into<String>,
    actual: impl Into<String>,
) -> ArtifactCheck {
    ArtifactCheck {
        name: name.into(),
        passed: false,
        expected: expected.into(),
        actual: actual.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::config::KdfConfig;
    use crate::manifest::{
        write_manifest, ChallengeManifest, DocumentationLinks, ManifestKdf, MANIFEST_VERSION,
    };

    fn write_manifest_for(dir: &Path, files: &[(&str, &[u8])]) {
        for (name, content) in files {
            std::fs::write(dir.join(name), content).expect("write artifact");
        }

        let artifacts = files
            .iter()
            .map(|(name, content)| ((*name).to_owned(), sha256_prefixed(content)))
            .collect::<BTreeMap<_, _>>();

        let manifest = ChallengeManifest {
            version: MANIFEST_VERSION,
            git_commit: "test-commit".into(),
            expected_age_pubkey: "age1test".into(),
            kdf: ManifestKdf::from(&KdfConfig {
                salt: "test-salt".into(),
                m_cost_mib: 1,
                t_cost: 1,
                p_cost: 1,
            }),
            documentation: DocumentationLinks {
                challenger_guide: "bounty-challenger.zh.md".into(),
            },
            artifacts,
        };
        write_manifest(&manifest, &dir.join("manifest.json")).expect("write manifest");
    }

    #[test]
    fn test_audit_all_pass() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_manifest_for(dir.path(), &[("a.txt", b"hello"), ("b.txt", b"world")]);

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
        write_manifest_for(dir.path(), &[("a.txt", b"hello"), ("b.txt", b"world")]);

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
            err.contains("manifest"),
            "error should mention manifest: {err}"
        );
    }

    #[test]
    fn test_audit_missing_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_manifest_for(dir.path(), &[("a.txt", b"hello")]);

        std::fs::remove_file(dir.path().join("a.txt")).expect("remove");

        let result = audit_artifacts(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("a.txt"),
            "error should mention missing file: {err}"
        );
    }

    #[test]
    fn test_audit_invalid_poll_bundle_protobuf() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_manifest_for(dir.path(), &[("poll-bundle.bin", b"not-protobuf")]);

        let results = audit_artifacts(dir.path()).expect("audit");
        let protobuf = results
            .iter()
            .find(|c| c.name == "poll-bundle.bin::protobuf")
            .expect("protobuf check");
        assert!(!protobuf.passed, "invalid protobuf should fail");
    }
}
