//! Canonical JSON serialization and hashing.

use crate::ids::ContentHash;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use super::primitives::{DigestAlgorithm, Sha3_256Digest};

/// Errors from canonical serialization and hashing.
#[derive(Debug, Error)]
pub enum CanonicalHashError {
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Serialize to canonical JSON (sorted keys, no whitespace) for stable hashing.
pub fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, CanonicalHashError> {
    let mut v = serde_json::to_value(value)?;
    canonicalize_json_value(&mut v);
    let mut buf = Vec::new();
    serde_json::to_writer(&mut buf, &v)?;
    Ok(buf)
}

/// Recursively canonicalize a JSON value by sorting object keys.
/// Arrays preserve their original order (semantically significant).
fn canonicalize_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> =
                map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            map.clear();
            for (k, mut v) in entries {
                canonicalize_json_value(&mut v);
                map.insert(k, v);
            }
        }
        Value::Array(items) => {
            for v in items.iter_mut() {
                canonicalize_json_value(v);
            }
        }
        _ => {}
    }
}

/// Compute a canonical content hash using SHA3-256 with domain separation.
pub fn canonical_content_hash_sha3_256(
    domain: &[u8],
    value: &impl Serialize,
) -> Result<ContentHash, CanonicalHashError> {
    let json = canonical_json(value)?;
    let hash = Sha3_256Digest::hash_with_domain(domain, &json);
    Ok(ContentHash(hash.into_inner()))
}
