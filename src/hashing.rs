//! Hashing helpers with a SHA3-first policy.
//!
//! - Default digest: SHA3-256.
//! - SHA3-512 is available when a longer digest is strictly required.
//! - Provides helpers for raw bytes, ciphertexts, and ring consensus hashes
//!   using nazgul's `Ring::consensus_hash`.

use crate::crypto::ciphertext::Ciphertext;
use crate::ids::ContentHash;
use nazgul::ring::{Ring, RingHash};
use serde::Serialize;
use serde_json::Value;
use sha3::{Digest, Sha3_256, Sha3_512};
use thiserror::Error;

/// 256-bit hash output type (newtype for stronger typing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; 32]> for Hash256 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 512-bit hash output type (newtype for stronger typing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hash512(pub [u8; 64]);

impl Hash512 {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn into_inner(self) -> [u8; 64] {
        self.0
    }
}

impl From<[u8; 64]> for Hash512 {
    fn from(value: [u8; 64]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; 64]> for Hash512 {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Hash arbitrary bytes with SHA3-256.
pub fn sha3_256_bytes(data: impl AsRef<[u8]>) -> Hash256 {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    Hash256(hasher.finalize().into())
}

/// Hash arbitrary bytes with SHA3-512 (use only when digest extension is required).
pub fn sha3_512_bytes(data: impl AsRef<[u8]>) -> Hash512 {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    Hash512(hasher.finalize().into())
}

/// Compute a `ContentHash` for plaintext bytes using SHA3-256.
pub fn content_hash_bytes(data: impl AsRef<[u8]>) -> ContentHash {
    ContentHash(sha3_256_bytes(data).into_inner())
}

/// Compute a `ContentHash` over an encrypted payload.
pub fn content_hash_ciphertext(ciphertext: &Ciphertext) -> ContentHash {
    ContentHash(sha3_256_bytes(&ciphertext.0).into_inner())
}

/// Derive a deterministic ring hash using nazgul's consensus hash with SHA3-256.
/// The underlying `Ring` already sorts members, so the result is order-invariant.
pub fn ring_hash_sha3_256(ring: &Ring) -> RingHash {
    let bytes: [u8; 32] = ring.consensus_hash::<Sha3_256>().into();
    RingHash(bytes)
}

/// Domain prefixes for hashing distinct mandate payloads.
pub mod domain {
    /// Domain prefix for events.
    pub const EVENT: &[u8] = b"mandate:event";
    /// Domain prefix for polls.
    pub const POLL: &[u8] = b"mandate:poll";
    /// Domain prefix for votes.
    pub const VOTE: &[u8] = b"mandate:vote";
    /// Domain prefix for messages.
    pub const MESSAGE: &[u8] = b"mandate:message";
    /// Domain prefix for ring snapshots or deltas.
    pub const RING: &[u8] = b"mandate:ring";
}

/// Errors from canonical serialization and hashing.
#[derive(Debug, Error)]
pub enum CanonicalHashError {
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Digest trait to allow future hash algorithm swaps (e.g., BLAKE3) without API breakage.
pub trait DigestAlgorithm {
    type Output;

    /// Hash `domain || message`, returning the algorithm-specific output type.
    fn hash_with_domain(domain: &[u8], message: &[u8]) -> Self::Output;
}

/// SHA3-256 digest algorithm (default).
pub struct Sha3_256Digest;

impl DigestAlgorithm for Sha3_256Digest {
    type Output = Hash256;

    fn hash_with_domain(domain: &[u8], message: &[u8]) -> Self::Output {
        let mut hasher = Sha3_256::new();
        hasher.update(domain);
        hasher.update(message);
        Hash256(hasher.finalize().into())
    }
}

/// SHA3-512 digest algorithm for extended outputs.
pub struct Sha3_512Digest;

impl DigestAlgorithm for Sha3_512Digest {
    type Output = Hash512;

    fn hash_with_domain(domain: &[u8], message: &[u8]) -> Self::Output {
        let mut hasher = Sha3_512::new();
        hasher.update(domain);
        hasher.update(message);
        Hash512(hasher.finalize().into())
    }
}

/// Serialize to canonical JSON (sorted keys, no whitespace) for stable hashing.
pub fn canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>, CanonicalHashError> {
    let mut v = serde_json::to_value(value)?;
    normalize_value(&mut v);
    let mut buf = Vec::new();
    serde_json::to_writer(&mut buf, &v)?;
    Ok(buf)
}

fn normalize_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> =
                map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            map.clear();
            for (k, mut v) in entries {
                normalize_value(&mut v);
                map.insert(k, v);
            }
        }
        Value::Array(items) => {
            for v in items.iter_mut() {
                normalize_value(v);
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
    let json = canonical_json_bytes(value)?;
    let hash = Sha3_256Digest::hash_with_domain(domain, &json);
    Ok(ContentHash(hash.into_inner()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use serde::Serialize;
    use sha3::Sha3_512;

    fn point(label: &[u8]) -> RistrettoPoint {
        RistrettoPoint::hash_from_bytes::<Sha3_512>(label)
    }

    #[test]
    fn sha3_256_deterministic() {
        let h1 = sha3_256_bytes(b"mandate");
        let h2 = sha3_256_bytes(b"mandate");
        assert_eq!(h1, h2);
    }

    #[test]
    fn ring_hash_order_invariant() {
        let p1 = point(b"member-1");
        let p2 = point(b"member-2");
        let p3 = point(b"member-3");

        let ring_a = Ring::new(vec![p1, p2, p3]);
        let ring_b = Ring::new(vec![p3, p1, p2]);

        let ha = ring_hash_sha3_256(&ring_a);
        let hb = ring_hash_sha3_256(&ring_b);

        assert_eq!(ha, hb, "ring hash should be independent of input order");
    }

    #[test]
    fn content_hash_ciphertext_matches_bytes() {
        let payload = b"sealed".to_vec();
        let ct = Ciphertext(payload.clone());
        assert_eq!(
            content_hash_ciphertext(&ct).0,
            content_hash_bytes(&payload).0
        );
    }

    #[derive(Serialize)]
    struct DemoObj {
        b: u8,
        a: u8,
    }

    #[test]
    fn canonical_json_sorts_keys_and_hashes() {
        let obj1 = DemoObj { a: 1, b: 2 };
        let obj2 = DemoObj { b: 2, a: 1 };

        let j1 = canonical_json_bytes(&obj1).expect("json");
        let j2 = canonical_json_bytes(&obj2).expect("json");
        assert_eq!(j1, j2, "canonical JSON must be order independent");

        let h1 = canonical_content_hash_sha3_256(domain::EVENT, &obj1).expect("hash");
        let h2 = canonical_content_hash_sha3_256(domain::EVENT, &obj2).expect("hash");
        assert_eq!(h1, h2, "hash should ignore map insertion order");
    }

    #[test]
    fn domain_separation_alters_hash() {
        let obj = DemoObj { a: 7, b: 9 };
        let h_event =
            canonical_content_hash_sha3_256(domain::EVENT, &obj).expect("hash event domain");
        let h_poll = canonical_content_hash_sha3_256(domain::POLL, &obj).expect("hash poll domain");
        assert_ne!(h_event, h_poll, "domain separator must change digest");
    }

    #[derive(Serialize)]
    struct WithArray {
        items: Vec<u8>,
    }

    #[test]
    fn arrays_preserve_order() {
        let ascending = WithArray {
            items: vec![1, 2, 3],
        };
        let descending = WithArray {
            items: vec![3, 2, 1],
        };

        let h1 = canonical_content_hash_sha3_256(domain::EVENT, &ascending).expect("hash");
        let h2 = canonical_content_hash_sha3_256(domain::EVENT, &descending).expect("hash");
        assert_ne!(h1, h2, "array order must remain significant");
    }
}
