//! Hashing helpers with a SHA3-first policy.
//!
//! - Default digest: SHA3-256.
//! - SHA3-512 is available when a longer digest is strictly required.
//! - Provides helpers for raw bytes, ciphertexts, and ring consensus hashes
//!   using nazgul's `Ring::consensus_hash`.

use crate::crypto::ciphertext::Ciphertext;
use crate::ids::ContentHash;
use nazgul::ring::{Ring, RingHash};
use sha3::{Digest, Sha3_256, Sha3_512};

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

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
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
}
