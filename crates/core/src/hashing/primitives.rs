//! Primitive hashing functions and types.

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

/// Derive a deterministic ring hash using nazgul's consensus hash with SHA3-512.
/// The underlying `Ring` already sorts members, so the result is order-invariant.
///
/// This matches the hash stored by ContextualBLSAG compact signatures
/// (Sha3_512 consensus hash truncated to 32 bytes).
pub fn ring_hash_sha3_256(ring: &Ring) -> RingHash {
    RingHash::from_output::<Sha3_512>(ring.consensus_hash::<Sha3_512>())
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
