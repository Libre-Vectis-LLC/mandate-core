//! BLAKE3-XOF wrapper for mandate protocol paths that require 64-byte digest output.
//!
//! # Security analysis
//!
//! - Collision resistance: BLAKE3's 256-bit internal state yields about 128-bit collision
//!   resistance, which matches the security level of Curve25519/Ristretto and is sufficient for
//!   BLSAG challenge transcripts and compact ring-hash commitments.
//! - XOF output: extending BLAKE3 output to 64 bytes via XOF does not raise collision resistance
//!   above 128 bits, but it preserves the full security margin of the base hash while satisfying
//!   APIs that require `Digest<OutputSize = U64>`.
//! - `H_p(P)` mapping: nazgul and curve25519-dalek consume a 64-byte digest when mapping points to
//!   scalars or curve points. Feeding them BLAKE3 XOF output keeps the mapping deterministic,
//!   domain-separated, and free from ad hoc truncation.

use sha3::digest::consts::U64;
use sha3::digest::crypto_common::BlockSizeUser;
use sha3::digest::{FixedOutput, HashMarker, Output, OutputSizeUser, Update};

/// `blake3::Hasher` exposed as a 64-byte `Digest`.
#[derive(Clone)]
pub struct Blake3_512(blake3::Hasher);

impl Default for Blake3_512 {
    fn default() -> Self {
        Self(blake3::Hasher::new())
    }
}

impl OutputSizeUser for Blake3_512 {
    type OutputSize = U64;
}

impl BlockSizeUser for Blake3_512 {
    type BlockSize = U64;
}

impl Update for Blake3_512 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl FixedOutput for Blake3_512 {
    fn finalize_into(self, out: &mut Output<Self>) {
        let mut reader = self.0.finalize_xof();
        reader.fill(out.as_mut_slice());
    }
}

impl HashMarker for Blake3_512 {}

#[cfg(test)]
mod tests {
    use super::Blake3_512;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use hkdf::SimpleHkdf;
    use sha3::digest::consts::U64;
    use sha3::Digest;

    fn assert_digest_impl<D>()
    where
        D: Digest<OutputSize = U64> + Clone + Default,
    {
    }

    #[test]
    fn blake3_512_matches_direct_xof_output() {
        let message = b"mandate-blake3-512";

        let digest = Blake3_512::digest(message);

        let mut expected = [0u8; 64];
        let mut hasher = blake3::Hasher::new();
        hasher.update(message);
        hasher.finalize_xof().fill(&mut expected);

        assert_eq!(digest.as_slice(), expected);
    }

    #[test]
    fn blake3_512_satisfies_digest_trait_bounds() {
        assert_digest_impl::<Blake3_512>();
    }

    #[test]
    fn blake3_512_supports_hash_to_curve() {
        let left = RistrettoPoint::hash_from_bytes::<Blake3_512>(b"mandate:h_p");
        let right = RistrettoPoint::hash_from_bytes::<Blake3_512>(b"mandate:h_p");

        assert_eq!(left.compress().to_bytes(), right.compress().to_bytes());
    }

    #[test]
    fn blake3_512_supports_simple_hkdf() {
        let hkdf = SimpleHkdf::<Blake3_512>::new(None, b"ikm");
        let mut okm = [0u8; 32];

        hkdf.expand(b"info", &mut okm).expect("valid hkdf expand");

        assert_ne!(okm, [0u8; 32]);
    }
}
