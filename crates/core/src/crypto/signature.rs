//! Signature abstractions built on Nazgul `ContextualBLSAG`.
//!
//! - Uses Nazgul types directly (Ring, RingHash, ContextualBLSAG).
//! - Derives session/current keys from master using ring hash (SHA3-256 for performance).
//! - Exposes key images as `ids::KeyImage` (RistrettoPoint, uncompressed).
//! - Keeps APIs pure and panic-free; validates signer membership before signing.

use crate::hashing::ring_hash_sha3_256;
use crate::ids::KeyImage;
use nazgul::blsag::ContextualBLSAG;
use nazgul::keypair::KeyPair;
use nazgul::ring::{Ring, RingContext, RingHash};
use nazgul::traits::Derivable;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json;
use sha3::Sha3_512;
use thiserror::Error;

/// Storage mode of the contextual signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageMode {
    Compact,
    Archival,
}

/// Semantic role of the signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureKind {
    Anonymous,
    Authoritative,
}

/// Unified signature for mandate events.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub kind: SignatureKind,
    pub proof: ContextualBLSAG,
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        if self.kind != other.kind {
            return false;
        }
        serialize_proof(&self.proof) == serialize_proof(&other.proof)
    }
}

impl Eq for Signature {}

fn serialize_proof(proof: &ContextualBLSAG) -> Option<Vec<u8>> {
    // Serde-based comparison to avoid implementing equality for third-party types.
    serde_json::to_vec(proof).ok()
}

impl Signature {
    /// Extract the key image (uncompressed Ristretto point).
    pub fn key_image(&self) -> KeyImage {
        self.proof.signature.key_image()
    }

    /// Return the storage mode (Compact/Archival).
    pub fn mode(&self) -> StorageMode {
        match &self.proof.context {
            RingContext::Compact(_) => StorageMode::Compact,
            RingContext::Archival(_) => StorageMode::Archival,
        }
    }

    /// Verify with SHA3-512; external ring required for compact mode.
    ///
    /// For Compact signatures, the external ring must be provided.
    /// The nazgul library internally validates that the ring matches the stored hash.
    pub fn verify(
        &self,
        external_ring: Option<&Ring>,
        message: &[u8],
    ) -> Result<bool, SigVerificationError> {
        match self.mode() {
            StorageMode::Compact => {
                let ring = external_ring.ok_or(SigVerificationError::MissingRingForCompact)?;
                // The nazgul library's verify method internally validates
                // that the provided ring matches the stored ring hash
                Ok(self.proof.verify::<Sha3_512>(Some(ring), None, message))
            }
            StorageMode::Archival => {
                Ok(self.proof.verify::<Sha3_512>(external_ring, None, message))
            }
        }
    }

    pub fn ring_context(&self) -> &RingContext {
        &self.proof.context
    }

    /// Ring hash associated with this signature (32-byte).
    pub fn ring_hash(&self) -> RingHash {
        match &self.proof.context {
            RingContext::Compact(h) => h.to_owned(),
            RingContext::Archival(ring) => ring_hash_sha3_256(ring),
        }
    }
}

/// Wrapper for the master keypair to derive session/current keys.
#[derive(Clone, Debug)]
pub struct MasterKeypair(pub KeyPair);

/// Wrapper for derived/session keypairs (to differentiate from master).
#[derive(Clone, Debug)]
pub struct NazgulKeypair(pub KeyPair);

impl MasterKeypair {
    pub fn new(inner: KeyPair) -> Self {
        Self(inner)
    }

    pub fn as_keypair(&self) -> &KeyPair {
        &self.0
    }

    pub fn public(&self) -> &curve25519_dalek::ristretto::RistrettoPoint {
        self.0.public()
    }

    /// Derive a session keypair using ring context (SHA3-512 per nazgul bound).
    pub fn derive_for_ring_context(&self, ctx: &RingContext) -> KeyPair {
        let rh = match ctx {
            RingContext::Compact(h) => h.to_owned(),
            RingContext::Archival(ring) => ring_hash_sha3_256(ring),
        };
        self.derive_for_context(&rh.0)
    }

    /// Derive using arbitrary context (SHA3-512).
    pub fn derive_for_context(&self, derivation: &[u8]) -> KeyPair {
        self.0.derive_child::<Sha3_512>(derivation)
    }
}

/// Errors from signature verification.
#[derive(Debug, Error)]
pub enum SigVerificationError {
    #[error("compact signature requires external ring for verification")]
    MissingRingForCompact,
}

/// Errors from signing helpers.
#[derive(Debug, Error)]
pub enum CryptoHelperError {
    #[error("signer's public key not found in ring")]
    SignerNotInRing,
    #[error("signing key is not available (public-only keypair)")]
    MissingSecret,
    #[error("nazgul error: {0}")]
    Nazgul(#[from] anyhow::Error),
}

/// Sign a message using ContextualBLSAG in the requested storage mode.
pub fn sign_contextual(
    kind: SignatureKind,
    storage: StorageMode,
    signer: &KeyPair,
    ring: &Ring,
    message: &[u8],
) -> Result<Signature, CryptoHelperError> {
    if !ring.members().contains(signer.public()) {
        return Err(CryptoHelperError::SignerNotInRing);
    }

    let secret = signer.secret().ok_or(CryptoHelperError::MissingSecret)?;

    let proof = match storage {
        StorageMode::Compact => {
            ContextualBLSAG::sign_compact::<Sha3_512, OsRng>(*secret, ring, None, message)
                .map_err(|e| CryptoHelperError::Nazgul(e.into()))?
        }
        StorageMode::Archival => {
            ContextualBLSAG::sign_archival::<Sha3_512, OsRng>(*secret, ring, None, message)
                .map_err(|e| CryptoHelperError::Nazgul(e.into()))?
        }
    };

    Ok(Signature { kind, proof })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ring(size: usize) -> (KeyPair, Ring) {
        let mut csprng = OsRng;
        let signer = KeyPair::generate(&mut csprng);
        let mut members: Vec<_> = (0..size - 1)
            .map(|_| *KeyPair::generate(&mut csprng).public())
            .collect();
        members.push(*signer.public());
        let ring = Ring::new(members);
        (signer, ring)
    }

    #[test]
    fn key_image_extracted() {
        let (signer, ring) = make_ring(3);
        let msg = b"hello";
        let sig = sign_contextual(
            SignatureKind::Anonymous,
            StorageMode::Archival,
            &signer,
            &ring,
            msg,
        )
        .expect("sign");
        let ki = sig.key_image();
        assert_eq!(ki.compress().to_bytes().len(), 32);
        assert!(sig.verify(Some(&ring), msg).expect("verify"));
    }

    #[test]
    fn compact_signature_needs_ring() {
        let (signer, ring) = make_ring(4);
        let msg = b"compact";
        let sig = sign_contextual(
            SignatureKind::Anonymous,
            StorageMode::Compact,
            &signer,
            &ring,
            msg,
        )
        .expect("sign");
        // Compact signature without ring should return error
        assert!(matches!(
            sig.verify(None, msg),
            Err(SigVerificationError::MissingRingForCompact)
        ));
        // With correct ring, verification should succeed
        assert!(sig.verify(Some(&ring), msg).expect("verify"));
    }

    #[test]
    fn compact_signature_rejects_wrong_ring() {
        let (signer, ring) = make_ring(4);
        let (_, wrong_ring) = make_ring(4); // Different ring
        let msg = b"compact";
        let sig = sign_contextual(
            SignatureKind::Anonymous,
            StorageMode::Compact,
            &signer,
            &ring,
            msg,
        )
        .expect("sign");
        // Wrong ring should fail verification (returns false, not error)
        // The nazgul library internally validates the ring hash
        assert!(!sig.verify(Some(&wrong_ring), msg).expect("verify"));
    }

    #[test]
    fn derive_for_ring_context_deterministic() {
        let mut csprng = OsRng;
        let master = MasterKeypair::new(KeyPair::generate(&mut csprng));
        let ring_hash = RingHash([42u8; 32]);
        let ctx = RingContext::Compact(ring_hash.to_owned());
        let k1 = master.derive_for_ring_context(&ctx);
        let k2 = master.derive_for_ring_context(&ctx);
        assert_eq!(k1.public(), k2.public());

        // Ensure derivation uses ring hash bytes (indirect check via Derivable trait)
        let pub_from_master = master
            .as_keypair()
            .public()
            .derive_child::<Sha3_512>(&ring_hash.0);
        assert_eq!(k1.public(), &pub_from_master);
    }

    #[test]
    fn signature_serde_roundtrip_preserves_verification() {
        let (signer, ring) = make_ring(4);
        let msg = b"serde";
        let sig = sign_contextual(
            SignatureKind::Anonymous,
            StorageMode::Compact,
            &signer,
            &ring,
            msg,
        )
        .expect("sign");

        let json = serde_json::to_string(&sig).expect("serialize");
        let de: Signature = serde_json::from_str(&json).expect("deserialize");
        assert!(de.verify(Some(&ring), msg).expect("verify"));
        assert_eq!(sig.kind, de.kind);
        assert_eq!(sig.ring_hash(), de.ring_hash());
    }
}
