//! Signature abstractions built on Nazgul `ContextualBLSAG`.
//!
//! - Uses Nazgul types directly (Ring, RingHash, ContextualBLSAG).
//! - Derives session/current keys from master using the current protocol ring hash.
//! - Exposes key images as `ids::KeyImage` (RistrettoPoint, uncompressed).
//! - Keeps APIs pure and panic-free; validates signer membership before signing.

use crate::hashing::{ring_hash, Blake3_512};
use crate::ids::KeyImage;
use nazgul::blsag::ContextualBLSAG;
use nazgul::keypair::KeyPair;
use nazgul::ring::{Ring, RingContext, RingHash};
use nazgul::traits::Derivable;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json;
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
        *self.proof.signature.key_image()
    }

    /// Return the storage mode (Compact/Archival).
    pub fn mode(&self) -> StorageMode {
        match &self.proof.context {
            RingContext::Compact(_) => StorageMode::Compact,
            RingContext::Archival(_) => StorageMode::Archival,
        }
    }

    /// Verify with BLAKE3-XOF-512; external ring required for compact mode.
    ///
    /// For Compact signatures, the external ring must be provided.
    /// The nazgul library internally validates that the ring matches the stored hash.
    pub fn verify(
        &self,
        external_ring: Option<&Ring>,
        precomputed: Option<&nazgul::ring::PreparedRing<Blake3_512>>,
        message: &[u8],
    ) -> Result<bool, SigVerificationError> {
        match self.mode() {
            StorageMode::Compact => {
                let ring = external_ring.ok_or(SigVerificationError::MissingRingForCompact)?;
                // The nazgul library's verify method internally validates
                // that the provided ring matches the stored ring hash
                Ok(self
                    .proof
                    .verify::<Blake3_512>(Some(ring), precomputed, message))
            }
            StorageMode::Archival => {
                Ok(self
                    .proof
                    .verify::<Blake3_512>(external_ring, precomputed, message))
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
            RingContext::Archival(ring) => ring_hash(ring),
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

    /// Derive a session keypair using ring context (BLAKE3-XOF-512 per protocol binding).
    pub fn derive_for_ring_context(&self, ctx: &RingContext) -> KeyPair {
        let rh = match ctx {
            RingContext::Compact(h) => h.to_owned(),
            RingContext::Archival(ring) => ring_hash(ring),
        };
        self.derive_for_context(&rh.0)
    }

    /// Derive using arbitrary context (BLAKE3-XOF-512).
    pub fn derive_for_context(&self, derivation: &[u8]) -> KeyPair {
        self.0.derive_child::<Blake3_512>(derivation)
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
            ContextualBLSAG::sign_compact::<Blake3_512, OsRng>(*secret, ring, None, message)
                .map_err(|e| CryptoHelperError::Nazgul(e.into()))?
        }
        StorageMode::Archival => {
            ContextualBLSAG::sign_archival::<Blake3_512, OsRng>(*secret, ring, None, message)
                .map_err(|e| CryptoHelperError::Nazgul(e.into()))?
        }
    };

    Ok(Signature { kind, proof })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
        assert!(sig.verify(Some(&ring), None, msg).expect("verify"));
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
            sig.verify(None, None, msg),
            Err(SigVerificationError::MissingRingForCompact)
        ));
        // With correct ring, verification should succeed
        assert!(sig.verify(Some(&ring), None, msg).expect("verify"));
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
        assert!(!sig.verify(Some(&wrong_ring), None, msg).expect("verify"));
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
            .derive_child::<Blake3_512>(&ring_hash.0);
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
        assert!(de.verify(Some(&ring), None, msg).expect("verify"));
        assert_eq!(sig.kind, de.kind);
        assert_eq!(sig.ring_hash(), de.ring_hash());
    }

    /// Test single-element ring signing for delegate key use case.
    /// This is critical for the delegate signer implementation where
    /// the delegate key signs with a ring containing only itself.
    #[test]
    fn single_element_ring_signing() {
        let (signer, ring) = make_ring(1);
        assert_eq!(ring.members().len(), 1);
        assert!(ring.members().contains(signer.public()));

        let msg = b"delegate-signed-event";

        // Test Archival mode (self-contained verification)
        let sig_archival = sign_contextual(
            SignatureKind::Authoritative,
            StorageMode::Archival,
            &signer,
            &ring,
            msg,
        )
        .expect("sign archival with single-element ring");

        assert!(
            sig_archival
                .verify(Some(&ring), None, msg)
                .expect("verify archival"),
            "single-element ring archival signature should verify"
        );

        // Test Compact mode (requires external ring for verification)
        let sig_compact = sign_contextual(
            SignatureKind::Authoritative,
            StorageMode::Compact,
            &signer,
            &ring,
            msg,
        )
        .expect("sign compact with single-element ring");

        assert!(
            sig_compact
                .verify(Some(&ring), None, msg)
                .expect("verify compact"),
            "single-element ring compact signature should verify"
        );

        // Verify key image is consistent
        let ki_archival = sig_archival.key_image();
        let ki_compact = sig_compact.key_image();
        assert_eq!(
            ki_archival.compress().to_bytes(),
            ki_compact.compress().to_bytes(),
            "key images should match regardless of storage mode"
        );
    }

    // Property-based tests using proptest

    proptest! {
        /// Property: Signature serialization roundtrip preserves verification.
        /// For any valid signature, serialize -> deserialize -> verify should succeed.
        #[test]
        fn prop_signature_serde_roundtrip(
            ring_size in 1usize..10,
            msg in prop::collection::vec(any::<u8>(), 0..256),
            use_compact in any::<bool>(),
            use_anonymous in any::<bool>(),
        ) {
            let (signer, ring) = make_ring(ring_size);
            let storage = if use_compact { StorageMode::Compact } else { StorageMode::Archival };
            let kind = if use_anonymous { SignatureKind::Anonymous } else { SignatureKind::Authoritative };

            let sig = sign_contextual(kind, storage, &signer, &ring, &msg)
                .expect("signing should succeed");

            // Serialize and deserialize
            let json = serde_json::to_string(&sig).expect("serialize");
            let deserialized: Signature = serde_json::from_str(&json).expect("deserialize");

            // Verification should still succeed
            let ring_ref = if storage == StorageMode::Compact { Some(&ring) } else { None };
            prop_assert!(deserialized.verify(ring_ref, None, &msg).expect("verify"));

            // Properties should be preserved
            prop_assert_eq!(sig.kind, deserialized.kind);
            prop_assert_eq!(sig.mode(), deserialized.mode());
            prop_assert_eq!(sig.ring_hash(), deserialized.ring_hash());
            prop_assert_eq!(
                sig.key_image().compress().to_bytes(),
                deserialized.key_image().compress().to_bytes()
            );
        }

        /// Property: Key derivation is deterministic.
        /// For any master key and context, deriving twice yields identical public keys.
        #[test]
        fn prop_key_derivation_deterministic(
            context_bytes in prop::collection::vec(any::<u8>(), 32),
        ) {
            let mut csprng = OsRng;
            let master = MasterKeypair::new(KeyPair::generate(&mut csprng));

            let derived1 = master.derive_for_context(&context_bytes);
            let derived2 = master.derive_for_context(&context_bytes);

            prop_assert_eq!(derived1.public(), derived2.public());
        }

        /// Property: Ring hash is order-invariant.
        /// The ring hash should be identical regardless of member insertion order.
        #[test]
        fn prop_ring_hash_order_invariant(
            ring_size in 2usize..10,
        ) {
            use crate::hashing::ring_hash;

            // Generate unique ring members
            let mut csprng = OsRng;
            let members: Vec<_> = (0..ring_size)
                .map(|_| *KeyPair::generate(&mut csprng).public())
                .collect();

            // Create rings with different orderings
            let mut shuffled = members.clone();
            shuffled.reverse();

            let ring1 = Ring::new(members);
            let ring2 = Ring::new(shuffled);

            let hash1 = ring_hash(&ring1);
            let hash2 = ring_hash(&ring2);

            prop_assert_eq!(hash1, hash2);
        }

        /// Property: Compact signature verification fails without correct ring.
        /// A compact signature must reject verification when given the wrong ring.
        #[test]
        fn prop_compact_signature_rejects_wrong_ring(
            ring_size in 2usize..10,
            msg in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            let (signer, ring) = make_ring(ring_size);
            let (_, wrong_ring) = make_ring(ring_size);

            let sig = sign_contextual(
                SignatureKind::Anonymous,
                StorageMode::Compact,
                &signer,
                &ring,
                &msg,
            )
            .expect("sign");

            // Correct ring should verify
            prop_assert!(sig.verify(Some(&ring), None, &msg).expect("verify"));

            // Wrong ring should fail (returns false, not error)
            prop_assert!(!sig.verify(Some(&wrong_ring), None, &msg).expect("verify"));
        }

        /// Property: Key image is stable across different messages.
        /// For the same signer and ring, signing different messages produces the same key image.
        /// This is a critical security property of BLSAG - the key image is bound to the
        /// signer's identity, not the message, enabling double-spend detection.
        #[test]
        fn prop_key_image_stable_across_messages(
            ring_size in 2usize..10,
            msg1 in prop::collection::vec(any::<u8>(), 1..256),
            msg2 in prop::collection::vec(any::<u8>(), 1..256),
        ) {
            prop_assume!(msg1 != msg2);

            let (signer, ring) = make_ring(ring_size);

            let sig1 = sign_contextual(
                SignatureKind::Anonymous,
                StorageMode::Archival,
                &signer,
                &ring,
                &msg1,
            )
            .expect("sign msg1");

            let sig2 = sign_contextual(
                SignatureKind::Anonymous,
                StorageMode::Archival,
                &signer,
                &ring,
                &msg2,
            )
            .expect("sign msg2");

            // Key images should be the SAME - bound to signer, not message
            // This allows detection of double-voting/double-signing
            prop_assert_eq!(
                sig1.key_image().compress().to_bytes(),
                sig2.key_image().compress().to_bytes()
            );
        }

        /// Property: Different signers produce different key images.
        /// Even with the same message and ring, different signers yield different key images.
        #[test]
        fn prop_different_signers_different_key_images(
            ring_size in 3usize..10,
            msg in prop::collection::vec(any::<u8>(), 1..256),
        ) {
            // Create two different signers in the same ring
            let mut csprng = OsRng;
            let signer1 = KeyPair::generate(&mut csprng);
            let signer2 = KeyPair::generate(&mut csprng);

            let mut members: Vec<_> = (0..ring_size - 2)
                .map(|_| *KeyPair::generate(&mut csprng).public())
                .collect();
            members.push(*signer1.public());
            members.push(*signer2.public());
            let ring = Ring::new(members);

            let sig1 = sign_contextual(
                SignatureKind::Anonymous,
                StorageMode::Archival,
                &signer1,
                &ring,
                &msg,
            )
            .expect("sign with signer1");

            let sig2 = sign_contextual(
                SignatureKind::Anonymous,
                StorageMode::Archival,
                &signer2,
                &ring,
                &msg,
            )
            .expect("sign with signer2");

            // Different signers should produce different key images
            prop_assert_ne!(
                sig1.key_image().compress().to_bytes(),
                sig2.key_image().compress().to_bytes()
            );
        }

        /// Property: Archival signatures are self-contained.
        /// Archival signatures should verify without external ring.
        #[test]
        fn prop_archival_signature_self_contained(
            ring_size in 1usize..10,
            msg in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            let (signer, ring) = make_ring(ring_size);

            let sig = sign_contextual(
                SignatureKind::Anonymous,
                StorageMode::Archival,
                &signer,
                &ring,
                &msg,
            )
            .expect("sign");

            // Should verify without external ring
            prop_assert!(sig.verify(None, None, &msg).expect("verify"));

            // Should also verify with ring provided
            prop_assert!(sig.verify(Some(&ring), None, &msg).expect("verify"));
        }
    }
}
