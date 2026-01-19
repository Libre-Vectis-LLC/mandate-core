//! Signature verification abstractions.
//!
//! This module defines a small, injectable verifier interface so that:
//! - WASM clients can verify locally,
//! - the CE server can reuse the same semantics,
//! - Enterprise can swap in faster / distributed implementations without changing RPC logic.

use crate::crypto::signature::Signature;
use async_trait::async_trait;
use nazgul::ring::Ring;
use std::sync::Arc;
use thiserror::Error;

/// One verification job.
#[derive(Clone, Debug)]
pub struct SignatureItem {
    /// The signature to verify.
    pub signature: Signature,
    /// The signed message bytes.
    pub message: Vec<u8>,
    /// Scheduling weight (per-item), forwarded to cluster verifiers. MVP default is 1.
    pub weight: u64,
    /// External ring required for compact signatures.
    pub external_ring: Option<Arc<Ring>>,
}

use crate::crypto::signature::SigVerificationError;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("internal verifier error: {0}")]
    Internal(String),
    #[error("signature verification error: {0}")]
    Signature(#[from] SigVerificationError),
}

/// Batch signature verifier (WASM-safe).
#[async_trait]
pub trait SignatureVerifier: Send + Sync {
    async fn verify_batch(&self, items: &[SignatureItem]) -> Result<Vec<bool>, VerificationError>;
}

/// Local verifier implementation.
///
/// This implementation is intentionally simple and sequential to stay WASM-friendly
/// and audit-friendly. Runtimes may parallelize at a higher layer if needed.
#[derive(Clone, Default, Debug)]
pub struct LocalSignatureVerifier;

#[async_trait]
impl SignatureVerifier for LocalSignatureVerifier {
    async fn verify_batch(&self, items: &[SignatureItem]) -> Result<Vec<bool>, VerificationError> {
        items
            .iter()
            .map(|item| {
                item.signature
                    .verify(item.external_ring.as_deref(), &item.message)
                    .map_err(VerificationError::from)
            })
            .collect()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::crypto::signature::{sign_contextual, SignatureKind, StorageMode};
    use nazgul::keypair::KeyPair;
    use rand::rngs::OsRng;

    fn make_ring(size: usize) -> (KeyPair, Arc<Ring>) {
        let mut csprng = OsRng;
        let signer = KeyPair::generate(&mut csprng);
        let mut members: Vec<_> = (0..size - 1)
            .map(|_| *KeyPair::generate(&mut csprng).public())
            .collect();
        members.push(*signer.public());
        (signer, Arc::new(Ring::new(members)))
    }

    #[tokio::test]
    async fn verify_batch_accepts_valid_archival_signature() {
        let (signer, ring) = make_ring(4);
        let msg = b"hello";
        let sig = sign_contextual(
            SignatureKind::Anonymous,
            StorageMode::Archival,
            &signer,
            ring.as_ref(),
            msg,
        )
        .expect("sign");

        let verifier = LocalSignatureVerifier;
        let items = [SignatureItem {
            signature: sig,
            message: msg.to_vec(),
            weight: 1,
            external_ring: None,
        }];
        let out = verifier.verify_batch(&items).await.expect("verify");
        assert_eq!(out, vec![true]);
    }

    #[tokio::test]
    async fn verify_batch_requires_external_ring_for_compact() {
        let (signer, ring) = make_ring(4);
        let msg = b"hello";
        let sig = sign_contextual(
            SignatureKind::Anonymous,
            StorageMode::Compact,
            &signer,
            ring.as_ref(),
            msg,
        )
        .expect("sign");

        let verifier = LocalSignatureVerifier;

        // Missing ring should return error
        let items = [SignatureItem {
            signature: sig.clone(),
            message: msg.to_vec(),
            weight: 1,
            external_ring: None,
        }];
        let err = verifier
            .verify_batch(&items)
            .await
            .expect_err("should error");
        assert!(matches!(err, VerificationError::Signature(_)));

        // With correct ring, verification should succeed
        let items = [SignatureItem {
            signature: sig,
            message: msg.to_vec(),
            weight: 1,
            external_ring: Some(ring.clone()),
        }];
        let out = verifier.verify_batch(&items).await.expect("verify");
        assert_eq!(out, vec![true]);
    }
}
