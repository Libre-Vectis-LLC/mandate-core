//! Helper functions for the `push_event` handler.
//!
//! Extracted from `push_event.rs` to keep the main handler file under the
//! 800-line module budget.  All functions here are `impl EventServiceImpl`
//! methods with `pub(super)` visibility so the handler can call them.

use super::super::to_status;
use super::service::EventServiceImpl;
use crate::billing::MeteringError;
use crate::event::RingUpdate;
use crate::hashing::ring_hash;
use crate::key_manager::manager::derive_poll_signing_ring;
use crate::ring_log::{apply_delta, RingDelta};
use crate::rpc::RpcError;
use mandate_proto::mandate::v1::PowChallenge;
use nazgul::ring::{Ring, RingContext};
use std::sync::Arc;
use tonic::Status;

impl EventServiceImpl {
    // ── vote-signing ring cache ─────────────────────────────────────────

    /// Look up or derive the per-poll vote signing ring.
    ///
    /// Results are cached in `self.vote_signing_ring_cache` so repeated
    /// vote submissions for the same poll avoid re-derivation.
    pub(super) async fn get_or_derive_vote_signing_ring(
        &self,
        tenant: crate::ids::TenantId,
        org_id: crate::ids::OrganizationId,
        poll_ring_hash: crate::ids::RingHash,
        poll_id: &str,
    ) -> Result<Arc<Ring>, Status> {
        let cache_key = (tenant, org_id, poll_ring_hash, poll_id.to_string());
        if let Some(cached) = self.vote_signing_ring_cache.get(&cache_key).await {
            return Ok(cached);
        }

        let poll_member_ring = self
            .store
            .ring_by_hash(tenant, org_id, &poll_ring_hash)
            .await
            .map_err(to_status)?;
        let vote_signing_ring =
            derive_poll_signing_ring(&org_id, &poll_ring_hash, poll_id, &poll_member_ring);
        let vote_signing_ring = Arc::new(vote_signing_ring);
        self.vote_signing_ring_cache
            .insert(cache_key, Arc::clone(&vote_signing_ring))
            .await;
        Ok(vote_signing_ring)
    }

    // ── Proof-of-Work helpers ───────────────────────────────────────────

    /// Build a `ResourceExhausted` status with POW challenge parameters encoded in details.
    ///
    /// The challenge is serialized as a protobuf `PowChallenge` message in the status details,
    /// allowing clients to parse the difficulty parameters and compute a valid proof.
    pub(super) fn make_pow_challenge_status(
        &self,
        tenant: crate::ids::TenantId,
        org_id: crate::ids::OrganizationId,
    ) -> Status {
        use prost::Message;

        let pow_key = (tenant, org_id);
        let multiplier = self
            .pow_states
            .get(&pow_key)
            .map(|s| s.get_current_multiplier())
            .unwrap_or(3.0);

        // Calculate POW parameters based on a conservative ring size estimate.
        // The actual ring size is unknown at this point (we haven't loaded it yet),
        // so we use a reasonable upper bound that produces adequate difficulty.
        let params = self.pow_calculator.calculate_pow_params(
            16,   // conservative ring size estimate
            1024, // conservative message size estimate
            multiplier,
        );

        let issued = match self.pow_verifier.issue_params(&params) {
            Ok(issued) => issued,
            Err(err) => {
                return Status::internal(format!("failed to issue POW challenge: {err}"));
            }
        };

        let pow_challenge = PowChallenge {
            bits: params.bits,
            required_proofs: params.required_proofs as u32,
            time_window_secs: params.time_window_secs,
            challenge: issued.deterministic_nonce.to_vec(),
            deterministic_nonce: issued.deterministic_nonce.to_vec(),
            timestamp: issued.timestamp,
        };

        // Encode PowChallenge into status details so clients can parse it.
        let details = pow_challenge.encode_to_vec();

        Status::with_details(
            tonic::Code::ResourceExhausted,
            format!(
                "pow_required: {} proofs at {} bits difficulty",
                params.required_proofs, params.bits
            ),
            details.into(),
        )
    }

    /// Verify a POW submission from the client.
    ///
    /// Converts the proto `PowSubmission` to the internal type and delegates
    /// to `PowVerifier`. Returns `Ok(())` if valid, or an appropriate `Status` error.
    pub(super) async fn verify_pow_submission(
        &self,
        tenant: crate::ids::TenantId,
        org_id: crate::ids::OrganizationId,
        proto_sub: &mandate_proto::mandate::v1::PowSubmission,
    ) -> Result<(), Status> {
        let submission_timestamp =
            u64::try_from(proto_sub.timestamp).map_err(|_| RpcError::InvalidArgument {
                field: "pow_submission.timestamp",
                reason: format!(
                    "expected non-negative timestamp, got {}",
                    proto_sub.timestamp
                ),
            })?;

        let expected_deterministic_nonce = self
            .pow_verifier
            .deterministic_nonce_for_timestamp(submission_timestamp);
        if !proto_sub.challenge.is_empty()
            && proto_sub.challenge.as_slice() != expected_deterministic_nonce
        {
            return Err(self.make_pow_challenge_status(tenant, org_id));
        }

        // Convert client_nonce from Vec<u8> to [u8; 32]
        let client_nonce: [u8; 32] =
            proto_sub.client_nonce.as_slice().try_into().map_err(|_| {
                RpcError::InvalidArgument {
                    field: "pow_submission.client_nonce",
                    reason: format!("expected 32 bytes, got {}", proto_sub.client_nonce.len()),
                }
            })?;

        let submission = crate::pow::PowSubmission::new(
            submission_timestamp,
            client_nonce,
            proto_sub.proof_bundle.clone(),
        );

        // Get current POW parameters for verification
        let pow_key = (tenant, org_id);
        let multiplier = self
            .pow_states
            .get(&pow_key)
            .map(|s| s.get_current_multiplier())
            .unwrap_or(3.0);

        let params = self
            .pow_calculator
            .calculate_pow_params(16, 1024, multiplier);

        match self
            .pow_verifier
            .verify_submission(&submission, &params)
            .await
        {
            Ok(result) if result.valid => Ok(()),
            Ok(_) => Err(RpcError::ResourceExhausted {
                resource: "pow_verification",
                limit: "proof verification failed".into(),
            }
            .into()),
            Err(e) => Err(RpcError::ResourceExhausted {
                resource: "pow_verification",
                limit: e.to_string(),
            }
            .into()),
        }
    }

    // ── Signature verification utilities ────────────────────────────────

    /// Return the ring size used for signature verification, if available.
    pub(super) fn verification_ring_size(
        sig: &crate::crypto::signature::Signature,
        external_ring: Option<&Ring>,
    ) -> Option<usize> {
        match sig.ring_context() {
            RingContext::Compact(_) => external_ring.map(|ring| ring.len()),
            RingContext::Archival(ring) => Some(ring.len()),
        }
    }

    /// Convert a [`MeteringError`] into a gRPC [`Status`].
    pub(super) fn verification_meter_error_to_status(error: MeteringError) -> Status {
        match error {
            MeteringError::InsufficientBalance {
                required,
                available,
            } => RpcError::ResourceExhausted {
                resource: "verification_balance",
                limit: format!("required {required}, available {available}"),
            }
            .into(),
            MeteringError::OrgNotFound(org_id) => RpcError::NotFound {
                resource: "organization",
                id: org_id,
            }
            .into(),
            MeteringError::TenantNotFound(tenant_id) => RpcError::NotFound {
                resource: "tenant",
                id: tenant_id,
            }
            .into(),
            MeteringError::StoreError(details) => RpcError::Internal {
                operation: "verification_meter",
                details,
            }
            .into(),
        }
    }

    // ── Ring update validation & application ────────────────────────────

    /// Validate and apply ring-update operations.
    ///
    /// 1. Verify that the declared ring hash matches the current stored ring.
    /// 2. Dry-run every delta against a clone of the current ring.
    /// 3. Persist each delta to storage.
    pub(super) async fn validate_and_apply_ring_update(
        &self,
        tenant: crate::ids::TenantId,
        org_id: crate::ids::OrganizationId,
        update: &RingUpdate,
    ) -> Result<(), Status> {
        let current_ring = self
            .store
            .current_ring(tenant, org_id)
            .await
            .map_err(to_status)?;
        let current_hash = ring_hash(&current_ring);
        if current_hash != update.ring_hash {
            return Err(RpcError::FailedPrecondition {
                operation: "ring_update",
                reason: "ring hash mismatch".into(),
            }
            .into());
        }

        let mut validation_ring = (*current_ring).clone();
        for operation in &update.operations {
            let delta = match operation {
                crate::event::RingOperation::AddMember { public_key, .. } => {
                    RingDelta::Add(*public_key)
                }
                crate::event::RingOperation::RemoveMember { public_key } => {
                    RingDelta::Remove(*public_key)
                }
            };
            apply_delta(&mut validation_ring, &delta).map_err(|e| {
                RpcError::FailedPrecondition {
                    operation: "ring_delta_validation",
                    reason: e.to_string(),
                }
            })?;
        }

        for operation in &update.operations {
            let delta = match operation {
                crate::event::RingOperation::AddMember { public_key, .. } => {
                    RingDelta::Add(*public_key)
                }
                crate::event::RingOperation::RemoveMember { public_key } => {
                    RingDelta::Remove(*public_key)
                }
            };
            self.store
                .append_ring_delta(tenant, org_id, delta)
                .await
                .map_err(to_status)?;
        }

        Ok(())
    }
}
