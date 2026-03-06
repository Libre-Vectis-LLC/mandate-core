//! push_event gRPC handler implementation.

use super::service::EventServiceImpl;
use super::validation::banned_operation_for_event;
use crate::billing::MeteringError;
use crate::event::Event;
use crate::hashing::ring_hash_sha3_256;
use crate::key_manager::manager::derive_poll_signing_ring;
use crate::ring_log::{apply_delta, RingDelta};
use crate::rpc::RpcError;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use mandate_proto::mandate::v1::{PushEventRequest, PushEventResponse};
use nazgul::keypair::KeyPair as NazgulKeyPair;
use nazgul::ring::{Ring, RingContext};
use nazgul::traits::Derivable;
use sha3::Sha3_512;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use mandate_proto::mandate::v1::PowChallenge;

use super::super::{
    extract_tenant_id, max_event_bytes, max_message_content_chars, max_poll_id_length, to_status,
};

impl EventServiceImpl {
    pub(super) async fn push_event(
        &self,
        request: Request<PushEventRequest>,
    ) -> Result<Response<PushEventResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let event_bytes: crate::storage::EventBytes = body.event_bytes.into();
        if event_bytes.len() > max_event_bytes() {
            return Err(RpcError::InvalidArgument {
                field: "event_bytes",
                reason: format!("too large: {} > {}", event_bytes.len(), max_event_bytes()),
            }
            .into());
        }
        let mut event: Event =
            serde_json::from_slice(&event_bytes).map_err(|e| RpcError::InvalidArgument {
                field: "event_bytes",
                reason: format!("invalid JSON payload: {e}"),
            })?;

        // Verify tenant owns the organization referenced by this event
        let (org_tenant, _) = self
            .store
            .get_organization(event.org_id)
            .await
            .map_err(to_status)?;
        if tenant != org_tenant {
            return Err(RpcError::NotFound {
                resource: "organization",
                id: "not found".into(),
            }
            .into());
        }

        // Validate poll_id length for poll/vote events to prevent resource exhaustion
        let max_id_len = max_poll_id_length();
        match &event.event_type {
            crate::event::EventType::PollCreate(poll) => {
                if poll.poll_id.len() > max_id_len {
                    return Err(RpcError::InvalidArgument {
                        field: "poll_id",
                        reason: format!("too long: {} > {}", poll.poll_id.len(), max_id_len),
                    }
                    .into());
                }
                for q in &poll.questions {
                    if q.question_id.len() > max_id_len {
                        return Err(RpcError::InvalidArgument {
                            field: "question_id",
                            reason: format!("too long: {} > {}", q.question_id.len(), max_id_len),
                        }
                        .into());
                    }
                }
            }
            crate::event::EventType::VoteCast(vote) => {
                if vote.poll_id.len() > max_id_len {
                    return Err(RpcError::InvalidArgument {
                        field: "poll_id",
                        reason: format!("too long: {} > {}", vote.poll_id.len(), max_id_len),
                    }
                    .into());
                }
            }
            crate::event::EventType::MessageCreate(msg) => {
                // Count UTF-8 characters (not bytes) for proper international text support
                let content_chars = String::from_utf8_lossy(&msg.content.0).chars().count();
                let max_chars = max_message_content_chars();
                if content_chars > max_chars {
                    return Err(RpcError::InvalidArgument {
                        field: "message_content",
                        reason: format!(
                            "too long: {} characters > {} limit",
                            content_chars, max_chars
                        ),
                    }
                    .into());
                }
            }
            _ => {}
        }

        // Validate poll existence for VoteCast events (before expensive signature verification)
        // This provides fast-path rejection for votes targeting non-existent polls.
        //
        // SECURITY: We MUST reject NotFound because signature verification alone cannot
        // validate poll existence - it only verifies the ring hash is valid. An attacker
        // could craft a VoteCast with any valid ring hash but a fake poll_id.
        if let crate::event::EventType::VoteCast(vote) = &event.event_type {
            match self
                .store
                .get_poll_ring_hash(tenant, event.org_id, &vote.poll_id)
                .await
            {
                Ok(poll_ring_hash) => {
                    // Poll exists — verify the vote's declared poll_ring_hash matches
                    // the ring hash snapshot stored at poll creation time.
                    //
                    // SECURITY: Without this check, an attacker could cast a vote using
                    // a newer (or different) ring while claiming it targets a poll that
                    // was created under a different ring. This binds votes to the exact
                    // ring membership that existed when the poll was created.
                    if vote.poll_ring_hash != poll_ring_hash {
                        return Err(RpcError::FailedPrecondition {
                            operation: "vote_ring_binding",
                            reason: "vote.poll_ring_hash does not match poll snapshot".into(),
                        }
                        .into());
                    }
                }
                Err(crate::storage::StorageError::NotFound(_)) => {
                    // Poll not found in ring-hash index - reject the vote.
                    // This prevents votes against non-existent polls.
                    return Err(RpcError::FailedPrecondition {
                        operation: "poll_existence",
                        reason: format!("poll does not exist: {}", vote.poll_id),
                    }
                    .into());
                }
                Err(other) => return Err(to_status(other)),
            }
        }

        // 1. Auto-fill Chain Hash
        //
        // The server automatically assigns the correct previous_event_hash based on chain state.
        // This enables O(n) concurrent event submissions without client re-signing on conflicts.
        //
        // Security note: Chain integrity is enforced by Party A's Edge and Bot monitoring.
        // The signature does NOT include previous_event_hash (see Event::to_signing_bytes).
        match self.store.event_tail(tenant, event.org_id).await {
            Ok((tail_id, _, _)) => {
                // Chain exists - set previous_event_hash to current tail
                event.previous_event_hash = crate::ids::EventId(tail_id.0);
            }
            Err(crate::storage::StorageError::NotFound(_)) => {
                // Genesis event - set zero prev hash
                event.previous_event_hash = crate::ids::EventId([0u8; 32]);
            }
            Err(e) => return Err(to_status(e)),
        }

        let sig = event
            .signature
            .as_ref()
            .ok_or_else(|| RpcError::Unauthenticated {
                credential: "signature",
                reason: "missing".into(),
            })?;
        let key_image = sig.key_image();

        // 2. Cheap checks (anti-replay, bans)
        if let crate::event::EventType::VoteCast(vote) = &event.event_type {
            let used = self
                .store
                .is_vote_key_image_used(tenant, event.org_id, &vote.poll_id, &key_image)
                .await
                .map_err(to_status)?;
            if used {
                return Err(RpcError::FailedPrecondition {
                    operation: "vote_cast",
                    reason: "duplicate key image (vote already cast)".into(),
                }
                .into());
            }
        }

        if let Some(operation) = banned_operation_for_event(&event.event_type) {
            let banned = self
                .store
                .is_banned(tenant, event.org_id, &key_image, operation)
                .await
                .map_err(to_status)?;
            if banned {
                return Err(RpcError::FailedPrecondition {
                    operation: "banned_check",
                    reason: format!("key image banned for {:?}", operation),
                }
                .into());
            }
        }

        // 2b. Verify owner/delegate for admin events (ban + ring management)
        let delegate_external_ring = match &event.event_type {
            crate::event::EventType::BanCreate(_)
            | crate::event::EventType::BanRevoke(_)
            | crate::event::EventType::RingUpdate(_) => {
                // Get owner's public key from storage
                let owner_pubkey = self
                    .store
                    .get_owner_pubkey(event.org_id)
                    .await
                    .map_err(to_status)?
                    .ok_or_else(|| RpcError::FailedPrecondition {
                        operation: "delegate_verification",
                        reason: "owner public key not set".into(),
                    })?;

                // Decompress owner's public key to a RistrettoPoint
                let compressed = CompressedRistretto::from_slice(&owner_pubkey.0).map_err(|e| {
                    RpcError::FailedPrecondition {
                        operation: "delegate_verification",
                        reason: format!("invalid owner public key: {e}"),
                    }
                })?;
                let owner_point: RistrettoPoint =
                    compressed
                        .decompress()
                        .ok_or_else(|| RpcError::FailedPrecondition {
                            operation: "delegate_verification",
                            reason: "invalid owner public key".into(),
                        })?;

                // Create owner keypair (public key only) for derivation
                let owner_kp = NazgulKeyPair::from_public_key_only(owner_point);

                // Derive delegate key using org_id as context
                let org_bytes = event.org_id.to_bytes();
                let mut ctx =
                    Vec::with_capacity(b"mandate-delegate-signer-v1".len() + org_bytes.len());
                ctx.extend_from_slice(b"mandate-delegate-signer-v1");
                ctx.extend_from_slice(&org_bytes);

                let delegate_kp = owner_kp.derive_child::<Sha3_512>(&ctx);

                // Build single-element ring containing only the delegate public key
                let delegate_ring = Ring::new(vec![*delegate_kp.public()]);
                let delegate_hash = ring_hash_sha3_256(&delegate_ring);

                // Verify that the signature's ring hash matches the expected delegate ring hash
                // Use sig.ring_hash() as the authoritative source for what ring was used to sign
                let actual_ring_hash = sig.ring_hash();
                if actual_ring_hash != delegate_hash {
                    return Err(RpcError::PermissionDenied {
                        resource: "admin_event",
                        reason: "signature ring is not the owner/delegate ring".into(),
                    }
                    .into());
                }

                // Only provide delegate ring for Compact mode; Archival mode embeds its own ring
                match sig.mode() {
                    crate::crypto::signature::StorageMode::Compact => Some(Arc::new(delegate_ring)),
                    crate::crypto::signature::StorageMode::Archival => None,
                }
            }
            _ => None,
        };

        // 2c. Check ban limit for BanCreate events (OOM protection)
        if let crate::event::EventType::BanCreate(ban) = &event.event_type {
            let current_count = self
                .store
                .count_bans_for_ring(tenant, event.org_id, &ban.ring_hash)
                .await
                .map_err(to_status)?;
            if current_count >= crate::storage::MAX_BANS_PER_RING_HASH {
                return Err(RpcError::FailedPrecondition {
                    operation: "ban_create",
                    reason: format!(
                        "too many bans for ring hash (limit: {})",
                        crate::storage::MAX_BANS_PER_RING_HASH
                    ),
                }
                .into());
            }
        }

        // 3. POW gate: if this org is in POW mode, require valid proof before
        //    spending CPU on expensive signature verification.
        let mut pow_proof_count: Option<usize> = None;
        {
            let pow_key = (tenant, event.org_id);
            let pow_required = self
                .pow_states
                .get(&pow_key)
                .map(|s| s.should_require_pow())
                .unwrap_or(false);

            if pow_required {
                match &body.pow_submission {
                    None => {
                        // POW required but not provided — return challenge parameters.
                        return Err(self.make_pow_challenge_status(tenant, event.org_id));
                    }
                    Some(proto_sub) => {
                        // Validate the submitted POW proof.
                        self.verify_pow_submission(tenant, event.org_id, proto_sub)
                            .await?;
                        // Track proof count for billing after signature verification.
                        let multiplier = self
                            .pow_states
                            .get(&pow_key)
                            .map(|s| s.get_current_multiplier())
                            .unwrap_or(3.0);
                        let params = self
                            .pow_calculator
                            .calculate_pow_params(16, 1024, multiplier);
                        pow_proof_count = Some(params.required_proofs as usize);
                    }
                }
            }
        }

        // 3b. Verify Signature
        // Load ring if needed (Compact signature)
        let external_ring = if let Some(ring) = delegate_external_ring {
            Some(ring)
        } else {
            match sig.mode() {
                crate::crypto::signature::StorageMode::Compact => {
                    if let crate::event::EventType::VoteCast(vote) = &event.event_type {
                        let vote_signing_ring = self
                            .get_or_derive_vote_signing_ring(
                                tenant,
                                event.org_id,
                                vote.poll_ring_hash,
                                &vote.poll_id,
                            )
                            .await?;
                        let expected_vote_ring_hash =
                            ring_hash_sha3_256(vote_signing_ring.as_ref());
                        if vote.ring_hash != expected_vote_ring_hash {
                            return Err(RpcError::FailedPrecondition {
                                operation: "vote_signing_ring_binding",
                                reason:
                                    "vote.ring_hash does not match derived per-poll signing ring"
                                        .into(),
                            }
                            .into());
                        }
                        Some(vote_signing_ring)
                    } else {
                        // Get ring hash from event body if available, otherwise use signature's ring hash.
                        // BanRevoke events don't store ring_hash in body, so we use the signature's.
                        let ring_hash = event
                            .event_type
                            .ring_hash()
                            .unwrap_or_else(|| sig.ring_hash());

                        Some(
                            self.store
                                .ring_by_hash(tenant, event.org_id, &ring_hash)
                                .await
                                .map_err(to_status)?,
                        )
                    }
                }
                crate::crypto::signature::StorageMode::Archival => None,
            }
        };

        // Enforce per-poll vote signing ring derivation for archival votes.
        if matches!(sig.mode(), crate::crypto::signature::StorageMode::Archival) {
            if let crate::event::EventType::VoteCast(vote) = &event.event_type {
                let vote_signing_ring = self
                    .get_or_derive_vote_signing_ring(
                        tenant,
                        event.org_id,
                        vote.poll_ring_hash,
                        &vote.poll_id,
                    )
                    .await?;
                let expected_vote_ring_hash = ring_hash_sha3_256(vote_signing_ring.as_ref());
                if vote.ring_hash != expected_vote_ring_hash {
                    return Err(RpcError::FailedPrecondition {
                        operation: "vote_signing_ring_binding",
                        reason: "vote.ring_hash does not match derived per-poll signing ring"
                            .into(),
                    }
                    .into());
                }
            }
        }

        let signed_msg = event.to_signing_bytes().map_err(|e| RpcError::Internal {
            operation: "event_serialization",
            details: format!("canonical serialization failed: {e}"),
        })?;

        let ring_size =
            Self::verification_ring_size(sig, external_ring.as_deref()).ok_or_else(|| {
                RpcError::Internal {
                    operation: "verification_meter",
                    details: "compact signature missing external ring".into(),
                }
            })?;
        let message_bytes = signed_msg.len();

        let item = crate::crypto::verifier::SignatureItem {
            signature: sig.clone(),
            message: signed_msg,
            weight: 1,
            external_ring,
        };

        let results =
            self.verifier
                .verify_batch(&[item])
                .await
                .map_err(|e| RpcError::Internal {
                    operation: "signature_verification",
                    details: e.to_string(),
                })?;
        if !results[0] {
            // Record failure in POW state machine — may trigger or escalate POW requirement.
            {
                let pow_key = (tenant, event.org_id);
                let mut state = self.pow_states.entry(pow_key).or_default();
                state.on_verification_failure(&self.pow_config);

                // If POW just became required, return ResourceExhausted with challenge
                // so the client knows to submit POW on retry.
                if state.should_require_pow() {
                    drop(state);
                    return Err(self.make_pow_challenge_status(tenant, event.org_id));
                }
            }

            return Err(RpcError::Unauthenticated {
                credential: "signature",
                reason: "verification failed".into(),
            }
            .into());
        }

        // Signature verified successfully — record success, potentially recover from POW mode.
        {
            let pow_key = (tenant, event.org_id);
            if let Some(mut state) = self.pow_states.get_mut(&pow_key) {
                state.on_verification_success(&self.pow_config);
            }
        }

        // Charge verification AFTER successful signature verification.
        // This prevents economic DoS where attackers drain balance with invalid signatures.
        // PoW proof count is included when applicable so CPU-heavy PoW work is billed.
        self.verification_meter
            .charge_verification(
                &event.org_id.to_string(),
                ring_size,
                message_bytes,
                pow_proof_count,
            )
            .await
            .map_err(Self::verification_meter_error_to_status)?;

        // 3b. Archival ring_hash consistency check
        //
        // For Archival signatures, the ring is embedded in the signature itself.
        // Verify that the embedded ring's hash matches the ring_hash declared in
        // the event body. Without this check, an attacker could declare ring_hash X
        // (matching a legitimate ring) but embed a different ring Y in the signature.
        //
        // Admin events (BanCreate/BanRevoke/RingUpdate) are excluded because their
        // ring hash was already verified against the delegate ring in step 2b.
        if matches!(sig.mode(), crate::crypto::signature::StorageMode::Archival) {
            let is_admin_event = matches!(
                &event.event_type,
                crate::event::EventType::BanCreate(_)
                    | crate::event::EventType::BanRevoke(_)
                    | crate::event::EventType::RingUpdate(_)
            );
            if !is_admin_event {
                if let Some(declared_hash) = event.event_type.ring_hash() {
                    let sig_ring_hash = sig.ring_hash();
                    if sig_ring_hash != declared_hash {
                        return Err(RpcError::FailedPrecondition {
                            operation: "archival_ring_hash_consistency",
                            reason: "embedded ring hash does not match declared ring_hash".into(),
                        }
                        .into());
                    }
                }
            }
        }

        if let crate::event::EventType::RingUpdate(update) = &event.event_type {
            let current_ring = self
                .store
                .current_ring(tenant, event.org_id)
                .await
                .map_err(to_status)?;
            let current_hash = crate::hashing::ring_hash_sha3_256(&current_ring);
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
                    .append_ring_delta(tenant, event.org_id, delta)
                    .await
                    .map_err(to_status)?;
            }
        }

        // 4. Store poll ring hash BEFORE committing the event
        //
        // DESIGN DECISION: Index write happens before event commit for consistent error handling.
        // - If index write fails → Event not committed, clean failure
        // - If event commit fails → Orphan index entry exists, but harmless:
        //   VoteCast validates ring hash against signature, so votes against orphan entries
        //   will fail signature verification (ring hash won't match any real poll)
        //
        // This ordering ensures we never return an error after the event is committed,
        // which would confuse clients about the actual state.
        if let crate::event::EventType::PollCreate(poll) = &event.event_type {
            self.store
                .store_poll_ring_hash(tenant, event.org_id, &poll.poll_id, poll.ring_hash)
                .await
                .map_err(to_status)?;
        }

        // 5. Commit the event
        //
        // Re-serialize the event to include the server-assigned previous_event_hash.
        // This ensures the stored event has the correct chain linkage.
        let final_event_bytes: crate::storage::EventBytes = serde_json::to_vec(&event)
            .map_err(|e| RpcError::Internal {
                operation: "event_serialization",
                details: format!("failed to serialize event: {e}"),
            })?
            .into();

        let id = self
            .store
            .append_event(tenant, event.org_id, final_event_bytes)
            .await
            .map_err(to_status)?;

        let event_hash = crate::proto::event_id_to_hash32(&id.0);
        let event_ulid = crate::proto::ulid_to_proto(&event.event_ulid.as_ulid());
        Ok(Response::new(PushEventResponse {
            event_ulid: Some(event_ulid),
            event_hash: Some(event_hash),
            sequence_no: id.1.as_i64(),
            event_url: None, // Set by Edge proxy for poll events with Onion URL
        }))
    }

    async fn get_or_derive_vote_signing_ring(
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

    /// Build a `ResourceExhausted` status with POW challenge parameters encoded in details.
    ///
    /// The challenge is serialized as a protobuf `PowChallenge` message in the status details,
    /// allowing clients to parse the difficulty parameters and compute a valid proof.
    fn make_pow_challenge_status(
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

        // Generate deterministic challenge bytes from tenant + org + current timestamp.
        // This makes challenges verifiable without server-side state.
        let challenge = Self::generate_challenge(tenant, org_id);

        let pow_challenge = PowChallenge {
            bits: params.bits,
            required_proofs: params.required_proofs as u32,
            time_window_secs: params.time_window_secs,
            challenge: challenge.to_vec(),
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
    async fn verify_pow_submission(
        &self,
        tenant: crate::ids::TenantId,
        org_id: crate::ids::OrganizationId,
        proto_sub: &mandate_proto::mandate::v1::PowSubmission,
    ) -> Result<(), Status> {
        // Convert client_nonce from Vec<u8> to [u8; 32]
        let client_nonce: [u8; 32] =
            proto_sub.client_nonce.as_slice().try_into().map_err(|_| {
                RpcError::InvalidArgument {
                    field: "pow_submission.client_nonce",
                    reason: format!("expected 32 bytes, got {}", proto_sub.client_nonce.len()),
                }
            })?;

        let submission = crate::pow::PowSubmission::new(
            proto_sub.timestamp as u64,
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

    /// Generate deterministic challenge bytes from tenant, org, and current time bucket.
    ///
    /// Uses a 60-second time bucket to make challenges stable within the POW time window,
    /// allowing clients to solve and submit within the same window without the challenge
    /// changing underneath them.
    fn generate_challenge(
        tenant: crate::ids::TenantId,
        org_id: crate::ids::OrganizationId,
    ) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        // 60-second time bucket aligns with PowParams::time_window_secs
        let time_bucket = now / 60;

        let mut hasher = Sha3_256::new();
        hasher.update(b"mandate-pow-challenge-v1");
        hasher.update(tenant.0.to_bytes());
        hasher.update(org_id.0.to_bytes());
        hasher.update(time_bucket.to_le_bytes());
        hasher.finalize().into()
    }

    fn verification_ring_size(
        sig: &crate::crypto::signature::Signature,
        external_ring: Option<&Ring>,
    ) -> Option<usize> {
        match sig.ring_context() {
            RingContext::Compact(_) => external_ring.map(|ring| ring.members().len()),
            RingContext::Archival(ring) => Some(ring.members().len()),
        }
    }

    fn verification_meter_error_to_status(error: MeteringError) -> Status {
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
}
