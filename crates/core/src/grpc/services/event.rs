//! EventService gRPC implementation.

use crate::billing::{default_egress_meter, SharedEgressMeter};
use crate::event::Event;
use crate::hashing::ring_hash_sha3_256;
use crate::ids::{GroupId, SequenceNo};
use crate::ring_log::{apply_delta, RingDelta};
use crate::rpc::RpcError;
use crate::storage::facade::StorageFacade;
use crate::storage::BannedOperation;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use mandate_proto::mandate::v1::{
    event_service_server::EventService, PushEventRequest, PushEventResponse, StreamEventsRequest,
    StreamEventsResponse,
};
use nazgul::keypair::KeyPair as NazgulKeyPair;
use nazgul::ring::Ring;
use nazgul::traits::Derivable;
use sha3::Sha3_512;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::{
    clamp_events_limit, extract_tenant_id, max_event_bytes, max_message_content_chars,
    max_poll_id_length, to_status,
};

fn banned_operation_for_event(event_type: &crate::event::EventType) -> Option<BannedOperation> {
    match event_type {
        crate::event::EventType::MessageCreate(_) => Some(BannedOperation::PostMessage),
        crate::event::EventType::PollCreate(_) => Some(BannedOperation::CreatePoll),
        crate::event::EventType::VoteCast(_) => Some(BannedOperation::CastVote),
        _ => None,
    }
}

/// Basic EventService stub wired to EventStore.
#[derive(Clone)]
pub struct EventServiceImpl {
    store: StorageFacade,
    verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
    egress_meter: SharedEgressMeter,
}

impl EventServiceImpl {
    /// Create a new EventService with the default no-op egress meter.
    pub fn new(
        store: StorageFacade,
        verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
    ) -> Self {
        Self {
            store,
            verifier,
            egress_meter: default_egress_meter(),
        }
    }

    /// Create a new EventService with a custom egress meter.
    pub fn with_egress_meter(
        store: StorageFacade,
        verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
        egress_meter: SharedEgressMeter,
    ) -> Self {
        Self {
            store,
            verifier,
            egress_meter,
        }
    }
}

#[tonic::async_trait]
impl EventService for EventServiceImpl {
    async fn push_event(
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
        let event: Event =
            serde_json::from_slice(&event_bytes).map_err(|e| RpcError::InvalidArgument {
                field: "event_bytes",
                reason: format!("invalid JSON payload: {e}"),
            })?;

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
                .get_poll_ring_hash(tenant, event.group_id, &vote.poll_id)
                .await
            {
                Ok(_) => {
                    // Poll exists in index, fast-path validation passed.
                    // Signature verification (step 3) will validate ring hash matches.
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

        // 1. Verify Chain Hash
        match self.store.event_tail(tenant, event.group_id).await {
            Ok((tail_id, _, _)) => {
                let tail_hash = crate::ids::ContentHash(tail_id.0);
                if event.previous_event_hash.0 != tail_hash.0 {
                    return Err(RpcError::FailedPrecondition {
                        operation: "chain_verification",
                        reason: format!(
                            "hash mismatch: expected prev={:?}, got {:?}",
                            tail_hash, event.previous_event_hash
                        ),
                    }
                    .into());
                }
            }
            Err(crate::storage::StorageError::NotFound(_)) => {
                // Genesis event must have zero prev hash
                if event.previous_event_hash.0 != [0u8; 32] {
                    return Err(RpcError::FailedPrecondition {
                        operation: "genesis_validation",
                        reason: "first event must have zero prev hash".into(),
                    }
                    .into());
                }
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
                .is_vote_key_image_used(tenant, event.group_id, &vote.poll_id, &key_image)
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
                .is_banned(tenant, event.group_id, &key_image, operation)
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

        // 2b. Verify owner/delegate for admin ban events
        let delegate_external_ring = match &event.event_type {
            crate::event::EventType::BanCreate(_) | crate::event::EventType::BanRevoke(_) => {
                // Get owner's public key from storage
                let owner_pubkey = self
                    .store
                    .get_owner_pubkey(event.group_id)
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

                // Derive delegate key using group_id as context
                let group_bytes = event.group_id.to_bytes();
                let mut ctx =
                    Vec::with_capacity(b"mandate-delegate-signer-v1".len() + group_bytes.len());
                ctx.extend_from_slice(b"mandate-delegate-signer-v1");
                ctx.extend_from_slice(&group_bytes);

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
                .count_bans_for_ring(tenant, event.group_id, &ban.ring_hash)
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

        // 3. Verify Signature
        // Load ring if needed (Compact signature)
        let external_ring = if let Some(ring) = delegate_external_ring {
            Some(ring)
        } else {
            match sig.mode() {
                crate::crypto::signature::StorageMode::Compact => {
                    // Get ring hash from event body if available, otherwise use signature's ring hash.
                    // BanRevoke events don't store ring_hash in body, so we use the signature's.
                    let ring_hash = event
                        .event_type
                        .ring_hash()
                        .unwrap_or_else(|| sig.ring_hash());

                    Some(
                        self.store
                            .ring_by_hash(tenant, event.group_id, &ring_hash)
                            .await
                            .map_err(to_status)?,
                    )
                }
                crate::crypto::signature::StorageMode::Archival => None,
            }
        };

        let signed_msg = event.to_signing_bytes().map_err(|e| RpcError::Internal {
            operation: "event_serialization",
            details: format!("canonical serialization failed: {e}"),
        })?;

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
            return Err(RpcError::Unauthenticated {
                credential: "signature",
                reason: "verification failed".into(),
            }
            .into());
        }

        if let crate::event::EventType::RingUpdate(update) = &event.event_type {
            let current_ring = self
                .store
                .current_ring(tenant, event.group_id)
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
                    crate::event::RingOperation::AddMember { public_key } => {
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
                    crate::event::RingOperation::AddMember { public_key } => {
                        RingDelta::Add(*public_key)
                    }
                    crate::event::RingOperation::RemoveMember { public_key } => {
                        RingDelta::Remove(*public_key)
                    }
                };
                self.store
                    .append_ring_delta(tenant, event.group_id, delta)
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
                .store_poll_ring_hash(tenant, event.group_id, &poll.poll_id, poll.ring_hash)
                .await
                .map_err(to_status)?;
        }

        // 5. Commit the event
        let id = self
            .store
            .append_event(tenant, event.group_id, event_bytes.clone())
            .await
            .map_err(to_status)?;

        let event_hash = crate::proto::event_id_to_hash32(&id.0);
        let event_ulid = crate::proto::ulid_to_proto(&event.event_ulid.as_ulid());
        Ok(Response::new(PushEventResponse {
            event_ulid: Some(event_ulid),
            event_hash: Some(event_hash),
            sequence_no: id.1.as_i64(),
        }))
    }

    type StreamEventsStream = ReceiverStream<Result<StreamEventsResponse, Status>>;

    async fn stream_events(
        &self,
        request: Request<StreamEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();
        let group_id = GroupId(crate::proto::parse_ulid(&body.group_id).map_err(|e| {
            RpcError::InvalidArgument {
                field: "group_id",
                reason: e.to_string(),
            }
        })?);
        let cursor = if body.start_sequence_no < 0 {
            None
        } else {
            Some(SequenceNo::new(body.start_sequence_no))
        };
        let limit = clamp_events_limit(body.limit);
        let records = self
            .store
            .stream_events(tenant, group_id, cursor, limit)
            .await
            .map_err(to_status)?;

        // Calculate total egress bytes for billing
        let total_bytes: usize = records.iter().map(|(_, b, _)| b.len()).sum();
        let group_id_str = group_id.to_string();

        // Check egress balance before sending data
        self.egress_meter
            .check_egress(&group_id_str, total_bytes)
            .await
            .map_err(|e| Status::resource_exhausted(format!("egress check failed: {}", e)))?;

        let (tx, rx) = mpsc::channel(1);
        let sequence_nos: Vec<i64> = records.iter().map(|(_, _, seq)| seq.as_i64()).collect();
        let event_bytes: Vec<Vec<u8>> = records.into_iter().map(|(_, b, _)| b.to_vec()).collect();

        // Record egress after preparing response (charge for data transfer)
        // Note: We intentionally ignore errors here - the data is already prepared
        // and the check_egress call above already validated the balance.
        let _ = self
            .egress_meter
            .record_egress(&group_id_str, total_bytes)
            .await;

        let _ = tx
            .send(Ok(StreamEventsResponse {
                event_bytes,
                sequence_nos,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
