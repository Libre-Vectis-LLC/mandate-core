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
    event_service_server::EventService, GetPollBundleRequest, GetPollBundleResponse,
    GetPollResultsRequest, GetPollResultsResponse, PushEventRequest, PushEventResponse,
    StreamEventsRequest, StreamEventsResponse,
};
use nazgul::keypair::KeyPair as NazgulKeyPair;
use nazgul::ring::Ring;
use nazgul::traits::{Derivable, LocalByteConvertible};
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
        let mut event: Event =
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

        // 1. Auto-fill Chain Hash
        //
        // The server automatically assigns the correct previous_event_hash based on chain state.
        // This enables O(n) concurrent event submissions without client re-signing on conflicts.
        //
        // Security note: Chain integrity is enforced by Party A's Edge and Bot monitoring.
        // The signature does NOT include previous_event_hash (see Event::to_signing_bytes).
        match self.store.event_tail(tenant, event.group_id).await {
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
            .append_event(tenant, event.group_id, final_event_bytes)
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

    async fn get_poll_results(
        &self,
        request: Request<GetPollResultsRequest>,
    ) -> Result<Response<GetPollResultsResponse>, Status> {
        use crate::key_manager::decrypt_event_content;
        use crate::proto::ring_hash_to_hash32;
        use age::x25519::Identity as RageIdentity;
        use mandate_proto::mandate::v1::PollOption as ProtoPollOption;
        use std::collections::HashMap;
        use std::time::{SystemTime, UNIX_EPOCH};

        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();

        // 1. Parse request fields
        let group_id = GroupId(
            crate::proto::parse_ulid(&body.group_id)
                .map_err(|e| Status::invalid_argument(format!("invalid group_id: {e}")))?,
        );

        let event_ulid_proto = body
            .event_ulid
            .ok_or_else(|| Status::invalid_argument("missing event_ulid"))?;
        let event_ulid = crate::ids::EventUlid(
            crate::proto::parse_ulid(&event_ulid_proto.value)
                .map_err(|e| Status::invalid_argument(format!("invalid event_ulid: {e}")))?,
        );

        // 2. Decode poll_key hex to age Identity
        let poll_key_bytes: [u8; 32] = hex::decode(&body.poll_key)
            .map_err(|e| Status::invalid_argument(format!("invalid poll_key hex: {e}")))?
            .try_into()
            .map_err(|_| Status::invalid_argument("poll_key must be exactly 32 bytes"))?;

        let identity = RageIdentity::from_secret_bytes(poll_key_bytes);

        // 3. Find the Poll event
        let event_records = self
            .store
            .stream_events(tenant, group_id, None, usize::MAX)
            .await
            .map_err(to_status)?;

        // Deserialize all events
        let mut events: Vec<Event> = Vec::new();
        for (_event_id, event_bytes, _seq) in &event_records {
            let event: Event = serde_json::from_slice(event_bytes)
                .map_err(|e| Status::internal(format!("failed to deserialize event: {e}")))?;
            events.push(event);
        }

        let poll_event = events
            .iter()
            .find(|event| event.event_ulid == event_ulid)
            .ok_or_else(|| Status::not_found("poll event not found"))?;

        let poll = match &poll_event.event_type {
            crate::event::EventType::PollCreate(p) => p,
            _ => {
                return Err(Status::invalid_argument(
                    "specified event is not a poll creation event",
                ))
            }
        };

        // 4. Decrypt and validate poll_key by attempting to decrypt the question title
        let question_bytes = decrypt_event_content(&identity, &poll.questions[0].title.0)
            .map_err(|_| Status::permission_denied("invalid poll_key: decryption failed"))?;

        let question_title = String::from_utf8_lossy(&question_bytes).to_string();

        // 5. Decrypt option labels and build option_id -> (index, label) map
        let mut option_map: HashMap<String, (usize, String)> = HashMap::new();

        if let Some(first_question) = poll.questions.first() {
            let options_vec = match &first_question.kind {
                crate::event::PollQuestionKind::SingleChoice { options } => options,
                crate::event::PollQuestionKind::MultipleChoice { options, .. } => options,
                crate::event::PollQuestionKind::FillInTheBlank => {
                    // No options to decrypt for fill-in-the-blank
                    &vec![]
                }
            };

            for (idx, opt) in options_vec.iter().enumerate() {
                let label_bytes = decrypt_event_content(&identity, &opt.text.0).map_err(|e| {
                    Status::internal(format!("failed to decrypt option label: {e}"))
                })?;

                let label = String::from_utf8_lossy(&label_bytes).to_string();
                option_map.insert(opt.id.clone(), (idx, label));
            }
        }

        // 6. Count votes for this poll
        let mut vote_counts: HashMap<String, u32> = HashMap::new();

        for event in events.iter() {
            if let crate::event::EventType::VoteCast(vote) = &event.event_type {
                if vote.poll_id == poll.poll_id {
                    // Aggregate votes from all selections
                    for selection in &vote.selections {
                        for option_id in &selection.option_ids {
                            *vote_counts.entry(option_id.clone()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }

        // 7. Build response
        let mut proto_options: Vec<ProtoPollOption> = option_map
            .iter()
            .map(|(option_id, (idx, label))| ProtoPollOption {
                index: *idx as u32,
                label: label.clone(),
                vote_count: vote_counts.get(option_id).copied().unwrap_or(0),
            })
            .collect();

        // Sort by index to maintain option order
        proto_options.sort_by_key(|opt| opt.index);

        let total_votes: u32 = vote_counts.values().sum();

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let is_open = poll
            .deadline
            .map(|deadline| current_time < deadline)
            .unwrap_or(true);

        Ok(Response::new(GetPollResultsResponse {
            question: question_title,
            created_at: poll.created_at as i64,
            options: proto_options,
            total_votes,
            ring_hash: Some(ring_hash_to_hash32(&poll.ring_hash)),
            is_open,
        }))
    }

    async fn get_poll_bundle(
        &self,
        request: Request<GetPollBundleRequest>,
    ) -> Result<Response<GetPollBundleResponse>, Status> {
        use crate::key_manager::decrypt_event_content;
        use age::x25519::Identity as RageIdentity;
        use mandate_proto::mandate::v1::PollVoteData;

        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();

        // 1. Parse request fields
        let group_id = GroupId(
            crate::proto::parse_ulid(&body.group_id)
                .map_err(|e| Status::invalid_argument(format!("invalid group_id: {e}")))?,
        );

        let event_ulid_proto = body
            .event_ulid
            .ok_or_else(|| Status::invalid_argument("missing event_ulid"))?;
        let event_ulid = crate::ids::EventUlid(
            crate::proto::parse_ulid(&event_ulid_proto.value)
                .map_err(|e| Status::invalid_argument(format!("invalid event_ulid: {e}")))?,
        );

        // 2. Decode poll_key hex to age Identity
        let poll_key_bytes: [u8; 32] = hex::decode(&body.poll_key)
            .map_err(|e| Status::invalid_argument(format!("invalid poll_key hex: {e}")))?
            .try_into()
            .map_err(|_| Status::invalid_argument("poll_key must be exactly 32 bytes"))?;

        let identity = RageIdentity::from_secret_bytes(poll_key_bytes);

        // 3. Stream all events for this group
        let event_records = self
            .store
            .stream_events(tenant, group_id, None, usize::MAX)
            .await
            .map_err(to_status)?;

        // 4. Find poll event and validate poll_key by attempting decryption
        let mut poll_event_opt: Option<(Event, Vec<u8>, i64)> = None;

        for (_event_id, event_bytes, seq) in &event_records {
            let event: Event = serde_json::from_slice(event_bytes)
                .map_err(|e| Status::internal(format!("failed to deserialize event: {e}")))?;

            if event.event_ulid == event_ulid {
                let poll = match &event.event_type {
                    crate::event::EventType::PollCreate(p) => p,
                    _ => {
                        return Err(Status::invalid_argument(
                            "specified event is not a poll creation event",
                        ))
                    }
                };

                // Validate poll_key by attempting to decrypt the first question title
                let _question_bytes = decrypt_event_content(&identity, &poll.questions[0].title.0)
                    .map_err(|_| {
                        Status::permission_denied("invalid poll_key: decryption failed")
                    })?;

                poll_event_opt = Some((event, event_bytes.to_vec(), seq.0));
                break;
            }
        }

        let (poll_event, poll_event_bytes, _poll_seq) =
            poll_event_opt.ok_or_else(|| Status::not_found("poll event not found"))?;

        let poll = match &poll_event.event_type {
            crate::event::EventType::PollCreate(p) => p,
            _ => unreachable!(),
        };

        // 5. Collect all vote events for this poll
        let mut vote_data_vec: Vec<PollVoteData> = Vec::new();

        for (_event_id, event_bytes, seq) in &event_records {
            let event: Event = serde_json::from_slice(event_bytes)
                .map_err(|e| Status::internal(format!("failed to deserialize event: {e}")))?;

            if let crate::event::EventType::VoteCast(vote) = &event.event_type {
                if vote.poll_id == poll.poll_id {
                    // Extract key image from signature
                    let sig = event
                        .signature
                        .as_ref()
                        .ok_or_else(|| Status::internal("vote event missing signature"))?;

                    let key_image_bytes = sig.key_image().to_bytes();
                    let key_image_hex = hex::encode(key_image_bytes);

                    // Serialize event to JSON for human readability
                    let event_json = serde_json::to_string(&event)
                        .map_err(|e| Status::internal(format!("failed to serialize event: {e}")))?;

                    vote_data_vec.push(PollVoteData {
                        event_ulid: event.event_ulid.0.to_string(),
                        sequence_no: seq.0,
                        key_image_hex,
                        event_bytes: event_bytes.to_vec(),
                        event_json,
                    });
                }
            }
        }

        // Sort votes by sequence number for deterministic ordering
        vote_data_vec.sort_by_key(|v| v.sequence_no);

        // 6. Build response
        let poll_hash = crate::hashing::sha3_256_bytes(&poll_event_bytes);
        let poll_hash_hex = hex::encode(poll_hash.0);

        let ring_hash_hex = hex::encode(poll.ring_hash.0);
        let poll_key_hex = hex::encode(poll_key_bytes);

        // Convert poll_key to age-secret format for external tools
        let poll_key_age_secret = format!(
            "AGE-SECRET-KEY-1{}",
            bs58::encode(&poll_key_bytes).into_string().to_uppercase()
        );

        let poll_event_json = serde_json::to_string(&poll_event)
            .map_err(|e| Status::internal(format!("failed to serialize poll event: {e}")))?;

        Ok(Response::new(GetPollBundleResponse {
            group_id: group_id.0.to_string(),
            poll_id: poll.poll_id.to_string(),
            poll_event_ulid: event_ulid.0.to_string(),
            poll_hash_hex,
            ring_hash_hex,
            poll_key_hex,
            poll_key_age_secret,
            vote_count: vote_data_vec.len() as u32,
            poll_event_bytes,
            poll_event_json,
            votes: vote_data_vec,
        }))
    }
}
