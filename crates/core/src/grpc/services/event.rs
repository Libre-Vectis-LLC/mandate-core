//! EventService gRPC implementation.

use crate::event::Event;
use crate::ids::{GroupId, SequenceNo};
use crate::ring_log::{apply_delta, RingDelta};
use crate::rpc::RpcError;
use crate::storage::facade::StorageFacade;
use crate::storage::BannedOperation;
use mandate_proto::mandate::v1::{
    event_service_server::EventService, PushEventRequest, PushEventResponse, StreamEventsRequest,
    StreamEventsResponse,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use super::{clamp_events_limit, extract_tenant_id, max_event_bytes, to_status};

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
}

impl EventServiceImpl {
    pub fn new(
        store: StorageFacade,
        verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
    ) -> Self {
        Self { store, verifier }
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

        // 3. Verify Signature
        // Load ring if needed (Compact signature)
        let external_ring = match sig.mode() {
            crate::crypto::signature::StorageMode::Compact => {
                // Extract ring hash from event body.
                // We need to inspect event_type to get ring_hash.
                // This is slightly brittle if event structure changes, but for now:
                let ring_hash = match &event.event_type {
                    crate::event::EventType::PollCreate(p) => p.ring_hash,
                    crate::event::EventType::VoteCast(v) => v.ring_hash,
                    crate::event::EventType::MessageCreate(m) => m.ring_hash,
                    crate::event::EventType::RingUpdate(r) => r.ring_hash,
                    crate::event::EventType::BanCreate(b) => b.ring_hash,
                    crate::event::EventType::BanRevoke(b) => b.ring_hash,
                    crate::event::EventType::ProofOfInnocence(p) => p.historical_ring_hash,
                };

                Some(
                    self.store
                        .ring_by_hash(tenant, event.group_id, &ring_hash)
                        .await
                        .map_err(to_status)?,
                )
            }
            crate::crypto::signature::StorageMode::Archival => None,
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

        // 4. Commit
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

        let (tx, rx) = mpsc::channel(1);
        let sequence_nos: Vec<i64> = records.iter().map(|(_, _, seq)| seq.as_i64()).collect();
        let _ = tx
            .send(Ok(StreamEventsResponse {
                event_bytes: records.into_iter().map(|(_, b, _)| b.to_vec()).collect(),
                sequence_nos,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
