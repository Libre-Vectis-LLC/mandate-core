use crate::proto::API_TOKEN_METADATA_KEY;
use crate::rpc::RpcError;
use crate::storage::{EventStore, RingView};
use crate::{
    ids::{GroupId, RingHash},
    ring_log::RingDelta,
};
use mandate_proto::mandate::v1::{
    auth_service_server::AuthService, billing_service_server::BillingService,
    event_service_server::EventService, ring_service_server::RingService, GetRingHeadRequest,
    GetRingHeadResponse, PushEventRequest, PushEventResponse, StreamEventsRequest,
    StreamEventsResponse, StreamRingRequest, StreamRingResponse,
};
use nazgul::traits::LocalByteConvertible;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

/// Basic EventService stub wired to EventStore.
pub struct EventServiceImpl<S: EventStore> {
    store: S,
}

impl<S: EventStore> EventServiceImpl<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl<S: EventStore + Send + Sync + 'static> EventService for EventServiceImpl<S> {
    async fn push_event(
        &self,
        request: Request<PushEventRequest>,
    ) -> Result<Response<PushEventResponse>, Status> {
        // In a full implementation we'd parse event_bytes, verify signature, etc.
        let tenant = extract_tenant(&request)?;
        let body = request.into_inner();
        let event_bytes: crate::storage::EventBytes = body.event_bytes.into();
        let id = self
            .store
            .append(tenant, event_bytes.clone())
            .map_err(to_status)?;
        let event_id = format_event_id(&id.0)?;
        Ok(Response::new(PushEventResponse {
            event_id,
            sequence_no: id.1,
        }))
    }

    type StreamEventsStream = ReceiverStream<Result<StreamEventsResponse, Status>>;

    async fn stream_events(
        &self,
        request: Request<StreamEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let tenant = extract_tenant(&request)?;
        let body = request.into_inner();
        let group_id = GroupId(
            crate::proto::parse_ulid(&body.group_id)
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?,
        );
        let mut cursor = if body.start_sequence_no < 0 {
            None
        } else {
            Some(body.start_sequence_no)
        };
        let limit = body.limit as usize;

        let mut filtered = Vec::new();
        loop {
            let records = self
                .store
                .stream_from(tenant, cursor, limit.max(1))
                .map_err(to_status)?;

            if records.is_empty() {
                break;
            }

            let last_seq = records.last().map(|(_, _, seq)| *seq);

            for (id, bytes, seq) in records {
                let view: EventGroupView = serde_json::from_slice(&bytes).map_err(|_| {
                    RpcError::Internal("stored event missing or invalid group_id".into())
                })?;
                if view.group_id == group_id {
                    filtered.push((id, bytes, seq));
                }
            }

            cursor = last_seq;

            if !filtered.is_empty() {
                break;
            }
        }

        let (tx, rx) = mpsc::channel(1);
        let sequence_nos: Vec<i64> = filtered.iter().map(|(_, _, seq)| *seq).collect();
        let _ = tx
            .send(Ok(StreamEventsResponse {
                event_bytes: filtered.into_iter().map(|(_, b, _)| b.to_vec()).collect(),
                sequence_nos,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[derive(Debug, Deserialize)]
struct EventGroupView {
    group_id: GroupId,
}

fn to_status(err: crate::storage::StorageError) -> Status {
    match err {
        crate::storage::StorageError::NotFound(_) => RpcError::NotFound(err.to_string()).into(),
        crate::storage::StorageError::Backend(msg) => RpcError::Internal(msg).into(),
    }
}

#[allow(clippy::result_large_err)]
fn format_event_id(id: &crate::ids::EventId) -> Result<String, Status> {
    // EventId is 32-byte content hash; not ULID. For demo, hex it.
    Ok(hex::encode(id.0))
}

#[allow(clippy::result_large_err)]
fn extract_tenant<T>(req: &Request<T>) -> Result<crate::ids::TenantId, Status> {
    let token = req
        .metadata()
        .get(API_TOKEN_METADATA_KEY)
        .ok_or_else(|| RpcError::Unauthenticated("missing api token".into()))?
        .to_str()
        .map_err(|_| RpcError::Unauthenticated("bad token".into()))?;
    // Placeholder: treat token as ULID string for tenant
    let ulid = ulid::Ulid::from_string(token)
        .map_err(|_| RpcError::Unauthenticated("invalid token ulid".into()))?;
    Ok(crate::ids::TenantId(ulid))
}

/// Ring service backed by a `RingView`.
pub struct RingServiceImpl<R: RingView> {
    rings: R,
}

impl<R: RingView> RingServiceImpl<R> {
    pub fn new(rings: R) -> Self {
        Self { rings }
    }
}

#[tonic::async_trait]
impl<R: RingView + Send + Sync + 'static> RingService for RingServiceImpl<R> {
    async fn get_ring_head(
        &self,
        request: Request<GetRingHeadRequest>,
    ) -> Result<Response<GetRingHeadResponse>, Status> {
        let tenant = extract_tenant(&request)?;
        let group = request.into_inner().group_id;
        let _group_id = crate::proto::parse_ulid(&group)
            .map_err(|e| RpcError::InvalidArgument(e.to_string()))?;

        // Current ring for tenant; group_id currently ignored (single-ring per tenant).
        let ring = self.rings.current_ring(tenant).map_err(to_status)?;
        let ring_hash = crate::hashing::ring_hash_sha3_256(&ring);
        let members: Vec<Vec<u8>> = ring
            .members()
            .iter()
            .map(|p| p.to_bytes().to_vec())
            .collect();
        Ok(Response::new(GetRingHeadResponse {
            ring_hash: ring_hash.0.to_vec(),
            member_count: members.len() as u32,
            members,
        }))
    }

    type StreamRingStream = ReceiverStream<Result<StreamRingResponse, Status>>;

    async fn stream_ring(
        &self,
        request: Request<StreamRingRequest>,
    ) -> Result<Response<Self::StreamRingStream>, Status> {
        let tenant = extract_tenant(&request)?;
        let req = request.into_inner();
        let after_hash = if req.after_ring_hash.is_empty() {
            None
        } else {
            Some(RingHash(
                crate::proto::hash32_to_ring_hash(&mandate_proto::mandate::v1::Hash32 {
                    value: req.after_ring_hash.clone(),
                })
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?
                .0,
            ))
        };

        // For now, stream a single batch from optional anchor to current ring head.
        let current_ring = self.rings.current_ring(tenant).map_err(to_status)?;
        let current_hash = crate::hashing::ring_hash_sha3_256(&current_ring);
        let path = self
            .rings
            .ring_delta_path(tenant, after_hash, current_hash)
            .map_err(to_status)?;

        let entries = encode_ring_delta_path(&path)?;
        let (tx, rx) = mpsc::channel(1);
        let _ = tx
            .send(Ok(StreamRingResponse {
                entries,
                next_ring_hash: path.to.0.to_vec(),
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[allow(clippy::result_large_err)]
fn encode_ring_delta_path(
    path: &crate::storage::RingDeltaPath,
) -> Result<Vec<mandate_proto::mandate::v1::RingDeltaEntry>, Status> {
    let mut deltas_bytes = Vec::new();
    for delta in &path.deltas {
        deltas_bytes.push(encode_ring_delta(delta)?);
    }
    Ok(vec![mandate_proto::mandate::v1::RingDeltaEntry {
        ring_hash: path.to.0.to_vec(),
        deltas: deltas_bytes,
    }])
}

#[allow(clippy::result_large_err)]
fn encode_ring_delta(delta: &RingDelta) -> Result<Vec<u8>, Status> {
    let mut buf = Vec::with_capacity(1 + 32);
    match delta {
        RingDelta::Add(pk) => {
            buf.push(0u8);
            buf.extend_from_slice(&pk.0);
        }
        RingDelta::Remove(pk) => {
            buf.push(1u8);
            buf.extend_from_slice(&pk.0);
        }
    }
    Ok(buf)
}

/// Auth service placeholder (token validation is external in core).
pub struct AuthServiceImpl;

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    async fn validate_token(
        &self,
        _request: Request<mandate_proto::mandate::v1::ValidateTokenRequest>,
    ) -> Result<Response<mandate_proto::mandate::v1::ValidateTokenResponse>, Status> {
        Err(RpcError::Unavailable("auth backend not wired".into()).into())
    }
}

/// Billing service placeholder.
pub struct BillingServiceImpl;

#[tonic::async_trait]
impl BillingService for BillingServiceImpl {
    async fn issue_gift_card(
        &self,
        _request: Request<mandate_proto::mandate::v1::IssueGiftCardRequest>,
    ) -> Result<Response<mandate_proto::mandate::v1::IssueGiftCardResponse>, Status> {
        Err(RpcError::Unavailable("billing backend not wired".into()).into())
    }

    async fn redeem_gift_card(
        &self,
        _request: Request<mandate_proto::mandate::v1::RedeemGiftCardRequest>,
    ) -> Result<Response<mandate_proto::mandate::v1::RedeemGiftCardResponse>, Status> {
        Err(RpcError::Unavailable("billing backend not wired".into()).into())
    }

    async fn transfer_to_group(
        &self,
        _request: Request<mandate_proto::mandate::v1::TransferToGroupRequest>,
    ) -> Result<Response<mandate_proto::mandate::v1::TransferToGroupResponse>, Status> {
        Err(RpcError::Unavailable("billing backend not wired".into()).into())
    }
}
