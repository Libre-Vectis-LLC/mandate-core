use crate::proto::API_TOKEN_METADATA_KEY;
use crate::ring_log::apply_delta;
use crate::rpc::RpcError;
use crate::storage::{EventReader, EventStore, RingView};
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
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

/// Basic EventService stub wired to EventStore.
pub struct EventServiceImpl<S: EventStore + EventReader> {
    store: S,
}

impl<S: EventStore + EventReader> EventServiceImpl<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl<S: EventStore + EventReader + Send + Sync + 'static> EventService for EventServiceImpl<S> {
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
        let cursor = if body.start_sequence_no < 0 {
            None
        } else {
            Some(body.start_sequence_no)
        };
        let limit = clamp_events_limit(body.limit);
        let records = self
            .store
            .stream_group(tenant, group_id, cursor, limit)
            .map_err(to_status)?;

        let (tx, rx) = mpsc::channel(1);
        let sequence_nos: Vec<i64> = records.iter().map(|(_, _, seq)| *seq).collect();
        let _ = tx
            .send(Ok(StreamEventsResponse {
                event_bytes: records.into_iter().map(|(_, b, _)| b.to_vec()).collect(),
                sequence_nos,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

fn clamp_limit(client_limit: u32) -> usize {
    let max_limit = std::env::var("MANDATE_GRPC_EVENTS_MAX_LIMIT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100);
    let requested = if client_limit == 0 {
        max_limit
    } else {
        client_limit as usize
    };
    requested.clamp(1, max_limit)
}

fn clamp_events_limit(client_limit: u32) -> usize {
    clamp_limit(client_limit)
}

fn clamp_ring_limit(client_limit: u32) -> usize {
    let max_limit = std::env::var("MANDATE_GRPC_RING_MAX_LIMIT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100);
    let requested = if client_limit == 0 {
        max_limit
    } else {
        client_limit as usize
    };
    requested.clamp(1, max_limit)
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

        let entries =
            encode_ring_delta_path(&self.rings, tenant, &path, clamp_ring_limit(req.limit))?;
        let next_hash = entries
            .last()
            .map(|e| e.ring_hash.clone())
            .unwrap_or_default();
        let (tx, rx) = mpsc::channel(1);
        let _ = tx
            .send(Ok(StreamRingResponse {
                entries,
                next_ring_hash: next_hash,
            }))
            .await;
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[allow(clippy::result_large_err)]
fn encode_ring_delta_path(
    rings: &impl RingView,
    tenant: crate::ids::TenantId,
    path: &crate::storage::RingDeltaPath,
    limit: usize,
) -> Result<Vec<mandate_proto::mandate::v1::RingDeltaEntry>, Status> {
    let anchor = rings.ring_by_hash(tenant, &path.from).map_err(to_status)?;
    let mut ring = (*anchor).clone();

    let deltas_bytes = path
        .deltas
        .iter()
        .take(limit)
        .map(|d| {
            apply_delta(&mut ring, d).map_err(|e| RpcError::Internal(e.to_string()))?;
            encode_ring_delta(d)
        })
        .collect::<Result<Vec<_>, Status>>()?;

    let ring_hash = crate::hashing::ring_hash_sha3_256(&ring);

    Ok(vec![mandate_proto::mandate::v1::RingDeltaEntry {
        ring_hash: ring_hash.0.to_vec(),
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
