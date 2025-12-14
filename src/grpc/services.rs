use crate::event::Event;
use crate::ids::{GroupId, RingHash};
use crate::proto::ring_delta_to_bytes;
use crate::proto::API_TOKEN_METADATA_KEY;
use crate::ring_log::apply_delta;
use crate::rpc::RpcError;
use crate::storage::facade::StorageFacade;
use crate::storage::{RingView, TenantTokenError, TenantTokenStore};
use mandate_proto::mandate::v1::{
    admin_service_server::AdminService, auth_service_server::AuthService,
    billing_service_server::BillingService, event_service_server::EventService,
    group_service_server::GroupService, member_service_server::MemberService,
    ring_service_server::RingService, storage_service_server::StorageService, CreateGroupRequest,
    CreateGroupResponse, DownloadMyKeyBlobRequest, DownloadMyKeyBlobResponse,
    GetGroupBalanceRequest, GetGroupBalanceResponse, GetGroupRequest, GetGroupResponse,
    GetRingHeadRequest, GetRingHeadResponse, IssueGiftCardRequest, IssueGiftCardResponse,
    ListPendingMembersRequest, ListPendingMembersResponse, PushEventRequest, PushEventResponse,
    RedeemGiftCardRequest, RedeemGiftCardResponse, SetOwnerPublicKeyRequest,
    SetOwnerPublicKeyResponse, StreamEventsRequest, StreamEventsResponse, StreamRingRequest,
    StreamRingResponse, SubmitPendingMemberRequest, SubmitPendingMemberResponse,
    TransferToGroupRequest, TransferToGroupResponse, UploadKeyBlobsRequest, UploadKeyBlobsResponse,
};
use nazgul::traits::LocalByteConvertible;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

/// Basic EventService stub wired to EventStore.
#[derive(Clone)]
pub struct EventServiceImpl {
    store: StorageFacade,
}

impl EventServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl EventService for EventServiceImpl {
    async fn push_event(
        &self,
        request: Request<PushEventRequest>,
    ) -> Result<Response<PushEventResponse>, Status> {
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens)?;
        let body = request.into_inner();
        let event_bytes: crate::storage::EventBytes = body.event_bytes.into();
        let event: Event = serde_json::from_slice(&event_bytes)
            .map_err(|e| RpcError::InvalidArgument(format!("invalid event payload: {e}")))?;

        // Pass group_id to append for scoping
        let id = self
            .store
            .event_writer
            .append(tenant, event.group_id, event_bytes.clone())
            .map_err(to_status)?;

        let event_hash = crate::proto::event_id_to_hash32(&id.0);
        let event_ulid = crate::proto::ulid_to_proto(&event.event_ulid.as_ulid());
        Ok(Response::new(PushEventResponse {
            event_ulid: Some(event_ulid),
            event_hash: Some(event_hash),
            sequence_no: id.1,
        }))
    }

    type StreamEventsStream = ReceiverStream<Result<StreamEventsResponse, Status>>;

    async fn stream_events(
        &self,
        request: Request<StreamEventsRequest>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens)?;
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
            .event_reader
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

fn clamp_limit(client_limit: u32, default_limit: usize, max_limit: usize) -> usize {
    let requested = if client_limit == 0 {
        default_limit
    } else {
        client_limit as usize
    };
    requested.clamp(1, max_limit)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

fn clamp_events_limit(client_limit: u32) -> usize {
    let max_limit = env_usize("MANDATE_GRPC_EVENTS_MAX_LIMIT", 100);
    let default_limit = env_usize("MANDATE_GRPC_EVENTS_DEFAULT_LIMIT", 50).min(max_limit);
    clamp_limit(client_limit, default_limit, max_limit)
}

fn clamp_ring_limit(client_limit: u32) -> usize {
    let max_limit = env_usize("MANDATE_GRPC_RING_MAX_LIMIT", 100);
    let default_limit = env_usize("MANDATE_GRPC_RING_DEFAULT_LIMIT", 50).min(max_limit);
    clamp_limit(client_limit, default_limit, max_limit)
}

fn to_status(err: crate::storage::StorageError) -> Status {
    match err {
        crate::storage::StorageError::NotFound(_) => RpcError::NotFound(err.to_string()).into(),
        crate::storage::StorageError::Backend(msg) => RpcError::Internal(msg).into(),
    }
}

#[allow(clippy::result_large_err)]
fn extract_tenant_token<T>(req: &Request<T>) -> Result<crate::ids::TenantToken, Status> {
    if let Some(token) = req.extensions().get::<crate::ids::TenantToken>() {
        return Ok(token.clone());
    }

    let token = req
        .metadata()
        .get(API_TOKEN_METADATA_KEY)
        .ok_or_else(|| RpcError::Unauthenticated("missing api token".into()))?
        .to_str()
        .map_err(|_| RpcError::Unauthenticated("bad token".into()))?;

    if token.is_empty() {
        return Err(RpcError::Unauthenticated("empty api token".into()).into());
    }

    Ok(crate::ids::TenantToken::from(token))
}

fn to_status_token(err: TenantTokenError) -> Status {
    match err {
        TenantTokenError::Unknown => RpcError::Unauthenticated("unknown api token".into()).into(),
        TenantTokenError::Backend(msg) => RpcError::Unavailable(msg).into(),
    }
}

#[allow(clippy::result_large_err)]
fn extract_tenant_id<T>(
    req: &Request<T>,
    tokens: &(impl TenantTokenStore + ?Sized),
) -> Result<crate::ids::TenantId, Status> {
    if let Some(tenant) = req.extensions().get::<crate::ids::TenantId>() {
        return Ok(*tenant);
    }

    let token = extract_tenant_token(req)?;
    tokens.resolve_tenant(&token).map_err(to_status_token)
}

/// Ring service backed by a `RingView`.
#[derive(Clone)]
pub struct RingServiceImpl {
    store: StorageFacade,
}

impl RingServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl RingService for RingServiceImpl {
    async fn get_ring_head(
        &self,
        request: Request<GetRingHeadRequest>,
    ) -> Result<Response<GetRingHeadResponse>, Status> {
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens)?;
        let group = request.into_inner().group_id;
        let group_id = GroupId(
            crate::proto::parse_ulid(&group)
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?,
        );

        // Current ring for the requested group.
        let ring = self
            .store
            .ring_view
            .current_ring(tenant, group_id)
            .map_err(to_status)?;
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
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens)?;
        let req = request.into_inner();
        let group_id = GroupId(
            crate::proto::parse_ulid(&req.group_id)
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?,
        );
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
        let current_ring = self
            .store
            .ring_view
            .current_ring(tenant, group_id)
            .map_err(to_status)?;
        let current_hash = crate::hashing::ring_hash_sha3_256(&current_ring);

        if after_hash.as_ref() == Some(&current_hash) {
            let (tx, rx) = mpsc::channel(1);
            let _ = tx
                .send(Ok(StreamRingResponse {
                    entries: Vec::new(),
                    next_ring_hash: current_hash.0.to_vec(),
                }))
                .await;
            return Ok(Response::new(ReceiverStream::new(rx)));
        }

        let path = self
            .store
            .ring_view
            .ring_delta_path(tenant, group_id, after_hash, current_hash)
            .map_err(to_status)?;

        let entries = encode_ring_delta_path(
            &*self.store.ring_view,
            tenant,
            group_id,
            &path,
            clamp_ring_limit(req.limit),
        )?;
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
    rings: &(impl RingView + ?Sized),
    tenant: crate::ids::TenantId,
    group_id: GroupId,
    path: &crate::storage::RingDeltaPath,
    limit: usize,
) -> Result<Vec<mandate_proto::mandate::v1::RingDeltaEntry>, Status> {
    let anchor = rings
        .ring_by_hash(tenant, group_id, &path.from)
        .map_err(to_status)?;
    let mut ring = (*anchor).clone();

    let deltas_bytes = path
        .deltas
        .iter()
        .take(limit)
        .map(|d| {
            apply_delta(&mut ring, d).map_err(|e| RpcError::Internal(e.to_string()))?;
            Ok(ring_delta_to_bytes(d))
        })
        .collect::<Result<Vec<_>, Status>>()?;

    let ring_hash = crate::hashing::ring_hash_sha3_256(&ring);

    Ok(vec![mandate_proto::mandate::v1::RingDeltaEntry {
        ring_hash: ring_hash.0.to_vec(),
        deltas: deltas_bytes,
    }])
}

/// Admin service placeholder (operations-only RPCs live in server/enterprise).
#[derive(Clone)]
pub struct AdminServiceImpl;

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn issue_gift_card(
        &self,
        _request: Request<IssueGiftCardRequest>,
    ) -> Result<Response<IssueGiftCardResponse>, Status> {
        Err(RpcError::Unavailable("admin backend not wired".into()).into())
    }
}

/// Auth service placeholder (token issuance/rotation and redeem flow live in server/enterprise).
#[derive(Clone)]
pub struct AuthServiceImpl;

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    async fn redeem_gift_card(
        &self,
        _request: Request<RedeemGiftCardRequest>,
    ) -> Result<Response<RedeemGiftCardResponse>, Status> {
        Err(RpcError::Unavailable("auth backend not wired".into()).into())
    }
}

/// Billing service placeholder.
#[derive(Clone)]
pub struct BillingServiceImpl;

#[tonic::async_trait]
impl BillingService for BillingServiceImpl {
    async fn transfer_to_group(
        &self,
        _request: Request<TransferToGroupRequest>,
    ) -> Result<Response<TransferToGroupResponse>, Status> {
        Err(RpcError::Unavailable("billing backend not wired".into()).into())
    }

    async fn get_group_balance(
        &self,
        _request: Request<GetGroupBalanceRequest>,
    ) -> Result<Response<GetGroupBalanceResponse>, Status> {
        Err(RpcError::Unavailable("billing backend not wired".into()).into())
    }
}

/// Group service placeholder (tenant/group management lives in server/enterprise).
#[derive(Clone)]
pub struct GroupServiceImpl {
    store: StorageFacade,
}

impl GroupServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl GroupService for GroupServiceImpl {
    async fn create_group(
        &self,
        _request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        Err(RpcError::Unavailable("group backend not wired".into()).into())
    }

    async fn set_owner_public_key(
        &self,
        request: Request<SetOwnerPublicKeyRequest>,
    ) -> Result<Response<SetOwnerPublicKeyResponse>, Status> {
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens)?;
        let body = request.into_inner();
        let group_id = GroupId(
            crate::proto::parse_ulid(&body.group_id)
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?,
        );

        let owner_pubkey = body
            .owner_pubkey
            .as_ref()
            .ok_or_else(|| RpcError::InvalidArgument("missing owner_pubkey".into()))?;
        let owner_pubkey = crate::proto::nazgul_pub_from_proto(owner_pubkey)
            .map_err(|e| RpcError::InvalidArgument(e.to_string()))?;

        match self.store.ring_view.current_ring(tenant, group_id) {
            Ok(ring) => {
                let is_idempotent = ring.members().len() == 1
                    && ring
                        .members()
                        .iter()
                        .any(|p| p.to_bytes() == owner_pubkey.0);
                if is_idempotent {
                    return Ok(Response::new(SetOwnerPublicKeyResponse {}));
                }

                return Err(
                    RpcError::FailedPrecondition("group ring already initialized".into()).into(),
                );
            }
            Err(crate::storage::StorageError::NotFound(_)) => {}
            Err(err) => return Err(to_status(err)),
        }

        self.store
            .ring_writer
            .append_delta(
                tenant,
                group_id,
                crate::ring_log::RingDelta::Add(owner_pubkey),
            )
            .map_err(to_status)?;

        Ok(Response::new(SetOwnerPublicKeyResponse {}))
    }

    async fn get_group(
        &self,
        _request: Request<GetGroupRequest>,
    ) -> Result<Response<GetGroupResponse>, Status> {
        Err(RpcError::Unavailable("group backend not wired".into()).into())
    }
}

/// Member service placeholder (pending members handled in server/enterprise).
#[derive(Clone)]
pub struct MemberServiceImpl;

#[tonic::async_trait]
impl MemberService for MemberServiceImpl {
    async fn submit_pending_member(
        &self,
        _request: Request<SubmitPendingMemberRequest>,
    ) -> Result<Response<SubmitPendingMemberResponse>, Status> {
        Err(RpcError::Unavailable("member backend not wired".into()).into())
    }

    async fn list_pending_members(
        &self,
        _request: Request<ListPendingMembersRequest>,
    ) -> Result<Response<ListPendingMembersResponse>, Status> {
        Err(RpcError::Unavailable("member backend not wired".into()).into())
    }
}

/// Storage service backed by the injected key blob store.
#[derive(Clone)]
pub struct StorageServiceImpl {
    store: StorageFacade,
}

impl StorageServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl StorageService for StorageServiceImpl {
    async fn upload_key_blobs(
        &self,
        request: Request<UploadKeyBlobsRequest>,
    ) -> Result<Response<UploadKeyBlobsResponse>, Status> {
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens)?;
        let body = request.into_inner();
        let group_id = GroupId(
            crate::proto::parse_ulid(&body.group_id)
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?,
        );

        let mut entries = Vec::with_capacity(body.blobs.len());
        for blob in body.blobs {
            let rage_pub = blob
                .rage_pub
                .as_ref()
                .ok_or_else(|| RpcError::InvalidArgument("missing rage_pub".into()))?;
            let rage_pub = crate::proto::rage_pub_from_proto(rage_pub)
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?;
            entries.push((rage_pub, blob.blob.into()));
        }

        self.store
            .key_blobs
            .put_many(tenant, group_id, entries)
            .map_err(to_status)?;
        Ok(Response::new(UploadKeyBlobsResponse {}))
    }

    async fn download_my_key_blob(
        &self,
        request: Request<DownloadMyKeyBlobRequest>,
    ) -> Result<Response<DownloadMyKeyBlobResponse>, Status> {
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens)?;
        let body = request.into_inner();
        let group_id = GroupId(
            crate::proto::parse_ulid(&body.group_id)
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?,
        );
        let rage_pub = body
            .rage_pub
            .as_ref()
            .ok_or_else(|| RpcError::InvalidArgument("missing rage_pub".into()))?;
        let rage_pub = crate::proto::rage_pub_from_proto(rage_pub)
            .map_err(|e| RpcError::InvalidArgument(e.to_string()))?;

        let blob = self
            .store
            .key_blobs
            .get_one(tenant, group_id, rage_pub)
            .map_err(to_status)?;

        Ok(Response::new(DownloadMyKeyBlobResponse {
            blob: blob.to_vec(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventType, ProofOfInnocence};
    use crate::grpc::types::{
        InMemoryEvents, InMemoryKeyBlobs, InMemoryRings, InMemoryTenantTokens, NoopBanIndex,
    };
    use crate::ids::{EventId, MasterPublicKey, RingHash, TenantId};
    use crate::key_manager::KeyManager;
    use crate::ring_log::RingDelta;
    use crate::storage::RingWriter;
    use crate::test_utils::TEST_MNEMONIC;
    use mandate_proto::mandate::v1::KeyBlob;
    use nazgul::traits::{Derivable, LocalByteConvertible};
    use sha3::Sha3_512;
    use std::sync::Arc;
    use tokio_stream::StreamExt;
    use tonic::Code;

    fn mpk(label: &[u8]) -> MasterPublicKey {
        let km = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid test mnemonic");
        let master = km.derive_nazgul_master_keypair();
        let child = master.0.derive_child::<Sha3_512>(label);
        MasterPublicKey(child.public().to_bytes())
    }

    fn make_event_bytes(group_id: GroupId, marker: u8) -> Vec<u8> {
        let event_ulid = crate::ids::EventUlid(ulid::Ulid::from_bytes([marker; 16]));
        let previous_event_hash = EventId([marker.wrapping_sub(1); 32]);
        let ev = Event {
            event_ulid,
            previous_event_hash,
            group_id,
            sequence_no: None,
            processed_at: 0,
            serialization_version: 0,
            event_type: EventType::ProofOfInnocence(ProofOfInnocence {
                group_id,
                historical_ring_hash: RingHash([0u8; 32]),
            }),
            signature: None,
        };
        serde_json::to_vec(&ev).expect("serialize event")
    }

    fn tenant_request<T>(token: &str, msg: T) -> Request<T> {
        let mut req = Request::new(msg);
        req.metadata_mut().insert(
            API_TOKEN_METADATA_KEY,
            token.parse().expect("metadata value"),
        );
        req
    }

    #[tokio::test]
    async fn stream_events_filters_and_paginates_by_sequence() {
        let events = Arc::new(InMemoryEvents::new());
        let rings = Arc::new(InMemoryRings::new());
        let bans = Arc::new(NoopBanIndex::default());
        let tokens = Arc::new(InMemoryTenantTokens::new());

        let tenant = TenantId(ulid::Ulid::new());
        let token = "token-tenant-1";
        tokens.insert(token, tenant);

        let store = StorageFacade::new(
            tokens,
            events.clone(),
            events.clone(),
            Arc::new(InMemoryKeyBlobs::new()),
            rings.clone(),
            rings.clone(),
            bans,
        );
        let svc = EventServiceImpl::new(store);

        let g1 = GroupId(ulid::Ulid::new());
        let g2 = GroupId(ulid::Ulid::new());

        // seq 0 (g1), seq 1 (g2), seq 2 (g1)
        for (group, marker) in [(g1, 1u8), (g2, 2u8), (g1, 3u8)] {
            let bytes = make_event_bytes(group, marker);
            svc.push_event(tenant_request(
                token,
                PushEventRequest {
                    event_bytes: bytes,
                    ..Default::default()
                },
            ))
            .await
            .expect("push event");
        }

        // Full stream for g1 should return seq 0 and 2 only.
        let mut stream = svc
            .stream_events(tenant_request(
                token,
                StreamEventsRequest {
                    group_id: g1.to_string(),
                    start_sequence_no: -1,
                    limit: 10,
                },
            ))
            .await
            .expect("stream")
            .into_inner();
        let resp = stream.next().await.unwrap().unwrap();
        assert_eq!(resp.sequence_nos, vec![0, 1]);
        assert_eq!(resp.event_bytes.len(), 2);

        // Resume after seq 0 should return only seq 1.
        let mut stream = svc
            .stream_events(tenant_request(
                token,
                StreamEventsRequest {
                    group_id: g1.to_string(),
                    start_sequence_no: 0,
                    limit: 10,
                },
            ))
            .await
            .expect("stream")
            .into_inner();
        let resp = stream.next().await.unwrap().unwrap();
        assert_eq!(resp.sequence_nos, vec![1]);
        assert_eq!(resp.event_bytes.len(), 1);

        // Anchor beyond the tail should return an empty batch (no replay).
        let mut stream = svc
            .stream_events(tenant_request(
                token,
                StreamEventsRequest {
                    group_id: g1.to_string(),
                    start_sequence_no: 999,
                    limit: 10,
                },
            ))
            .await
            .expect("stream")
            .into_inner();
        let resp = stream.next().await.unwrap().unwrap();
        assert!(resp.sequence_nos.is_empty());
        assert!(resp.event_bytes.is_empty());
    }

    #[tokio::test]
    async fn stream_events_returns_empty_batch_for_empty_tenant() {
        let events = Arc::new(InMemoryEvents::new());
        let rings = Arc::new(InMemoryRings::new());
        let bans = Arc::new(NoopBanIndex::default());
        let tokens = Arc::new(InMemoryTenantTokens::new());

        let tenant = TenantId(ulid::Ulid::new());
        let token = "token-empty-tenant";
        tokens.insert(token, tenant);

        let store = StorageFacade::new(
            tokens,
            events.clone(),
            events.clone(),
            Arc::new(InMemoryKeyBlobs::new()),
            rings.clone(),
            rings.clone(),
            bans,
        );
        let svc = EventServiceImpl::new(store);

        let group = GroupId(ulid::Ulid::new());
        let mut stream = svc
            .stream_events(tenant_request(
                token,
                StreamEventsRequest {
                    group_id: group.to_string(),
                    start_sequence_no: -1,
                    limit: 10,
                },
            ))
            .await
            .expect("stream")
            .into_inner();
        let resp = stream.next().await.unwrap().unwrap();

        assert!(resp.event_bytes.is_empty());
        assert!(resp.sequence_nos.is_empty());
    }

    #[tokio::test]
    async fn stream_ring_returns_deltas_after_anchor_with_limit() {
        let events = Arc::new(InMemoryEvents::new());
        let rings = Arc::new(InMemoryRings::new());
        let bans = Arc::new(NoopBanIndex::default());
        let tokens = Arc::new(InMemoryTenantTokens::new());

        let tenant = TenantId(ulid::Ulid::new());
        let token = "token-tenant-2";
        tokens.insert(token, tenant);
        let group = GroupId(ulid::Ulid::new());

        let store = StorageFacade::new(
            tokens,
            events.clone(),
            events.clone(),
            Arc::new(InMemoryKeyBlobs::new()),
            rings.clone(),
            rings.clone(),
            bans,
        );
        let svc = RingServiceImpl::new(store);

        let h1 = rings
            .append_delta(tenant, group, RingDelta::Add(mpk(b"a")))
            .expect("founder");
        let h2 = rings
            .append_delta(tenant, group, RingDelta::Add(mpk(b"b")))
            .expect("member");

        let mut stream = svc
            .stream_ring(tenant_request(
                token,
                StreamRingRequest {
                    group_id: group.to_string(),
                    after_ring_hash: h1.0.to_vec(),
                    limit: 1,
                },
            ))
            .await
            .expect("stream ring")
            .into_inner();
        let resp = stream.next().await.unwrap().unwrap();

        assert_eq!(resp.entries.len(), 1);
        assert_eq!(resp.entries[0].deltas.len(), 1);
        assert_eq!(resp.entries[0].ring_hash, h2.0.to_vec());
    }

    #[tokio::test]
    async fn stream_ring_returns_empty_batch_when_up_to_date() {
        let events = Arc::new(InMemoryEvents::new());
        let rings = Arc::new(InMemoryRings::new());
        let bans = Arc::new(NoopBanIndex::default());
        let tokens = Arc::new(InMemoryTenantTokens::new());

        let tenant = TenantId(ulid::Ulid::new());
        let token = "token-tenant-ring-up-to-date";
        tokens.insert(token, tenant);
        let group = GroupId(ulid::Ulid::new());

        let store = StorageFacade::new(
            tokens,
            events.clone(),
            events.clone(),
            Arc::new(InMemoryKeyBlobs::new()),
            rings.clone(),
            rings.clone(),
            bans,
        );
        let svc = RingServiceImpl::new(store);

        let head = rings
            .append_delta(tenant, group, RingDelta::Add(mpk(b"a")))
            .expect("founder");

        let mut stream = svc
            .stream_ring(tenant_request(
                token,
                StreamRingRequest {
                    group_id: group.to_string(),
                    after_ring_hash: head.0.to_vec(),
                    limit: 10,
                },
            ))
            .await
            .expect("stream ring")
            .into_inner();
        let resp = stream.next().await.unwrap().unwrap();

        assert!(resp.entries.is_empty());
        assert_eq!(resp.next_ring_hash, head.0.to_vec());
    }

    #[tokio::test]
    async fn set_owner_public_key_initializes_genesis_ring() {
        let events = Arc::new(InMemoryEvents::new());
        let rings = Arc::new(InMemoryRings::new());
        let bans = Arc::new(NoopBanIndex::default());
        let tokens = Arc::new(InMemoryTenantTokens::new());

        let tenant = TenantId(ulid::Ulid::new());
        let token = "token-tenant-owner";
        tokens.insert(token, tenant);

        let store = StorageFacade::new(
            tokens,
            events.clone(),
            events.clone(),
            Arc::new(InMemoryKeyBlobs::new()),
            rings.clone(),
            rings.clone(),
            bans,
        );
        let svc = GroupServiceImpl::new(store);

        let group = GroupId(ulid::Ulid::new());
        let owner = mpk(b"owner");

        svc.set_owner_public_key(tenant_request(
            token,
            SetOwnerPublicKeyRequest {
                group_id: group.to_string(),
                owner_pubkey: Some(crate::proto::master_pub_to_proto(&owner)),
            },
        ))
        .await
        .expect("init should succeed");

        let ring = rings
            .current_ring(tenant, group)
            .expect("genesis ring should exist");
        assert_eq!(ring.members().len(), 1);
        assert_eq!(ring.members()[0].to_bytes(), owner.0);

        // Idempotent re-submit of the same owner key should succeed.
        svc.set_owner_public_key(tenant_request(
            token,
            SetOwnerPublicKeyRequest {
                group_id: group.to_string(),
                owner_pubkey: Some(crate::proto::master_pub_to_proto(&owner)),
            },
        ))
        .await
        .expect("idempotent init should succeed");

        // Different key must be rejected without mutating the genesis ring.
        let other = mpk(b"other");
        let err = svc
            .set_owner_public_key(tenant_request(
                token,
                SetOwnerPublicKeyRequest {
                    group_id: group.to_string(),
                    owner_pubkey: Some(crate::proto::master_pub_to_proto(&other)),
                },
            ))
            .await
            .expect_err("should reject overwriting owner key");
        assert_eq!(err.code(), Code::FailedPrecondition);

        let ring = rings
            .current_ring(tenant, group)
            .expect("genesis ring should exist");
        assert_eq!(ring.members().len(), 1);
        assert_eq!(ring.members()[0].to_bytes(), owner.0);
    }

    #[tokio::test]
    async fn get_ring_head_is_scoped_by_group() {
        let events = Arc::new(InMemoryEvents::new());
        let rings = Arc::new(InMemoryRings::new());
        let bans = Arc::new(NoopBanIndex::default());
        let tokens = Arc::new(InMemoryTenantTokens::new());

        let tenant = TenantId(ulid::Ulid::new());
        let token = "token-tenant-3";
        tokens.insert(token, tenant);

        let store = StorageFacade::new(
            tokens,
            events.clone(),
            events.clone(),
            Arc::new(InMemoryKeyBlobs::new()),
            rings.clone(),
            rings.clone(),
            bans,
        );
        let svc = RingServiceImpl::new(store);

        let g1 = GroupId(ulid::Ulid::new());
        let g2 = GroupId(ulid::Ulid::new());

        rings
            .append_delta(tenant, g1, RingDelta::Add(mpk(b"a")))
            .expect("append should succeed");

        let head = svc
            .get_ring_head(tenant_request(
                token,
                GetRingHeadRequest {
                    group_id: g1.to_string(),
                },
            ))
            .await
            .expect("head for g1")
            .into_inner();
        assert_eq!(head.member_count, 1);

        let err = svc
            .get_ring_head(tenant_request(
                token,
                GetRingHeadRequest {
                    group_id: g2.to_string(),
                },
            ))
            .await
            .expect_err("g2 must not see g1 ring state");
        assert_eq!(err.code(), Code::NotFound);
    }

    fn rage_pub(marker: u8) -> mandate_proto::mandate::v1::RagePublicKey {
        mandate_proto::mandate::v1::RagePublicKey {
            value: vec![marker; 32],
        }
    }

    #[tokio::test]
    async fn storage_key_blob_roundtrip_is_scoped_by_group() {
        let events = Arc::new(InMemoryEvents::new());
        let rings = Arc::new(InMemoryRings::new());
        let bans = Arc::new(NoopBanIndex::default());
        let tokens = Arc::new(InMemoryTenantTokens::new());
        let blobs = Arc::new(InMemoryKeyBlobs::new());

        let tenant = TenantId(ulid::Ulid::new());
        let token = "token-tenant-4";
        tokens.insert(token, tenant);

        let store = StorageFacade::new(
            tokens,
            events.clone(),
            events.clone(),
            blobs,
            rings.clone(),
            rings,
            bans,
        );
        let svc = StorageServiceImpl::new(store);

        let group_a = GroupId(ulid::Ulid::new());
        let group_b = GroupId(ulid::Ulid::new());

        svc.upload_key_blobs(tenant_request(
            token,
            UploadKeyBlobsRequest {
                group_id: group_a.to_string(),
                blobs: vec![
                    KeyBlob {
                        rage_pub: Some(rage_pub(1)),
                        blob: b"blob-a1".to_vec(),
                    },
                    KeyBlob {
                        rage_pub: Some(rage_pub(2)),
                        blob: b"blob-a2".to_vec(),
                    },
                ],
            },
        ))
        .await
        .expect("upload should succeed");

        let resp = svc
            .download_my_key_blob(tenant_request(
                token,
                DownloadMyKeyBlobRequest {
                    group_id: group_a.to_string(),
                    rage_pub: Some(rage_pub(1)),
                },
            ))
            .await
            .expect("download should succeed")
            .into_inner();
        assert_eq!(resp.blob, b"blob-a1".to_vec());

        let err = svc
            .download_my_key_blob(tenant_request(
                token,
                DownloadMyKeyBlobRequest {
                    group_id: group_b.to_string(),
                    rage_pub: Some(rage_pub(1)),
                },
            ))
            .await
            .expect_err("other group should not see blob");
        assert_eq!(err.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn storage_key_blob_same_rage_pub_does_not_collide_across_groups() {
        let events = Arc::new(InMemoryEvents::new());
        let rings = Arc::new(InMemoryRings::new());
        let bans = Arc::new(NoopBanIndex::default());
        let tokens = Arc::new(InMemoryTenantTokens::new());
        let blobs = Arc::new(InMemoryKeyBlobs::new());

        let tenant = TenantId(ulid::Ulid::new());
        let token = "token-tenant-5";
        tokens.insert(token, tenant);

        let store = StorageFacade::new(
            tokens,
            events.clone(),
            events,
            blobs,
            rings.clone(),
            rings,
            bans,
        );
        let svc = StorageServiceImpl::new(store);

        let group_a = GroupId(ulid::Ulid::new());
        let group_b = GroupId(ulid::Ulid::new());

        svc.upload_key_blobs(tenant_request(
            token,
            UploadKeyBlobsRequest {
                group_id: group_a.to_string(),
                blobs: vec![KeyBlob {
                    rage_pub: Some(rage_pub(1)),
                    blob: b"blob-a".to_vec(),
                }],
            },
        ))
        .await
        .expect("upload group a");

        svc.upload_key_blobs(tenant_request(
            token,
            UploadKeyBlobsRequest {
                group_id: group_b.to_string(),
                blobs: vec![KeyBlob {
                    rage_pub: Some(rage_pub(1)),
                    blob: b"blob-b".to_vec(),
                }],
            },
        ))
        .await
        .expect("upload group b");

        let resp_a = svc
            .download_my_key_blob(tenant_request(
                token,
                DownloadMyKeyBlobRequest {
                    group_id: group_a.to_string(),
                    rage_pub: Some(rage_pub(1)),
                },
            ))
            .await
            .expect("download group a")
            .into_inner();
        assert_eq!(resp_a.blob, b"blob-a".to_vec());

        let resp_b = svc
            .download_my_key_blob(tenant_request(
                token,
                DownloadMyKeyBlobRequest {
                    group_id: group_b.to_string(),
                    rage_pub: Some(rage_pub(1)),
                },
            ))
            .await
            .expect("download group b")
            .into_inner();
        assert_eq!(resp_b.blob, b"blob-b".to_vec());
    }
}
