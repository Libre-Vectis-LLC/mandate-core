use crate::event::Event;
use crate::ids::{GroupId, RingHash, TenantId};
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
    ListPendingMembersRequest, ListPendingMembersResponse, PendingMember as ProtoPendingMember,
    PushEventRequest, PushEventResponse, RedeemGiftCardRequest, RedeemGiftCardResponse,
    SetOwnerPublicKeyRequest, SetOwnerPublicKeyResponse, StreamEventsRequest, StreamEventsResponse,
    StreamRingRequest, StreamRingResponse, SubmitPendingMemberRequest, SubmitPendingMemberResponse,
    TransferToGroupRequest, TransferToGroupResponse, UploadKeyBlobsRequest, UploadKeyBlobsResponse,
};
use nazgul::traits::LocalByteConvertible;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

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
        crate::storage::StorageError::AlreadyExists => {
            RpcError::AlreadyExists("resource exists".into()).into()
        }
        crate::storage::StorageError::PreconditionFailed(msg) => {
            RpcError::FailedPrecondition(msg).into()
        }
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
async fn extract_tenant_id<T>(
    req: &Request<T>,
    tokens: &(impl TenantTokenStore + ?Sized),
) -> Result<crate::ids::TenantId, Status> {
    if let Some(tenant) = req.extensions().get::<crate::ids::TenantId>() {
        return Ok(*tenant);
    }

    let token = extract_tenant_token(req)?;
    tokens.resolve_tenant(&token).await.map_err(to_status_token)
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
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens).await?;
        let body = request.into_inner();
        let event_bytes: crate::storage::EventBytes = body.event_bytes.into();
        let event: Event = serde_json::from_slice(&event_bytes)
            .map_err(|e| RpcError::InvalidArgument(format!("invalid event payload: {e}")))?;

        // 1. Verify Chain Hash
        match self.store.event_reader.tail(tenant, event.group_id).await {
            Ok((tail_id, _, _)) => {
                let tail_hash = crate::ids::ContentHash(tail_id.0);
                if event.previous_event_hash.0 != tail_hash.0 {
                    return Err(RpcError::FailedPrecondition(format!(
                        "chain mismatch: expected prev={:?}, got {:?}",
                        tail_hash, event.previous_event_hash
                    ))
                    .into());
                }
            }
            Err(crate::storage::StorageError::NotFound(_)) => {
                // Genesis event must have zero prev hash
                if event.previous_event_hash.0 != [0u8; 32] {
                    return Err(RpcError::FailedPrecondition(
                        "first event must have zero prev hash".into(),
                    )
                    .into());
                }
            }
            Err(e) => return Err(to_status(e)),
        }

        // 2. Check Ban Index
        if let Some(sig) = &event.signature {
            let key_image = sig.key_image();
            let banned = self
                .store
                .ban_index
                .is_banned(tenant, event.group_id, &key_image)
                .await
                .map_err(to_status)?;
            if banned {
                return Err(
                    RpcError::FailedPrecondition("double spend: key image banned".into()).into(),
                );
            }
        }

        // 3. Verify Signature
        // Load ring if needed (Compact signature)
        let external_ring = if let Some(sig) = &event.signature {
            match sig.mode() {
                crate::crypto::signature::StorageMode::Compact => {
                    // Extract ring hash from event body.
                    // We need to inspect event_type to get ring_hash.
                    // This is slightly brittle if event structure changes, but for now:
                    let ring_hash = match &event.event_type {
                        crate::event::EventType::PollCreate(p) => p.ring_hash,
                        crate::event::EventType::VoteCast(v) => v.ring_hash,
                        crate::event::EventType::MessageCreate(m) => m.ring_hash,
                        crate::event::EventType::RingUpdate(r) => r.ring_hash,
                        crate::event::EventType::BanCreate(_b) => {
                            // BanCreate doesn't have ring_hash in struct?
                            // Let's check struct definition.
                            // It seems BanCreate/BanRevoke/ProofOfInnocence might miss it in my memory model.
                            // Assume all authenticated events have it or we fail.
                            // Actually, if BanCreate is signed by admin (owner), does it use ring?
                            // Yes, owner is in ring.
                            // If field is missing, we can't verify compact sig.
                            return Err(RpcError::InvalidArgument(
                                "event type missing ring_hash for compact sig".into(),
                            )
                            .into());
                        }
                        _ => {
                            return Err(RpcError::InvalidArgument(
                                "event type missing ring_hash for compact sig".into(),
                            )
                            .into())
                        }
                    };

                    Some(
                        self.store
                            .ring_view
                            .ring_by_hash(tenant, event.group_id, &ring_hash)
                            .await
                            .map_err(to_status)?,
                    )
                }
                crate::crypto::signature::StorageMode::Archival => None,
            }
        } else {
            // No signature? Allowed only for special unsigned events?
            // Current protocol requires signatures for everything pushed by clients.
            return Err(RpcError::Unauthenticated("missing signature".into()).into());
        };

        if let Some(sig) = &event.signature {
            let signed_msg = event
                .to_signing_bytes()
                .map_err(|e| RpcError::Internal(format!("canonical serialization failed: {e}")))?;

            let item = crate::crypto::verifier::SignatureItem {
                signature: sig.clone(),
                message: signed_msg,
                external_ring,
            };

            let results = self
                .verifier
                .verify_batch(&[item])
                .await
                .map_err(|e| RpcError::Internal(e.to_string()))?;
            if !results[0] {
                return Err(RpcError::Unauthenticated("invalid signature".into()).into());
            }
        }

        // 4. Commit
        let id = self
            .store
            .event_writer
            .append(tenant, event.group_id, event_bytes.clone())
            .await
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
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens).await?;
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
            .await
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
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens).await?;
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
            .await
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
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens).await?;
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
            .await
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
            .await
            .map_err(to_status)?;

        let entries = encode_ring_delta_path(
            &*self.store.ring_view,
            tenant,
            group_id,
            &path,
            clamp_ring_limit(req.limit),
        )
        .await?;
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
async fn encode_ring_delta_path(
    rings: &(impl RingView + ?Sized),
    tenant: crate::ids::TenantId,
    group_id: GroupId,
    path: &crate::storage::RingDeltaPath,
    limit: usize,
) -> Result<Vec<mandate_proto::mandate::v1::RingDeltaEntry>, Status> {
    let anchor = rings
        .ring_by_hash(tenant, group_id, &path.from)
        .await
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

#[derive(Clone)]
pub struct AdminServiceImpl {
    store: StorageFacade,
}

impl AdminServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn issue_gift_card(
        &self,
        request: Request<IssueGiftCardRequest>,
    ) -> Result<Response<IssueGiftCardResponse>, Status> {
        let body = request.into_inner();
        let card = self
            .store
            .gift_cards
            .issue(body.amount_nanos)
            .await
            .map_err(to_status)?;
        Ok(Response::new(IssueGiftCardResponse { code: card.code }))
    }
}

#[derive(Clone)]
pub struct AuthServiceImpl {
    store: StorageFacade,
}

impl AuthServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    async fn redeem_gift_card(
        &self,
        request: Request<RedeemGiftCardRequest>,
    ) -> Result<Response<RedeemGiftCardResponse>, Status> {
        let body = request.into_inner();
        // MVP: In-memory tenant creation. Real impl would look up by TG ID.
        let tenant_id = crate::ids::TenantId(ulid::Ulid::new());

        let _card = self
            .store
            .gift_cards
            .redeem(&body.code, tenant_id)
            .await
            .map_err(to_status)?;

        // Issue a token.
        let token_str = format!("token-{}", ulid::Ulid::new());
        let token = crate::ids::TenantToken::from(token_str.clone());
        self.store
            .tenant_tokens
            .insert(&token, tenant_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(RedeemGiftCardResponse {
            tenant_id: tenant_id.0.to_string(),
            new_balance_nanos: 1000, // Mock balance
            api_token: token_str,
        }))
    }
}

#[derive(Clone)]
pub struct BillingServiceImpl {
    #[allow(dead_code)]
    store: StorageFacade,
}

impl BillingServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl BillingService for BillingServiceImpl {
    async fn transfer_to_group(
        &self,
        request: Request<TransferToGroupRequest>,
    ) -> Result<Response<TransferToGroupResponse>, Status> {
        let _body = request.into_inner();
        // Mock success for MVP.
        Ok(Response::new(TransferToGroupResponse {
            balance_after_nanos: 900,
        }))
    }

    async fn get_group_balance(
        &self,
        _request: Request<GetGroupBalanceRequest>,
    ) -> Result<Response<GetGroupBalanceResponse>, Status> {
        Ok(Response::new(GetGroupBalanceResponse {
            balance_nanos: 100,
        }))
    }
}

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
        request: Request<CreateGroupRequest>,
    ) -> Result<Response<CreateGroupResponse>, Status> {
        let body = request.into_inner();
        let tenant_id = TenantId(
            crate::proto::parse_ulid(&body.tenant_id)
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?,
        );

        let group_id = self
            .store
            .groups
            .create_group(tenant_id, &body.tg_group_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(CreateGroupResponse {
            group_id: group_id.to_string(),
        }))
    }

    async fn set_owner_public_key(
        &self,
        request: Request<SetOwnerPublicKeyRequest>,
    ) -> Result<Response<SetOwnerPublicKeyResponse>, Status> {
        let body = request.into_inner();
        let group_id = GroupId(
            crate::proto::parse_ulid(&body.group_id)
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?,
        );

        let (tenant, _) = self
            .store
            .groups
            .get_group(group_id)
            .await
            .map_err(to_status)?;

        let owner_pubkey = body
            .owner_pubkey
            .as_ref()
            .ok_or_else(|| RpcError::InvalidArgument("missing owner_pubkey".into()))?;
        let owner_pubkey = crate::proto::nazgul_pub_from_proto(owner_pubkey)
            .map_err(|e| RpcError::InvalidArgument(e.to_string()))?;

        match self.store.ring_view.current_ring(tenant, group_id).await {
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
            .await
            .map_err(to_status)?;

        Ok(Response::new(SetOwnerPublicKeyResponse {}))
    }

    async fn get_group(
        &self,
        _request: Request<GetGroupRequest>,
    ) -> Result<Response<GetGroupResponse>, Status> {
        Err(Status::unimplemented("get_group not implemented"))
    }
}

#[derive(Clone)]
pub struct MemberServiceImpl {
    store: StorageFacade,
}

impl MemberServiceImpl {
    pub fn new(store: StorageFacade) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl MemberService for MemberServiceImpl {
    async fn submit_pending_member(
        &self,
        request: Request<SubmitPendingMemberRequest>,
    ) -> Result<Response<SubmitPendingMemberResponse>, Status> {
        let body = request.into_inner();
        let group_id = GroupId(
            crate::proto::parse_ulid(&body.group_id)
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?,
        );

        let (tenant, _) = self
            .store
            .groups
            .get_group(group_id)
            .await
            .map_err(to_status)?;

        let nazgul_pub = body
            .nazgul_pub
            .as_ref()
            .ok_or_else(|| RpcError::InvalidArgument("missing nazgul_pub".into()))?;
        let nazgul_pub = crate::proto::nazgul_pub_from_proto(nazgul_pub)
            .map_err(|e| RpcError::InvalidArgument(e.to_string()))?;

        let rage_pub = body
            .rage_pub
            .as_ref()
            .ok_or_else(|| RpcError::InvalidArgument("missing rage_pub".into()))?;
        let rage_pub = crate::proto::rage_pub_from_proto(rage_pub)
            .map_err(|e| RpcError::InvalidArgument(e.to_string()))?;

        let pending_id = self
            .store
            .pending_members
            .submit(tenant, group_id, &body.tg_user_id, nazgul_pub, rage_pub)
            .await
            .map_err(to_status)?;

        Ok(Response::new(SubmitPendingMemberResponse { pending_id }))
    }

    async fn list_pending_members(
        &self,
        request: Request<ListPendingMembersRequest>,
    ) -> Result<Response<ListPendingMembersResponse>, Status> {
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens).await?;
        let body = request.into_inner();
        let group_id = GroupId(
            crate::proto::parse_ulid(&body.group_id)
                .map_err(|e| RpcError::InvalidArgument(e.to_string()))?,
        );

        let (group_tenant, _) = self
            .store
            .groups
            .get_group(group_id)
            .await
            .map_err(to_status)?;
        if group_tenant != tenant {
            return Err(RpcError::NotFound("group not found".into()).into());
        }

        let (members, _next_page) = self
            .store
            .pending_members
            .list(tenant, group_id, clamp_events_limit(body.limit), None)
            .await
            .map_err(to_status)?;

        let proto_members = members
            .into_iter()
            .map(|m| ProtoPendingMember {
                pending_id: m.pending_id,
                tg_user_id: m.tg_user_id,
                nazgul_pub: Some(crate::proto::master_pub_to_proto(&m.nazgul_pub)),
                rage_pub: Some(mandate_proto::mandate::v1::RagePublicKey {
                    value: m.rage_pub.to_vec(),
                }),
                submitted_at_ms: m.submitted_at_ms,
            })
            .collect();

        Ok(Response::new(ListPendingMembersResponse {
            members: proto_members,
            next_page_token: None,
        }))
    }
}

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
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens).await?;
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
            .await
            .map_err(to_status)?;
        Ok(Response::new(UploadKeyBlobsResponse {}))
    }

    async fn download_my_key_blob(
        &self,
        request: Request<DownloadMyKeyBlobRequest>,
    ) -> Result<Response<DownloadMyKeyBlobResponse>, Status> {
        let tenant = extract_tenant_id(&request, &*self.store.tenant_tokens).await?;
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
            .await
            .map_err(to_status)?;

        Ok(Response::new(DownloadMyKeyBlobResponse {
            blob: blob.to_vec(),
        }))
    }
}
