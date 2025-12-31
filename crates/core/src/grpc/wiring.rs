use crate::grpc::inmemory::{
    InMemoryBanIndex, InMemoryBilling, InMemoryEvents, InMemoryGiftCards, InMemoryGroups,
    InMemoryKeyBlobs, InMemoryPendingMembers, InMemoryRings, InMemoryTenantTokens,
    InMemoryVoteKeyImages,
};
use crate::grpc::interceptor::{make_bot_secret_interceptor, require_api_token};
use crate::grpc::services::{
    AdminServiceImpl, AuthServiceImpl, BillingServiceImpl, EventServiceImpl, GroupServiceImpl,
    MemberServiceImpl, RingServiceImpl, StorageServiceImpl,
};
use crate::ids::{BotSecret, TenantId, TenantToken};
use crate::storage::facade::StorageFacade;
use mandate_proto::mandate::v1::{
    admin_service_server::AdminServiceServer, auth_service_server::AuthServiceServer,
    billing_service_server::BillingServiceServer, event_service_server::EventServiceServer,
    group_service_server::GroupServiceServer, member_service_server::MemberServiceServer,
    ring_service_server::RingServiceServer, storage_service_server::StorageServiceServer,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tonic::transport::Server;

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(default)
}

fn grpc_max_message_bytes() -> usize {
    env_usize("MANDATE_GRPC_MAX_MESSAGE_BYTES", 4 * 1024 * 1024)
}

#[derive(Clone)]
pub struct CoreServices {
    pub event: EventServiceImpl,
    pub ring: RingServiceImpl,
    pub storage: StorageServiceImpl,
    pub admin: AdminServiceImpl,
    pub auth: AuthServiceImpl,
    pub billing: BillingServiceImpl,
    pub group: GroupServiceImpl,
    pub member: MemberServiceImpl,
}

impl CoreServices {
    /// Create in-memory services with no pre-registered tokens.
    pub fn new_in_memory() -> Self {
        Self::new_in_memory_with_seed(None)
    }

    /// Create in-memory services with an optional seed token.
    ///
    /// Useful for E2E testing where a pre-registered API token is needed
    /// (e.g., for edge proxy authentication).
    pub fn new_in_memory_with_seed(seed: Option<(TenantToken, TenantId)>) -> Self {
        let tenant_tokens = Arc::new(InMemoryTenantTokens::new());
        if let Some((token, tenant)) = seed {
            tenant_tokens.insert(token, tenant);
        }
        let ban_index = Arc::new(InMemoryBanIndex::new());
        let vote_key_images = Arc::new(InMemoryVoteKeyImages::new());
        let pending_members = Arc::new(InMemoryPendingMembers::new());
        let events = Arc::new(InMemoryEvents::new(
            ban_index.clone(),
            vote_key_images.clone(),
            pending_members.clone(),
        ));
        let key_blobs = Arc::new(InMemoryKeyBlobs::new());
        let rings = Arc::new(InMemoryRings::new());
        let gift_cards = Arc::new(InMemoryGiftCards::new());
        let groups = Arc::new(InMemoryGroups::new());
        let billing = Arc::new(InMemoryBilling::new(groups.shared()));
        let verifier = Arc::new(crate::crypto::verifier::LocalSignatureVerifier);

        #[allow(deprecated)]
        let facade = StorageFacade::new(
            tenant_tokens,
            events.clone(), // reader
            events,         // writer
            key_blobs,
            rings.clone(), // view
            rings,         // writer
            ban_index,
            vote_key_images,
            billing,
            gift_cards,
            groups,
            pending_members,
        );

        Self {
            event: EventServiceImpl::new(facade.clone(), verifier),
            ring: RingServiceImpl::new(facade.clone()),
            storage: StorageServiceImpl::new(facade.clone()),
            admin: AdminServiceImpl::new(facade.clone()),
            auth: AuthServiceImpl::new(facade.clone()),
            billing: BillingServiceImpl::new(facade.clone()),
            group: GroupServiceImpl::new(facade.clone()),
            member: MemberServiceImpl::new(facade.clone()),
        }
    }
}

pub fn run_public_server(
    event: EventServiceImpl,
    ring: RingServiceImpl,
    storage: StorageServiceImpl,
    member: MemberServiceImpl, // ListPendingMembers is public
    addr: SocketAddr,
) -> impl std::future::Future<Output = Result<(), tonic::transport::Error>> {
    let max_bytes = grpc_max_message_bytes();
    Server::builder()
        .layer(tonic::service::interceptor(require_api_token))
        .accept_http1(true)
        .add_service(tonic_web::enable(
            EventServiceServer::new(event)
                .max_decoding_message_size(max_bytes)
                .max_encoding_message_size(max_bytes),
        ))
        .add_service(tonic_web::enable(
            RingServiceServer::new(ring)
                .max_decoding_message_size(max_bytes)
                .max_encoding_message_size(max_bytes),
        ))
        .add_service(tonic_web::enable(
            StorageServiceServer::new(storage)
                .max_decoding_message_size(max_bytes)
                .max_encoding_message_size(max_bytes),
        ))
        .add_service(tonic_web::enable(
            MemberServiceServer::new(member)
                .max_decoding_message_size(max_bytes)
                .max_encoding_message_size(max_bytes),
        ))
        .serve(addr)
}

pub fn run_internal_server(
    admin: AdminServiceImpl,
    auth: AuthServiceImpl,
    billing: BillingServiceImpl,
    group: GroupServiceImpl,
    member: MemberServiceImpl,
    bot_secret: BotSecret,
    addr: SocketAddr,
) -> impl std::future::Future<Output = Result<(), tonic::transport::Error>> {
    let max_bytes = grpc_max_message_bytes();
    let interceptor = make_bot_secret_interceptor(bot_secret);
    Server::builder()
        .layer(tonic::service::interceptor(interceptor))
        .accept_http1(true)
        .add_service(tonic_web::enable(
            AdminServiceServer::new(admin)
                .max_decoding_message_size(max_bytes)
                .max_encoding_message_size(max_bytes),
        ))
        .add_service(tonic_web::enable(
            AuthServiceServer::new(auth)
                .max_decoding_message_size(max_bytes)
                .max_encoding_message_size(max_bytes),
        ))
        .add_service(tonic_web::enable(
            BillingServiceServer::new(billing)
                .max_decoding_message_size(max_bytes)
                .max_encoding_message_size(max_bytes),
        ))
        .add_service(tonic_web::enable(
            GroupServiceServer::new(group)
                .max_decoding_message_size(max_bytes)
                .max_encoding_message_size(max_bytes),
        ))
        .add_service(tonic_web::enable(
            MemberServiceServer::new(member)
                .max_decoding_message_size(max_bytes)
                .max_encoding_message_size(max_bytes),
        ))
        .serve(addr)
}
