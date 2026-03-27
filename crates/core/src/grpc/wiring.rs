use crate::grpc::inmemory::{
    InMemoryBanIndex, InMemoryBilling, InMemoryBundlePublished, InMemoryEvents, InMemoryGiftCards,
    InMemoryInviteCodeStore, InMemoryKeyBlobs, InMemoryOrgs, InMemoryPendingMembers,
    InMemoryPollRingHashes, InMemoryRings, InMemoryTenantTokens, InMemoryVoteKeyImages,
    InMemoryVoteRevocations,
};
use crate::grpc::interceptor::{make_bot_secret_interceptor, require_api_token};
use crate::grpc::services::{
    AdminServiceImpl, AuthServiceImpl, BillingServiceImpl, EventServiceImpl, InviteServiceImpl,
    MemberServiceImpl, OrganizationServiceImpl, RingServiceImpl, StorageServiceImpl,
};
use crate::ids::{BotSecret, TenantId, TenantToken};
use crate::storage::facade::{StorageFacade, StorageFacadeBuilderError};
use mandate_proto::mandate::v1::{
    admin_service_server::AdminServiceServer, auth_service_server::AuthServiceServer,
    billing_service_server::BillingServiceServer, event_service_server::EventServiceServer,
    invite_service_server::InviteServiceServer, member_service_server::MemberServiceServer,
    organization_service_server::OrganizationServiceServer, ring_service_server::RingServiceServer,
    storage_service_server::StorageServiceServer,
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
    pub organization: OrganizationServiceImpl,
    pub member: MemberServiceImpl,
    pub invite: InviteServiceImpl,
}

impl CoreServices {
    /// Create in-memory services with no pre-registered tokens.
    pub fn new_in_memory() -> Result<Self, StorageFacadeBuilderError> {
        Self::new_in_memory_with_seed(None)
    }

    /// Create in-memory services with an optional seed token.
    ///
    /// Useful for E2E testing where a pre-registered API token is needed
    /// (e.g., for edge proxy authentication).
    pub fn new_in_memory_with_seed(
        seed: Option<(TenantToken, TenantId)>,
    ) -> Result<Self, StorageFacadeBuilderError> {
        let tenant_tokens = Arc::new(InMemoryTenantTokens::new());
        if let Some((token, tenant)) = seed {
            tenant_tokens.insert(token, tenant);
        }
        let ban_index = Arc::new(InMemoryBanIndex::new());
        let vote_key_images = Arc::new(InMemoryVoteKeyImages::new());
        let vote_revocations = Arc::new(InMemoryVoteRevocations::new());
        let bundle_published = Arc::new(InMemoryBundlePublished::new());
        let poll_ring_hashes = Arc::new(InMemoryPollRingHashes::new());
        let pending_members = Arc::new(InMemoryPendingMembers::new());
        let events = Arc::new(InMemoryEvents::new(
            ban_index.clone(),
            vote_key_images.clone(),
            pending_members.clone(),
        ));
        let key_blobs = Arc::new(InMemoryKeyBlobs::new());
        let rings = Arc::new(InMemoryRings::new());
        let gift_cards = Arc::new(InMemoryGiftCards::new());
        let orgs = Arc::new(InMemoryOrgs::new());
        let billing = Arc::new(InMemoryBilling::new(orgs.shared()));
        let verifier = Arc::new(crate::crypto::verifier::LocalSignatureVerifier);

        let invite_codes = Arc::new(InMemoryInviteCodeStore::new());

        let facade = StorageFacade::builder()
            .tenant_tokens(tenant_tokens)
            .event_storage(events.clone(), events)
            .key_blobs(key_blobs)
            .ring_storage(rings.clone(), rings)
            .ban_index(ban_index)
            .vote_key_images(vote_key_images)
            .vote_revocations(vote_revocations)
            .bundle_published(bundle_published)
            .poll_ring_hashes(poll_ring_hashes)
            .billing(billing)
            .gift_cards(gift_cards)
            .orgs(orgs)
            .pending_members(pending_members)
            .invite_codes(invite_codes)
            .build()?;

        Ok(Self {
            event: EventServiceImpl::new(facade.clone(), verifier),
            ring: RingServiceImpl::new(facade.clone()),
            storage: StorageServiceImpl::new(facade.clone()),
            admin: AdminServiceImpl::new(facade.clone()),
            auth: AuthServiceImpl::new(facade.clone()),
            billing: BillingServiceImpl::new(facade.clone()),
            organization: OrganizationServiceImpl::new(facade.clone()),
            member: MemberServiceImpl::new(facade.clone()),
            invite: InviteServiceImpl::new(facade.clone()),
        })
    }
}

pub fn run_public_server(
    event: EventServiceImpl,
    ring: RingServiceImpl,
    storage: StorageServiceImpl,
    member: MemberServiceImpl, // ListPendingMembers is public
    invite: InviteServiceImpl,
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
        .add_service(tonic_web::enable(
            InviteServiceServer::new(invite)
                .max_decoding_message_size(max_bytes)
                .max_encoding_message_size(max_bytes),
        ))
        .serve(addr)
}

pub fn run_internal_server(
    admin: AdminServiceImpl,
    auth: AuthServiceImpl,
    billing: BillingServiceImpl,
    organization: OrganizationServiceImpl,
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
            OrganizationServiceServer::new(organization)
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
