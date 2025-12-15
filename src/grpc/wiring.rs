use crate::grpc::interceptor::{require_api_token, require_bot_secret};
use crate::grpc::services::{
    AdminServiceImpl, AuthServiceImpl, BillingServiceImpl, EventServiceImpl, GroupServiceImpl,
    MemberServiceImpl, RingServiceImpl, StorageServiceImpl,
};
use crate::grpc::types::{
    InMemoryEvents, InMemoryGiftCards, InMemoryGroups, InMemoryKeyBlobs, InMemoryPendingMembers,
    InMemoryRings, InMemoryTenantTokens, NoopBanIndex,
};
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
    pub fn new_in_memory() -> Self {
        let tenant_tokens = Arc::new(InMemoryTenantTokens::new());
        let events = Arc::new(InMemoryEvents::new());
        let key_blobs = Arc::new(InMemoryKeyBlobs::new());
        let rings = Arc::new(InMemoryRings::new());
        let ban_index = Arc::new(NoopBanIndex);
        let gift_cards = Arc::new(InMemoryGiftCards::new());
        let groups = Arc::new(InMemoryGroups::new());
        let pending_members = Arc::new(InMemoryPendingMembers::new());

        let facade = StorageFacade::new(
            tenant_tokens,
            events.clone(), // reader
            events,         // writer
            key_blobs,
            rings.clone(), // view
            rings,         // writer
            ban_index,
            gift_cards,
            groups,
            pending_members,
        );

        Self {
            event: EventServiceImpl::new(facade.clone()),
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
    Server::builder()
        .layer(tonic::service::interceptor(require_api_token))
        .accept_http1(true)
        .add_service(tonic_web::enable(EventServiceServer::new(event)))
        .add_service(tonic_web::enable(RingServiceServer::new(ring)))
        .add_service(tonic_web::enable(StorageServiceServer::new(storage)))
        .add_service(tonic_web::enable(MemberServiceServer::new(member)))
        .serve(addr)
}

pub fn run_internal_server(
    admin: AdminServiceImpl,
    auth: AuthServiceImpl,
    billing: BillingServiceImpl,
    group: GroupServiceImpl,
    member: MemberServiceImpl,
    _bot_secret: &str, // Injected via env/config usually, but interceptor uses env var directly in current impl
    addr: SocketAddr,
) -> impl std::future::Future<Output = Result<(), tonic::transport::Error>> {
    Server::builder()
        .layer(tonic::service::interceptor(require_bot_secret))
        .accept_http1(true)
        .add_service(tonic_web::enable(AdminServiceServer::new(admin)))
        .add_service(tonic_web::enable(AuthServiceServer::new(auth)))
        .add_service(tonic_web::enable(BillingServiceServer::new(billing)))
        .add_service(tonic_web::enable(GroupServiceServer::new(group)))
        .add_service(tonic_web::enable(MemberServiceServer::new(member)))
        .serve(addr)
}
