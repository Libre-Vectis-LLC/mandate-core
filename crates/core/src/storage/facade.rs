use std::sync::Arc;

use crate::storage::{
    BanIndex, BillingStore, EventReader, EventWriter, GiftCardStore, GroupMetadataStore,
    KeyBlobStore, PendingMemberStore, RingView, RingWriter, TenantTokenStore, VoteKeyImageIndex,
};

/// Thin convenience wrapper to inject storage capabilities as a single handle.
#[derive(Clone)]
pub struct StorageFacade {
    pub tenant_tokens: Arc<dyn TenantTokenStore + Send + Sync>,
    pub event_reader: Arc<dyn EventReader + Send + Sync>,
    pub event_writer: Arc<dyn EventWriter + Send + Sync>,
    pub key_blobs: Arc<dyn KeyBlobStore + Send + Sync>,
    pub ring_view: Arc<dyn RingView + Send + Sync>,
    pub ring_writer: Arc<dyn RingWriter + Send + Sync>,
    pub ban_index: Arc<dyn BanIndex + Send + Sync>,
    pub vote_key_images: Arc<dyn VoteKeyImageIndex + Send + Sync>,
    pub billing: Arc<dyn BillingStore + Send + Sync>,
    pub gift_cards: Arc<dyn GiftCardStore + Send + Sync>,
    pub groups: Arc<dyn GroupMetadataStore + Send + Sync>,
    pub pending_members: Arc<dyn PendingMemberStore + Send + Sync>,
}

impl StorageFacade {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_tokens: Arc<dyn TenantTokenStore + Send + Sync>,
        event_reader: Arc<dyn EventReader + Send + Sync>,
        event_writer: Arc<dyn EventWriter + Send + Sync>,
        key_blobs: Arc<dyn KeyBlobStore + Send + Sync>,
        ring_view: Arc<dyn RingView + Send + Sync>,
        ring_writer: Arc<dyn RingWriter + Send + Sync>,
        ban_index: Arc<dyn BanIndex + Send + Sync>,
        vote_key_images: Arc<dyn VoteKeyImageIndex + Send + Sync>,
        billing: Arc<dyn BillingStore + Send + Sync>,
        gift_cards: Arc<dyn GiftCardStore + Send + Sync>,
        groups: Arc<dyn GroupMetadataStore + Send + Sync>,
        pending_members: Arc<dyn PendingMemberStore + Send + Sync>,
    ) -> Self {
        Self {
            tenant_tokens,
            event_reader,
            event_writer,
            key_blobs,
            ring_view,
            ring_writer,
            ban_index,
            vote_key_images,
            billing,
            gift_cards,
            groups,
            pending_members,
        }
    }
}
