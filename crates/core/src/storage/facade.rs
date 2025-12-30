use std::sync::Arc;

use crate::ids::{GroupId, KeyImage, RingHash, TenantId, TenantToken};
use crate::ring_log::RingDelta;
use crate::storage::{
    BanIndex, BannedOperation, BillingStore, EventBytes, EventReader, EventRecord, EventWriter,
    GiftCard, GiftCardStore, GroupMetadataStore, KeyBlobStore, PendingMember, PendingMemberStore,
    RingDeltaPath, RingView, RingWriter, SequenceNo, StorageError, TenantTokenError,
    TenantTokenStore, VoteKeyImageIndex,
};
use nazgul::ring::Ring;

use crate::ids::MasterPublicKey;

/// Thin convenience wrapper to inject storage capabilities as a single handle.
///
/// This facade provides a unified interface to all storage backends, hiding the
/// internal trait object fields and exposing typed delegation methods.
#[derive(Clone)]
pub struct StorageFacade {
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

    // ─────────────────────────────────────────────────────────────────────────
    // Tenant token methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Resolve a tenant token to a tenant ID.
    pub async fn resolve_tenant(&self, token: &TenantToken) -> Result<TenantId, TenantTokenError> {
        self.tenant_tokens.resolve_tenant(token).await
    }

    /// Insert a new tenant token mapping.
    pub async fn insert_tenant_token(
        &self,
        token: &TenantToken,
        tenant: TenantId,
    ) -> Result<(), StorageError> {
        self.tenant_tokens.insert(token, tenant).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Event methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the tail (most recent) event for a group.
    pub async fn event_tail(
        &self,
        tenant: TenantId,
        group_id: GroupId,
    ) -> Result<EventRecord, StorageError> {
        self.event_reader.tail(tenant, group_id).await
    }

    /// Stream events for a group, starting after the given sequence number.
    pub async fn stream_events(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        after_sequence: Option<SequenceNo>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError> {
        self.event_reader
            .stream_group(tenant, group_id, after_sequence, limit)
            .await
    }

    /// Append an event to the event log.
    pub async fn append_event(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        event_bytes: EventBytes,
    ) -> Result<(crate::ids::EventId, SequenceNo), StorageError> {
        self.event_writer
            .append(tenant, group_id, event_bytes)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Vote key image methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Check if a vote key image has been used for a poll.
    pub async fn is_vote_key_image_used(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
        key_image: &KeyImage,
    ) -> Result<bool, StorageError> {
        self.vote_key_images
            .is_used(tenant, group_id, poll_id, key_image)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ban index methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Check if a key image is banned for a specific operation.
    pub async fn is_banned(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        key_image: &KeyImage,
        operation: BannedOperation,
    ) -> Result<bool, StorageError> {
        self.ban_index
            .is_banned(tenant, group_id, key_image, operation)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ring methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Get a ring by its hash.
    pub async fn ring_by_hash(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        hash: &RingHash,
    ) -> Result<Arc<Ring>, StorageError> {
        self.ring_view.ring_by_hash(tenant, group_id, hash).await
    }

    /// Get the current ring for a group.
    pub async fn current_ring(
        &self,
        tenant: TenantId,
        group_id: GroupId,
    ) -> Result<Arc<Ring>, StorageError> {
        self.ring_view.current_ring(tenant, group_id).await
    }

    /// Get the delta path between two ring hashes.
    pub async fn ring_delta_path(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        from: Option<RingHash>,
        to: RingHash,
    ) -> Result<RingDeltaPath, StorageError> {
        self.ring_view
            .ring_delta_path(tenant, group_id, from, to)
            .await
    }

    /// Append a ring delta to the ring log.
    pub async fn append_ring_delta(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        delta: RingDelta,
    ) -> Result<RingHash, StorageError> {
        self.ring_writer.append_delta(tenant, group_id, delta).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gift card methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Issue a new gift card.
    pub async fn issue_gift_card(&self, amount_nanos: u64) -> Result<GiftCard, StorageError> {
        self.gift_cards.issue(amount_nanos).await
    }

    /// Redeem a gift card for a tenant.
    pub async fn redeem_gift_card(
        &self,
        code: &str,
        tenant: TenantId,
    ) -> Result<GiftCard, StorageError> {
        self.gift_cards.redeem(code, tenant).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Billing methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Credit a tenant's balance.
    pub async fn credit_tenant(
        &self,
        tenant: TenantId,
        owner_tg_user_id: &str,
        amount_nanos: u64,
    ) -> Result<i64, StorageError> {
        self.billing
            .credit_tenant(tenant, owner_tg_user_id, amount_nanos)
            .await
    }

    /// Transfer funds from tenant balance to a group's budget.
    pub async fn transfer_to_group(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        amount_nanos: u64,
    ) -> Result<i64, StorageError> {
        self.billing
            .transfer_to_group(tenant, group_id, amount_nanos)
            .await
    }

    /// Get a group's current budget balance.
    pub async fn get_group_balance(&self, group_id: GroupId) -> Result<i64, StorageError> {
        self.billing.get_group_balance(group_id).await
    }

    /// Resolve a Telegram user ID to their associated tenant and group.
    ///
    /// Returns `None` if no tenant or group is found for this user.
    pub async fn resolve_telegram_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<(TenantId, GroupId)>, StorageError> {
        self.billing.resolve_telegram_user(tg_user_id).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Create a new group.
    pub async fn create_group(
        &self,
        tenant: TenantId,
        tg_group_id: &str,
    ) -> Result<GroupId, StorageError> {
        self.groups.create_group(tenant, tg_group_id).await
    }

    /// Get a group's metadata (tenant ID and Telegram group ID).
    pub async fn get_group(&self, group_id: GroupId) -> Result<(TenantId, String), StorageError> {
        self.groups.get_group(group_id).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Pending member methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Submit a pending member application.
    pub async fn submit_pending_member(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        tg_user_id: &str,
        nazgul_pub: MasterPublicKey,
        rage_pub: [u8; 32],
    ) -> Result<String, StorageError> {
        self.pending_members
            .submit(tenant, group_id, tg_user_id, nazgul_pub, rage_pub)
            .await
    }

    /// List pending members for a group.
    pub async fn list_pending_members(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        limit: usize,
        page_token: Option<String>,
    ) -> Result<(Vec<PendingMember>, Option<String>), StorageError> {
        self.pending_members
            .list(tenant, group_id, limit, page_token)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Key blob methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Store multiple key blobs.
    pub async fn put_key_blobs(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        blobs: Vec<([u8; 32], Arc<[u8]>)>,
    ) -> Result<(), StorageError> {
        self.key_blobs.put_many(tenant, group_id, blobs).await
    }

    /// Retrieve a single key blob by rage public key.
    pub async fn get_key_blob(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        rage_pub: [u8; 32],
    ) -> Result<Arc<[u8]>, StorageError> {
        self.key_blobs.get_one(tenant, group_id, rage_pub).await
    }
}
