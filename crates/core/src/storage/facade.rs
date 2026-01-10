use std::sync::Arc;

use crate::ids::{GroupId, KeyImage, MasterPublicKey, Nanos, RingHash, TenantId, TenantToken};
use crate::ring_log::RingDelta;
use crate::storage::{
    BanIndex, BannedOperation, BillingStore, EventBytes, EventReader, EventRecord, EventWriter,
    GiftCard, GiftCardStore, GroupMetadataStore, IdempotencyResult, KeyBlobStore, PendingMember,
    PendingMemberStore, PollRingHashIndex, RingDeltaPath, RingView, RingWriter, SequenceNo,
    StorageError, TenantTokenError, TenantTokenStore, VoteKeyImageIndex,
};
use nazgul::ring::Ring;

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
    poll_ring_hashes: Arc<dyn PollRingHashIndex + Send + Sync>,
    billing: Arc<dyn BillingStore + Send + Sync>,
    gift_cards: Arc<dyn GiftCardStore + Send + Sync>,
    groups: Arc<dyn GroupMetadataStore + Send + Sync>,
    pending_members: Arc<dyn PendingMemberStore + Send + Sync>,
}

/// Error returned when building a `StorageFacade` with missing components.
#[derive(Debug, Clone)]
pub struct StorageFacadeBuilderError {
    /// The name of the missing field.
    pub missing_field: &'static str,
}

impl std::fmt::Display for StorageFacadeBuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "StorageFacade builder missing required field: {}",
            self.missing_field
        )
    }
}

impl std::error::Error for StorageFacadeBuilderError {}

/// Builder for constructing a `StorageFacade` with a fluent API.
///
/// # Example
///
/// ```ignore
/// let facade = StorageFacadeBuilder::new()
///     .tenant_tokens(tokens)
///     .event_storage(reader, writer)
///     .ring_storage(view, writer)
///     .key_blobs(blobs)
///     .ban_index(bans)
///     .vote_key_images(images)
///     .poll_ring_hashes(poll_hashes)
///     .billing(billing)
///     .gift_cards(cards)
///     .groups(groups)
///     .pending_members(members)
///     .build()?;
/// ```
#[derive(Default)]
pub struct StorageFacadeBuilder {
    tenant_tokens: Option<Arc<dyn TenantTokenStore + Send + Sync>>,
    event_reader: Option<Arc<dyn EventReader + Send + Sync>>,
    event_writer: Option<Arc<dyn EventWriter + Send + Sync>>,
    key_blobs: Option<Arc<dyn KeyBlobStore + Send + Sync>>,
    ring_view: Option<Arc<dyn RingView + Send + Sync>>,
    ring_writer: Option<Arc<dyn RingWriter + Send + Sync>>,
    ban_index: Option<Arc<dyn BanIndex + Send + Sync>>,
    vote_key_images: Option<Arc<dyn VoteKeyImageIndex + Send + Sync>>,
    poll_ring_hashes: Option<Arc<dyn PollRingHashIndex + Send + Sync>>,
    billing: Option<Arc<dyn BillingStore + Send + Sync>>,
    gift_cards: Option<Arc<dyn GiftCardStore + Send + Sync>>,
    groups: Option<Arc<dyn GroupMetadataStore + Send + Sync>>,
    pending_members: Option<Arc<dyn PendingMemberStore + Send + Sync>>,
}

impl StorageFacadeBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the tenant token store.
    pub fn tenant_tokens(mut self, store: Arc<dyn TenantTokenStore + Send + Sync>) -> Self {
        self.tenant_tokens = Some(store);
        self
    }

    /// Set both event reader and writer.
    pub fn event_storage(
        mut self,
        reader: Arc<dyn EventReader + Send + Sync>,
        writer: Arc<dyn EventWriter + Send + Sync>,
    ) -> Self {
        self.event_reader = Some(reader);
        self.event_writer = Some(writer);
        self
    }

    /// Set both ring view and writer.
    pub fn ring_storage(
        mut self,
        view: Arc<dyn RingView + Send + Sync>,
        writer: Arc<dyn RingWriter + Send + Sync>,
    ) -> Self {
        self.ring_view = Some(view);
        self.ring_writer = Some(writer);
        self
    }

    /// Set the key blob store.
    pub fn key_blobs(mut self, store: Arc<dyn KeyBlobStore + Send + Sync>) -> Self {
        self.key_blobs = Some(store);
        self
    }

    /// Set the ban index.
    pub fn ban_index(mut self, index: Arc<dyn BanIndex + Send + Sync>) -> Self {
        self.ban_index = Some(index);
        self
    }

    /// Set the vote key image index.
    pub fn vote_key_images(mut self, index: Arc<dyn VoteKeyImageIndex + Send + Sync>) -> Self {
        self.vote_key_images = Some(index);
        self
    }

    /// Set the poll ring hash index.
    pub fn poll_ring_hashes(mut self, index: Arc<dyn PollRingHashIndex + Send + Sync>) -> Self {
        self.poll_ring_hashes = Some(index);
        self
    }

    /// Set the billing store.
    pub fn billing(mut self, store: Arc<dyn BillingStore + Send + Sync>) -> Self {
        self.billing = Some(store);
        self
    }

    /// Set the gift card store.
    pub fn gift_cards(mut self, store: Arc<dyn GiftCardStore + Send + Sync>) -> Self {
        self.gift_cards = Some(store);
        self
    }

    /// Set the group metadata store.
    pub fn groups(mut self, store: Arc<dyn GroupMetadataStore + Send + Sync>) -> Self {
        self.groups = Some(store);
        self
    }

    /// Set the pending member store.
    pub fn pending_members(mut self, store: Arc<dyn PendingMemberStore + Send + Sync>) -> Self {
        self.pending_members = Some(store);
        self
    }

    /// Build the `StorageFacade`, returning an error if any required field is missing.
    pub fn build(self) -> Result<StorageFacade, StorageFacadeBuilderError> {
        Ok(StorageFacade {
            tenant_tokens: self.tenant_tokens.ok_or(StorageFacadeBuilderError {
                missing_field: "tenant_tokens",
            })?,
            event_reader: self.event_reader.ok_or(StorageFacadeBuilderError {
                missing_field: "event_reader",
            })?,
            event_writer: self.event_writer.ok_or(StorageFacadeBuilderError {
                missing_field: "event_writer",
            })?,
            key_blobs: self.key_blobs.ok_or(StorageFacadeBuilderError {
                missing_field: "key_blobs",
            })?,
            ring_view: self.ring_view.ok_or(StorageFacadeBuilderError {
                missing_field: "ring_view",
            })?,
            ring_writer: self.ring_writer.ok_or(StorageFacadeBuilderError {
                missing_field: "ring_writer",
            })?,
            ban_index: self.ban_index.ok_or(StorageFacadeBuilderError {
                missing_field: "ban_index",
            })?,
            vote_key_images: self.vote_key_images.ok_or(StorageFacadeBuilderError {
                missing_field: "vote_key_images",
            })?,
            poll_ring_hashes: self.poll_ring_hashes.ok_or(StorageFacadeBuilderError {
                missing_field: "poll_ring_hashes",
            })?,
            billing: self.billing.ok_or(StorageFacadeBuilderError {
                missing_field: "billing",
            })?,
            gift_cards: self.gift_cards.ok_or(StorageFacadeBuilderError {
                missing_field: "gift_cards",
            })?,
            groups: self.groups.ok_or(StorageFacadeBuilderError {
                missing_field: "groups",
            })?,
            pending_members: self.pending_members.ok_or(StorageFacadeBuilderError {
                missing_field: "pending_members",
            })?,
        })
    }
}

impl StorageFacade {
    /// Create a new builder for constructing a `StorageFacade`.
    pub fn builder() -> StorageFacadeBuilder {
        StorageFacadeBuilder::new()
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
    // Poll ring hash methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Store the ring hash for a newly created poll.
    ///
    /// This should be called when processing a `PollCreate` event to record
    /// the ring that was in effect at poll creation time.
    pub async fn store_poll_ring_hash(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
        ring_hash: RingHash,
    ) -> Result<(), StorageError> {
        self.poll_ring_hashes
            .store(tenant, group_id, poll_id, ring_hash)
            .await
    }

    /// Retrieve the ring hash for a poll.
    ///
    /// This is used during vote verification to get the ring against which
    /// the vote's ring signature must be verified.
    pub async fn get_poll_ring_hash(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
    ) -> Result<RingHash, StorageError> {
        self.poll_ring_hashes.get(tenant, group_id, poll_id).await
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
    pub async fn issue_gift_card(&self, amount: Nanos) -> Result<GiftCard, StorageError> {
        self.gift_cards.issue(amount).await
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
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        self.billing
            .credit_tenant(tenant, owner_tg_user_id, amount)
            .await
    }

    /// Transfer funds from tenant balance to a group's budget.
    pub async fn transfer_to_group(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        self.billing
            .transfer_to_group(tenant, group_id, amount)
            .await
    }

    /// Get a group's current budget balance.
    pub async fn get_group_balance(&self, group_id: GroupId) -> Result<Nanos, StorageError> {
        self.billing.get_group_balance(group_id).await
    }

    /// Find a tenant by their Telegram user ID.
    ///
    /// Returns the TenantId if found, regardless of whether they have any groups.
    pub async fn find_tenant_by_tg_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<TenantId>, StorageError> {
        self.billing.find_tenant_by_tg_user(tg_user_id).await
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

    /// Check if an idempotency key has been used.
    ///
    /// Returns `Some(result)` if the key was previously used, allowing the
    /// caller to replay the original response. Returns `None` if the key
    /// is new and the operation should proceed.
    pub async fn check_idempotency_key(
        &self,
        key: &str,
    ) -> Result<Option<IdempotencyResult>, StorageError> {
        self.billing.check_idempotency_key(key).await
    }

    /// Record the result of an idempotent operation.
    ///
    /// Stores the result with the given TTL so future requests with the same
    /// key can replay this response.
    pub async fn record_idempotency_result(
        &self,
        key: &str,
        result: IdempotencyResult,
        ttl_secs: u64,
    ) -> Result<(), StorageError> {
        self.billing
            .record_idempotency_result(key, result, ttl_secs)
            .await
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

    /// Set the owner's Nazgul public key for a group.
    ///
    /// This key is used for verifying owner/delegate signatures on admin events.
    pub async fn set_owner_pubkey(
        &self,
        group_id: GroupId,
        owner_pubkey: MasterPublicKey,
    ) -> Result<(), StorageError> {
        self.groups.set_owner_pubkey(group_id, owner_pubkey).await
    }

    /// Get the owner's Nazgul public key for a group.
    ///
    /// Returns `None` if the owner pubkey has not been set yet.
    pub async fn get_owner_pubkey(
        &self,
        group_id: GroupId,
    ) -> Result<Option<MasterPublicKey>, StorageError> {
        self.groups.get_owner_pubkey(group_id).await
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

    // ─────────────────────────────────────────────────────────────────────────
    // Internal accessor methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Get a reference to the underlying billing store.
    ///
    /// This is primarily used for constructing metering interceptors in
    /// enterprise deployments where egress billing is required.
    pub fn billing_store(&self) -> Arc<dyn BillingStore + Send + Sync> {
        self.billing.clone()
    }
}
