use std::sync::Arc;

use crate::storage::{
    AccessTokenBlobStore, BanIndex, BillingStore, EdgeAccessTokenStore, EventReader, EventWriter,
    GiftCardStore, GroupMetadataStore, KeyBlobStore, PendingMemberStore, PollRingHashIndex,
    RingView, RingWriter, TenantTokenStore, VoteKeyImageIndex,
};

mod billing;
mod event;
mod group;
mod keys;
mod ring;
mod token;

/// Thin convenience wrapper to inject storage capabilities as a single handle.
///
/// This facade provides a unified interface to all storage backends, hiding the
/// internal trait object fields and exposing typed delegation methods.
#[derive(Clone)]
pub struct StorageFacade {
    pub(super) tenant_tokens: Arc<dyn TenantTokenStore + Send + Sync>,
    pub(super) event_reader: Arc<dyn EventReader + Send + Sync>,
    pub(super) event_writer: Arc<dyn EventWriter + Send + Sync>,
    pub(super) key_blobs: Arc<dyn KeyBlobStore + Send + Sync>,
    pub(super) ring_view: Arc<dyn RingView + Send + Sync>,
    pub(super) ring_writer: Arc<dyn RingWriter + Send + Sync>,
    pub(super) ban_index: Arc<dyn BanIndex + Send + Sync>,
    pub(super) vote_key_images: Arc<dyn VoteKeyImageIndex + Send + Sync>,
    pub(super) poll_ring_hashes: Arc<dyn PollRingHashIndex + Send + Sync>,
    pub(super) billing: Arc<dyn BillingStore + Send + Sync>,
    pub(super) gift_cards: Arc<dyn GiftCardStore + Send + Sync>,
    pub(super) groups: Arc<dyn GroupMetadataStore + Send + Sync>,
    pub(super) pending_members: Arc<dyn PendingMemberStore + Send + Sync>,
    pub(super) access_token_blobs: Option<Arc<dyn AccessTokenBlobStore + Send + Sync>>,
    pub(super) edge_access_tokens: Option<Arc<dyn EdgeAccessTokenStore + Send + Sync>>,
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
    access_token_blobs: Option<Arc<dyn AccessTokenBlobStore + Send + Sync>>,
    edge_access_tokens: Option<Arc<dyn EdgeAccessTokenStore + Send + Sync>>,
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

    /// Set the access token blob store (optional, enterprise-only).
    pub fn access_token_blobs(
        mut self,
        store: Arc<dyn AccessTokenBlobStore + Send + Sync>,
    ) -> Self {
        self.access_token_blobs = Some(store);
        self
    }

    /// Set the edge access token store (optional, enterprise-only).
    pub fn edge_access_tokens(
        mut self,
        store: Arc<dyn EdgeAccessTokenStore + Send + Sync>,
    ) -> Self {
        self.edge_access_tokens = Some(store);
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
            access_token_blobs: self.access_token_blobs,
            edge_access_tokens: self.edge_access_tokens,
        })
    }
}

impl StorageFacade {
    /// Create a new builder for constructing a `StorageFacade`.
    pub fn builder() -> StorageFacadeBuilder {
        StorageFacadeBuilder::new()
    }
}
