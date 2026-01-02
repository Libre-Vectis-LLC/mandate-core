//! Storage-facing traits for audit-first, single-writer append workflows.
//!
//! Design goals:
//! - Single table, multi-tenant, append-only event log (no routine replay; audit-focused).
//! - Zero-copy reads via `Arc<[u8]>`/slices; deterministic ordering by append sequence.
//! - Ring reconstruction is the only replay scenario; implementations find a shortest-path delta slice.
//! - PostgreSQL-friendly: btree/hash indexes on `(ring_hash)`, `(tenant_id, group_id, ring_hash)`,
//!   `(master_pubkey, created_at)`, keyset pagination.

use crate::ids::{
    EventId, GroupId, KeyImage, MasterPublicKey, Nanos, RingHash, SequenceNo, TenantId, TenantToken,
};
use crate::ring_log::{apply_delta, RingDelta, RingLogError};
use async_trait::async_trait;
use nazgul::ring::Ring;
use std::sync::Arc;

pub mod facade;

/// Canonical, signed event bytes (audit-preserving).
pub type EventBytes = Arc<[u8]>;

/// Event identifier, canonical bytes, and sequence number.
pub type EventRecord = (EventId, EventBytes, SequenceNo);

/// Path-limited slice of a ring delta log, usable for incremental replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingDeltaPath {
    /// Starting ring hash (anchor) of this slice.
    pub from: RingHash,
    /// Target ring hash after applying all deltas.
    pub to: RingHash,
    /// Ordered deltas leading from `from` to `to` (shortest path chosen by storage layer).
    pub deltas: Vec<RingDelta>,
}

impl RingDeltaPath {
    /// Replay the delta path onto an anchor ring, returning the final ring.
    /// Caller supplies the anchor ring whose hash must equal `from`.
    pub fn apply(self, mut anchor_ring: Ring) -> Result<Ring, RingLogError> {
        for delta in &self.deltas {
            apply_delta(&mut anchor_ring, delta)?;
        }
        Ok(anchor_ring)
    }
}

/// Unified storage error for trait implementors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StorageError {
    #[error("not found: {0}")]
    NotFound(NotFound),
    #[error("backend error: {0}")]
    Backend(String),
    #[error("already exists")]
    AlreadyExists,
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),
}

/// Errors returned while resolving a tenant token to a tenant identity.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TenantTokenError {
    #[error("unknown tenant token")]
    Unknown,
    #[error("backend error: {0}")]
    Backend(String),
}

/// Resolve a tenant-scoped API token into a tenant identity.
///
/// The real implementation belongs to server/enterprise (cache + DB). Core uses this
/// abstraction so it does not bake in any assumptions about token format or rotation.
#[async_trait]
pub trait TenantTokenStore {
    /// Resolve a tenant token into the associated tenant identifier.
    ///
    /// # Arguments
    /// * `token` - Opaque tenant token provided by the client
    ///
    /// # Returns
    /// The `TenantId` associated with this token.
    ///
    /// # Errors
    /// * `TenantTokenError::Unknown` - When the token does not exist in the store
    /// * `TenantTokenError::Backend` - When the underlying storage layer fails
    async fn resolve_tenant(&self, token: &TenantToken) -> Result<TenantId, TenantTokenError>;

    /// Insert a new tenant token mapping.
    ///
    /// # Arguments
    /// * `token` - The token to store
    /// * `tenant` - The tenant identifier to associate with this token
    ///
    /// # Returns
    /// `Ok(())` on successful insertion.
    ///
    /// # Errors
    /// * `StorageError::AlreadyExists` - When a mapping for this token already exists
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn insert(&self, token: &TenantToken, tenant: TenantId) -> Result<(), StorageError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotFound {
    #[error("event {id:?} for tenant {tenant:?} group {group_id:?}")]
    Event {
        id: EventId,
        tenant: TenantId,
        group_id: GroupId,
    },
    #[error("tenant {tenant:?}")]
    Tenant { tenant: TenantId },
    #[error("group {group_id:?}")]
    Group { group_id: GroupId },
    #[error("tail for tenant {tenant:?} group {group_id:?}")]
    Tail { tenant: TenantId, group_id: GroupId },
    #[error("ring {hash:?} for tenant {tenant:?} group {group_id:?}")]
    Ring {
        hash: RingHash,
        tenant: TenantId,
        group_id: GroupId,
    },
    #[error("ring delta path from {from:?} to {to:?} for tenant {tenant:?} group {group_id:?}")]
    RingDeltaPath {
        from: Option<RingHash>,
        to: RingHash,
        tenant: TenantId,
        group_id: GroupId,
    },
    #[error("key blob for tenant {tenant:?} group {group_id:?} rage_pub {rage_pub:?}")]
    KeyBlob {
        tenant: TenantId,
        group_id: GroupId,
        rage_pub: [u8; 32],
    },
    #[error("gift card {code}")]
    GiftCard { code: String },
}

/// Append-only event storage. Intended for a single-writer per tenant; multi-tenant shares one table.
pub trait EventStore: EventReader + EventWriter {}

/// Write-only surface for events; separated to allow distinct read/write backends.
#[async_trait]
pub trait EventWriter {
    /// Append a canonical, signed event to the append-only log.
    ///
    /// This method is the primary write interface for the audit log. Events are
    /// written in serialized form and never modified after insertion. The returned
    /// sequence number establishes a total order for replay and streaming.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier owning this event
    /// * `group_id` - The group identifier scoping this event
    /// * `event_bytes` - Canonical, signed, serialized event bytes
    ///
    /// # Returns
    /// A tuple of `(EventId, SequenceNo)` uniquely identifying this event and its
    /// position in the total order.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When tenant or group does not exist
    ///
    /// # Invariants
    /// * Events are immutable once appended
    /// * Sequence numbers are strictly increasing per `(tenant, group_id)` pair
    /// * Single-writer assumption: concurrent appends for the same group are undefined
    async fn append(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        event_bytes: EventBytes,
    ) -> Result<(EventId, SequenceNo), StorageError>;
}

/// Read-only grouping helper to support backend-specific implementations (e.g., Postgres).
#[async_trait]
pub trait EventReader {
    /// Stream events for a group in deterministic append order.
    ///
    /// This method supports keyset pagination using sequence numbers. Results are
    /// always ordered by increasing `SequenceNo`, enabling efficient forward iteration
    /// without offset-based pagination.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `after_sequence` - Optional anchor; if `None`, starts from the first event
    /// * `limit` - Maximum number of events to return
    ///
    /// # Returns
    /// A vector of `EventRecord` tuples in ascending sequence order, potentially empty.
    ///
    /// # Errors
    /// * `StorageError::NotFound` - When tenant or group does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Results are always ordered by increasing `SequenceNo`
    /// * No duplicates across successive calls with keyset pagination
    async fn stream_group(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        after_sequence: Option<SequenceNo>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError>;

    /// Retrieve a single event by its identifier.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `id` - The event identifier
    ///
    /// # Returns
    /// The full `EventRecord` including canonical bytes and sequence number.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Event)` - When the event does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        id: &EventId,
    ) -> Result<EventRecord, StorageError>;

    /// Retrieve the most recent event for a group.
    ///
    /// This is a shortcut for retrieving the event with the highest sequence number
    /// for the given `(tenant, group_id)` pair.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    ///
    /// # Returns
    /// The most recent `EventRecord` in append order.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Tail)` - When the group has no events yet
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn tail(&self, tenant: TenantId, group_id: GroupId) -> Result<EventRecord, StorageError>;
}

// Redefine EventStore to inherit async traits?
// Trait inheritance with async_trait is tricky.
// Usually we just implement the supertraits.
// Or we can just use EventReader + EventWriter.
// The `EventStore` trait in previous code combined them and added `get` and `tail`.
// I moved `get` and `tail` to `EventReader`.

/// Store for member key blobs, indexed by Rage public key.
///
/// Keys are scoped by `(tenant, group_id, rage_pub)` to avoid cross-group and cross-tenant leaks.
#[async_trait]
pub trait KeyBlobStore {
    /// Insert multiple encrypted key blobs atomically.
    ///
    /// This method is used during member onboarding to store encrypted key material
    /// for all existing members. Each blob is indexed by the recipient's Rage public key.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `blobs` - Vector of `(rage_pub, encrypted_blob)` pairs
    ///
    /// # Returns
    /// `Ok(())` on successful insertion of all blobs.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When tenant or group does not exist
    ///
    /// # Invariants
    /// * All blobs are inserted atomically (all or nothing)
    /// * Duplicate `rage_pub` keys within a single call may cause implementation-defined behavior
    async fn put_many(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        blobs: Vec<([u8; 32], Arc<[u8]>)>,
    ) -> Result<(), StorageError>;

    /// Retrieve an encrypted key blob by Rage public key.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `rage_pub` - The recipient's Rage public key
    ///
    /// # Returns
    /// The encrypted key blob as `Arc<[u8]>`.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::KeyBlob)` - When no blob exists for this key
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get_one(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        rage_pub: [u8; 32],
    ) -> Result<Arc<[u8]>, StorageError>;
}

/// Access to ring snapshots and delta paths; caching strategy is implementation-defined.
#[async_trait]
pub trait RingView {
    /// Resolve a ring snapshot by its content-addressed hash.
    ///
    /// Implementations may cache ring snapshots or reconstruct them from deltas on demand.
    /// If the ring hash is unknown (not in cache and not reconstructible from deltas), this
    /// method returns `NotFound`.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `hash` - The content-addressed hash of the ring
    ///
    /// # Returns
    /// An `Arc<Ring>` snapshot corresponding to the given hash.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Ring)` - When the ring hash is unknown
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * The returned ring's computed hash matches the provided `hash`
    async fn ring_by_hash(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        hash: &RingHash,
    ) -> Result<Arc<Ring>, StorageError>;

    /// Retrieve the current (latest) ring for a group.
    ///
    /// This method returns the ring corresponding to the most recent delta applied to the group.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    ///
    /// # Returns
    /// An `Arc<Ring>` representing the current group membership ring.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Ring)` - When the group has no ring yet
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn current_ring(
        &self,
        tenant: TenantId,
        group_id: GroupId,
    ) -> Result<Arc<Ring>, StorageError>;

    /// Compute the shortest delta path from one ring to another.
    ///
    /// This method returns a replayable sequence of deltas that transforms `ring_hash_current`
    /// into `ring_hash_target`. Implementations may use graph traversal or other algorithms to
    /// find the shortest path. If `ring_hash_current` is `None`, the path starts from the genesis
    /// (empty) ring.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `ring_hash_current` - Optional starting ring hash; `None` means start from genesis
    /// * `ring_hash_target` - Target ring hash
    ///
    /// # Returns
    /// A `RingDeltaPath` containing the ordered sequence of deltas.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::RingDeltaPath)` - When no path exists
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Applying the returned deltas in order transforms `from` into `to`
    /// * The path is deterministic and reproducible
    async fn ring_delta_path(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        ring_hash_current: Option<RingHash>,
        ring_hash_target: RingHash,
    ) -> Result<RingDeltaPath, StorageError>;
}

/// Write-only interface for ring mutations (e.g., Postgres or in-memory log).
#[async_trait]
pub trait RingWriter {
    /// Append a delta to the ring log, advancing the group's current ring.
    ///
    /// This method applies a membership change (add or remove) to the group's ring and
    /// persists the delta to the log. The returned hash is the content-addressed hash
    /// of the new ring state.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `delta` - The ring delta to apply (Add or Remove variant)
    ///
    /// # Returns
    /// The `RingHash` of the new ring state after applying the delta.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When tenant or group does not exist
    ///
    /// # Invariants
    /// * Deltas are applied in strict append order
    /// * The returned hash is deterministic and matches the hash of the resulting ring
    async fn append_delta(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        delta: RingDelta,
    ) -> Result<RingHash, StorageError>;
}

/// Operation categories enforced by ban scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BannedOperation {
    /// Message creation and other content posts.
    PostMessage,
    /// Vote casting within a poll.
    CastVote,
    /// Poll creation (treated as a content post for bans).
    CreatePoll,
}

/// Optional ban index for fast key-image checks.
#[async_trait]
pub trait BanIndex {
    /// Check whether a key image is currently banned for a specific operation.
    ///
    /// This method provides fast lookups for ban enforcement. Implementations may use
    /// an index (e.g., PostgreSQL partial index on active bans) to avoid full table scans.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `key_image` - The key image to check
    /// * `operation` - The operation type being attempted
    ///
    /// # Returns
    /// `true` if the key image is currently banned for this operation, `false` otherwise.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Bans are scoped per `(group_id, operation)` pair
    /// * A banned key image for `PostMessage` does not affect `CastVote` unless separately banned
    async fn is_banned(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        key_image: &KeyImage,
        operation: BannedOperation,
    ) -> Result<bool, StorageError>;
}

/// Index to prevent vote key-image reuse within a poll.
#[async_trait]
pub trait VoteKeyImageIndex {
    /// Check whether a key image has already been used to vote in a specific poll.
    ///
    /// This enforces the one-vote-per-member rule by tracking key images per poll.
    /// Implementations should use an index on `(poll_id, key_image)` for fast lookups.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `poll_id` - The poll identifier
    /// * `key_image` - The key image to check
    ///
    /// # Returns
    /// `true` if this key image has already voted in this poll, `false` otherwise.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Key images are scoped per `(poll_id, group_id)` pair
    /// * A key image used in Poll A does not affect eligibility in Poll B
    async fn is_used(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
        key_image: &KeyImage,
    ) -> Result<bool, StorageError>;
}

/// Index mapping poll IDs to the ring hash at poll creation time.
///
/// This index is used during vote verification to retrieve the exact ring
/// that was in effect when the poll was created. Votes must be verified
/// against this ring to ensure only eligible members (those present at
/// poll creation) can vote.
#[async_trait]
pub trait PollRingHashIndex {
    /// Store the ring hash for a newly created poll.
    ///
    /// This should be called atomically when a `PollCreate` event is appended
    /// to the event log. The stored ring hash represents the membership snapshot
    /// at poll creation time.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `poll_id` - The poll identifier (unique within the group)
    /// * `ring_hash` - The ring hash at poll creation time
    ///
    /// # Returns
    /// `Ok(())` on successful storage.
    ///
    /// # Errors
    /// * `StorageError::AlreadyExists` - When a mapping for this poll already exists
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Each poll has exactly one associated ring hash (immutable after creation)
    /// * The ring hash is scoped per `(tenant, group_id, poll_id)` tuple
    async fn store(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
        ring_hash: RingHash,
    ) -> Result<(), StorageError>;

    /// Retrieve the ring hash for a poll.
    ///
    /// This is used during vote verification to get the ring against which
    /// the vote's ring signature must be verified.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `poll_id` - The poll identifier
    ///
    /// # Returns
    /// The `RingHash` that was in effect when the poll was created.
    ///
    /// # Errors
    /// * `StorageError::NotFound` - When the poll does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
    ) -> Result<RingHash, StorageError>;
}

#[async_trait]
pub trait BillingStore {
    /// Credit a tenant's balance, creating the tenant record if it does not exist.
    ///
    /// This method is used when a tenant redeems a gift card or receives a service credit.
    /// The tenant is associated with a Telegram user ID for future lookups.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `owner_tg_user_id` - The Telegram user ID of the tenant owner
    /// * `amount` - Amount to credit
    ///
    /// # Returns
    /// The updated tenant balance after crediting.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Balance is always non-negative after credit operations
    /// * Credits are idempotent-safe (may be retried on transient failures)
    async fn credit_tenant(
        &self,
        tenant: TenantId,
        owner_tg_user_id: &str,
        amount: Nanos,
    ) -> Result<Nanos, StorageError>;

    /// Transfer funds from tenant balance to a group's operational budget.
    ///
    /// This method moves funds from the tenant's account to a specific group's budget,
    /// which is used to pay for group operations (storage, compute, etc.).
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `amount` - Amount to transfer
    ///
    /// # Returns
    /// The updated group balance after the transfer.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When tenant has insufficient balance
    ///
    /// # Invariants
    /// * Transfers are atomic (tenant debit and group credit happen together)
    /// * Group balance is always non-negative
    async fn transfer_to_group(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError>;

    /// Retrieve the current operational budget balance for a group.
    ///
    /// # Arguments
    /// * `group_id` - The group identifier
    ///
    /// # Returns
    /// The group's current balance.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Group)` - When the group does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get_group_balance(&self, group_id: GroupId) -> Result<Nanos, StorageError>;

    /// Deduct funds from a group's operational budget.
    ///
    /// This method is used to charge a group for resource consumption (verification, storage, etc.).
    ///
    /// # Arguments
    /// * `group_id` - The group identifier
    /// * `amount` - Amount to deduct
    ///
    /// # Returns
    /// The updated group balance after deduction.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Group)` - When the group does not exist
    /// * `StorageError::PreconditionFailed` - When group has insufficient balance
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Deductions are atomic
    /// * Balance cannot go negative (checked via precondition)
    async fn deduct_group_balance(
        &self,
        group_id: GroupId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError>;

    /// Find a tenant by their Telegram user ID.
    ///
    /// Returns the TenantId if found, regardless of whether they have any groups.
    /// Use this for gift card redemption where we want to credit an existing tenant.
    async fn find_tenant_by_tg_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<TenantId>, StorageError>;

    /// Resolve a Telegram user ID to their associated tenant and group.
    ///
    /// This method looks up the tenant record by the owner's Telegram user ID, then
    /// finds the associated group. If the user owns multiple groups, the most recently
    /// created group is returned.
    ///
    /// # Arguments
    /// * `tg_user_id` - The Telegram user ID to resolve
    ///
    /// # Returns
    /// `Some((TenantId, GroupId))` if found, `None` if no tenant or group exists.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn resolve_telegram_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<(TenantId, GroupId)>, StorageError>;
}

#[derive(Clone, Debug)]
pub struct GiftCard {
    pub code: String,
    pub amount: Nanos,
    pub used_by: Option<TenantId>,
}

#[async_trait]
pub trait GiftCardStore {
    /// Issue a new gift card with a specified amount.
    ///
    /// This method generates a unique redemption code and creates a new gift card record.
    /// The card is initially unassigned (`used_by = None`).
    ///
    /// # Arguments
    /// * `amount` - The gift card value
    ///
    /// # Returns
    /// A `GiftCard` with a unique `code` and the specified `amount`.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Generated codes are globally unique
    /// * Cards are initially unassigned
    async fn issue(&self, amount: Nanos) -> Result<GiftCard, StorageError>;

    /// Redeem a gift card for a tenant, crediting their balance.
    ///
    /// This method marks the gift card as used by the specified tenant and prevents
    /// future redemptions. The card's amount is not directly credited here; the caller
    /// must invoke `BillingStore::credit_tenant` separately.
    ///
    /// # Arguments
    /// * `code` - The gift card redemption code
    /// * `tenant` - The tenant redeeming the card
    ///
    /// # Returns
    /// The `GiftCard` record with `used_by` set to the tenant.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::GiftCard)` - When the code does not exist
    /// * `StorageError::AlreadyExists` - When the card has already been redeemed
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * A card can only be redeemed once
    /// * Redemption is atomic (check-and-set operation)
    async fn redeem(&self, code: &str, tenant: TenantId) -> Result<GiftCard, StorageError>;
}

#[async_trait]
pub trait GroupMetadataStore {
    /// Create a new group record.
    ///
    /// This method initializes a new group within a tenant's account and associates it
    /// with a Telegram group identifier.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier owning this group
    /// * `tg_group_id` - The Telegram group ID (e.g., `-1001234567890`)
    ///
    /// # Returns
    /// A newly generated `GroupId` for the created group.
    ///
    /// # Errors
    /// * `StorageError::AlreadyExists` - When a group with this Telegram ID already exists
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Group IDs are globally unique
    /// * Each Telegram group ID maps to at most one Mandate group
    async fn create_group(
        &self,
        tenant: TenantId,
        tg_group_id: &str,
    ) -> Result<GroupId, StorageError>;

    /// Retrieve group metadata by group ID.
    ///
    /// # Arguments
    /// * `group_id` - The group identifier
    ///
    /// # Returns
    /// A tuple of `(TenantId, tg_group_id)` containing the owning tenant and Telegram group ID.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Group)` - When the group does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get_group(&self, group_id: GroupId) -> Result<(TenantId, String), StorageError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingMemberStatus {
    Pending,
    Approved,
}

impl PendingMemberStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            PendingMemberStatus::Pending => "pending",
            PendingMemberStatus::Approved => "approved",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PendingMember {
    pub pending_id: String,
    pub tg_user_id: String,
    pub nazgul_pub: MasterPublicKey,
    pub rage_pub: [u8; 32],
    pub submitted_at_ms: i64,
}

#[async_trait]
pub trait PendingMemberStore {
    /// Submit a new member join request.
    ///
    /// This method creates a pending member record awaiting owner approval. The member
    /// provides their cryptographic public keys upfront for efficient onboarding after approval.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `tg_user_id` - The Telegram user ID of the joining member
    /// * `nazgul_pub` - The member's Nazgul master public key (for ring signatures)
    /// * `rage_pub` - The member's Rage public key (for encrypted key distribution)
    ///
    /// # Returns
    /// A unique `pending_id` identifying this join request.
    ///
    /// # Errors
    /// * `StorageError::AlreadyExists` - When this user already has a pending request
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Each Telegram user can have at most one pending request per group
    /// * `submitted_at_ms` is set to the current timestamp in milliseconds
    async fn submit(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        tg_user_id: &str,
        nazgul_pub: MasterPublicKey,
        rage_pub: [u8; 32],
    ) -> Result<String, StorageError>;

    /// List pending member join requests (approved members are excluded).
    ///
    /// This method supports keyset pagination using opaque page tokens for efficient
    /// iteration over large pending queues.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `group_id` - The group identifier
    /// * `limit` - Maximum number of pending members to return
    /// * `page_token` - Optional continuation token from a previous call
    ///
    /// # Returns
    /// A tuple of `(pending_members, next_page_token)` where `next_page_token` is `None`
    /// if no more results exist.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Results are ordered by `submitted_at_ms` (oldest first)
    /// * Approved members (status = Approved) are never included
    async fn list(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        limit: usize,
        page_token: Option<String>,
    ) -> Result<(Vec<PendingMember>, Option<String>), StorageError>;
}
