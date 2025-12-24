//! Storage-facing traits for audit-first, single-writer append workflows.
//!
//! Design goals:
//! - Single table, multi-tenant, append-only event log (no routine replay; audit-focused).
//! - Zero-copy reads via `Arc<[u8]>`/slices; deterministic ordering by append sequence.
//! - Ring reconstruction is the only replay scenario; implementations find a shortest-path delta slice.
//! - PostgreSQL-friendly: btree/hash indexes on `(ring_hash)`, `(tenant_id, group_id, ring_hash)`,
//!   `(master_pubkey, created_at)`, keyset pagination.

use crate::ids::{EventId, GroupId, KeyImage, MasterPublicKey, RingHash, TenantId, TenantToken};
use crate::ring_log::{apply_delta, RingDelta, RingLogError};
use async_trait::async_trait;
use nazgul::ring::Ring;
use std::sync::Arc;

pub mod facade;

/// Canonical, signed event bytes (audit-preserving).
pub type EventBytes = Arc<[u8]>;

pub type SequenceNo = i64;

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
    pub fn apply(self, mut ring: Ring) -> Result<Ring, RingLogError> {
        for delta in &self.deltas {
            apply_delta(&mut ring, delta)?;
        }
        Ok(ring)
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
    async fn resolve_tenant(&self, token: &TenantToken) -> Result<TenantId, TenantTokenError>;
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
    /// Append a canonical, signed event (already serialized). Returns (event_id, sequence_no).
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
    /// Deterministic forward slice for a specific group, after an optional anchor.
    async fn stream_group(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        after_sequence: Option<SequenceNo>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError>;

    async fn get(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        id: &EventId,
    ) -> Result<EventRecord, StorageError>;

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
    async fn put_many(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        blobs: Vec<([u8; 32], Arc<[u8]>)>,
    ) -> Result<(), StorageError>;

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
    /// Resolve a ring by its hash for the tenant. Reconstruct on miss; `NotFound` if unknown.
    async fn ring_by_hash(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        hash: &RingHash,
    ) -> Result<Arc<Ring>, StorageError>;

    /// Current ring for the group. `NotFound` if the group has no ring yet.
    async fn current_ring(
        &self,
        tenant: TenantId,
        group_id: GroupId,
    ) -> Result<Arc<Ring>, StorageError>;

    /// Shortest-path delta slice from `ring_hash_current` (if provided) to `ring_hash_target`.
    /// Implementations choose the path (e.g., via SQL graph query) and return a replayable slice.
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
    /// Append a delta to the group ring log, returning the new head hash.
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
    /// Return whether `key_image` is currently banned for `group_id` and operation.
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
    /// Return whether `key_image` has already been used for `poll_id`.
    async fn is_used(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
        key_image: &KeyImage,
    ) -> Result<bool, StorageError>;
}

#[async_trait]
pub trait BillingStore {
    /// Credit a tenant balance by `amount_nanos`, creating the tenant if needed.
    /// Returns the updated tenant balance.
    async fn credit_tenant(
        &self,
        tenant: TenantId,
        owner_tg_user_id: &str,
        amount_nanos: u64,
    ) -> Result<i64, StorageError>;

    /// Transfer funds from tenant balance to the group's budget.
    /// Returns the updated group balance.
    async fn transfer_to_group(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        amount_nanos: u64,
    ) -> Result<i64, StorageError>;

    /// Returns the group's current budget balance.
    async fn get_group_balance(&self, group_id: GroupId) -> Result<i64, StorageError>;
}

#[derive(Clone, Debug)]
pub struct GiftCard {
    pub code: String,
    pub amount_nanos: u64,
    pub used_by: Option<TenantId>,
}

#[async_trait]
pub trait GiftCardStore {
    async fn issue(&self, amount_nanos: u64) -> Result<GiftCard, StorageError>;
    async fn redeem(&self, code: &str, tenant: TenantId) -> Result<GiftCard, StorageError>;
}

#[async_trait]
pub trait GroupMetadataStore {
    async fn create_group(
        &self,
        tenant: TenantId,
        tg_group_id: &str,
    ) -> Result<GroupId, StorageError>;
    async fn get_group(&self, group_id: GroupId) -> Result<(TenantId, String), StorageError>;
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
    async fn submit(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        tg_user_id: &str,
        nazgul_pub: MasterPublicKey,
        rage_pub: [u8; 32],
    ) -> Result<String, StorageError>;

    async fn list(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        limit: usize,
        page_token: Option<String>,
    ) -> Result<(Vec<PendingMember>, Option<String>), StorageError>;
}
