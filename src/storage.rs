//! Storage-facing traits for audit-first, single-writer append workflows.
//!
//! Design goals:
//! - Single table, multi-tenant, append-only event log (no routine replay; audit-focused).
//! - Zero-copy reads via `Arc<[u8]>`/slices; deterministic ordering by append sequence.
//! - Ring reconstruction is the only replay scenario; implementations find a shortest-path delta slice.
//! - PostgreSQL-friendly: btree/hash indexes on `(ring_hash)`, `(tenant_id, group_id, ring_hash)`,
//!   `(master_pubkey, created_at)`, keyset pagination.

use crate::ids::{EventId, GroupId, KeyImage, RingHash, TenantId, TenantToken};
use crate::ring_log::{apply_delta, RingDelta, RingLogError};
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
pub trait TenantTokenStore {
    fn resolve_tenant(&self, token: &TenantToken) -> Result<TenantId, TenantTokenError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotFound {
    #[error("event {id:?} for tenant {tenant:?} group {group_id:?}")]
    Event {
        id: EventId,
        tenant: TenantId,
        group_id: GroupId,
    },
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
}

/// Append-only event storage. Intended for a single-writer per tenant; multi-tenant shares one table.
pub trait EventStore: EventReader + EventWriter {
    /// Fetch canonical bytes by ID for audit/verification; `NotFound` if absent.
    fn get(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        id: &EventId,
    ) -> Result<EventRecord, StorageError>;

    /// Latest (tail) event for the group; `NotFound` if empty.
    fn tail(&self, tenant: TenantId, group_id: GroupId) -> Result<EventRecord, StorageError>;
}

/// Write-only surface for events; separated to allow distinct read/write backends.
pub trait EventWriter {
    /// Append a canonical, signed event (already serialized). Returns (event_id, sequence_no).
    fn append(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        event_bytes: EventBytes,
    ) -> Result<(EventId, SequenceNo), StorageError>;
}

/// Read-only grouping helper to support backend-specific implementations (e.g., Postgres).
pub trait EventReader {
    /// Deterministic forward slice for a specific group, after an optional anchor.
    fn stream_group(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        after_sequence: Option<SequenceNo>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError>;
}

/// Store for member key blobs, indexed by Rage public key.
///
/// Keys are scoped by `(tenant, group_id, rage_pub)` to avoid cross-group and cross-tenant leaks.
pub trait KeyBlobStore {
    fn put_many(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        blobs: Vec<([u8; 32], Arc<[u8]>)>,
    ) -> Result<(), StorageError>;

    fn get_one(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        rage_pub: [u8; 32],
    ) -> Result<Arc<[u8]>, StorageError>;
}

/// Access to ring snapshots and delta paths; caching strategy is implementation-defined.
pub trait RingView {
    /// Resolve a ring by its hash for the tenant. Reconstruct on miss; `NotFound` if unknown.
    fn ring_by_hash(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        hash: &RingHash,
    ) -> Result<Arc<Ring>, StorageError>;

    /// Current ring for the group. `NotFound` if the group has no ring yet.
    fn current_ring(&self, tenant: TenantId, group_id: GroupId) -> Result<Arc<Ring>, StorageError>;

    /// Shortest-path delta slice from `ring_hash_current` (if provided) to `ring_hash_target`.
    /// Implementations choose the path (e.g., via SQL graph query) and return a replayable slice.
    fn ring_delta_path(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        ring_hash_current: Option<RingHash>,
        ring_hash_target: RingHash,
    ) -> Result<RingDeltaPath, StorageError>;
}

/// Write-only interface for ring mutations (e.g., Postgres or in-memory log).
pub trait RingWriter {
    /// Append a delta to the group ring log, returning the new head hash.
    fn append_delta(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        delta: RingDelta,
    ) -> Result<RingHash, StorageError>;
}

/// Optional ban index for fast key-image checks.
pub trait BanIndex {
    /// Return whether `key_image` is currently banned for `group_id`.
    fn is_banned(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        key_image: &KeyImage,
    ) -> Result<bool, StorageError>;
}
