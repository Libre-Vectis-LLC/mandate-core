//! Storage-facing traits for audit-first, single-writer append workflows.
//!
//! Design goals:
//! - Single table, multi-tenant, append-only event log (no routine replay; audit-focused).
//! - Zero-copy reads via `Arc<[u8]>`/slices; deterministic ordering by append sequence.
//! - Ring reconstruction is the only replay scenario; implementations find a shortest-path delta slice.
//! - PostgreSQL-friendly: btree/hash indexes on `(ring_hash)`, `(tenant_id, ring_hash)`, `(master_pubkey, created_at)`, keyset pagination.

use crate::ids::{EventId, RingHash, TenantId};
use crate::ring_log::{apply_delta, RingDelta};
use nazgul::ring::Ring;
use std::sync::Arc;

/// Canonical, signed event bytes (audit-preserving).
pub type EventBytes = Arc<[u8]>;

/// Event identifier paired with its canonical bytes.
pub type EventRecord = (EventId, EventBytes);

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
    pub fn apply(self, mut ring: Ring) -> Ring {
        for delta in &self.deltas {
            apply_delta(&mut ring, delta).expect("storage must only emit valid deltas");
        }
        ring
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

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotFound {
    #[error("event {id:?} for tenant {tenant:?}")]
    Event { id: EventId, tenant: TenantId },
    #[error("tail for tenant {tenant:?}")]
    Tail { tenant: TenantId },
    #[error("ring {hash:?} for tenant {tenant:?}")]
    Ring { hash: RingHash, tenant: TenantId },
    #[error("ring delta path from {from:?} to {to:?} for tenant {tenant:?}")]
    RingDeltaPath {
        from: Option<RingHash>,
        to: RingHash,
        tenant: TenantId,
    },
}

/// Append-only event storage. Intended for a single-writer per tenant; multi-tenant shares one table.
pub trait EventStore {
    /// Append a canonical, signed event (already serialized, e.g., canonical JSON) for the tenant.
    /// Must preserve write order as the audit chain source of truth.
    fn append(&self, tenant: TenantId, event_bytes: EventBytes) -> Result<EventId, StorageError>;

    /// Fetch canonical bytes by ID for audit/verification; `NotFound` if absent.
    fn get(&self, tenant: TenantId, id: &EventId) -> Result<EventBytes, StorageError>;

    /// Latest (tail) event for the tenant; `NotFound` if empty.
    fn tail(&self, tenant: TenantId) -> Result<EventRecord, StorageError>;

    /// Deterministic forward slice after an optional anchor (exclusive), bounded by `limit`.
    fn stream_from(
        &self,
        tenant: TenantId,
        after: Option<EventId>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError>;
}

/// Access to ring snapshots and delta paths; caching strategy is implementation-defined.
pub trait RingView {
    /// Resolve a ring by its hash for the tenant. Reconstruct on miss; `NotFound` if unknown.
    fn ring_by_hash(&self, tenant: TenantId, hash: &RingHash) -> Result<Arc<Ring>, StorageError>;

    /// Current ring (one per tenant). `NotFound` if the tenant has no ring yet.
    fn current_ring(&self, tenant: TenantId) -> Result<Arc<Ring>, StorageError>;

    /// Shortest-path delta slice from `ring_hash_current` (if provided) to `ring_hash_target`.
    /// Implementations choose the path (e.g., via SQL graph query) and return a replayable slice.
    fn ring_delta_path(
        &self,
        tenant: TenantId,
        ring_hash_current: Option<RingHash>,
        ring_hash_target: RingHash,
    ) -> Result<RingDeltaPath, StorageError>;
}
