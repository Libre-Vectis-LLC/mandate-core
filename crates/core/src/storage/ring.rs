//! Ring topology state and reconstruction.

use crate::ids::{OrganizationId, RingHash, TenantId};
use crate::ring_log::RingDelta;
use async_trait::async_trait;
use nazgul::ring::Ring;
use std::sync::Arc;

use super::types::{RingDeltaPath, StorageError};

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
    /// * `org_id` - The org IDentifier
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
        org_id: OrganizationId,
        hash: &RingHash,
    ) -> Result<Arc<Ring>, StorageError>;

    /// Retrieve the current (latest) ring for an org.
    ///
    /// This method returns the ring corresponding to the most recent delta applied to the org.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier
    ///
    /// # Returns
    /// An `Arc<Ring>` representing the current org membership ring.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Ring)` - When the org has no ring yet
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn current_ring(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
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
    /// * `org_id` - The org IDentifier
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
        org_id: OrganizationId,
        ring_hash_current: Option<RingHash>,
        ring_hash_target: RingHash,
    ) -> Result<RingDeltaPath, StorageError>;
}

/// Write-only interface for ring mutations (e.g., Postgres or in-memory log).
#[async_trait]
pub trait RingWriter {
    /// Append a delta to the ring log, advancing the org's current ring.
    ///
    /// This method applies a membership change (add or remove) to the org's ring and
    /// persists the delta to the log. The returned hash is the content-addressed hash
    /// of the new ring state.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier
    /// * `delta` - The ring delta to apply (Add or Remove variant)
    ///
    /// # Returns
    /// The `RingHash` of the new ring state after applying the delta.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When tenant or org does not exist
    ///
    /// # Invariants
    /// * Deltas are applied in strict append order
    /// * The returned hash is deterministic and matches the hash of the resulting ring
    async fn append_delta(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        delta: RingDelta,
    ) -> Result<RingHash, StorageError>;
}
