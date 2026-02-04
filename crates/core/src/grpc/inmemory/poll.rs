/// In-memory poll ring hash index.
use crate::ids::{OrganizationId, RingHash, TenantId};
use crate::storage::{PollRingHashIndex, StorageError};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

/// Composite key for poll ring hash lookup.
type PollKey = (TenantId, OrganizationId, String);

/// In-memory implementation of `PollRingHashIndex`.
///
/// Stores a mapping from `(tenant, org_id, poll_id)` to the ring hash
/// that was in effect when the poll was created.
#[derive(Clone, Default)]
pub struct InMemoryPollRingHashes {
    hashes: Arc<Mutex<HashMap<PollKey, RingHash>>>,
}

impl InMemoryPollRingHashes {
    /// Create a new empty poll ring hash index.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl PollRingHashIndex for InMemoryPollRingHashes {
    async fn store(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
        ring_hash: RingHash,
    ) -> Result<(), StorageError> {
        let key = (tenant, org_id, poll_id.to_string());
        let mut hashes = self.hashes.lock();
        if hashes.contains_key(&key) {
            return Err(StorageError::AlreadyExists);
        }
        hashes.insert(key, ring_hash);
        Ok(())
    }

    async fn get(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
    ) -> Result<RingHash, StorageError> {
        let key = (tenant, org_id, poll_id.to_string());
        let hashes = self.hashes.lock();
        hashes
            .get(&key)
            .copied()
            .ok_or(StorageError::NotFound(crate::storage::NotFound::Organization {
                org_id,
            }))
    }
}

/// No-op implementation for testing scenarios where poll ring hash tracking is not needed.
#[derive(Default, Clone)]
pub struct NoopPollRingHashes;

#[async_trait]
impl PollRingHashIndex for NoopPollRingHashes {
    async fn store(
        &self,
        _tenant: TenantId,
        _org_id: OrganizationId,
        _poll_id: &str,
        _ring_hash: RingHash,
    ) -> Result<(), StorageError> {
        Ok(())
    }

    async fn get(
        &self,
        _tenant: TenantId,
        org_id: OrganizationId,
        _poll_id: &str,
    ) -> Result<RingHash, StorageError> {
        // Return a zero hash for noop - this should only be used in tests
        // where poll ring hash verification is not being tested
        Err(StorageError::NotFound(crate::storage::NotFound::Organization {
            org_id,
        }))
    }
}
