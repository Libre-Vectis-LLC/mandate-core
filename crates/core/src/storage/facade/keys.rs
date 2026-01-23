use std::sync::Arc;

use super::StorageFacade;
use crate::ids::{GroupId, TenantId};
use crate::storage::StorageError;

impl StorageFacade {
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
