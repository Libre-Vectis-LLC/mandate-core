/// In-memory bundle published index using DashMap for lock-free concurrent access.
use crate::ids::{OrganizationId, TenantId};
use crate::storage::{BundlePublishedIndex, StorageError};
use async_trait::async_trait;
use dashmap::DashMap;

type BundleKey = (TenantId, OrganizationId, String);

/// In-memory implementation of the `BundlePublishedIndex` trait.
///
/// Tracks when poll bundles were published using a DashMap keyed by
/// `(TenantId, OrganizationId, poll_id)`.
#[derive(Clone, Default)]
pub struct InMemoryBundlePublished {
    timestamps: DashMap<BundleKey, u64>,
}

impl InMemoryBundlePublished {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BundlePublishedIndex for InMemoryBundlePublished {
    async fn get_bundle_published_at(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
    ) -> Result<Option<u64>, StorageError> {
        let key = (tenant, org_id, poll_id.to_string());
        Ok(self.timestamps.get(&key).map(|r| *r))
    }

    async fn store_bundle_published_at(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
        published_at: u64,
    ) -> Result<(), StorageError> {
        let key = (tenant, org_id, poll_id.to_string());
        use dashmap::mapref::entry::Entry;
        match self.timestamps.entry(key) {
            Entry::Occupied(_) => Err(StorageError::AlreadyExists),
            Entry::Vacant(v) => {
                v.insert(published_at);
                Ok(())
            }
        }
    }
}
