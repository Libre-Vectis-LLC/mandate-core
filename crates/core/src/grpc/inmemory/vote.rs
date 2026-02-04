/// In-memory vote key image deduplication.
use crate::ids::{OrganizationId, KeyImage, TenantId};
use crate::storage::{StorageError, VoteKeyImageIndex};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::Arc;

type VoteKey = (TenantId, OrganizationId, String, [u8; 32]);
type VoteKeySet = HashSet<VoteKey>;

fn key_image_bytes(key_image: &KeyImage) -> [u8; 32] {
    *key_image.compress().as_bytes()
}

#[derive(Clone, Default)]
pub struct InMemoryVoteKeyImages {
    used: Arc<Mutex<VoteKeySet>>,
}

impl InMemoryVoteKeyImages {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_vote(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
        key_image: KeyImage,
    ) -> Result<(), StorageError> {
        let key = (
            tenant,
            org_id,
            poll_id.to_string(),
            key_image_bytes(&key_image),
        );
        let mut used = self.used.lock();
        if !used.insert(key) {
            return Err(StorageError::PreconditionFailed("vote already cast".into()));
        }
        Ok(())
    }
}

#[async_trait]
impl VoteKeyImageIndex for InMemoryVoteKeyImages {
    async fn is_used(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
        key_image: &KeyImage,
    ) -> Result<bool, StorageError> {
        let key = (
            tenant,
            org_id,
            poll_id.to_string(),
            key_image_bytes(key_image),
        );
        let used = self.used.lock();
        Ok(used.contains(&key))
    }
}

#[derive(Default, Clone)]
pub struct NoopVoteKeyImages;

#[async_trait]
impl VoteKeyImageIndex for NoopVoteKeyImages {
    async fn is_used(
        &self,
        _tenant: TenantId,
        _org_id: OrganizationId,
        _poll_id: &str,
        _key_image: &KeyImage,
    ) -> Result<bool, StorageError> {
        Ok(false)
    }
}
