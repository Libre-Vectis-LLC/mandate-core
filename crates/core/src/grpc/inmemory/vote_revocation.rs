/// In-memory vote revocation index using DashMap for lock-free concurrent access.
use crate::ids::{EventId, KeyImage, OrganizationId, TenantId};
use crate::storage::{StorageError, VoteRevocationIndex};
use async_trait::async_trait;
use dashmap::DashMap;

type RevocationKey = (TenantId, OrganizationId, String, [u8; 32]);

fn key_image_bytes(key_image: &KeyImage) -> [u8; 32] {
    *key_image.compress().as_bytes()
}

/// In-memory implementation of the `VoteRevocationIndex` trait.
///
/// Tracks which votes have been revoked using a DashMap keyed by
/// `(TenantId, OrganizationId, poll_id, key_image_bytes)`.
#[derive(Clone, Default)]
pub struct InMemoryVoteRevocations {
    revocations: DashMap<RevocationKey, EventId>,
}

impl InMemoryVoteRevocations {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl VoteRevocationIndex for InMemoryVoteRevocations {
    async fn is_vote_revoked(
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
        Ok(self.revocations.contains_key(&key))
    }

    async fn store_vote_revocation(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
        key_image: &KeyImage,
        revocation_event_id: &EventId,
    ) -> Result<(), StorageError> {
        let key = (
            tenant,
            org_id,
            poll_id.to_string(),
            key_image_bytes(key_image),
        );
        // Use entry API for idempotent insertion — reject if already revoked.
        use dashmap::mapref::entry::Entry;
        match self.revocations.entry(key) {
            Entry::Occupied(_) => Err(StorageError::AlreadyExists),
            Entry::Vacant(v) => {
                v.insert(*revocation_event_id);
                Ok(())
            }
        }
    }
}
