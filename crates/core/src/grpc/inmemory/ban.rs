/// In-memory ban index tracking using DashMap for lock-free concurrent access.
use crate::event::BanScope;
use crate::ids::{EventId, GroupId, KeyImage, TenantId};
use crate::storage::{BanIndex, BannedOperation, StorageError};
use async_trait::async_trait;
use dashmap::DashMap;
use std::collections::HashSet;

type BanKey = (TenantId, GroupId, [u8; 32]);
type BanScopeSet = HashSet<BanScope>;

fn key_image_bytes(key_image: &KeyImage) -> [u8; 32] {
    *key_image.compress().as_bytes()
}

fn ban_scopes_for_operation(operation: BannedOperation) -> &'static [BanScope] {
    match operation {
        BannedOperation::PostMessage | BannedOperation::CreatePoll => {
            // BanPost covers content creation (messages + polls).
            &[BanScope::BanPost, BanScope::BanAll]
        }
        BannedOperation::CastVote => &[BanScope::BanVote, BanScope::BanAll],
    }
}

/// Ban record stored in the secondary index for revocation lookup.
#[derive(Clone)]
struct BanRecord {
    tenant: TenantId,
    group_id: GroupId,
    key_image: [u8; 32],
    scope: BanScope,
}

/// In-memory ban index using DashMap for concurrent access.
///
/// With "Option B" (bans only affect current ring), the design is simple:
/// - Bans are indexed by (TenantId, GroupId, KeyImage) for fast is_banned() lookup
/// - A secondary index by EventId allows fast revoke_ban() lookup
/// - When ring changes (RingUpdate), all KeyImages change, so old bans become ineffective
#[derive(Clone, Default)]
pub struct InMemoryBanIndex {
    /// Primary index: (TenantId, GroupId, KeyImage) → BanScopes
    /// Supports fast is_banned() lookup by key image.
    bans: DashMap<BanKey, BanScopeSet>,

    /// Secondary index: EventId → BanRecord
    /// Supports fast revoke_ban() lookup by ban event ID.
    ban_events: DashMap<EventId, BanRecord>,
}

impl InMemoryBanIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_ban(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        key_image: KeyImage,
        scope: BanScope,
        ban_event_id: EventId,
    ) -> Result<(), StorageError> {
        let key_image_bytes = key_image_bytes(&key_image);

        // Check if ban event already recorded (must be first to avoid partial state)
        if self.ban_events.contains_key(&ban_event_id) {
            return Err(StorageError::PreconditionFailed(
                "ban already recorded".into(),
            ));
        }

        // Insert into primary index
        let mut entry = self
            .bans
            .entry((tenant, group_id, key_image_bytes))
            .or_default();
        if !entry.insert(scope) {
            return Err(StorageError::PreconditionFailed(
                "ban already recorded".into(),
            ));
        }
        drop(entry); // Release lock before inserting into secondary index

        // Insert into secondary index for revocation lookup
        self.ban_events.insert(
            ban_event_id,
            BanRecord {
                tenant,
                group_id,
                key_image: key_image_bytes,
                scope,
            },
        );

        Ok(())
    }

    pub fn revoke_ban(&self, ban_event_id: EventId) -> Result<(), StorageError> {
        // Remove from secondary index
        let (_, record) = self
            .ban_events
            .remove(&ban_event_id)
            .ok_or_else(|| StorageError::PreconditionFailed("unknown ban event".into()))?;

        // Remove from primary index
        let ban_key = (record.tenant, record.group_id, record.key_image);
        if let Some(mut scopes) = self.bans.get_mut(&ban_key) {
            scopes.remove(&record.scope);
            if scopes.is_empty() {
                drop(scopes); // Release lock before remove
                self.bans.remove(&ban_key);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl BanIndex for InMemoryBanIndex {
    async fn is_banned(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        key_image: &KeyImage,
        operation: BannedOperation,
    ) -> Result<bool, StorageError> {
        let key_image_bytes = key_image_bytes(key_image);
        let Some(scopes) = self.bans.get(&(tenant, group_id, key_image_bytes)) else {
            return Ok(false);
        };
        let blocked = ban_scopes_for_operation(operation)
            .iter()
            .any(|scope| scopes.contains(scope));
        Ok(blocked)
    }
}

#[derive(Default, Clone)]
pub struct NoopBanIndex;

#[async_trait]
impl BanIndex for NoopBanIndex {
    async fn is_banned(
        &self,
        _tenant: TenantId,
        _group_id: GroupId,
        _key_image: &KeyImage,
        _operation: BannedOperation,
    ) -> Result<bool, StorageError> {
        Ok(false)
    }
}
