/// In-memory ban index tracking.
use crate::event::BanScope;
use crate::ids::{EventId, GroupId, KeyImage, TenantId};
use crate::storage::{BanIndex, BannedOperation, StorageError};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

type BanKey = (TenantId, GroupId, [u8; 32]);
type BanScopeSet = HashSet<BanScope>;
type BanMap = HashMap<BanKey, BanScopeSet>;

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

#[derive(Clone, Default)]
pub struct InMemoryBanIndex {
    bans: Arc<Mutex<BanMap>>,
    ban_events: Arc<Mutex<HashMap<EventId, BanRecord>>>,
}

#[derive(Clone)]
struct BanRecord {
    tenant: TenantId,
    group_id: GroupId,
    key_image: [u8; 32],
    scope: BanScope,
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
        let key_image = key_image_bytes(&key_image);
        let mut ban_events = self.ban_events.lock();
        if ban_events.contains_key(&ban_event_id) {
            return Err(StorageError::PreconditionFailed(
                "ban already recorded".into(),
            ));
        }
        ban_events.insert(
            ban_event_id,
            BanRecord {
                tenant,
                group_id,
                key_image,
                scope,
            },
        );

        let mut bans = self.bans.lock();
        let entry = bans.entry((tenant, group_id, key_image)).or_default();
        if !entry.insert(scope) {
            return Err(StorageError::PreconditionFailed(
                "ban already recorded".into(),
            ));
        }
        Ok(())
    }

    pub fn revoke_ban(&self, ban_event_id: EventId) -> Result<(), StorageError> {
        let mut ban_events = self.ban_events.lock();
        let record = ban_events
            .remove(&ban_event_id)
            .ok_or_else(|| StorageError::PreconditionFailed("unknown ban event".into()))?;

        let mut bans = self.bans.lock();
        if let Some(scopes) = bans.get_mut(&(record.tenant, record.group_id, record.key_image)) {
            scopes.remove(&record.scope);
            if scopes.is_empty() {
                bans.remove(&(record.tenant, record.group_id, record.key_image));
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
        let key_image = key_image_bytes(key_image);
        let bans = self.bans.lock();
        let Some(scopes) = bans.get(&(tenant, group_id, key_image)) else {
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
