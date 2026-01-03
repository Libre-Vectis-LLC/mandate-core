/// In-memory group metadata storage.
use crate::ids::{GroupId, MasterPublicKey, TenantId};
use crate::storage::{GroupMetadataStore, NotFound, StorageError};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) type GroupMap = HashMap<GroupId, GroupRecord>;

#[derive(Clone, Default)]
pub struct InMemoryGroups {
    groups: Arc<Mutex<GroupMap>>,
}

impl InMemoryGroups {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn shared(&self) -> Arc<Mutex<GroupMap>> {
        Arc::clone(&self.groups)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct GroupRecord {
    pub(crate) tenant: TenantId,
    pub(crate) tg_group_id: String,
    pub(crate) balance_nanos: i64,
    pub(crate) owner_pubkey: Option<MasterPublicKey>,
}

#[async_trait]
impl GroupMetadataStore for InMemoryGroups {
    async fn create_group(
        &self,
        tenant: TenantId,
        tg_group_id: &str,
    ) -> Result<GroupId, StorageError> {
        let mut map = self.groups.lock();
        let group_id = GroupId(ulid::Ulid::new());
        map.insert(
            group_id,
            GroupRecord {
                tenant,
                tg_group_id: tg_group_id.to_string(),
                balance_nanos: 0,
                owner_pubkey: None,
            },
        );
        Ok(group_id)
    }

    async fn get_group(&self, group_id: GroupId) -> Result<(TenantId, String), StorageError> {
        let map = self.groups.lock();
        map.get(&group_id)
            .map(|record| (record.tenant, record.tg_group_id.clone()))
            .ok_or(StorageError::NotFound(NotFound::Group { group_id }))
    }

    async fn set_owner_pubkey(
        &self,
        group_id: GroupId,
        owner_pubkey: MasterPublicKey,
    ) -> Result<(), StorageError> {
        let mut map = self.groups.lock();
        let record = map
            .get_mut(&group_id)
            .ok_or(StorageError::NotFound(NotFound::Group { group_id }))?;
        record.owner_pubkey = Some(owner_pubkey);
        Ok(())
    }

    async fn get_owner_pubkey(
        &self,
        group_id: GroupId,
    ) -> Result<Option<MasterPublicKey>, StorageError> {
        let map = self.groups.lock();
        let record = map
            .get(&group_id)
            .ok_or(StorageError::NotFound(NotFound::Group { group_id }))?;
        Ok(record.owner_pubkey)
    }
}
