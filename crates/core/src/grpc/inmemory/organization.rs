/// In-memory group metadata storage.
use crate::ids::{OrganizationId, MasterPublicKey, TenantId};
use crate::storage::{OrganizationMetadataStore, NotFound, StorageError};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) type OrgMap = HashMap<OrganizationId, OrganizationRecord>;

#[derive(Clone, Default)]
pub struct InMemoryGroups {
    groups: Arc<Mutex<OrgMap>>,
}

impl InMemoryGroups {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a shared reference to the internal group map.
    ///
    /// This is primarily used for constructing `InMemoryBilling` in tests.
    pub fn shared(&self) -> Arc<Mutex<OrgMap>> {
        Arc::clone(&self.groups)
    }
}

/// In-memory group metadata record.
///
/// This type is exposed publicly to support test infrastructure that needs
/// to share group maps between `InMemoryGroups` and `InMemoryBilling`.
#[derive(Clone, Debug)]
pub struct OrganizationRecord {
    /// Tenant that owns this group.
    pub tenant: TenantId,
    /// Telegram group ID.
    pub tg_group_id: String,
    /// Current balance in nanos.
    pub balance_nanos: i64,
    /// Owner's master public key, if set.
    pub owner_pubkey: Option<MasterPublicKey>,
}

#[async_trait]
impl OrganizationMetadataStore for InMemoryGroups {
    async fn create_organization(
        &self,
        tenant: TenantId,
        tg_group_id: &str,
    ) -> Result<OrganizationId, StorageError> {
        let mut map = self.groups.lock();
        let org_id = OrganizationId(ulid::Ulid::new());
        map.insert(
            org_id,
            OrganizationRecord {
                tenant,
                tg_group_id: tg_group_id.to_string(),
                balance_nanos: 0,
                owner_pubkey: None,
            },
        );
        Ok(org_id)
    }

    async fn get_organization(&self, org_id: OrganizationId) -> Result<(TenantId, String), StorageError> {
        let map = self.groups.lock();
        map.get(&org_id)
            .map(|record| (record.tenant, record.tg_group_id.clone()))
            .ok_or(StorageError::NotFound(NotFound::Group { org_id }))
    }

    async fn set_owner_pubkey(
        &self,
        org_id: OrganizationId,
        owner_pubkey: MasterPublicKey,
    ) -> Result<(), StorageError> {
        let mut map = self.groups.lock();
        let record = map
            .get_mut(&org_id)
            .ok_or(StorageError::NotFound(NotFound::Group { org_id }))?;
        record.owner_pubkey = Some(owner_pubkey);
        Ok(())
    }

    async fn get_owner_pubkey(
        &self,
        org_id: OrganizationId,
    ) -> Result<Option<MasterPublicKey>, StorageError> {
        let map = self.groups.lock();
        let record = map
            .get(&org_id)
            .ok_or(StorageError::NotFound(NotFound::Group { org_id }))?;
        Ok(record.owner_pubkey)
    }
}
