/// In-memory key blob storage.
use crate::ids::{GroupId, TenantId};
use crate::storage::{KeyBlobStore, NotFound, StorageError};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

type KeyBlobKey = (TenantId, GroupId, [u8; 32]);
type KeyBlobMap = HashMap<KeyBlobKey, Arc<[u8]>>;

#[derive(Clone, Default)]
pub struct InMemoryKeyBlobs {
    blobs: Arc<Mutex<KeyBlobMap>>,
}

impl InMemoryKeyBlobs {
    pub fn new() -> Self {
        Self::default()
    }

    fn inner(&self) -> parking_lot::MutexGuard<'_, KeyBlobMap> {
        self.blobs.lock()
    }
}

#[async_trait]
impl KeyBlobStore for InMemoryKeyBlobs {
    async fn put_many(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        blobs: Vec<([u8; 32], Arc<[u8]>)>,
    ) -> Result<(), StorageError> {
        let mut map = self.inner();
        for (rage_pub, blob) in blobs {
            map.insert((tenant, group_id, rage_pub), blob);
        }
        Ok(())
    }

    async fn get_one(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        rage_pub: [u8; 32],
    ) -> Result<Arc<[u8]>, StorageError> {
        let map = self.inner();
        map.get(&(tenant, group_id, rage_pub))
            .cloned()
            .ok_or(StorageError::NotFound(NotFound::KeyBlob {
                tenant,
                group_id,
                rage_pub,
            }))
    }
}
