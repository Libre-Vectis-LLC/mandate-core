use crate::ids::{EventId, TenantId};
use crate::storage::{EventBytes, EventRecord, EventStore, NotFound, StorageError};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct InMemoryEvents {
    events: Arc<Mutex<HashMap<TenantId, Vec<EventRecord>>>>,
}

impl InMemoryEvents {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, HashMap<TenantId, Vec<EventRecord>>> {
        self.events.lock().expect("poison-free")
    }
}

impl EventStore for InMemoryEvents {
    fn append(&self, tenant: TenantId, event_bytes: EventBytes) -> Result<EventId, StorageError> {
        let mut inner = self.inner();
        let entry = inner.entry(tenant).or_default();
        let mut hasher = Sha3_256::new();
        hasher.update(&*event_bytes);
        let id = EventId(hasher.finalize().into());
        entry.push((id, event_bytes));
        Ok(id)
    }

    fn get(&self, tenant: TenantId, id: &EventId) -> Result<EventBytes, StorageError> {
        let inner = self.inner();
        let events = inner
            .get(&tenant)
            .ok_or(StorageError::NotFound(NotFound::Event { id: *id, tenant }))?;
        events
            .iter()
            .find(|(ev_id, _)| ev_id == id)
            .map(|(_, b)| b.clone())
            .ok_or(StorageError::NotFound(NotFound::Event { id: *id, tenant }))
    }

    fn tail(&self, tenant: TenantId) -> Result<EventRecord, StorageError> {
        let inner = self.inner();
        let events = inner
            .get(&tenant)
            .ok_or(StorageError::NotFound(NotFound::Tail { tenant }))?;
        events
            .last()
            .cloned()
            .ok_or(StorageError::NotFound(NotFound::Tail { tenant }))
    }

    fn stream_from(
        &self,
        tenant: TenantId,
        after: Option<EventId>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError> {
        let inner = self.inner();
        let events = inner
            .get(&tenant)
            .ok_or(StorageError::NotFound(NotFound::Tail { tenant }))?;
        let start = after
            .and_then(|id| events.iter().position(|(eid, _)| *eid == id))
            .map(|idx| idx + 1)
            .unwrap_or(0);
        Ok(events.iter().skip(start).take(limit).cloned().collect())
    }
}
