use crate::ids::{EventId, TenantId};
use crate::storage::{
    EventBytes, EventRecord, EventStore, NotFound, RingView, RingWriter, StorageError,
};
use crate::{
    ids::{RingHash, TenantId as Tenant},
    ring_log::{RingDelta, RingDeltaLog, RingLogError},
};
use nazgul::ring::Ring;
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
    fn append(
        &self,
        tenant: TenantId,
        event_bytes: EventBytes,
    ) -> Result<(EventId, i64), StorageError> {
        let mut inner = self.inner();
        let entry = inner.entry(tenant).or_default();
        let mut hasher = Sha3_256::new();
        hasher.update(&*event_bytes);
        let id = EventId(hasher.finalize().into());
        let seq = entry.len() as i64;
        entry.push((id, event_bytes, seq));
        Ok((id, seq))
    }

    fn get(&self, tenant: TenantId, id: &EventId) -> Result<EventRecord, StorageError> {
        let inner = self.inner();
        let events = inner
            .get(&tenant)
            .ok_or(StorageError::NotFound(NotFound::Event { id: *id, tenant }))?;
        events
            .iter()
            .find(|(ev_id, _, _)| ev_id == id)
            .cloned()
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
        after: Option<i64>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError> {
        let inner = self.inner();
        let events = inner
            .get(&tenant)
            .ok_or(StorageError::NotFound(NotFound::Tail { tenant }))?;
        let start = after
            .and_then(|seq| events.iter().position(|(_, _, s)| *s == seq))
            .map(|idx| idx + 1)
            .unwrap_or(0);
        Ok(events.iter().skip(start).take(limit).cloned().collect())
    }
}

#[derive(Default, Clone)]
pub struct InMemoryRings {
    rings: Arc<Mutex<HashMap<Tenant, RingState>>>,
}

#[derive(Clone)]
struct RingState {
    log: RingDeltaLog,
    current: Ring,
    current_hash: RingHash,
}

impl InMemoryRings {
    pub fn new() -> Self {
        Self {
            rings: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, HashMap<Tenant, RingState>> {
        self.rings.lock().expect("ring mutex poisoned")
    }
}

impl RingView for InMemoryRings {
    fn ring_by_hash(&self, tenant: Tenant, hash: &RingHash) -> Result<Arc<Ring>, StorageError> {
        let mut map = self.inner();
        let state = map
            .get_mut(&tenant)
            .ok_or(StorageError::NotFound(NotFound::Ring {
                hash: *hash,
                tenant,
            }))?;

        if &state.current_hash == hash {
            return Ok(Arc::new(state.current.clone()));
        }

        let reconstructed = state
            .log
            .reconstruct(hash, Some(&state.current))
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(Arc::new(reconstructed))
    }

    fn current_ring(&self, tenant: Tenant) -> Result<Arc<Ring>, StorageError> {
        let map = self.inner();
        let state = map
            .get(&tenant)
            .ok_or(StorageError::NotFound(NotFound::Ring {
                hash: RingHash([0; 32]),
                tenant,
            }))?;
        Ok(Arc::new(state.current.clone()))
    }

    fn ring_delta_path(
        &self,
        tenant: Tenant,
        ring_hash_current: Option<RingHash>,
        ring_hash_target: RingHash,
    ) -> Result<crate::storage::RingDeltaPath, StorageError> {
        let map = self.inner();
        let state = map
            .get(&tenant)
            .ok_or(StorageError::NotFound(NotFound::Ring {
                hash: ring_hash_current.unwrap_or(ring_hash_target),
                tenant,
            }))?;

        let deltas = state
            .log
            .delta_path(ring_hash_current.as_ref(), &ring_hash_target)
            .map_err(|e| match e {
                RingLogError::TargetNotFound => StorageError::NotFound(NotFound::Ring {
                    hash: ring_hash_target,
                    tenant,
                }),
                RingLogError::AnchorNotFound => StorageError::NotFound(NotFound::Ring {
                    hash: ring_hash_current.unwrap_or(ring_hash_target),
                    tenant,
                }),
                other => StorageError::Backend(other.to_string()),
            })?;

        let from = ring_hash_current.unwrap_or_else(|| {
            state
                .log
                .genesis_hash()
                .cloned()
                .unwrap_or(state.current_hash)
        });

        Ok(crate::storage::RingDeltaPath {
            from,
            to: ring_hash_target,
            deltas,
        })
    }
}

impl RingWriter for InMemoryRings {
    fn append_delta(&self, tenant: Tenant, delta: RingDelta) -> Result<RingHash, StorageError> {
        let mut map = self.inner();
        let state = map.entry(tenant).or_insert_with(|| RingState {
            log: RingDeltaLog::default(),
            current: Ring::new(vec![]),
            current_hash: RingHash([0; 32]),
        });

        let (hash, _) = state
            .log
            .append(&mut state.current, delta.clone())
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        state.current_hash = hash;
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::ring_hash_sha3_256;
    use crate::ids::MasterPublicKey;
    use nazgul::{scalar::RistrettoPoint, traits::LocalByteConvertible};
    use sha3::Sha3_512;

    fn mpk(label: &[u8]) -> MasterPublicKey {
        let point = RistrettoPoint::hash_from_bytes::<Sha3_512>(label);
        MasterPublicKey(point.to_bytes())
    }

    #[test]
    fn ring_writer_roundtrip() {
        let rings = InMemoryRings::new();
        let tenant = Tenant(ulid::Ulid::new());

        let h1 = rings
            .append_delta(tenant, RingDelta::Add(mpk(b"a")))
            .expect("append should succeed");
        let ring = rings.current_ring(tenant).expect("ring exists");
        assert_eq!(ring_hash_sha3_256(&ring), h1);

        // Path from scratch to current should contain founder delta.
        let path = rings
            .ring_delta_path(tenant, None, h1)
            .expect("delta path should exist");
        assert_eq!(path.deltas.len(), 1);
        assert_eq!(path.to, h1);
    }
}
