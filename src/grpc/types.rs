use crate::event::Event;
use crate::hashing::event_hash_sha3_256;
use crate::ids::{EventId, GroupId, KeyImage, TenantId, TenantToken};
use crate::storage::{
    BanIndex, EventBytes, EventReader, EventRecord, EventStore, EventWriter, KeyBlobStore,
    NotFound, RingView, RingWriter, StorageError, TenantTokenError, TenantTokenStore,
};
use crate::{
    ids::{RingHash, TenantId as Tenant},
    ring_log::{RingDelta, RingDeltaLog, RingLogError},
};
use nazgul::ring::Ring;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct InMemoryTenantTokens {
    tokens: Arc<Mutex<HashMap<TenantToken, TenantId>>>,
}

impl InMemoryTenantTokens {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, token: impl Into<TenantToken>, tenant: TenantId) {
        let mut map = self.tokens.lock().expect("poison-free");
        map.insert(token.into(), tenant);
    }
}

impl TenantTokenStore for InMemoryTenantTokens {
    fn resolve_tenant(&self, token: &TenantToken) -> Result<TenantId, TenantTokenError> {
        let map = self.tokens.lock().expect("poison-free");
        map.get(token).copied().ok_or(TenantTokenError::Unknown)
    }
}

type InMemoryEventMap = HashMap<(TenantId, GroupId), Vec<EventRecord>>;

#[derive(Clone, Default)]
pub struct InMemoryEvents {
    // Keyed by (TenantId, GroupId) for isolation
    events: Arc<Mutex<InMemoryEventMap>>,
}

impl InMemoryEvents {
    pub fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, InMemoryEventMap> {
        self.events.lock().expect("poison-free")
    }
}

impl EventWriter for InMemoryEvents {
    fn append(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        event_bytes: EventBytes,
    ) -> Result<(EventId, i64), StorageError> {
        let mut inner = self.inner();
        let entry = inner.entry((tenant, group_id)).or_default();
        let event: Event = serde_json::from_slice(&event_bytes)
            .map_err(|e| StorageError::Backend(format!("invalid event bytes: {e}")))?;
        let hash = event_hash_sha3_256(&event)
            .map_err(|e| StorageError::Backend(format!("hash event: {e}")))?;
        let id = EventId(hash.0);
        let seq = entry.len() as i64;
        entry.push((id, event_bytes, seq));
        Ok((id, seq))
    }
}

impl EventReader for InMemoryEvents {
    fn stream_group(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        after: Option<i64>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError> {
        let inner = self.inner();
        let Some(events) = inner.get(&(tenant, group_id)) else {
            return Ok(Vec::new());
        };
        let start = match after {
            None => 0,
            Some(seq) if seq < 0 => 0,
            Some(seq) => match seq.checked_add(1) {
                Some(next) => usize::try_from(next).unwrap_or(events.len()),
                None => events.len(),
            },
        };
        let start = start.min(events.len());
        Ok(events.iter().skip(start).take(limit).cloned().collect())
    }
}

impl EventStore for InMemoryEvents {
    fn get(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        id: &EventId,
    ) -> Result<EventRecord, StorageError> {
        let inner = self.inner();
        let events = inner
            .get(&(tenant, group_id))
            .ok_or(StorageError::NotFound(NotFound::Event {
                id: *id,
                tenant,
                group_id,
            }))?;
        events
            .iter()
            .find(|(ev_id, _, _)| ev_id == id)
            .cloned()
            .ok_or(StorageError::NotFound(NotFound::Event {
                id: *id,
                tenant,
                group_id,
            }))
    }

    fn tail(&self, tenant: TenantId, group_id: GroupId) -> Result<EventRecord, StorageError> {
        let inner = self.inner();
        let events = inner
            .get(&(tenant, group_id))
            .ok_or(StorageError::NotFound(NotFound::Tail { tenant, group_id }))?;
        events
            .last()
            .cloned()
            .ok_or(StorageError::NotFound(NotFound::Tail { tenant, group_id }))
    }
}

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

    fn inner(&self) -> std::sync::MutexGuard<'_, KeyBlobMap> {
        self.blobs.lock().expect("poison-free")
    }
}

impl KeyBlobStore for InMemoryKeyBlobs {
    fn put_many(
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

    fn get_one(
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

#[derive(Default, Clone)]
pub struct InMemoryRings {
    rings: Arc<Mutex<HashMap<(Tenant, GroupId), RingState>>>,
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

    fn inner(&self) -> std::sync::MutexGuard<'_, HashMap<(Tenant, GroupId), RingState>> {
        self.rings.lock().expect("ring mutex poisoned")
    }
}

impl RingView for InMemoryRings {
    fn ring_by_hash(
        &self,
        tenant: Tenant,
        group_id: GroupId,
        hash: &RingHash,
    ) -> Result<Arc<Ring>, StorageError> {
        let mut map = self.inner();
        let key = (tenant, group_id);
        let state = map
            .get_mut(&key)
            .ok_or(StorageError::NotFound(NotFound::Ring {
                hash: *hash,
                tenant,
                group_id,
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

    fn current_ring(&self, tenant: Tenant, group_id: GroupId) -> Result<Arc<Ring>, StorageError> {
        let map = self.inner();
        let key = (tenant, group_id);
        let state = map.get(&key).ok_or(StorageError::NotFound(NotFound::Ring {
            hash: RingHash([0; 32]),
            tenant,
            group_id,
        }))?;
        Ok(Arc::new(state.current.clone()))
    }

    fn ring_delta_path(
        &self,
        tenant: Tenant,
        group_id: GroupId,
        ring_hash_current: Option<RingHash>,
        ring_hash_target: RingHash,
    ) -> Result<crate::storage::RingDeltaPath, StorageError> {
        let map = self.inner();
        let key = (tenant, group_id);
        let state = map.get(&key).ok_or(StorageError::NotFound(NotFound::Ring {
            hash: ring_hash_current.unwrap_or(ring_hash_target),
            tenant,
            group_id,
        }))?;

        let deltas = state
            .log
            .delta_path(ring_hash_current.as_ref(), &ring_hash_target)
            .map_err(|e| match e {
                RingLogError::TargetNotFound => StorageError::NotFound(NotFound::Ring {
                    hash: ring_hash_target,
                    tenant,
                    group_id,
                }),
                RingLogError::AnchorNotFound => StorageError::NotFound(NotFound::Ring {
                    hash: ring_hash_current.unwrap_or(ring_hash_target),
                    tenant,
                    group_id,
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
    fn append_delta(
        &self,
        tenant: Tenant,
        group_id: GroupId,
        delta: RingDelta,
    ) -> Result<RingHash, StorageError> {
        let mut map = self.inner();
        let key = (tenant, group_id);
        let state = map.entry(key).or_insert_with(|| RingState {
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

#[derive(Default, Clone)]
pub struct NoopBanIndex;

impl BanIndex for NoopBanIndex {
    fn is_banned(
        &self,
        _tenant: TenantId,
        _group_id: GroupId,
        _key_image: &KeyImage,
    ) -> Result<bool, StorageError> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::ring_hash_sha3_256;
    use crate::ids::MasterPublicKey;
    use crate::key_manager::KeyManager;
    use crate::test_utils::TEST_MNEMONIC;
    use nazgul::traits::{Derivable, LocalByteConvertible};
    use sha3::Sha3_512;

    fn mpk(label: &[u8]) -> MasterPublicKey {
        let km = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid test mnemonic");
        let master = km.derive_nazgul_master_keypair();
        let child = master.0.derive_child::<Sha3_512>(label);
        MasterPublicKey(child.public().to_bytes())
    }

    #[test]
    fn ring_writer_roundtrip() {
        let rings = InMemoryRings::new();
        let tenant = Tenant(ulid::Ulid::new());
        let group = GroupId(ulid::Ulid::new());

        let h1 = rings
            .append_delta(tenant, group, RingDelta::Add(mpk(b"a")))
            .expect("append should succeed");
        let ring = rings.current_ring(tenant, group).expect("ring exists");
        assert_eq!(ring_hash_sha3_256(&ring), h1);

        // Path from scratch to current should contain founder delta.
        let path = rings
            .ring_delta_path(tenant, group, None, h1)
            .expect("delta path should exist");
        assert_eq!(path.deltas.len(), 1);
        assert_eq!(path.to, h1);
    }

    #[test]
    fn rings_are_scoped_by_group() {
        let rings = InMemoryRings::new();
        let tenant = Tenant(ulid::Ulid::new());
        let g1 = GroupId(ulid::Ulid::new());
        let g2 = GroupId(ulid::Ulid::new());

        let h = rings
            .append_delta(tenant, g1, RingDelta::Add(mpk(b"a")))
            .expect("append should succeed");

        rings
            .ring_by_hash(tenant, g1, &h)
            .expect("ring exists for g1");

        let err = rings
            .ring_by_hash(tenant, g2, &h)
            .expect_err("g2 must not see g1 ring state");
        assert!(matches!(
            err,
            StorageError::NotFound(NotFound::Ring {
                tenant: t,
                group_id,
                hash
            }) if t == tenant && group_id == g2 && hash == h
        ));

        let h2 = rings
            .append_delta(tenant, g2, RingDelta::Add(mpk(b"a")))
            .expect("append should succeed");
        assert_eq!(
            h2, h,
            "ring hashes match when membership sets are identical"
        );
        rings
            .ring_by_hash(tenant, g2, &h)
            .expect("ring exists for g2 after append");
    }
}
