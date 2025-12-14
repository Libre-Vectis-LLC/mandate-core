use crate::event::Event;
use crate::hashing::event_hash_sha3_256;
use crate::ids::{EventId, GroupId, KeyImage, MasterPublicKey, TenantId, TenantToken};
use crate::storage::{
    BanIndex, EventBytes, EventReader, EventRecord, EventStore, EventWriter, GiftCard,
    GiftCardStore, GroupMetadataStore, KeyBlobStore, NotFound, PendingMember, PendingMemberStore,
    RingView, RingWriter, StorageError, TenantTokenError, TenantTokenStore,
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

    fn insert(&self, token: &TenantToken, tenant: TenantId) -> Result<(), StorageError> {
        let mut map = self.tokens.lock().expect("poison-free");
        map.insert(token.clone(), tenant);
        Ok(())
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

#[derive(Clone, Default)]
pub struct InMemoryGiftCards {
    cards: Arc<Mutex<HashMap<String, GiftCard>>>,
}

impl InMemoryGiftCards {
    pub fn new() -> Self {
        Self::default()
    }
}

impl GiftCardStore for InMemoryGiftCards {
    fn issue(&self, amount_nanos: u64) -> Result<GiftCard, StorageError> {
        let mut map = self.cards.lock().expect("poison-free");
        let code = format!("GIFT-{}", ulid::Ulid::new());
        let card = GiftCard {
            code: code.clone(),
            amount_nanos,
            used_by: None,
        };
        map.insert(code, card.clone());
        Ok(card)
    }

    fn redeem(&self, code: &str, tenant: TenantId) -> Result<GiftCard, StorageError> {
        let mut map = self.cards.lock().expect("poison-free");
        if let Some(card) = map.get_mut(code) {
            if card.used_by.is_some() {
                return Err(StorageError::PreconditionFailed("already redeemed".into()));
            }
            card.used_by = Some(tenant);
            Ok(card.clone())
        } else {
            Err(StorageError::NotFound(NotFound::GiftCard {
                code: code.to_string(),
            }))
        }
    }
}

#[derive(Clone, Default)]
pub struct InMemoryGroups {
    groups: Arc<Mutex<HashMap<GroupId, (TenantId, String)>>>,
}

impl InMemoryGroups {
    pub fn new() -> Self {
        Self::default()
    }
}

impl GroupMetadataStore for InMemoryGroups {
    fn create_group(&self, tenant: TenantId, tg_group_id: &str) -> Result<GroupId, StorageError> {
        let mut map = self.groups.lock().expect("poison-free");
        let group_id = GroupId(ulid::Ulid::new());
        map.insert(group_id, (tenant, tg_group_id.to_string()));
        Ok(group_id)
    }

    fn get_group(&self, group_id: GroupId) -> Result<(TenantId, String), StorageError> {
        let map = self.groups.lock().expect("poison-free");
        map.get(&group_id)
            .cloned()
            .ok_or(StorageError::Backend("group not found".into()))
    }
}

type PendingMemberMap = HashMap<(TenantId, GroupId), Vec<PendingMember>>;

#[derive(Clone, Default)]
pub struct InMemoryPendingMembers {
    // Keyed by (TenantId, GroupId)
    members: Arc<Mutex<PendingMemberMap>>,
}

impl InMemoryPendingMembers {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PendingMemberStore for InMemoryPendingMembers {
    fn submit(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        tg_user_id: &str,
        nazgul_pub: MasterPublicKey,
        rage_pub: [u8; 32],
    ) -> Result<String, StorageError> {
        let mut map = self.members.lock().expect("poison-free");
        let list = map.entry((tenant, group_id)).or_default();

        let pending_id = format!("PENDING-{}", ulid::Ulid::new());
        let member = PendingMember {
            pending_id: pending_id.clone(),
            tg_user_id: tg_user_id.to_string(),
            nazgul_pub,
            rage_pub,
            submitted_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        };
        // Idempotency: append for MVP
        list.push(member);
        Ok(pending_id)
    }

    fn list(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        limit: usize,
        _page_token: Option<String>,
    ) -> Result<(Vec<PendingMember>, Option<String>), StorageError> {
        let map = self.members.lock().expect("poison-free");
        if let Some(list) = map.get(&(tenant, group_id)) {
            // MVP: naive pagination
            let result = list.iter().take(limit).cloned().collect();
            Ok((result, None))
        } else {
            Ok((Vec::new(), None))
        }
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
