use crate::event::{BanScope, Event};
use crate::hashing::event_hash_sha3_256;
use crate::ids::{EventId, GroupId, KeyImage, MasterPublicKey, TenantId, TenantToken};
use crate::storage::{
    BanIndex, BannedOperation, BillingStore, EventBytes, EventReader, EventRecord, EventStore,
    EventWriter, GiftCard, GiftCardStore, GroupMetadataStore, KeyBlobStore, NotFound,
    PendingMember, PendingMemberStatus, PendingMemberStore, RingView, RingWriter, StorageError,
    TenantTokenError, TenantTokenStore, VoteKeyImageIndex,
};
use crate::{
    ids::{RingHash, TenantId as Tenant},
    ring_log::{RingDelta, RingDeltaLog, RingLogError},
};
use async_trait::async_trait;
use nazgul::ring::Ring;
use std::collections::{HashMap, HashSet};
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

#[async_trait]
impl TenantTokenStore for InMemoryTenantTokens {
    async fn resolve_tenant(&self, token: &TenantToken) -> Result<TenantId, TenantTokenError> {
        let map = self.tokens.lock().expect("poison-free");
        map.get(token).copied().ok_or(TenantTokenError::Unknown)
    }

    async fn insert(&self, token: &TenantToken, tenant: TenantId) -> Result<(), StorageError> {
        let mut map = self.tokens.lock().expect("poison-free");
        map.insert(token.clone(), tenant);
        Ok(())
    }
}

type InMemoryEventMap = HashMap<(TenantId, GroupId), Vec<EventRecord>>;
type BanKey = (TenantId, GroupId, [u8; 32]);
type BanScopeSet = HashSet<BanScope>;
type BanMap = HashMap<BanKey, BanScopeSet>;
type VoteKey = (TenantId, GroupId, String, [u8; 32]);
type VoteKeySet = HashSet<VoteKey>;
pub(crate) type GroupMap = HashMap<GroupId, GroupRecord>;
type TenantBalanceMap = HashMap<TenantId, i64>;
type PendingMemberMap = HashMap<(TenantId, GroupId), Vec<PendingMemberRecord>>;

#[derive(Clone, Debug)]
struct PendingMemberRecord {
    member: PendingMember,
    status: PendingMemberStatus,
}

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

fn approve_pending_member(
    members: &mut PendingMemberMap,
    tenant: TenantId,
    group_id: GroupId,
    public_key: MasterPublicKey,
) {
    let Some(list) = members.get_mut(&(tenant, group_id)) else {
        return;
    };
    for record in list.iter_mut() {
        if record.status == PendingMemberStatus::Pending && record.member.nazgul_pub == public_key {
            record.status = PendingMemberStatus::Approved;
        }
    }
}

#[derive(Clone)]
pub struct InMemoryEvents {
    // Keyed by (TenantId, GroupId) for isolation
    events: Arc<Mutex<InMemoryEventMap>>,
    ban_index: Arc<InMemoryBanIndex>,
    vote_key_images: Arc<InMemoryVoteKeyImages>,
    pending_members: Arc<Mutex<PendingMemberMap>>,
}

impl InMemoryEvents {
    pub fn new(
        ban_index: Arc<InMemoryBanIndex>,
        vote_key_images: Arc<InMemoryVoteKeyImages>,
        pending_members: Arc<InMemoryPendingMembers>,
    ) -> Self {
        Self {
            events: Arc::new(Mutex::new(HashMap::new())),
            ban_index,
            vote_key_images,
            pending_members: pending_members.shared(),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, InMemoryEventMap> {
        self.events.lock().expect("poison-free")
    }
}

#[async_trait]
impl EventWriter for InMemoryEvents {
    async fn append(
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
        self.apply_indexes(tenant, group_id, &event, id)?;
        let seq = entry.len() as i64;
        entry.push((id, event_bytes, seq));
        Ok((id, seq))
    }
}

impl InMemoryEvents {
    fn apply_indexes(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        event: &Event,
        event_id: EventId,
    ) -> Result<(), StorageError> {
        match &event.event_type {
            crate::event::EventType::BanCreate(ban) => {
                if event.signature.is_none() {
                    return Err(StorageError::PreconditionFailed("missing signature".into()));
                }
                self.ban_index
                    .record_ban(tenant, group_id, ban.target, ban.scope, event_id)?;
            }
            crate::event::EventType::BanRevoke(revoke) => {
                self.ban_index.revoke_ban(revoke.ban_event_id)?;
            }
            crate::event::EventType::VoteCast(vote) => {
                let sig = event
                    .signature
                    .as_ref()
                    .ok_or_else(|| StorageError::PreconditionFailed("missing signature".into()))?;
                self.vote_key_images.record_vote(
                    tenant,
                    group_id,
                    &vote.poll_id,
                    sig.key_image(),
                )?;
            }
            crate::event::EventType::RingUpdate(update) => {
                let mut members = self.pending_members.lock().expect("poison-free");
                for operation in &update.operations {
                    if let crate::event::RingOperation::AddMember { public_key } = operation {
                        approve_pending_member(&mut members, tenant, group_id, *public_key);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[async_trait]
impl EventReader for InMemoryEvents {
    async fn stream_group(
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

    async fn get(
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

    async fn tail(&self, tenant: TenantId, group_id: GroupId) -> Result<EventRecord, StorageError> {
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

impl EventStore for InMemoryEvents {}

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

#[async_trait]
impl RingView for InMemoryRings {
    async fn ring_by_hash(
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

    async fn current_ring(
        &self,
        tenant: Tenant,
        group_id: GroupId,
    ) -> Result<Arc<Ring>, StorageError> {
        let map = self.inner();
        let key = (tenant, group_id);
        let state = map.get(&key).ok_or(StorageError::NotFound(NotFound::Ring {
            hash: RingHash([0; 32]),
            tenant,
            group_id,
        }))?;
        Ok(Arc::new(state.current.clone()))
    }

    async fn ring_delta_path(
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

#[async_trait]
impl RingWriter for InMemoryRings {
    async fn append_delta(
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
        let mut ban_events = self.ban_events.lock().expect("poison-free");
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

        let mut bans = self.bans.lock().expect("poison-free");
        let entry = bans.entry((tenant, group_id, key_image)).or_default();
        if !entry.insert(scope) {
            return Err(StorageError::PreconditionFailed(
                "ban already recorded".into(),
            ));
        }
        Ok(())
    }

    pub fn revoke_ban(&self, ban_event_id: EventId) -> Result<(), StorageError> {
        let mut ban_events = self.ban_events.lock().expect("poison-free");
        let record = ban_events
            .remove(&ban_event_id)
            .ok_or_else(|| StorageError::PreconditionFailed("unknown ban event".into()))?;

        let mut bans = self.bans.lock().expect("poison-free");
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
        let bans = self.bans.lock().expect("poison-free");
        let Some(scopes) = bans.get(&(tenant, group_id, key_image)) else {
            return Ok(false);
        };
        let blocked = ban_scopes_for_operation(operation)
            .iter()
            .any(|scope| scopes.contains(scope));
        Ok(blocked)
    }
}

#[derive(Clone, Default)]
pub struct InMemoryVoteKeyImages {
    used: Arc<Mutex<VoteKeySet>>,
}

impl InMemoryVoteKeyImages {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_vote(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
        key_image: KeyImage,
    ) -> Result<(), StorageError> {
        let key = (
            tenant,
            group_id,
            poll_id.to_string(),
            key_image_bytes(&key_image),
        );
        let mut used = self.used.lock().expect("poison-free");
        if !used.insert(key) {
            return Err(StorageError::PreconditionFailed("vote already cast".into()));
        }
        Ok(())
    }
}

#[async_trait]
impl VoteKeyImageIndex for InMemoryVoteKeyImages {
    async fn is_used(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
        key_image: &KeyImage,
    ) -> Result<bool, StorageError> {
        let key = (
            tenant,
            group_id,
            poll_id.to_string(),
            key_image_bytes(key_image),
        );
        let used = self.used.lock().expect("poison-free");
        Ok(used.contains(&key))
    }
}

#[derive(Default, Clone)]
pub struct NoopVoteKeyImages;

#[async_trait]
impl VoteKeyImageIndex for NoopVoteKeyImages {
    async fn is_used(
        &self,
        _tenant: TenantId,
        _group_id: GroupId,
        _poll_id: &str,
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

#[async_trait]
impl GiftCardStore for InMemoryGiftCards {
    async fn issue(&self, amount_nanos: u64) -> Result<GiftCard, StorageError> {
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

    async fn redeem(&self, code: &str, tenant: TenantId) -> Result<GiftCard, StorageError> {
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
    tenant: TenantId,
    tg_group_id: String,
    balance_nanos: i64,
}

#[async_trait]
impl GroupMetadataStore for InMemoryGroups {
    async fn create_group(
        &self,
        tenant: TenantId,
        tg_group_id: &str,
    ) -> Result<GroupId, StorageError> {
        let mut map = self.groups.lock().expect("poison-free");
        let group_id = GroupId(ulid::Ulid::new());
        map.insert(
            group_id,
            GroupRecord {
                tenant,
                tg_group_id: tg_group_id.to_string(),
                balance_nanos: 0,
            },
        );
        Ok(group_id)
    }

    async fn get_group(&self, group_id: GroupId) -> Result<(TenantId, String), StorageError> {
        let map = self.groups.lock().expect("poison-free");
        map.get(&group_id)
            .map(|record| (record.tenant, record.tg_group_id.clone()))
            .ok_or(StorageError::NotFound(NotFound::Group { group_id }))
    }
}

#[derive(Clone)]
pub struct InMemoryBilling {
    tenants: Arc<Mutex<TenantBalanceMap>>,
    groups: Arc<Mutex<GroupMap>>,
}

impl InMemoryBilling {
    pub(crate) fn new(groups: Arc<Mutex<GroupMap>>) -> Self {
        Self {
            tenants: Arc::new(Mutex::new(HashMap::new())),
            groups,
        }
    }
}

#[async_trait]
impl BillingStore for InMemoryBilling {
    async fn credit_tenant(
        &self,
        tenant: TenantId,
        _owner_tg_user_id: &str,
        amount_nanos: u64,
    ) -> Result<i64, StorageError> {
        let delta = i64::try_from(amount_nanos)
            .map_err(|_| StorageError::PreconditionFailed("amount too large".into()))?;
        let mut map = self.tenants.lock().expect("poison-free");
        let balance = map.entry(tenant).or_insert(0);
        *balance = balance
            .checked_add(delta)
            .ok_or_else(|| StorageError::PreconditionFailed("balance overflow".into()))?;
        Ok(*balance)
    }

    async fn transfer_to_group(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        amount_nanos: u64,
    ) -> Result<i64, StorageError> {
        let delta = i64::try_from(amount_nanos)
            .map_err(|_| StorageError::PreconditionFailed("amount too large".into()))?;
        let mut tenants = self.tenants.lock().expect("poison-free");
        let tenant_balance = tenants.entry(tenant).or_insert(0);
        if *tenant_balance < delta {
            return Err(StorageError::PreconditionFailed(
                "insufficient balance".into(),
            ));
        }

        let mut groups = self.groups.lock().expect("poison-free");
        let record = groups
            .get_mut(&group_id)
            .ok_or(StorageError::NotFound(NotFound::Group { group_id }))?;
        if record.tenant != tenant {
            return Err(StorageError::PreconditionFailed(
                "group does not belong to tenant".into(),
            ));
        }

        *tenant_balance -= delta;
        record.balance_nanos = record
            .balance_nanos
            .checked_add(delta)
            .ok_or_else(|| StorageError::PreconditionFailed("balance overflow".into()))?;

        Ok(record.balance_nanos)
    }

    async fn get_group_balance(&self, group_id: GroupId) -> Result<i64, StorageError> {
        let groups = self.groups.lock().expect("poison-free");
        let record = groups
            .get(&group_id)
            .ok_or(StorageError::NotFound(NotFound::Group { group_id }))?;
        Ok(record.balance_nanos)
    }
}

#[derive(Clone, Default)]
pub struct InMemoryPendingMembers {
    // Keyed by (TenantId, GroupId)
    members: Arc<Mutex<PendingMemberMap>>,
}

impl InMemoryPendingMembers {
    pub fn new() -> Self {
        Self::default()
    }

    fn shared(&self) -> Arc<Mutex<PendingMemberMap>> {
        Arc::clone(&self.members)
    }
}

#[async_trait]
impl PendingMemberStore for InMemoryPendingMembers {
    async fn submit(
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
        let record = PendingMemberRecord {
            member,
            status: PendingMemberStatus::Pending,
        };
        // Idempotency: append for MVP
        list.push(record);
        Ok(pending_id)
    }

    async fn list(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        limit: usize,
        _page_token: Option<String>,
    ) -> Result<(Vec<PendingMember>, Option<String>), StorageError> {
        let map = self.members.lock().expect("poison-free");
        if let Some(list) = map.get(&(tenant, group_id)) {
            // MVP: naive pagination
            let result = list
                .iter()
                .filter(|record| record.status == PendingMemberStatus::Pending)
                .take(limit)
                .map(|record| record.member.clone())
                .collect();
            Ok((result, None))
        } else {
            Ok((Vec::new(), None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventType, RingOperation, RingUpdate};
    use crate::hashing::ring_hash_sha3_256;
    use crate::ids::{EventId, EventUlid, MasterPublicKey, RingHash};
    use crate::key_manager::KeyManager;
    use crate::test_utils::TEST_MNEMONIC;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use nazgul::traits::{Derivable, LocalByteConvertible};
    use sha3::Sha3_512;
    use std::sync::Arc;

    fn mpk(label: &[u8]) -> MasterPublicKey {
        let km = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid test mnemonic");
        let master = km.derive_nazgul_master_keypair();
        let child = master.0.derive_child::<Sha3_512>(label);
        MasterPublicKey(child.public().to_bytes())
    }

    #[tokio::test]
    async fn ring_writer_roundtrip() {
        let rings = InMemoryRings::new();
        let tenant = Tenant(ulid::Ulid::new());
        let group = GroupId(ulid::Ulid::new());

        let h1 = rings
            .append_delta(tenant, group, RingDelta::Add(mpk(b"a")))
            .await
            .expect("append should succeed");
        let ring = rings
            .current_ring(tenant, group)
            .await
            .expect("ring exists");
        assert_eq!(ring_hash_sha3_256(&ring), h1);

        // Path from scratch to current should contain founder delta.
        let path = rings
            .ring_delta_path(tenant, group, None, h1)
            .await
            .expect("delta path should exist");
        assert_eq!(path.deltas.len(), 1);
        assert_eq!(path.to, h1);
    }

    #[tokio::test]
    async fn pending_members_only_list_pending_after_ring_add() {
        let tenant = Tenant(ulid::Ulid::new());
        let group = GroupId(ulid::Ulid::new());
        let pending = Arc::new(InMemoryPendingMembers::new());
        let events = InMemoryEvents::new(
            Arc::new(InMemoryBanIndex::new()),
            Arc::new(InMemoryVoteKeyImages::new()),
            Arc::clone(&pending),
        );

        let member_key = MasterPublicKey([0x11; 32]);
        pending
            .submit(tenant, group, "tg-user", member_key, [0x22; 32])
            .await
            .expect("pending submit");

        let event = Event {
            event_ulid: EventUlid(ulid::Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            group_id: group,
            sequence_no: None,
            processed_at: 0,
            serialization_version: 1,
            event_type: EventType::RingUpdate(RingUpdate {
                group_id: group,
                ring_hash: RingHash([7u8; 32]),
                operations: vec![RingOperation::AddMember {
                    public_key: member_key,
                }],
            }),
            signature: None,
        };

        events
            .append(
                tenant,
                group,
                serde_json::to_vec(&event).expect("serialize").into(),
            )
            .await
            .expect("append event");

        let (members, _) = pending
            .list(tenant, group, 10, None)
            .await
            .expect("list pending");
        assert!(members.is_empty());
    }

    #[tokio::test]
    async fn rings_are_scoped_by_group() {
        let rings = InMemoryRings::new();
        let tenant = Tenant(ulid::Ulid::new());
        let g1 = GroupId(ulid::Ulid::new());
        let g2 = GroupId(ulid::Ulid::new());

        let h = rings
            .append_delta(tenant, g1, RingDelta::Add(mpk(b"a")))
            .await
            .expect("append should succeed");

        rings
            .ring_by_hash(tenant, g1, &h)
            .await
            .expect("ring exists for g1");

        let err = rings
            .ring_by_hash(tenant, g2, &h)
            .await
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
            .await
            .expect("append should succeed");
        assert_eq!(
            h2, h,
            "ring hashes match when membership sets are identical"
        );
        rings
            .ring_by_hash(tenant, g2, &h)
            .await
            .expect("ring exists for g2 after append");
    }

    #[tokio::test]
    async fn ban_index_respects_scope_and_revoke() {
        let ban_index = InMemoryBanIndex::new();
        let tenant = TenantId(ulid::Ulid::new());
        let group = GroupId(ulid::Ulid::new());
        let key_image = RistrettoPoint::default();
        let ban_event_id = EventId([42u8; 32]);

        ban_index
            .record_ban(
                tenant,
                group,
                key_image.clone(),
                BanScope::BanVote,
                ban_event_id,
            )
            .expect("ban recorded");

        let banned_vote = ban_index
            .is_banned(tenant, group, &key_image, BannedOperation::CastVote)
            .await
            .expect("ban check");
        assert!(banned_vote);

        let banned_post = ban_index
            .is_banned(tenant, group, &key_image, BannedOperation::PostMessage)
            .await
            .expect("ban check");
        assert!(!banned_post);

        ban_index.revoke_ban(ban_event_id).expect("ban revoked");

        let banned_after = ban_index
            .is_banned(tenant, group, &key_image, BannedOperation::CastVote)
            .await
            .expect("ban check");
        assert!(!banned_after);
    }

    #[tokio::test]
    async fn vote_key_images_block_duplicates() {
        let vote_index = InMemoryVoteKeyImages::new();
        let tenant = TenantId(ulid::Ulid::new());
        let group = GroupId(ulid::Ulid::new());
        let key_image = RistrettoPoint::default();
        let poll_id = "poll-1";

        let used = vote_index
            .is_used(tenant, group, poll_id, &key_image)
            .await
            .expect("check");
        assert!(!used);

        vote_index
            .record_vote(tenant, group, poll_id, key_image.clone())
            .expect("record vote");

        let used = vote_index
            .is_used(tenant, group, poll_id, &key_image)
            .await
            .expect("check");
        assert!(used);

        let err = vote_index
            .record_vote(tenant, group, poll_id, key_image)
            .expect_err("duplicate vote");
        assert!(matches!(err, StorageError::PreconditionFailed(_)));
    }

    #[tokio::test]
    async fn billing_transfer_updates_group_balance() {
        let tenant = TenantId(ulid::Ulid::new());
        let groups = InMemoryGroups::new();
        let group_id = groups
            .create_group(tenant, "tg-group")
            .await
            .expect("group created");
        let billing = InMemoryBilling::new(groups.shared());

        let balance = billing
            .credit_tenant(tenant, "tg-user", 100)
            .await
            .expect("tenant credited");
        assert_eq!(balance, 100);

        let group_balance = billing
            .transfer_to_group(tenant, group_id, 60)
            .await
            .expect("transfer succeeds");
        assert_eq!(group_balance, 60);

        let group_balance = billing
            .get_group_balance(group_id)
            .await
            .expect("balance query succeeds");
        assert_eq!(group_balance, 60);
    }

    #[tokio::test]
    async fn billing_rejects_overdraft() {
        let tenant = TenantId(ulid::Ulid::new());
        let groups = InMemoryGroups::new();
        let group_id = groups
            .create_group(tenant, "tg-group")
            .await
            .expect("group created");
        let billing = InMemoryBilling::new(groups.shared());

        billing
            .credit_tenant(tenant, "tg-user", 40)
            .await
            .expect("tenant credited");

        let err = billing
            .transfer_to_group(tenant, group_id, 60)
            .await
            .expect_err("overdraft rejected");

        assert!(matches!(err, StorageError::PreconditionFailed(_)));
    }
}
