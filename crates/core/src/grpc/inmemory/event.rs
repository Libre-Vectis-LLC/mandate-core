/// In-memory event storage and streaming.
use crate::event::{Event, EventType};
use crate::hashing::event_hash_sha3_256;
use crate::ids::{EventId, OrganizationId, SequenceNo, TenantId};
use crate::storage::{
    EventBytes, EventReader, EventRecord, EventStore, EventWriter, NotFound, StorageError,
};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

use super::ban::InMemoryBanIndex;
use super::member::InMemoryPendingMembers;
use super::vote::InMemoryVoteKeyImages;

type InMemoryEventMap = HashMap<(TenantId, OrganizationId), Vec<EventRecord>>;

#[derive(Clone)]
pub struct InMemoryEvents {
    // Keyed by (TenantId, OrganizationId) for isolation
    events: Arc<Mutex<InMemoryEventMap>>,
    ban_index: Arc<InMemoryBanIndex>,
    vote_key_images: Arc<InMemoryVoteKeyImages>,
    pending_members: Arc<InMemoryPendingMembers>,
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
            pending_members,
        }
    }

    fn inner(&self) -> parking_lot::MutexGuard<'_, InMemoryEventMap> {
        self.events.lock()
    }

    fn apply_indexes(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        event: &Event,
        event_id: EventId,
    ) -> Result<(), StorageError> {
        match &event.event_type {
            EventType::BanCreate(ban) => {
                if event.signature.is_none() {
                    return Err(StorageError::PreconditionFailed("missing signature".into()));
                }
                self.ban_index.record_ban(
                    tenant,
                    org_id,
                    ban.target,
                    ban.scope,
                    event_id,
                    ban.ring_hash,
                )?;
            }
            EventType::BanRevoke(revoke) => {
                self.ban_index.revoke_ban(revoke.ban_event_id)?;
            }
            EventType::VoteCast(vote) => {
                let sig = event
                    .signature
                    .as_ref()
                    .ok_or_else(|| StorageError::PreconditionFailed("missing signature".into()))?;
                self.vote_key_images
                    .record_vote(tenant, org_id, &vote.poll_id, sig.key_image())?;
            }
            EventType::RingUpdate(update) => {
                for operation in &update.operations {
                    if let crate::event::RingOperation::AddMember { public_key, .. } = operation {
                        self.pending_members
                            .approve_member(tenant, org_id, *public_key);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[async_trait]
impl EventWriter for InMemoryEvents {
    async fn append(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        event_bytes: EventBytes,
    ) -> Result<(EventId, SequenceNo), StorageError> {
        let mut inner = self.inner();
        let entry = inner.entry((tenant, org_id)).or_default();
        let event: Event = serde_json::from_slice(&event_bytes)
            .map_err(|e| StorageError::Backend(format!("invalid event bytes: {e}")))?;
        let hash = event_hash_sha3_256(&event)
            .map_err(|e| StorageError::Backend(format!("hash event: {e}")))?;
        let id = EventId(hash.0);
        self.apply_indexes(tenant, org_id, &event, id)?;
        let seq = SequenceNo::new(
            i64::try_from(entry.len())
                .map_err(|_| StorageError::Backend("sequence number overflow".into()))?,
        );
        entry.push((id, event_bytes, seq));
        Ok((id, seq))
    }
}

#[async_trait]
impl EventReader for InMemoryEvents {
    async fn stream_group(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        after: Option<SequenceNo>,
        limit: usize,
    ) -> Result<Vec<EventRecord>, StorageError> {
        let inner = self.inner();
        let Some(events) = inner.get(&(tenant, org_id)) else {
            return Ok(Vec::new());
        };
        let start = match after {
            None => 0,
            Some(seq) if seq.as_i64() < 0 => 0,
            Some(seq) => match seq.as_i64().checked_add(1) {
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
        org_id: OrganizationId,
        id: &EventId,
    ) -> Result<EventRecord, StorageError> {
        let inner = self.inner();
        let events =
            inner
                .get(&(tenant, org_id))
                .ok_or(StorageError::NotFound(NotFound::Event {
                    id: *id,
                    tenant,
                    org_id,
                }))?;
        events
            .iter()
            .find(|(ev_id, _, _)| ev_id == id)
            .cloned()
            .ok_or(StorageError::NotFound(NotFound::Event {
                id: *id,
                tenant,
                org_id,
            }))
    }

    async fn tail(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
    ) -> Result<EventRecord, StorageError> {
        let inner = self.inner();
        let events = inner
            .get(&(tenant, org_id))
            .ok_or(StorageError::NotFound(NotFound::Tail { tenant, org_id }))?;
        events
            .last()
            .cloned()
            .ok_or(StorageError::NotFound(NotFound::Tail { tenant, org_id }))
    }
}

impl EventStore for InMemoryEvents {}
