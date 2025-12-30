/// In-memory pending member storage.
use crate::ids::{GroupId, MasterPublicKey, TenantId};
use crate::storage::{PendingMember, PendingMemberStatus, PendingMemberStore, StorageError};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) type PendingMemberMap = HashMap<(TenantId, GroupId), Vec<PendingMemberRecord>>;

#[derive(Clone, Debug)]
pub(crate) struct PendingMemberRecord {
    pub(crate) member: PendingMember,
    pub(crate) status: PendingMemberStatus,
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

    pub(crate) fn approve_member(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        public_key: MasterPublicKey,
    ) {
        let mut members = self.members.lock();
        let Some(list) = members.get_mut(&(tenant, group_id)) else {
            return;
        };
        for record in list.iter_mut() {
            if record.status == PendingMemberStatus::Pending
                && record.member.nazgul_pub == public_key
            {
                record.status = PendingMemberStatus::Approved;
            }
        }
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
        let mut map = self.members.lock();
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
        let map = self.members.lock();
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
