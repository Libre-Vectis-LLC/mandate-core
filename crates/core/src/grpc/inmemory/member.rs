/// In-memory pending member storage.
use crate::event::MemberIdentity;
use crate::ids::{GroupId, MasterPublicKey, TenantId};
use crate::storage::{
    GroupMembershipInfo, MemberInfo, NotFound, PendingMember, PendingMemberStatus,
    PendingMemberStore, StorageError,
};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) type PendingMemberMap = HashMap<(TenantId, GroupId), Vec<PendingMemberRecord>>;

/// In-memory invite code record for testing.
#[derive(Clone, Debug)]
pub(crate) struct InMemoryInviteCode {
    pub(crate) tenant_id: TenantId,
    pub(crate) group_id: GroupId,
    pub(crate) max_uses: u32,
    pub(crate) current_uses: u32,
    pub(crate) is_active: bool,
    pub(crate) expires_at_ms: Option<i64>,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingMemberRecord {
    pub(crate) member: PendingMember,
    pub(crate) status: PendingMemberStatus,
}

#[derive(Clone, Default)]
pub struct InMemoryPendingMembers {
    // Keyed by (TenantId, GroupId)
    members: Arc<Mutex<PendingMemberMap>>,
    // Keyed by invite code string (for register_standalone testing)
    invite_codes: Arc<Mutex<HashMap<String, InMemoryInviteCode>>>,
}

impl InMemoryPendingMembers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an invite code for testing purposes.
    ///
    /// This allows testing the register_standalone flow without a real database.
    pub fn add_invite_code(
        &self,
        code: impl Into<String>,
        tenant_id: TenantId,
        group_id: GroupId,
        max_uses: u32,
    ) {
        let mut codes = self.invite_codes.lock();
        codes.insert(
            code.into(),
            InMemoryInviteCode {
                tenant_id,
                group_id,
                max_uses,
                current_uses: 0,
                is_active: true,
                expires_at_ms: None,
            },
        );
    }

    /// Add an invite code with expiration for testing.
    pub fn add_invite_code_with_expiry(
        &self,
        code: impl Into<String>,
        tenant_id: TenantId,
        group_id: GroupId,
        max_uses: u32,
        expires_at_ms: i64,
    ) {
        let mut codes = self.invite_codes.lock();
        codes.insert(
            code.into(),
            InMemoryInviteCode {
                tenant_id,
                group_id,
                max_uses,
                current_uses: 0,
                is_active: true,
                expires_at_ms: Some(expires_at_ms),
            },
        );
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

    async fn get_approved_by_tg_user_id(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        tg_user_id: &str,
    ) -> Result<Option<PendingMember>, StorageError> {
        let map = self.members.lock();
        if let Some(list) = map.get(&(tenant, group_id)) {
            // Find the most recently submitted approved member with matching tg_user_id
            let result = list
                .iter()
                .filter(|record| {
                    record.status == PendingMemberStatus::Approved
                        && record.member.tg_user_id == tg_user_id
                })
                .max_by_key(|record| record.member.submitted_at_ms)
                .map(|record| record.member.clone());
            Ok(result)
        } else {
            Ok(None)
        }
    }

    async fn register_standalone(
        &self,
        tenant: TenantId,
        invite_code: &str,
        nazgul_pub: MasterPublicKey,
        rage_pub: [u8; 32],
        _display_name: Option<String>,
        _organization_id: Option<String>,
    ) -> Result<(String, GroupId), StorageError> {
        // Validate and consume invite code atomically
        let (group_id, code_tenant) = {
            let mut codes = self.invite_codes.lock();
            let code = codes.get_mut(invite_code).ok_or_else(|| {
                StorageError::NotFound(NotFound::InviteCode {
                    code: invite_code.to_string(),
                })
            })?;

            // Check tenant matches
            if code.tenant_id != tenant {
                return Err(StorageError::NotFound(NotFound::InviteCode {
                    code: invite_code.to_string(),
                }));
            }

            // Check if active
            if !code.is_active {
                return Err(StorageError::PreconditionFailed(
                    "invite code is revoked".into(),
                ));
            }

            // Check expiration
            if let Some(expires_at) = code.expires_at_ms {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                if now_ms > expires_at {
                    return Err(StorageError::PreconditionFailed(
                        "invite code has expired".into(),
                    ));
                }
            }

            // Check usage limit
            if code.current_uses >= code.max_uses {
                return Err(StorageError::PreconditionFailed(
                    "invite code has reached maximum uses".into(),
                ));
            }

            // Increment usage
            code.current_uses += 1;

            (code.group_id, code.tenant_id)
        };

        // Verify tenant consistency
        if code_tenant != tenant {
            return Err(StorageError::NotFound(NotFound::InviteCode {
                code: invite_code.to_string(),
            }));
        }

        // Create pending member record
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let pending_id = format!("PENDING-{}", ulid::Ulid::new());
        let member = PendingMember {
            pending_id: pending_id.clone(),
            tg_user_id: String::new(), // Standalone users don't have Telegram ID
            nazgul_pub,
            rage_pub,
            submitted_at_ms: now_ms,
        };

        let record = PendingMemberRecord {
            member,
            status: PendingMemberStatus::Pending,
        };

        let mut map = self.members.lock();
        let list = map.entry((tenant, group_id)).or_default();
        list.push(record);

        Ok((pending_id, group_id))
    }

    async fn list_all_members(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        limit: usize,
        _page_token: Option<String>,
        filter_source: Option<&str>,
        filter_status: Option<&str>,
    ) -> Result<(Vec<MemberInfo>, Option<String>, u32), StorageError> {
        let map = self.members.lock();
        if let Some(list) = map.get(&(tenant, group_id)) {
            // Apply filters
            let status_filter = filter_status.unwrap_or("approved");
            let filtered: Vec<_> = list
                .iter()
                .filter(|record| {
                    // Status filter
                    let status_match = record.status.as_str() == status_filter;

                    // Source filter (inmemory doesn't store source, so we simulate based on tg_user_id)
                    let source_match = if let Some(source) = filter_source {
                        match source {
                            "telegram" => !record.member.tg_user_id.is_empty(),
                            "standalone" => record.member.tg_user_id.is_empty(),
                            _ => true,
                        }
                    } else {
                        true
                    };

                    status_match && source_match
                })
                .take(limit)
                .collect();

            let total_count = filtered.len() as u32;

            let members: Vec<MemberInfo> = filtered
                .into_iter()
                .map(|record| {
                    // Construct identity based on whether tg_user_id is present
                    let identity = if !record.member.tg_user_id.is_empty() {
                        MemberIdentity::telegram(record.member.tg_user_id.clone(), None)
                    } else {
                        MemberIdentity::standalone(record.member.pending_id.clone(), None, None)
                    };

                    MemberInfo {
                        nazgul_pub: record.member.nazgul_pub,
                        identity,
                        status: record.status.as_str().to_string(),
                        joined_at_ms: record.member.submitted_at_ms,
                    }
                })
                .collect();

            Ok((members, None, total_count))
        } else {
            Ok((Vec::new(), None, 0))
        }
    }

    async fn list_groups_for_member(
        &self,
        tenant: TenantId,
        nazgul_pub: &[u8],
        limit: usize,
        _page_token: Option<String>,
        filter_status: Option<&str>,
    ) -> Result<(Vec<GroupMembershipInfo>, Option<String>, u32), StorageError> {
        let members = self.members.lock();

        let status_filter = filter_status.unwrap_or("approved");

        let mut results = Vec::new();

        // Iterate all (tenant, group_id) pairs
        for ((t, g), records) in members.iter() {
            // Skip if tenant doesn't match
            if *t != tenant {
                continue;
            }

            // Check if this group contains a member with matching nazgul_pub and status
            for record in records {
                if record.member.nazgul_pub.0.as_slice() == nazgul_pub
                    && record.status.as_str() == status_filter
                {
                    results.push(GroupMembershipInfo {
                        group_id: *g,
                        joined_at_ms: record.member.submitted_at_ms,
                        status: record.status.as_str().to_string(),
                    });
                    break; // One match per group is enough
                }
            }
        }

        // Sort by joined_at_ms (oldest first) for deterministic ordering
        results.sort_by_key(|r| r.joined_at_ms);

        let total = results.len() as u32;
        results.truncate(limit);
        Ok((results, None, total))
    }
}
