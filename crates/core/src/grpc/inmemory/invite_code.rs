/// In-memory invite code storage backed by DashMap and atomic usage counters.
use crate::ids::{OrganizationId, TenantId};
use crate::storage::invite_code::{CreateInviteCodeParams, InviteCodeEntry, InviteCodeStore};
use crate::storage::{NotFound, StorageError};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Internal entry stored in the DashMap.
///
/// `current_uses` is an `AtomicU32` to support lock-free CAS in
/// `validate_and_increment_usage`.
struct InMemoryInviteCodeEntry {
    code: String,
    tenant_id: TenantId,
    org_id: OrganizationId,
    created_by: String,
    created_at_ms: i64,
    expires_at_ms: Option<i64>,
    max_uses: u32,
    current_uses: AtomicU32,
    metadata: Option<String>,
    is_active: bool,
}

impl InMemoryInviteCodeEntry {
    fn to_entry(&self) -> InviteCodeEntry {
        InviteCodeEntry {
            code: self.code.clone(),
            tenant_id: self.tenant_id,
            org_id: self.org_id,
            created_by: self.created_by.clone(),
            created_at_ms: self.created_at_ms,
            expires_at_ms: self.expires_at_ms,
            max_uses: self.max_uses,
            current_uses: self.current_uses.load(Ordering::Acquire),
            metadata: self.metadata.clone(),
            is_active: self.is_active,
        }
    }
}

/// In-memory invite code store using `DashMap` for concurrent access.
#[derive(Default)]
pub struct InMemoryInviteCodeStore {
    /// Map from invite code string to entry.
    codes: DashMap<String, Arc<InMemoryInviteCodeEntry>>,
}

impl InMemoryInviteCodeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Generate a 20-character URL-safe random code using Base58-style alphabet
/// (excludes ambiguous characters: 0, O, I, l).
fn generate_code() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    (0..20)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[async_trait]
impl InviteCodeStore for InMemoryInviteCodeStore {
    async fn create_invite_code(
        &self,
        tenant: TenantId,
        params: CreateInviteCodeParams,
    ) -> Result<String, StorageError> {
        let code = generate_code();
        let entry = Arc::new(InMemoryInviteCodeEntry {
            code: code.clone(),
            tenant_id: tenant,
            org_id: params.org_id,
            created_by: params.created_by,
            created_at_ms: now_ms(),
            expires_at_ms: params.expires_at_ms,
            max_uses: params.max_uses,
            current_uses: AtomicU32::new(0),
            metadata: params.metadata,
            is_active: true,
        });
        self.codes.insert(code.clone(), entry);
        Ok(code)
    }

    async fn get_invite_code(
        &self,
        tenant: TenantId,
        code: &str,
    ) -> Result<InviteCodeEntry, StorageError> {
        let entry = self.codes.get(code).ok_or_else(|| {
            StorageError::NotFound(NotFound::InviteCode {
                code: code.to_string(),
            })
        })?;

        if entry.tenant_id != tenant {
            return Err(StorageError::NotFound(NotFound::InviteCode {
                code: code.to_string(),
            }));
        }

        Ok(entry.to_entry())
    }

    async fn list_invite_codes(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        limit: usize,
        _page_token: Option<String>,
    ) -> Result<(Vec<InviteCodeEntry>, Option<String>), StorageError> {
        let mut entries: Vec<InviteCodeEntry> = self
            .codes
            .iter()
            .filter(|r| r.value().tenant_id == tenant && r.value().org_id == org_id)
            .map(|r| r.value().to_entry())
            .collect();

        // Reverse chronological order (newest first)
        entries.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
        entries.truncate(limit);
        Ok((entries, None))
    }

    async fn validate_and_increment_usage(
        &self,
        tenant: TenantId,
        code: &str,
    ) -> Result<InviteCodeEntry, StorageError> {
        let entry = self.codes.get(code).ok_or_else(|| {
            StorageError::NotFound(NotFound::InviteCode {
                code: code.to_string(),
            })
        })?;

        // Tenant isolation
        if entry.tenant_id != tenant {
            return Err(StorageError::NotFound(NotFound::InviteCode {
                code: code.to_string(),
            }));
        }

        // Check active
        if !entry.is_active {
            return Err(StorageError::PreconditionFailed(
                "invite code is revoked".into(),
            ));
        }

        // Check expiry
        if let Some(expires_at) = entry.expires_at_ms {
            if now_ms() > expires_at {
                return Err(StorageError::PreconditionFailed(
                    "invite code has expired".into(),
                ));
            }
        }

        // CAS loop: atomically increment current_uses if < max_uses
        loop {
            let current = entry.current_uses.load(Ordering::Acquire);
            if current >= entry.max_uses {
                return Err(StorageError::PreconditionFailed(
                    "invite code has reached maximum uses".into(),
                ));
            }
            match entry.current_uses.compare_exchange(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(_) => continue, // Retry on CAS failure
            }
        }

        Ok(entry.to_entry())
    }

    async fn revoke_invite_code(&self, tenant: TenantId, code: &str) -> Result<(), StorageError> {
        // We need mutable access to set is_active = false.
        // DashMap does not allow mutation through get(), so we remove-and-reinsert
        // with a new Arc that has is_active=false.
        let (key, old_entry) = self.codes.remove(code).ok_or_else(|| {
            StorageError::NotFound(NotFound::InviteCode {
                code: code.to_string(),
            })
        })?;

        if old_entry.tenant_id != tenant {
            // Put it back — wrong tenant
            self.codes.insert(key, old_entry);
            return Err(StorageError::NotFound(NotFound::InviteCode {
                code: code.to_string(),
            }));
        }

        // Create a new entry with is_active = false (idempotent)
        let revoked = Arc::new(InMemoryInviteCodeEntry {
            code: old_entry.code.clone(),
            tenant_id: old_entry.tenant_id,
            org_id: old_entry.org_id,
            created_by: old_entry.created_by.clone(),
            created_at_ms: old_entry.created_at_ms,
            expires_at_ms: old_entry.expires_at_ms,
            max_uses: old_entry.max_uses,
            current_uses: AtomicU32::new(old_entry.current_uses.load(Ordering::Acquire)),
            metadata: old_entry.metadata.clone(),
            is_active: false,
        });
        self.codes.insert(key, revoked);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{OrganizationId, TenantId};

    fn test_tenant() -> TenantId {
        TenantId(ulid::Ulid::new())
    }

    fn test_org() -> OrganizationId {
        OrganizationId(ulid::Ulid::new())
    }

    fn test_params(org_id: OrganizationId) -> CreateInviteCodeParams {
        CreateInviteCodeParams {
            org_id,
            created_by: "admin-1".to_string(),
            expires_at_ms: None,
            max_uses: 5,
            metadata: None,
        }
    }

    #[tokio::test]
    async fn test_create_and_get_invite_code() {
        let store = InMemoryInviteCodeStore::new();
        let tenant = test_tenant();
        let org = test_org();

        let code = store
            .create_invite_code(tenant, test_params(org))
            .await
            .expect("create should succeed");

        assert_eq!(code.len(), 20);

        let entry = store
            .get_invite_code(tenant, &code)
            .await
            .expect("get should succeed");

        assert_eq!(entry.code, code);
        assert_eq!(entry.org_id, org);
        assert_eq!(entry.max_uses, 5);
        assert_eq!(entry.current_uses, 0);
        assert!(entry.is_active);
    }

    #[tokio::test]
    async fn test_get_nonexistent_code_returns_not_found() {
        let store = InMemoryInviteCodeStore::new();
        let tenant = test_tenant();

        let err = store
            .get_invite_code(tenant, "nonexistent")
            .await
            .expect_err("should fail");

        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_validate_and_increment_usage() {
        let store = InMemoryInviteCodeStore::new();
        let tenant = test_tenant();
        let org = test_org();

        let code = store
            .create_invite_code(
                tenant,
                CreateInviteCodeParams {
                    org_id: org,
                    created_by: "admin".to_string(),
                    expires_at_ms: None,
                    max_uses: 2,
                    metadata: None,
                },
            )
            .await
            .expect("create");

        // First use
        let entry = store
            .validate_and_increment_usage(tenant, &code)
            .await
            .expect("first use");
        assert_eq!(entry.current_uses, 1);

        // Second use
        let entry = store
            .validate_and_increment_usage(tenant, &code)
            .await
            .expect("second use");
        assert_eq!(entry.current_uses, 2);

        // Third use should fail (exhausted)
        let err = store
            .validate_and_increment_usage(tenant, &code)
            .await
            .expect_err("exhausted");
        assert!(matches!(err, StorageError::PreconditionFailed(_)));
    }

    #[tokio::test]
    async fn test_expired_code_rejected() {
        let store = InMemoryInviteCodeStore::new();
        let tenant = test_tenant();
        let org = test_org();

        let code = store
            .create_invite_code(
                tenant,
                CreateInviteCodeParams {
                    org_id: org,
                    created_by: "admin".to_string(),
                    expires_at_ms: Some(1), // Expired in the past (1ms since epoch)
                    max_uses: 10,
                    metadata: None,
                },
            )
            .await
            .expect("create");

        let err = store
            .validate_and_increment_usage(tenant, &code)
            .await
            .expect_err("expired");
        assert!(matches!(err, StorageError::PreconditionFailed(_)));
    }

    #[tokio::test]
    async fn test_revoke_invite_code() {
        let store = InMemoryInviteCodeStore::new();
        let tenant = test_tenant();
        let org = test_org();

        let code = store
            .create_invite_code(tenant, test_params(org))
            .await
            .expect("create");

        store
            .revoke_invite_code(tenant, &code)
            .await
            .expect("revoke");

        let err = store
            .validate_and_increment_usage(tenant, &code)
            .await
            .expect_err("revoked code");
        assert!(matches!(err, StorageError::PreconditionFailed(_)));

        // Idempotent: revoking again should succeed
        store
            .revoke_invite_code(tenant, &code)
            .await
            .expect("revoke again");
    }

    #[tokio::test]
    async fn test_list_invite_codes() {
        let store = InMemoryInviteCodeStore::new();
        let tenant = test_tenant();
        let org = test_org();

        // Create 3 codes
        for _ in 0..3 {
            store
                .create_invite_code(tenant, test_params(org))
                .await
                .expect("create");
        }

        let (codes, _) = store
            .list_invite_codes(tenant, org, 10, None)
            .await
            .expect("list");
        assert_eq!(codes.len(), 3);
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let store = InMemoryInviteCodeStore::new();
        let tenant_a = test_tenant();
        let tenant_b = test_tenant();
        let org = test_org();

        let code = store
            .create_invite_code(tenant_a, test_params(org))
            .await
            .expect("create for tenant A");

        // Tenant B cannot access tenant A's code
        let err = store
            .get_invite_code(tenant_b, &code)
            .await
            .expect_err("tenant isolation");
        assert!(matches!(err, StorageError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_concurrent_cas_race() {
        let store = Arc::new(InMemoryInviteCodeStore::new());
        let tenant = test_tenant();
        let org = test_org();

        let code = store
            .create_invite_code(
                tenant,
                CreateInviteCodeParams {
                    org_id: org,
                    created_by: "admin".to_string(),
                    expires_at_ms: None,
                    max_uses: 5,
                    metadata: None,
                },
            )
            .await
            .expect("create");

        // Spawn 10 tasks all trying to validate the same code (max_uses=5)
        let mut handles = Vec::new();
        for _ in 0..10 {
            let store = Arc::clone(&store);
            let code = code.clone();
            handles.push(tokio::spawn(async move {
                store.validate_and_increment_usage(tenant, &code).await
            }));
        }

        let results: Vec<_> = futures_util::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("join"))
            .collect();

        let successes = results.iter().filter(|r| r.is_ok()).count();
        let failures = results.iter().filter(|r| r.is_err()).count();

        assert_eq!(successes, 5, "exactly max_uses should succeed");
        assert_eq!(failures, 5, "rest should fail");

        // Verify final usage count
        let entry = store
            .get_invite_code(tenant, &code)
            .await
            .expect("get after race");
        assert_eq!(entry.current_uses, 5);
    }
}
