/// In-memory billing store and gift card management.
use crate::ids::{Nanos, OrganizationId, TenantId};
use crate::storage::{
    BillingStore, GiftCard, GiftCardStore, IdempotencyResult, NotFound, StorageError,
};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::organization::OrgMap;

/// Tenant balance record with timestamp.
#[derive(Debug, Clone, Copy)]
struct TenantBalance {
    balance: i64,
    updated_at_ms: i64,
}

type TenantBalanceMap = HashMap<TenantId, TenantBalance>;

/// Get current Unix timestamp in milliseconds.
fn current_timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_millis() as i64
}

/// Cached idempotency result with expiration.
struct IdempotencyEntry {
    result: IdempotencyResult,
    expires_at: Instant,
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
    async fn issue(&self, amount: Nanos) -> Result<GiftCard, StorageError> {
        let mut map = self.cards.lock();
        let code = format!("GIFT-{}", ulid::Ulid::new());
        let card = GiftCard {
            code: code.clone(),
            amount,
            used_by: None,
        };
        map.insert(code, card.clone());
        Ok(card)
    }

    async fn redeem(&self, code: &str, tenant: TenantId) -> Result<GiftCard, StorageError> {
        let mut map = self.cards.lock();
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

#[derive(Clone)]
pub struct InMemoryBilling {
    tenants: Arc<Mutex<TenantBalanceMap>>,
    orgs: Arc<Mutex<OrgMap>>,
    tg_user_to_tenant: Arc<Mutex<HashMap<String, TenantId>>>,
    idempotency_keys: Arc<Mutex<HashMap<String, IdempotencyEntry>>>,
}

impl InMemoryBilling {
    /// Creates a new in-memory billing store.
    ///
    /// This is intended for testing purposes where billing needs to interact
    /// with an in-memory org store.
    pub fn new(orgs: Arc<Mutex<OrgMap>>) -> Self {
        Self {
            tenants: Arc::new(Mutex::new(HashMap::new())),
            orgs,
            tg_user_to_tenant: Arc::new(Mutex::new(HashMap::new())),
            idempotency_keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl BillingStore for InMemoryBilling {
    async fn credit_tenant(
        &self,
        tenant: TenantId,
        owner_tg_user_id: &str,
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        let delta = i64::try_from(amount.as_u64())
            .map_err(|_| StorageError::PreconditionFailed("amount too large".into()))?;

        // Record tg_user_id -> tenant mapping
        let mut tg_map = self.tg_user_to_tenant.lock();
        tg_map.insert(owner_tg_user_id.to_string(), tenant);
        drop(tg_map); // Release lock before acquiring tenants lock

        let mut map = self.tenants.lock();
        let record = map.entry(tenant).or_insert(TenantBalance {
            balance: 0,
            updated_at_ms: current_timestamp_ms(),
        });
        record.balance = record
            .balance
            .checked_add(delta)
            .ok_or_else(|| StorageError::PreconditionFailed("balance overflow".into()))?;
        record.updated_at_ms = current_timestamp_ms();
        let balance_u64 = u64::try_from(record.balance)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        Ok(Nanos::new(balance_u64))
    }

    async fn transfer_to_organization(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        let delta = i64::try_from(amount.as_u64())
            .map_err(|_| StorageError::PreconditionFailed("amount too large".into()))?;
        let mut tenants = self.tenants.lock();
        let tenant_record = tenants.entry(tenant).or_insert(TenantBalance {
            balance: 0,
            updated_at_ms: current_timestamp_ms(),
        });
        if tenant_record.balance < delta {
            return Err(StorageError::PreconditionFailed(
                "insufficient balance".into(),
            ));
        }

        let mut orgs = self.orgs.lock();
        let record = orgs
            .get_mut(&org_id)
            .ok_or(StorageError::NotFound(NotFound::Organization { org_id }))?;
        if record.tenant != tenant {
            return Err(StorageError::PreconditionFailed(
                "org does not belong to tenant".into(),
            ));
        }

        tenant_record.balance -= delta;
        tenant_record.updated_at_ms = current_timestamp_ms();
        record.balance_nanos = record
            .balance_nanos
            .checked_add(delta)
            .ok_or_else(|| StorageError::PreconditionFailed("balance overflow".into()))?;

        let balance_u64 = u64::try_from(record.balance_nanos)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        Ok(Nanos::new(balance_u64))
    }

    async fn get_organization_balance(
        &self,
        org_id: OrganizationId,
    ) -> Result<Nanos, StorageError> {
        let orgs = self.orgs.lock();
        let record = orgs
            .get(&org_id)
            .ok_or(StorageError::NotFound(NotFound::Organization { org_id }))?;
        let balance_u64 = u64::try_from(record.balance_nanos)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        Ok(Nanos::new(balance_u64))
    }

    async fn get_tenant_balance(
        &self,
        tenant: TenantId,
    ) -> Result<crate::storage::TenantBalanceInfo, StorageError> {
        let tenants = self.tenants.lock();
        let record = tenants
            .get(&tenant)
            .ok_or(StorageError::NotFound(NotFound::Tenant { tenant }))?;
        let balance_u64 = u64::try_from(record.balance)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        Ok(crate::storage::TenantBalanceInfo {
            balance: Nanos::new(balance_u64),
            updated_at_ms: record.updated_at_ms,
        })
    }

    async fn deduct_organization_balance(
        &self,
        org_id: OrganizationId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        let delta = i64::try_from(amount.as_u64())
            .map_err(|_| StorageError::PreconditionFailed("amount too large".into()))?;

        let mut orgs = self.orgs.lock();
        let record = orgs
            .get_mut(&org_id)
            .ok_or(StorageError::NotFound(NotFound::Organization { org_id }))?;

        if record.balance_nanos < delta {
            return Err(StorageError::PreconditionFailed(
                "insufficient balance".into(),
            ));
        }

        record.balance_nanos -= delta;

        let balance_u64 = u64::try_from(record.balance_nanos)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        Ok(Nanos::new(balance_u64))
    }

    async fn find_tenant_by_tg_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<TenantId>, StorageError> {
        let tg_map = self.tg_user_to_tenant.lock();
        Ok(tg_map.get(tg_user_id).copied())
    }

    async fn resolve_telegram_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<(TenantId, OrganizationId)>, StorageError> {
        let tg_map = self.tg_user_to_tenant.lock();
        let tenant_id = match tg_map.get(tg_user_id) {
            Some(&id) => id,
            None => return Ok(None),
        };
        drop(tg_map);

        // 2. Find the first org owned by this tenant
        // (In production, we might want to return the most recently created one)
        let orgs = self.orgs.lock();
        let org_id = orgs.iter().find_map(|(gid, record)| {
            if record.tenant == tenant_id {
                Some(*gid)
            } else {
                None
            }
        });

        match org_id {
            Some(gid) => Ok(Some((tenant_id, gid))),
            None => Ok(None),
        }
    }

    async fn check_idempotency_key(
        &self,
        key: &str,
    ) -> Result<Option<IdempotencyResult>, StorageError> {
        let keys = self.idempotency_keys.lock();
        match keys.get(key) {
            Some(entry) if entry.expires_at > Instant::now() => Ok(Some(entry.result.clone())),
            _ => Ok(None),
        }
    }

    async fn record_idempotency_result(
        &self,
        key: &str,
        result: IdempotencyResult,
        ttl_secs: u64,
    ) -> Result<(), StorageError> {
        let mut keys = self.idempotency_keys.lock();
        let entry = IdempotencyEntry {
            result,
            expires_at: Instant::now() + Duration::from_secs(ttl_secs),
        };
        keys.insert(key.to_string(), entry);
        Ok(())
    }

    async fn withdraw_from_org(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        let delta = i64::try_from(amount.as_u64())
            .map_err(|_| StorageError::PreconditionFailed("amount too large".into()))?;

        let mut orgs = self.orgs.lock();
        let org_record = orgs
            .get_mut(&org_id)
            .ok_or(StorageError::NotFound(NotFound::Organization { org_id }))?;

        // Verify org belongs to tenant
        if org_record.tenant != tenant {
            return Err(StorageError::PreconditionFailed(
                "org does not belong to tenant".into(),
            ));
        }

        // Check org has sufficient balance
        if org_record.balance_nanos < delta {
            return Err(StorageError::PreconditionFailed(
                "insufficient org balance".into(),
            ));
        }

        // Deduct from org
        org_record.balance_nanos -= delta;

        // Release orgs lock before acquiring tenants lock
        drop(orgs);

        // Credit to tenant
        let mut tenants = self.tenants.lock();
        let tenant_record = tenants.entry(tenant).or_insert(TenantBalance {
            balance: 0,
            updated_at_ms: current_timestamp_ms(),
        });
        tenant_record.balance = tenant_record
            .balance
            .checked_add(delta)
            .ok_or_else(|| StorageError::PreconditionFailed("tenant balance overflow".into()))?;
        tenant_record.updated_at_ms = current_timestamp_ms();

        let balance_u64 = u64::try_from(tenant_record.balance)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        Ok(Nanos::new(balance_u64))
    }

    async fn transfer_between_orgs(
        &self,
        tenant: TenantId,
        source_org: OrganizationId,
        dest_org: OrganizationId,
        amount: Nanos,
    ) -> Result<(Nanos, Nanos), StorageError> {
        let delta = i64::try_from(amount.as_u64())
            .map_err(|_| StorageError::PreconditionFailed("amount too large".into()))?;

        let mut orgs = self.orgs.lock();

        // Get source org
        let source_record =
            orgs.get(&source_org)
                .ok_or(StorageError::NotFound(NotFound::Organization {
                    org_id: source_org,
                }))?;

        // Verify source org belongs to tenant
        if source_record.tenant != tenant {
            return Err(StorageError::PreconditionFailed(
                "source org does not belong to tenant".into(),
            ));
        }

        // Get destination org
        let dest_record =
            orgs.get(&dest_org)
                .ok_or(StorageError::NotFound(NotFound::Organization {
                    org_id: dest_org,
                }))?;

        // Verify destination org belongs to tenant
        if dest_record.tenant != tenant {
            return Err(StorageError::PreconditionFailed(
                "destination org does not belong to tenant".into(),
            ));
        }

        // Check source org has sufficient balance
        let source_balance = source_record.balance_nanos;
        if source_balance < delta {
            return Err(StorageError::PreconditionFailed(
                "insufficient source org balance".into(),
            ));
        }

        // Perform atomic transfer
        // SAFETY: We checked above that both orgs exist and belong to the same tenant
        let source_record = orgs.get_mut(&source_org).unwrap();
        source_record.balance_nanos -= delta;
        let new_source_balance = source_record.balance_nanos;

        let dest_record = orgs.get_mut(&dest_org).unwrap();
        dest_record.balance_nanos =
            dest_record
                .balance_nanos
                .checked_add(delta)
                .ok_or_else(|| {
                    StorageError::PreconditionFailed("destination balance overflow".into())
                })?;
        let new_dest_balance = dest_record.balance_nanos;

        let source_u64 = u64::try_from(new_source_balance)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        let dest_u64 = u64::try_from(new_dest_balance)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;

        Ok((Nanos::new(source_u64), Nanos::new(dest_u64)))
    }
}
