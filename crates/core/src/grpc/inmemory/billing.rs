/// In-memory billing store and gift card management.
use crate::ids::{GroupId, Nanos, TenantId};
use crate::storage::{
    BillingStore, GiftCard, GiftCardStore, IdempotencyResult, NotFound, StorageError,
};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::group::GroupMap;

type TenantBalanceMap = HashMap<TenantId, i64>;

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
    groups: Arc<Mutex<GroupMap>>,
    tg_user_to_tenant: Arc<Mutex<HashMap<String, TenantId>>>,
    idempotency_keys: Arc<Mutex<HashMap<String, IdempotencyEntry>>>,
}

impl InMemoryBilling {
    pub(crate) fn new(groups: Arc<Mutex<GroupMap>>) -> Self {
        Self {
            tenants: Arc::new(Mutex::new(HashMap::new())),
            groups,
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
        let balance = map.entry(tenant).or_insert(0);
        *balance = balance
            .checked_add(delta)
            .ok_or_else(|| StorageError::PreconditionFailed("balance overflow".into()))?;
        let balance_u64 = u64::try_from(*balance)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        Ok(Nanos::new(balance_u64))
    }

    async fn transfer_to_group(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        let delta = i64::try_from(amount.as_u64())
            .map_err(|_| StorageError::PreconditionFailed("amount too large".into()))?;
        let mut tenants = self.tenants.lock();
        let tenant_balance = tenants.entry(tenant).or_insert(0);
        if *tenant_balance < delta {
            return Err(StorageError::PreconditionFailed(
                "insufficient balance".into(),
            ));
        }

        let mut groups = self.groups.lock();
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

        let balance_u64 = u64::try_from(record.balance_nanos)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        Ok(Nanos::new(balance_u64))
    }

    async fn get_group_balance(&self, group_id: GroupId) -> Result<Nanos, StorageError> {
        let groups = self.groups.lock();
        let record = groups
            .get(&group_id)
            .ok_or(StorageError::NotFound(NotFound::Group { group_id }))?;
        let balance_u64 = u64::try_from(record.balance_nanos)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        Ok(Nanos::new(balance_u64))
    }

    async fn get_tenant_balance(&self, tenant: TenantId) -> Result<Nanos, StorageError> {
        let tenants = self.tenants.lock();
        let balance = *tenants
            .get(&tenant)
            .ok_or(StorageError::NotFound(NotFound::Tenant { tenant }))?;
        let balance_u64 = u64::try_from(balance)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        Ok(Nanos::new(balance_u64))
    }

    async fn deduct_group_balance(
        &self,
        group_id: GroupId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        let delta = i64::try_from(amount.as_u64())
            .map_err(|_| StorageError::PreconditionFailed("amount too large".into()))?;

        let mut groups = self.groups.lock();
        let record = groups
            .get_mut(&group_id)
            .ok_or(StorageError::NotFound(NotFound::Group { group_id }))?;

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
    ) -> Result<Option<(TenantId, GroupId)>, StorageError> {
        let tg_map = self.tg_user_to_tenant.lock();
        let tenant_id = match tg_map.get(tg_user_id) {
            Some(&id) => id,
            None => return Ok(None),
        };
        drop(tg_map);

        // 2. Find the first group owned by this tenant
        // (In production, we might want to return the most recently created one)
        let groups = self.groups.lock();
        let group_id = groups.iter().find_map(|(gid, record)| {
            if record.tenant == tenant_id {
                Some(*gid)
            } else {
                None
            }
        });

        match group_id {
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

    async fn withdraw_from_group(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        let delta = i64::try_from(amount.as_u64())
            .map_err(|_| StorageError::PreconditionFailed("amount too large".into()))?;

        let mut groups = self.groups.lock();
        let group_record = groups
            .get_mut(&group_id)
            .ok_or(StorageError::NotFound(NotFound::Group { group_id }))?;

        // Verify group belongs to tenant
        if group_record.tenant != tenant {
            return Err(StorageError::PreconditionFailed(
                "group does not belong to tenant".into(),
            ));
        }

        // Check group has sufficient balance
        if group_record.balance_nanos < delta {
            return Err(StorageError::PreconditionFailed(
                "insufficient group balance".into(),
            ));
        }

        // Deduct from group
        group_record.balance_nanos -= delta;

        // Release groups lock before acquiring tenants lock
        drop(groups);

        // Credit to tenant
        let mut tenants = self.tenants.lock();
        let tenant_balance = tenants.entry(tenant).or_insert(0);
        *tenant_balance = tenant_balance
            .checked_add(delta)
            .ok_or_else(|| StorageError::PreconditionFailed("tenant balance overflow".into()))?;

        let balance_u64 = u64::try_from(*tenant_balance)
            .map_err(|_| StorageError::Backend("corrupted balance: negative value".into()))?;
        Ok(Nanos::new(balance_u64))
    }

    async fn transfer_between_groups(
        &self,
        tenant: TenantId,
        source_group: GroupId,
        dest_group: GroupId,
        amount: Nanos,
    ) -> Result<(Nanos, Nanos), StorageError> {
        let delta = i64::try_from(amount.as_u64())
            .map_err(|_| StorageError::PreconditionFailed("amount too large".into()))?;

        let mut groups = self.groups.lock();

        // Get source group
        let source_record =
            groups
                .get(&source_group)
                .ok_or(StorageError::NotFound(NotFound::Group {
                    group_id: source_group,
                }))?;

        // Verify source group belongs to tenant
        if source_record.tenant != tenant {
            return Err(StorageError::PreconditionFailed(
                "source group does not belong to tenant".into(),
            ));
        }

        // Get destination group
        let dest_record =
            groups
                .get(&dest_group)
                .ok_or(StorageError::NotFound(NotFound::Group {
                    group_id: dest_group,
                }))?;

        // Verify destination group belongs to tenant
        if dest_record.tenant != tenant {
            return Err(StorageError::PreconditionFailed(
                "destination group does not belong to tenant".into(),
            ));
        }

        // Check source group has sufficient balance
        let source_balance = source_record.balance_nanos;
        if source_balance < delta {
            return Err(StorageError::PreconditionFailed(
                "insufficient source group balance".into(),
            ));
        }

        // Perform atomic transfer
        // SAFETY: We checked above that both groups exist and belong to the same tenant
        let source_record = groups.get_mut(&source_group).unwrap();
        source_record.balance_nanos -= delta;
        let new_source_balance = source_record.balance_nanos;

        let dest_record = groups.get_mut(&dest_group).unwrap();
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
