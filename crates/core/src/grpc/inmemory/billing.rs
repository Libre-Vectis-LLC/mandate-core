/// In-memory billing store and gift card management.
use crate::ids::{GroupId, Nanos, TenantId};
use crate::storage::{BillingStore, GiftCard, GiftCardStore, NotFound, StorageError};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

use super::group::GroupMap;

type TenantBalanceMap = HashMap<TenantId, i64>;

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
}

impl InMemoryBilling {
    pub(crate) fn new(groups: Arc<Mutex<GroupMap>>) -> Self {
        Self {
            tenants: Arc::new(Mutex::new(HashMap::new())),
            groups,
            tg_user_to_tenant: Arc::new(Mutex::new(HashMap::new())),
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

    async fn resolve_telegram_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<(TenantId, GroupId)>, StorageError> {
        // 1. Lookup tenant ID from tg_user_id
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
}
