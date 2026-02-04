use std::sync::Arc;

use super::StorageFacade;
use crate::ids::{Nanos, OrganizationId, TenantId};
use crate::storage::{BillingStore, GiftCard, IdempotencyResult, StorageError, TenantBalanceInfo};

impl StorageFacade {
    // ─────────────────────────────────────────────────────────────────────────
    // Gift card methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Issue a new gift card.
    pub async fn issue_gift_card(&self, amount: Nanos) -> Result<GiftCard, StorageError> {
        self.gift_cards.issue(amount).await
    }

    /// Redeem a gift card for a tenant.
    pub async fn redeem_gift_card(
        &self,
        code: &str,
        tenant: TenantId,
    ) -> Result<GiftCard, StorageError> {
        self.gift_cards.redeem(code, tenant).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Billing methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Credit a tenant's balance.
    pub async fn credit_tenant(
        &self,
        tenant: TenantId,
        owner_tg_user_id: &str,
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        self.billing
            .credit_tenant(tenant, owner_tg_user_id, amount)
            .await
    }

    /// Transfer funds from tenant balance to a group's budget.
    pub async fn transfer_to_organization(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        self.billing
            .transfer_to_organization(tenant, org_id, amount)
            .await
    }

    /// Get a group's current budget balance.
    pub async fn get_organization_balance(
        &self,
        org_id: OrganizationId,
    ) -> Result<Nanos, StorageError> {
        self.billing.get_organization_balance(org_id).await
    }

    /// Retrieve the current balance for a tenant with metadata.
    pub async fn get_tenant_balance(
        &self,
        tenant: TenantId,
    ) -> Result<TenantBalanceInfo, StorageError> {
        self.billing.get_tenant_balance(tenant).await
    }

    /// Find a tenant by their Telegram user ID.
    ///
    /// Returns the TenantId if found, regardless of whether they have any groups.
    pub async fn find_tenant_by_tg_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<TenantId>, StorageError> {
        self.billing.find_tenant_by_tg_user(tg_user_id).await
    }

    /// Resolve a Telegram user ID to their associated tenant and group.
    ///
    /// Returns `None` if no tenant or group is found for this user.
    pub async fn resolve_telegram_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<(TenantId, OrganizationId)>, StorageError> {
        self.billing.resolve_telegram_user(tg_user_id).await
    }

    /// Check if an idempotency key has been used.
    ///
    /// Returns `Some(result)` if the key was previously used, allowing the
    /// caller to replay the original response. Returns `None` if the key
    /// is new and the operation should proceed.
    pub async fn check_idempotency_key(
        &self,
        key: &str,
    ) -> Result<Option<IdempotencyResult>, StorageError> {
        self.billing.check_idempotency_key(key).await
    }

    /// Record the result of an idempotent operation.
    ///
    /// Stores the result with the given TTL so future requests with the same
    /// key can replay this response.
    pub async fn record_idempotency_result(
        &self,
        key: &str,
        result: IdempotencyResult,
        ttl_secs: u64,
    ) -> Result<(), StorageError> {
        self.billing
            .record_idempotency_result(key, result, ttl_secs)
            .await
    }

    /// Withdraw credits from group wallet back to tenant wallet.
    ///
    /// This is the reverse operation of `transfer_to_organization`, moving funds from
    /// a group's operational budget back to the tenant's personal balance.
    pub async fn withdraw_from_group(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError> {
        self.billing
            .withdraw_from_group(tenant, org_id, amount)
            .await
    }

    /// Transfer credits between two group wallets.
    ///
    /// Both groups must belong to the same tenant. Returns a tuple of
    /// (source_balance, dest_balance) after the transfer.
    pub async fn transfer_between_groups(
        &self,
        tenant: TenantId,
        source_group: OrganizationId,
        dest_group: OrganizationId,
        amount: Nanos,
    ) -> Result<(Nanos, Nanos), StorageError> {
        self.billing
            .transfer_between_groups(tenant, source_group, dest_group, amount)
            .await
    }

    /// Get a reference to the underlying billing store.
    ///
    /// This is primarily used for constructing metering interceptors in
    /// enterprise deployments where egress billing is required.
    pub fn billing_store(&self) -> Arc<dyn BillingStore + Send + Sync> {
        self.billing.clone()
    }
}
