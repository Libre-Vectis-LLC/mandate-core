//! Billing, idempotency, and gift cards.

use crate::ids::{Nanos, OrganizationId, TenantId};
use async_trait::async_trait;

use super::types::{IdempotencyErrorCode, IdempotencyResult, StorageError};

/// Tenant balance information with metadata.
#[derive(Debug, Clone, Copy)]
pub struct TenantBalanceInfo {
    /// Current balance.
    pub balance: Nanos,
    /// Unix timestamp (milliseconds) when balance was last updated.
    pub updated_at_ms: i64,
}

fn storage_error_to_idempotency(err: &StorageError) -> IdempotencyErrorCode {
    match err {
        StorageError::NotFound(_) => IdempotencyErrorCode::NotFound,
        StorageError::AlreadyExists => IdempotencyErrorCode::AlreadyExists,
        StorageError::PreconditionFailed(_) => IdempotencyErrorCode::FailedPrecondition,
        StorageError::Backend(_) => IdempotencyErrorCode::Internal,
    }
}

#[async_trait]
pub trait BillingStore: Send + Sync {
    /// Credit a tenant's balance, creating the tenant record if it does not exist.
    ///
    /// This method is used when a tenant redeems a gift card or receives a service credit.
    /// The tenant is associated with a Telegram user ID for future lookups.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `owner_tg_user_id` - The Telegram user ID of the tenant owner
    /// * `amount` - Amount to credit
    ///
    /// # Returns
    /// The updated tenant balance after crediting.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Balance is always non-negative after credit operations
    /// * Credits are idempotent-safe (may be retried on transient failures)
    async fn credit_tenant(
        &self,
        tenant: TenantId,
        owner_tg_user_id: &str,
        amount: Nanos,
    ) -> Result<Nanos, StorageError>;

    /// Transfer funds from tenant balance to an org's operational budget.
    ///
    /// This method moves funds from the tenant's account to a specific org's budget,
    /// which is used to pay for org operations (storage, compute, etc.).
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier
    /// * `amount` - Amount to transfer
    ///
    /// # Returns
    /// The updated org balance after the transfer.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When tenant has insufficient balance
    ///
    /// # Invariants
    /// * Transfers are atomic (tenant debit and org credit happen together)
    /// * Organization balance is always non-negative
    async fn transfer_to_organization(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError>;

    /// Transfer funds from tenant balance to an org with optional idempotency replay.
    ///
    /// # Implementation Note (M-05)
    ///
    /// The default implementation has a TOCTOU (time-of-check-to-time-of-use) race window
    /// between `check_idempotency_key` and `record_idempotency_result`. Two concurrent
    /// requests with the same idempotency key can both pass the check, both execute the
    /// transfer, and then race to record the result — potentially causing a double-spend.
    ///
    /// Concrete implementations MUST override this method with an atomic
    /// check-and-insert operation (e.g., `INSERT ... ON CONFLICT DO NOTHING` in SQL,
    /// or a single lock scope covering check + execute + record) to prevent duplicate
    /// processing.
    ///
    /// The `InMemoryBilling` implementation correctly holds `idempotency_keys` lock
    /// across check + execute + record, eliminating the race. Database-backed
    /// implementations should use a transaction with serializable isolation or an
    /// atomic upsert.
    async fn transfer_to_organization_idempotent(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        amount: Nanos,
        idempotency_key: Option<&str>,
        ttl_secs: u64,
    ) -> Result<IdempotencyResult, StorageError> {
        let Some(key) = idempotency_key.filter(|k| !k.is_empty()) else {
            let balance = self
                .transfer_to_organization(tenant, org_id, amount)
                .await?;
            return Ok(IdempotencyResult::Success {
                balance_nanos: balance.as_u64(),
            });
        };

        if let Some(existing) = self.check_idempotency_key(tenant, key).await? {
            return Ok(existing);
        }

        let op_result = match self.transfer_to_organization(tenant, org_id, amount).await {
            Ok(balance) => IdempotencyResult::Success {
                balance_nanos: balance.as_u64(),
            },
            Err(err) => IdempotencyResult::Error {
                code: storage_error_to_idempotency(&err),
                message: err.to_string(),
            },
        };

        match self
            .record_idempotency_result(tenant, key, op_result.clone(), ttl_secs)
            .await?
        {
            Some(existing) => Ok(existing),
            None => Ok(op_result),
        }
    }

    /// Retrieve the current operational budget balance for an org.
    ///
    /// # Arguments
    /// * `org_id` - The org IDentifier
    ///
    /// # Returns
    /// The org's current balance.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Organization)` - When the org does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get_organization_balance(&self, org_id: OrganizationId)
        -> Result<Nanos, StorageError>;

    /// Retrieve the current balance for a tenant with metadata.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    ///
    /// # Returns
    /// Tenant balance information including the balance and last update timestamp.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Tenant)` - When the tenant does not exist
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn get_tenant_balance(&self, tenant: TenantId)
        -> Result<TenantBalanceInfo, StorageError>;

    /// Deduct funds from an org's operational budget.
    ///
    /// This method is used to charge an org for resource consumption (verification, storage, etc.).
    ///
    /// # Arguments
    /// * `org_id` - The org IDentifier
    /// * `amount` - Amount to deduct
    ///
    /// # Returns
    /// The updated org balance after deduction.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Organization)` - When the org does not exist
    /// * `StorageError::PreconditionFailed` - When org has insufficient balance
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Deductions are atomic
    /// * Balance cannot go negative (checked via precondition)
    async fn deduct_organization_balance(
        &self,
        org_id: OrganizationId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError>;

    /// Find a tenant by their Telegram user ID.
    ///
    /// Returns the TenantId if found, regardless of whether they have any orgs.
    /// Use this for gift card redemption where we want to credit an existing tenant.
    async fn find_tenant_by_tg_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<TenantId>, StorageError>;

    /// Resolve a Telegram user ID to their associated tenant and org.
    ///
    /// This method looks up the tenant record by the owner's Telegram user ID, then
    /// finds the associated org. If the user owns multiple orgs, the most recently
    /// created org is returned.
    ///
    /// # Arguments
    /// * `tg_user_id` - The Telegram user ID to resolve
    ///
    /// # Returns
    /// `Some((TenantId, OrganizationId))` if found, `None` if no tenant or org exists.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn resolve_telegram_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<(TenantId, OrganizationId)>, StorageError>;

    /// Check if an idempotency key has been used and return the cached result.
    ///
    /// Idempotency keys are scoped per-tenant to prevent cross-tenant collisions
    /// where different tenants using the same key would interfere with each other.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier (scoping key)
    /// * `key` - The client-provided idempotency key (typically UUID or ULID)
    ///
    /// # Returns
    /// * `Some(IdempotencyResult)` - If the key was previously used, returns the cached result
    /// * `None` - If the key has not been used or has expired
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn check_idempotency_key(
        &self,
        tenant: TenantId,
        key: &str,
    ) -> Result<Option<IdempotencyResult>, StorageError>;

    /// Atomically record the result of an idempotent operation for future replays.
    ///
    /// This method uses an atomic upsert pattern to prevent TOCTOU race conditions:
    /// if two concurrent requests attempt to record the same key, only the first
    /// one succeeds. The method returns the winning result (either the one just
    /// recorded, or the previously existing one).
    ///
    /// Idempotency keys are scoped per-tenant to prevent cross-tenant collisions.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier (scoping key)
    /// * `key` - The client-provided idempotency key
    /// * `result` - The result to cache (success with balance or error)
    /// * `ttl_secs` - Time-to-live in seconds (typically 24 hours = 86400)
    ///
    /// # Returns
    /// * `None` - If this was the first write (our result was recorded)
    /// * `Some(IdempotencyResult)` - If a previous result already existed (first-write wins)
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Notes
    /// * Expired keys may be automatically cleaned up by the storage layer
    async fn record_idempotency_result(
        &self,
        tenant: TenantId,
        key: &str,
        result: IdempotencyResult,
        ttl_secs: u64,
    ) -> Result<Option<IdempotencyResult>, StorageError>;

    /// Withdraw credits from org balance back to tenant balance.
    ///
    /// This method moves funds from an org's operational budget back to the tenant's
    /// personal balance. This is the reverse operation of `transfer_to_organization`.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The org IDentifier (must belong to the tenant)
    /// * `amount` - Amount to withdraw
    ///
    /// # Returns
    /// The updated tenant balance after the withdrawal.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When org has insufficient balance or org does not belong to tenant
    /// * `StorageError::NotFound` - When tenant or org does not exist
    ///
    /// # Invariants
    /// * Withdrawals are atomic (org debit and tenant credit happen together)
    /// * Tenant balance is always non-negative
    async fn withdraw_from_org(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError>;

    /// Transfer credits between two org balances (must be same tenant).
    ///
    /// This method moves funds from one org's operational budget to another org's
    /// budget. Both orgs must belong to the same tenant.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier (both orgs must belong to this tenant)
    /// * `source_org` - The source org IDentifier (funds withdrawn from here)
    /// * `dest_org` - The destination org IDentifier (funds deposited here)
    /// * `amount` - Amount to transfer
    ///
    /// # Returns
    /// A tuple of (source_balance, dest_balance) representing the updated balances
    /// after the transfer.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When source org has insufficient balance or orgs belong to different tenants
    /// * `StorageError::NotFound` - When either org does not exist
    ///
    /// # Invariants
    /// * Transfers are atomic (source debit and destination credit happen together)
    /// * Both org balances are always non-negative
    /// * Both orgs must belong to the same tenant
    async fn transfer_between_orgs(
        &self,
        tenant: TenantId,
        source_org: OrganizationId,
        dest_org: OrganizationId,
        amount: Nanos,
    ) -> Result<(Nanos, Nanos), StorageError>;
}

#[derive(Clone, Debug)]
pub struct GiftCard {
    pub code: String,
    pub amount: Nanos,
    pub used_by: Option<TenantId>,
}

#[async_trait]
pub trait GiftCardStore {
    /// Issue a new gift card with a specified amount.
    ///
    /// This method generates a unique redemption code and creates a new gift card record.
    /// The card is initially unassigned (`used_by = None`).
    ///
    /// # Arguments
    /// * `amount` - The gift card value
    ///
    /// # Returns
    /// A `GiftCard` with a unique `code` and the specified `amount`.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * Generated codes are globally unique
    /// * Cards are initially unassigned
    async fn issue(&self, amount: Nanos) -> Result<GiftCard, StorageError>;

    /// Redeem a gift card for a tenant, crediting their balance.
    ///
    /// This method marks the gift card as used by the specified tenant and prevents
    /// future redemptions. The card's amount is not directly credited here; the caller
    /// must invoke `BillingStore::credit_tenant` separately.
    ///
    /// # Arguments
    /// * `code` - The gift card redemption code
    /// * `tenant` - The tenant redeeming the card
    ///
    /// # Returns
    /// The `GiftCard` record with `used_by` set to the tenant.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::GiftCard)` - When the code does not exist
    /// * `StorageError::AlreadyExists` - When the card has already been redeemed
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Invariants
    /// * A card can only be redeemed once
    /// * Redemption is atomic (check-and-set operation)
    async fn redeem(&self, code: &str, tenant: TenantId) -> Result<GiftCard, StorageError>;
}
