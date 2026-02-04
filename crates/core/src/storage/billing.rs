//! Billing, idempotency, and gift cards.

use crate::ids::{Nanos, OrganizationId, TenantId};
use async_trait::async_trait;

use super::types::{IdempotencyResult, StorageError};

/// Tenant balance information with metadata.
#[derive(Debug, Clone, Copy)]
pub struct TenantBalanceInfo {
    /// Current balance.
    pub balance: Nanos,
    /// Unix timestamp (milliseconds) when balance was last updated.
    pub updated_at_ms: i64,
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

    /// Transfer funds from tenant balance to a group's operational budget.
    ///
    /// This method moves funds from the tenant's account to a specific group's budget,
    /// which is used to pay for group operations (storage, compute, etc.).
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The group identifier
    /// * `amount` - Amount to transfer
    ///
    /// # Returns
    /// The updated group balance after the transfer.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When tenant has insufficient balance
    ///
    /// # Invariants
    /// * Transfers are atomic (tenant debit and group credit happen together)
    /// * Organization balance is always non-negative
    async fn transfer_to_organization(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError>;

    /// Retrieve the current operational budget balance for a group.
    ///
    /// # Arguments
    /// * `org_id` - The group identifier
    ///
    /// # Returns
    /// The group's current balance.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Organization)` - When the group does not exist
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

    /// Deduct funds from a group's operational budget.
    ///
    /// This method is used to charge a group for resource consumption (verification, storage, etc.).
    ///
    /// # Arguments
    /// * `org_id` - The group identifier
    /// * `amount` - Amount to deduct
    ///
    /// # Returns
    /// The updated group balance after deduction.
    ///
    /// # Errors
    /// * `StorageError::NotFound(NotFound::Organization)` - When the group does not exist
    /// * `StorageError::PreconditionFailed` - When group has insufficient balance
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
    /// Returns the TenantId if found, regardless of whether they have any groups.
    /// Use this for gift card redemption where we want to credit an existing tenant.
    async fn find_tenant_by_tg_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<TenantId>, StorageError>;

    /// Resolve a Telegram user ID to their associated tenant and group.
    ///
    /// This method looks up the tenant record by the owner's Telegram user ID, then
    /// finds the associated group. If the user owns multiple groups, the most recently
    /// created group is returned.
    ///
    /// # Arguments
    /// * `tg_user_id` - The Telegram user ID to resolve
    ///
    /// # Returns
    /// `Some((TenantId, OrganizationId))` if found, `None` if no tenant or group exists.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    async fn resolve_telegram_user(
        &self,
        tg_user_id: &str,
    ) -> Result<Option<(TenantId, OrganizationId)>, StorageError>;

    /// Check if an idempotency key has been used and return the cached result.
    ///
    /// This method is called before executing an idempotent operation to check
    /// if the same operation was previously completed. If found, the cached result
    /// is returned instead of re-executing the operation.
    ///
    /// # Arguments
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
        key: &str,
    ) -> Result<Option<IdempotencyResult>, StorageError>;

    /// Record the result of an idempotent operation for future replays.
    ///
    /// This method stores the result of an operation so that retries with the same
    /// idempotency key return the cached result instead of re-executing.
    ///
    /// # Arguments
    /// * `key` - The client-provided idempotency key
    /// * `result` - The result to cache (success with balance or error)
    /// * `ttl_secs` - Time-to-live in seconds (typically 24 hours = 86400)
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    ///
    /// # Notes
    /// * If the key already exists, implementations should NOT overwrite it (first-write wins)
    /// * Expired keys may be automatically cleaned up by the storage layer
    async fn record_idempotency_result(
        &self,
        key: &str,
        result: IdempotencyResult,
        ttl_secs: u64,
    ) -> Result<(), StorageError>;

    /// Withdraw credits from group wallet back to tenant wallet.
    ///
    /// This method moves funds from a group's operational budget back to the tenant's
    /// personal balance. This is the reverse operation of `transfer_to_organization`.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier
    /// * `org_id` - The group identifier (must belong to the tenant)
    /// * `amount` - Amount to withdraw
    ///
    /// # Returns
    /// The updated tenant balance after the withdrawal.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When group has insufficient balance or group does not belong to tenant
    /// * `StorageError::NotFound` - When tenant or group does not exist
    ///
    /// # Invariants
    /// * Withdrawals are atomic (group debit and tenant credit happen together)
    /// * Tenant balance is always non-negative
    async fn withdraw_from_group(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        amount: Nanos,
    ) -> Result<Nanos, StorageError>;

    /// Transfer credits between two group wallets (must be same tenant).
    ///
    /// This method moves funds from one group's operational budget to another group's
    /// budget. Both groups must belong to the same tenant.
    ///
    /// # Arguments
    /// * `tenant` - The tenant identifier (both groups must belong to this tenant)
    /// * `source_group` - The source group identifier (funds withdrawn from here)
    /// * `dest_group` - The destination group identifier (funds deposited here)
    /// * `amount` - Amount to transfer
    ///
    /// # Returns
    /// A tuple of (source_balance, dest_balance) representing the updated balances
    /// after the transfer.
    ///
    /// # Errors
    /// * `StorageError::Backend` - When the underlying storage layer fails
    /// * `StorageError::PreconditionFailed` - When source group has insufficient balance or groups belong to different tenants
    /// * `StorageError::NotFound` - When either group does not exist
    ///
    /// # Invariants
    /// * Transfers are atomic (source debit and destination credit happen together)
    /// * Both group balances are always non-negative
    /// * Both groups must belong to the same tenant
    async fn transfer_between_groups(
        &self,
        tenant: TenantId,
        source_group: OrganizationId,
        dest_group: OrganizationId,
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
