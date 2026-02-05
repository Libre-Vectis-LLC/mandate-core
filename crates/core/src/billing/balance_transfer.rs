//! Balance transfer trait for moving funds between tenants and organizations.
//!
//! This module defines the interface for balance transfers. Implementations
//! are provided by mandate-enterprise with PostgreSQL backend.

use crate::billing::{Nanos, TransferError, TransferReceipt};

/// Trait for balance transfer operations.
///
/// Implemented by mandate-enterprise with PostgreSQL backend.
/// All transfers are atomic and generate receipts for audit trails.
///
/// # Safety Constraints
///
/// 1. All transfers must execute in database transactions
/// 2. Transfer amounts must be > 0 and ≤ source balance
/// 3. Groups can only transfer to same tenant.s orgs or back to tenant
/// 4. Complete audit logs must be maintained
///
/// # Examples
///
/// ```no_run
/// use mandate_core::billing::{BalanceTransferService, Nanos};
/// # async fn example(service: &dyn BalanceTransferService) -> Result<(), Box<dyn std::error::Error>> {
/// // Transfer from tenant to organization
/// let receipt = service.transfer_to_organization(
///     "tenant_123",
///     "org_abc",
///     Nanos::from_dollars(100.0),
/// ).await?;
///
/// println!("Transferred ${:.2}", receipt.amount.to_dollars());
/// # Ok(())
/// # }
/// ```
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait BalanceTransferService: Send + Sync {
    /// Transfer funds from tenant to organization.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Source tenant ID
    /// * `org_id` - Destination org ID
    /// * `amount` - Amount to transfer (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Tenant has insufficient balance
    /// - Org is not owned by tenant
    /// - Amount is invalid (zero or negative)
    /// - Database transaction fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use mandate_core::billing::{BalanceTransferService, Nanos};
    /// # async fn example(service: &dyn BalanceTransferService) -> Result<(), Box<dyn std::error::Error>> {
    /// let receipt = service.transfer_to_organization(
    ///     "tenant_123",
    ///     "org_abc",
    ///     Nanos::from_dollars(50.0),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn transfer_to_organization(
        &self,
        tenant_id: &str,
        org_id: &str,
        amount: Nanos,
    ) -> Result<TransferReceipt, TransferError>;

    /// Withdraw funds from organization back to tenant.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Destination tenant ID
    /// * `org_id` - Source org ID
    /// * `amount` - Amount to withdraw (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Org has insufficient balance
    /// - Org is not owned by tenant
    /// - Amount is invalid
    /// - Database transaction fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use mandate_core::billing::{BalanceTransferService, Nanos};
    /// # async fn example(service: &dyn BalanceTransferService) -> Result<(), Box<dyn std::error::Error>> {
    /// let receipt = service.withdraw_from_org(
    ///     "tenant_123",
    ///     "org_abc",
    ///     Nanos::from_dollars(25.0),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn withdraw_from_org(
        &self,
        tenant_id: &str,
        org_id: &str,
        amount: Nanos,
    ) -> Result<TransferReceipt, TransferError>;

    /// Transfer funds between orgs under the same tenant.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Owning tenant ID
    /// * `from_org` - Source org ID
    /// * `to_org` - Destination org ID
    /// * `amount` - Amount to transfer (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Source org has insufficient balance
    /// - Either org is not owned by tenant
    /// - Amount is invalid
    /// - Database transaction fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use mandate_core::billing::{BalanceTransferService, Nanos};
    /// # async fn example(service: &dyn BalanceTransferService) -> Result<(), Box<dyn std::error::Error>> {
    /// let receipt = service.transfer_between_orgs(
    ///     "tenant_123",
    ///     "org_abc",
    ///     "org_xyz",
    ///     Nanos::from_dollars(10.0),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn transfer_between_orgs(
        &self,
        tenant_id: &str,
        from_org: &str,
        to_org: &str,
        amount: Nanos,
    ) -> Result<TransferReceipt, TransferError>;
}
