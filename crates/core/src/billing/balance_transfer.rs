//! Balance transfer trait for moving funds between tenants and groups.
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
/// 3. Groups can only transfer to same tenant's groups or back to tenant
/// 4. Complete audit logs must be maintained
///
/// # Examples
///
/// ```no_run
/// use mandate_core::billing::{BalanceTransferService, Nanos};
/// # async fn example(service: &dyn BalanceTransferService) -> Result<(), Box<dyn std::error::Error>> {
/// // Transfer from tenant to group
/// let receipt = service.transfer_to_group(
///     "tenant_123",
///     "group_abc",
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
    /// Transfer funds from tenant to group.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Source tenant ID
    /// * `group_id` - Destination group ID
    /// * `amount` - Amount to transfer (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Tenant has insufficient balance
    /// - Group is not owned by tenant
    /// - Amount is invalid (zero or negative)
    /// - Database transaction fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use mandate_core::billing::{BalanceTransferService, Nanos};
    /// # async fn example(service: &dyn BalanceTransferService) -> Result<(), Box<dyn std::error::Error>> {
    /// let receipt = service.transfer_to_group(
    ///     "tenant_123",
    ///     "group_abc",
    ///     Nanos::from_dollars(50.0),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn transfer_to_group(
        &self,
        tenant_id: &str,
        group_id: &str,
        amount: Nanos,
    ) -> Result<TransferReceipt, TransferError>;

    /// Withdraw funds from group back to tenant.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Destination tenant ID
    /// * `group_id` - Source group ID
    /// * `amount` - Amount to withdraw (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Group has insufficient balance
    /// - Group is not owned by tenant
    /// - Amount is invalid
    /// - Database transaction fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use mandate_core::billing::{BalanceTransferService, Nanos};
    /// # async fn example(service: &dyn BalanceTransferService) -> Result<(), Box<dyn std::error::Error>> {
    /// let receipt = service.withdraw_from_group(
    ///     "tenant_123",
    ///     "group_abc",
    ///     Nanos::from_dollars(25.0),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn withdraw_from_group(
        &self,
        tenant_id: &str,
        group_id: &str,
        amount: Nanos,
    ) -> Result<TransferReceipt, TransferError>;

    /// Transfer funds between groups under the same tenant.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - Owning tenant ID
    /// * `from_group` - Source group ID
    /// * `to_group` - Destination group ID
    /// * `amount` - Amount to transfer (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Source group has insufficient balance
    /// - Either group is not owned by tenant
    /// - Amount is invalid
    /// - Database transaction fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use mandate_core::billing::{BalanceTransferService, Nanos};
    /// # async fn example(service: &dyn BalanceTransferService) -> Result<(), Box<dyn std::error::Error>> {
    /// let receipt = service.transfer_between_groups(
    ///     "tenant_123",
    ///     "group_abc",
    ///     "group_xyz",
    ///     Nanos::from_dollars(10.0),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn transfer_between_groups(
        &self,
        tenant_id: &str,
        from_group: &str,
        to_group: &str,
        amount: Nanos,
    ) -> Result<TransferReceipt, TransferError>;
}
