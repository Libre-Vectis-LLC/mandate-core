//! Core types for billing: Abstract Resource Units and monetary amounts.

use std::ops::{Add, Mul, Sub};

/// Abstract Resource Units: provider-agnostic resource measurements.
///
/// These units normalize resource consumption across different hardware and cloud providers.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::AbstractResourceUnits;
///
/// let aru = AbstractResourceUnits {
///     cpu_cycles_aru: 100,  // 100M CPU difficulty units
///     storage_gb_days: 5.0,
///     egress_gb: 2.0,
///     iops_aru: 10,
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AbstractResourceUnits {
    /// CPU cycles in ARU (1 ARU = 1M CPU difficulty units).
    /// Difficulty is normalized across CPUs via benchmarking.
    pub cpu_cycles_aru: u64,

    /// Storage consumption in GB-days.
    pub storage_gb_days: f64,

    /// Egress bandwidth in GB.
    pub egress_gb: f64,

    /// IOPS consumption in ARU (1 ARU = 1000 IOPS-seconds).
    pub iops_aru: u64,
}

impl Default for AbstractResourceUnits {
    fn default() -> Self {
        Self {
            cpu_cycles_aru: 0,
            storage_gb_days: 0.0,
            egress_gb: 0.0,
            iops_aru: 0,
        }
    }
}

impl Add for AbstractResourceUnits {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            cpu_cycles_aru: self.cpu_cycles_aru.saturating_add(rhs.cpu_cycles_aru),
            storage_gb_days: self.storage_gb_days + rhs.storage_gb_days,
            egress_gb: self.egress_gb + rhs.egress_gb,
            iops_aru: self.iops_aru.saturating_add(rhs.iops_aru),
        }
    }
}

/// Monetary amount in nanos (10^-9 USD).
///
/// Using i64 for nanos allows representing amounts from -$9.22B to +$9.22B
/// with nanosecond precision (9 decimal places).
///
/// # Examples
///
/// ```
/// use mandate_core::billing::Nanos;
///
/// let cost = Nanos::new(1_000_000_000);  // $1.00
/// let doubled = cost * 2i64;
/// assert_eq!(doubled.value(), 2_000_000_000);
///
/// let from_dollars = Nanos::from_dollars(3.50);
/// assert_eq!(from_dollars.to_dollars(), 3.50);
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Nanos(i64);

impl Nanos {
    /// Zero nanos (no cost).
    pub const ZERO: Self = Self(0);

    /// One dollar in nanos.
    pub const ONE_DOLLAR: Self = Self(1_000_000_000);

    /// Creates a new Nanos from raw nanosecond value.
    #[inline]
    pub const fn new(nanos: i64) -> Self {
        Self(nanos)
    }

    /// Creates Nanos from a dollar amount.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::Nanos;
    ///
    /// let amount = Nanos::from_dollars(5.99);
    /// assert_eq!(amount.value(), 5_990_000_000);
    /// ```
    #[inline]
    pub fn from_dollars(dollars: f64) -> Self {
        Self((dollars * 1_000_000_000.0) as i64)
    }

    /// Returns the raw nanosecond value.
    #[inline]
    pub const fn value(self) -> i64 {
        self.0
    }

    /// Converts to dollars (f64).
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::Nanos;
    ///
    /// let nanos = Nanos::new(2_500_000_000);
    /// assert_eq!(nanos.to_dollars(), 2.5);
    /// ```
    #[inline]
    pub fn to_dollars(self) -> f64 {
        self.0 as f64 / 1_000_000_000.0
    }

    /// Saturating multiplication by u64.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::Nanos;
    ///
    /// let cost = Nanos::new(100_000_000);  // $0.10
    /// let total = cost.saturating_mul(20);  // Apply 20× safety margin
    /// assert_eq!(total.value(), 2_000_000_000);  // $2.00
    /// ```
    #[inline]
    pub fn saturating_mul(self, rhs: u64) -> Self {
        Self(self.0.saturating_mul(rhs as i64))
    }

    /// Saturating addition.
    #[inline]
    pub fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Saturating subtraction.
    #[inline]
    pub fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl Add for Nanos {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Sub for Nanos {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Mul<i64> for Nanos {
    type Output = Self;

    fn mul(self, rhs: i64) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl Mul<u32> for Nanos {
    type Output = Self;

    fn mul(self, rhs: u32) -> Self::Output {
        Self(self.0 * rhs as i64)
    }
}

/// Entity that holds a balance.
///
/// Balances can be held by tenants (account-level) or groups (project-level).
/// Groups must transfer funds from their tenant before performing operations.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::BalanceHolder;
///
/// let tenant = BalanceHolder::Tenant("tenant_123".to_string());
/// let group = BalanceHolder::Group("group_abc".to_string());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BalanceHolder {
    /// Tenant account balance.
    Tenant(String),
    /// Group project balance.
    Group(String),
}

impl BalanceHolder {
    /// Returns true if this is a tenant balance holder.
    pub fn is_tenant(&self) -> bool {
        matches!(self, BalanceHolder::Tenant(_))
    }

    /// Returns true if this is a group balance holder.
    pub fn is_group(&self) -> bool {
        matches!(self, BalanceHolder::Group(_))
    }

    /// Returns the ID as a string reference.
    pub fn id(&self) -> &str {
        match self {
            BalanceHolder::Tenant(id) | BalanceHolder::Group(id) => id,
        }
    }
}

/// Receipt for balance transfers (for audit trail).
///
/// Every balance transfer generates a receipt for accountability and debugging.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::{TransferReceipt, BalanceHolder, Nanos};
///
/// let receipt = TransferReceipt {
///     transfer_id: "uuid-1234".to_string(),
///     from: BalanceHolder::Tenant("tenant_1".to_string()),
///     to: BalanceHolder::Group("group_a".to_string()),
///     amount: Nanos::from_dollars(10.0),
///     timestamp_ms: 1609459200000,
///     reason: Some("Initial funding".to_string()),
/// };
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransferReceipt {
    /// Unique transfer identifier (UUID).
    pub transfer_id: String,
    /// Source of funds.
    pub from: BalanceHolder,
    /// Destination of funds.
    pub to: BalanceHolder,
    /// Amount transferred.
    pub amount: Nanos,
    /// Timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
    /// Optional reason for the transfer.
    pub reason: Option<String>,
}

/// Errors that can occur during balance transfers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    /// Insufficient balance for the transfer.
    InsufficientBalance {
        /// Amount required for the transfer.
        required: Nanos,
        /// Amount currently available.
        available: Nanos,
    },
    /// Group is not owned by the tenant attempting the transfer.
    GroupNotOwned(String),
    /// Invalid amount (e.g., zero or negative).
    InvalidAmount(String),
    /// Database error during transfer.
    Database(String),
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferError::InsufficientBalance {
                required,
                available,
            } => {
                write!(
                    f,
                    "insufficient balance: required ${:.9}, available ${:.9}",
                    required.to_dollars(),
                    available.to_dollars()
                )
            }
            TransferError::GroupNotOwned(group_id) => {
                write!(f, "group {} not owned by tenant", group_id)
            }
            TransferError::InvalidAmount(msg) => write!(f, "invalid amount: {}", msg),
            TransferError::Database(msg) => write!(f, "database error: {}", msg),
        }
    }
}

impl std::error::Error for TransferError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aru_default() {
        let aru = AbstractResourceUnits::default();
        assert_eq!(aru.cpu_cycles_aru, 0);
        assert_eq!(aru.storage_gb_days, 0.0);
        assert_eq!(aru.egress_gb, 0.0);
        assert_eq!(aru.iops_aru, 0);
    }

    #[test]
    fn test_aru_addition() {
        let a = AbstractResourceUnits {
            cpu_cycles_aru: 10,
            storage_gb_days: 1.5,
            egress_gb: 0.5,
            iops_aru: 5,
        };
        let b = AbstractResourceUnits {
            cpu_cycles_aru: 20,
            storage_gb_days: 2.5,
            egress_gb: 1.0,
            iops_aru: 10,
        };
        let sum = a + b;
        assert_eq!(sum.cpu_cycles_aru, 30);
        assert_eq!(sum.storage_gb_days, 4.0);
        assert_eq!(sum.egress_gb, 1.5);
        assert_eq!(sum.iops_aru, 15);
    }

    #[test]
    fn test_nanos_zero() {
        assert_eq!(Nanos::ZERO.value(), 0);
    }

    #[test]
    fn test_nanos_one_dollar() {
        assert_eq!(Nanos::ONE_DOLLAR.value(), 1_000_000_000);
        assert_eq!(Nanos::ONE_DOLLAR.to_dollars(), 1.0);
    }

    #[test]
    fn test_nanos_from_dollars() {
        let amount = Nanos::from_dollars(5.99);
        assert_eq!(amount.value(), 5_990_000_000);
        assert_eq!(amount.to_dollars(), 5.99);
    }

    #[test]
    fn test_nanos_to_dollars() {
        let nanos = Nanos::new(2_500_000_000);
        assert_eq!(nanos.to_dollars(), 2.5);
    }

    #[test]
    fn test_nanos_arithmetic() {
        let a = Nanos::new(1_000_000_000);
        let b = Nanos::new(500_000_000);

        assert_eq!((a + b).value(), 1_500_000_000);
        assert_eq!((a - b).value(), 500_000_000);
        assert_eq!((a * 2i64).value(), 2_000_000_000);
    }

    #[test]
    fn test_nanos_saturating_mul() {
        let cost = Nanos::new(100_000_000);
        let total = cost.saturating_mul(20);
        assert_eq!(total.value(), 2_000_000_000);
    }

    #[test]
    fn test_nanos_ordering() {
        let a = Nanos::new(1_000_000_000);
        let b = Nanos::new(2_000_000_000);
        assert!(a < b);
        assert!(b > a);
    }

    #[test]
    fn test_balance_holder_tenant() {
        let holder = BalanceHolder::Tenant("tenant_123".to_string());
        assert!(holder.is_tenant());
        assert!(!holder.is_group());
        assert_eq!(holder.id(), "tenant_123");
    }

    #[test]
    fn test_balance_holder_group() {
        let holder = BalanceHolder::Group("group_abc".to_string());
        assert!(!holder.is_tenant());
        assert!(holder.is_group());
        assert_eq!(holder.id(), "group_abc");
    }

    #[test]
    fn test_transfer_receipt_creation() {
        let receipt = TransferReceipt {
            transfer_id: "uuid-1234".to_string(),
            from: BalanceHolder::Tenant("tenant_1".to_string()),
            to: BalanceHolder::Group("group_a".to_string()),
            amount: Nanos::from_dollars(10.0),
            timestamp_ms: 1609459200000,
            reason: Some("Initial funding".to_string()),
        };

        assert_eq!(receipt.transfer_id, "uuid-1234");
        assert!(receipt.from.is_tenant());
        assert!(receipt.to.is_group());
        assert_eq!(receipt.amount.to_dollars(), 10.0);
    }

    #[test]
    fn test_transfer_error_display() {
        let err = TransferError::InsufficientBalance {
            required: Nanos::from_dollars(100.0),
            available: Nanos::from_dollars(50.0),
        };
        let msg = format!("{}", err);
        assert!(msg.contains("insufficient balance"));
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));

        let err = TransferError::GroupNotOwned("group_123".to_string());
        assert_eq!(format!("{}", err), "group group_123 not owned by tenant");

        let err = TransferError::InvalidAmount("amount must be positive".to_string());
        assert_eq!(
            format!("{}", err),
            "invalid amount: amount must be positive"
        );
    }
}
