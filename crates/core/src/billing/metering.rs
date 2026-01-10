//! Metering types for usage tracking and balance validation.
//!
//! This module provides WASM-compatible types for metering operations:
//! - `MeteringError`: Errors during balance checks and deductions
//! - `UsageEvent`: Records of resource consumption for audit and billing
//! - `EgressMeter`: Trait for egress (outbound data) metering

use crate::billing::{AbstractResourceUnits, Nanos};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Errors that occur during metering operations.
///
/// These errors indicate balance check failures, insufficient funds, or storage issues.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MeteringError {
    /// Insufficient balance for the requested operation.
    #[error("insufficient balance: required {required}, available {available}")]
    InsufficientBalance {
        /// Amount required for the operation.
        required: Nanos,
        /// Amount currently available.
        available: Nanos,
    },

    /// Billing store backend error.
    #[error("billing store error: {0}")]
    StoreError(String),

    /// Tenant not found in billing system.
    #[error("tenant not found: {0}")]
    TenantNotFound(String),

    /// Group not found in billing system.
    #[error("group not found: {0}")]
    GroupNotFound(String),
}

/// Usage event for recording resource consumption.
///
/// Events are queued for async batch insertion into the database for audit trails
/// and billing reconciliation.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::{UsageEvent, AbstractResourceUnits};
///
/// let event = UsageEvent {
///     tenant_id: "tenant_123".to_string(),
///     group_id: Some("group_abc".to_string()),
///     event_type: "verification".to_string(),
///     aru: AbstractResourceUnits {
///         cpu_cycles_aru: 100,
///         ..Default::default()
///     },
///     metadata: None,
///     timestamp_ms: 1609459200000,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsageEvent {
    /// Tenant ID responsible for this usage.
    pub tenant_id: String,

    /// Optional group ID (if operation is group-scoped).
    pub group_id: Option<String>,

    /// Type of event (e.g., "verification", "pow_verify", "event_read").
    pub event_type: String,

    /// Abstract Resource Units consumed by this operation.
    pub aru: AbstractResourceUnits,

    /// Optional metadata for debugging and audit (JSON-serializable).
    pub metadata: Option<serde_json::Value>,

    /// Timestamp in milliseconds since Unix epoch.
    pub timestamp_ms: u64,
}

/// Trait for metering egress (outbound data transfer) charges.
///
/// This trait allows services to check and charge for egress without
/// depending on a specific metering implementation. Enterprise deployments
/// provide a real implementation; community edition uses [`NoOpEgressMeter`].
///
/// # Design
///
/// The egress metering follows a check-then-charge pattern:
/// 1. Before sending data, call [`check_egress`](EgressMeter::check_egress) to verify balance
/// 2. After sending data, call [`record_egress`](EgressMeter::record_egress) to charge
///
/// This allows rejecting requests upfront if the group has insufficient balance,
/// preventing data exfiltration without payment.
#[async_trait]
pub trait EgressMeter: Send + Sync {
    /// Check if there's sufficient balance for the estimated egress.
    ///
    /// This should be called **before** executing the actual data transfer.
    ///
    /// # Arguments
    /// * `group_id` - The group being charged (as string for crate independence)
    /// * `estimated_bytes` - Estimated data size to be transferred
    ///
    /// # Returns
    /// * `Ok(())` - Sufficient balance for the transfer
    /// * `Err(MeteringError::InsufficientBalance)` - Not enough credits
    /// * `Err(MeteringError::GroupNotFound)` - Unknown group
    async fn check_egress(
        &self,
        group_id: &str,
        estimated_bytes: usize,
    ) -> Result<(), MeteringError>;

    /// Record and charge for actual egress after successful transfer.
    ///
    /// This should be called **after** successfully sending data to the client.
    ///
    /// # Arguments
    /// * `group_id` - The group being charged
    /// * `actual_bytes` - Actual data size transferred
    ///
    /// # Returns
    /// * `Ok(())` - Charge recorded successfully
    /// * `Err(MeteringError)` - Failed to record (balance issue or store error)
    async fn record_egress(&self, group_id: &str, actual_bytes: usize)
        -> Result<(), MeteringError>;
}

/// No-op egress meter for community edition or when metering is disabled.
///
/// This implementation always succeeds, effectively making egress free.
/// Used when billing is not configured or in test environments.
#[derive(Clone, Debug, Default)]
pub struct NoOpEgressMeter;

#[async_trait]
impl EgressMeter for NoOpEgressMeter {
    async fn check_egress(
        &self,
        _group_id: &str,
        _estimated_bytes: usize,
    ) -> Result<(), MeteringError> {
        Ok(())
    }

    async fn record_egress(
        &self,
        _group_id: &str,
        _actual_bytes: usize,
    ) -> Result<(), MeteringError> {
        Ok(())
    }
}

/// Type alias for a shared egress meter reference.
pub type SharedEgressMeter = Arc<dyn EgressMeter>;

/// Create a default no-op egress meter.
pub fn default_egress_meter() -> SharedEgressMeter {
    Arc::new(NoOpEgressMeter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metering_error_insufficient_balance() {
        let err = MeteringError::InsufficientBalance {
            required: Nanos::from_dollars(10.0),
            available: Nanos::from_dollars(5.0),
        };

        let msg = err.to_string();
        assert!(msg.contains("insufficient balance"));
        assert!(msg.contains("10000000000")); // raw nanos
        assert!(msg.contains("5000000000"));
    }

    #[test]
    fn test_metering_error_display() {
        let err = MeteringError::StoreError("connection timeout".to_string());
        assert_eq!(err.to_string(), "billing store error: connection timeout");

        let err = MeteringError::TenantNotFound("tenant_123".to_string());
        assert_eq!(err.to_string(), "tenant not found: tenant_123");

        let err = MeteringError::GroupNotFound("group_abc".to_string());
        assert_eq!(err.to_string(), "group not found: group_abc");
    }

    #[test]
    fn test_usage_event_creation() {
        let event = UsageEvent {
            tenant_id: "tenant_123".to_string(),
            group_id: Some("group_abc".to_string()),
            event_type: "verification".to_string(),
            aru: AbstractResourceUnits {
                cpu_cycles_aru: 100,
                storage_gb_days: 0.5,
                egress_gb: 0.1,
                iops_aru: 10,
            },
            metadata: Some(serde_json::json!({"ring_size": 16})),
            timestamp_ms: 1609459200000,
        };

        assert_eq!(event.tenant_id, "tenant_123");
        assert_eq!(event.group_id, Some("group_abc".to_string()));
        assert_eq!(event.event_type, "verification");
        assert_eq!(event.aru.cpu_cycles_aru, 100);
    }

    #[test]
    fn test_usage_event_serialization() {
        let event = UsageEvent {
            tenant_id: "tenant_123".to_string(),
            group_id: None,
            event_type: "pow_verify".to_string(),
            aru: AbstractResourceUnits {
                cpu_cycles_aru: 50,
                ..Default::default()
            },
            metadata: None,
            timestamp_ms: 1609459200000,
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: UsageEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    // Async tests require tokio, only available on non-wasm targets
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_no_op_egress_meter() {
        let meter = NoOpEgressMeter;

        // Check always succeeds
        assert!(meter.check_egress("group_123", 1_000_000).await.is_ok());

        // Record always succeeds
        assert!(meter.record_egress("group_123", 1_000_000).await.is_ok());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn test_default_egress_meter() {
        let meter = default_egress_meter();

        // Default meter should be NoOp, always succeeds
        assert!(meter.check_egress("any_group", 999_999_999).await.is_ok());
        assert!(meter.record_egress("any_group", 999_999_999).await.is_ok());
    }
}
