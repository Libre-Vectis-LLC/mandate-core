//! Storage metering types for usage tracking and quota management.
//!
//! This module provides WASM-compatible types for storage metering:
//! - `OrgStorageUsage`: Records per-org storage consumption
//! - `OrgStorageStatus`: Quota status based on balance and usage
//!
//! # Design
//!
//! Storage is charged using a prepayment model:
//! 1. On write: deduct 30 days of storage cost upfront
//! 2. Daily job: charge 1 day for existing data (30-day prepay already done)
//! 3. Warning when balance < 30 days of storage
//! 4. Suspend writes when balance <= 0
//! 5. Delete org data after 30 days of suspension

use serde::{Deserialize, Serialize};

/// Per-group storage usage record.
///
/// Tracks storage consumption across different data types within an organization.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::OrgStorageUsage;
///
/// let usage = OrgStorageUsage {
///     org_id: "org_abc".to_string(),
///     tenant_id: "tenant_123".to_string(),
///     event_bytes: 1_048_576,      // 1 MB of events
///     keyblob_bytes: 512,          // 512 bytes of key blobs
///     ring_bytes: 2048,            // 2 KB of ring snapshots
///     total_bytes: 1_051_136,      // Sum of all
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgStorageUsage {
    /// Organization ID this usage belongs to.
    pub org_id: String,

    /// Tenant ID that owns this group.
    pub tenant_id: String,

    /// Total bytes used by event data.
    pub event_bytes: i64,

    /// Total bytes used by key blobs.
    pub keyblob_bytes: i64,

    /// Total bytes used by ring snapshots.
    pub ring_bytes: i64,

    /// Sum of all storage bytes.
    pub total_bytes: i64,
}

impl OrgStorageUsage {
    /// Creates a new storage usage record.
    ///
    /// Automatically calculates `total_bytes` from component values.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::OrgStorageUsage;
    ///
    /// let usage = OrgStorageUsage::new(
    ///     "org_abc".to_string(),
    ///     "tenant_123".to_string(),
    ///     1_000_000,
    ///     500,
    ///     2000,
    /// );
    ///
    /// assert_eq!(usage.total_bytes, 1_002_500);
    /// ```
    pub fn new(
        org_id: String,
        tenant_id: String,
        event_bytes: i64,
        keyblob_bytes: i64,
        ring_bytes: i64,
    ) -> Self {
        let total_bytes = event_bytes
            .saturating_add(keyblob_bytes)
            .saturating_add(ring_bytes);

        Self {
            org_id,
            tenant_id,
            event_bytes,
            keyblob_bytes,
            ring_bytes,
            total_bytes,
        }
    }

    /// Returns total storage in GB (for cost calculation).
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::OrgStorageUsage;
    ///
    /// let usage = OrgStorageUsage::new(
    ///     "org_abc".to_string(),
    ///     "tenant_123".to_string(),
    ///     1_073_741_824, // 1 GB
    ///     0,
    ///     0,
    /// );
    ///
    /// assert!((usage.total_gb() - 1.0).abs() < 0.001);
    /// ```
    pub fn total_gb(&self) -> f64 {
        self.total_bytes as f64 / 1_073_741_824.0
    }
}

/// Storage status for a group based on balance and usage.
///
/// Determines whether the org can accept new writes and how long until
/// suspension or deletion.
///
/// # State Transitions
///
/// ```text
/// Normal → Warning → Suspended → PendingDeletion
///   ↑                                      ↓
///   └──────── (add balance) ───────────────┘
/// ```
///
/// # Examples
///
/// ```
/// use mandate_core::billing::OrgStorageStatus;
///
/// // Group with sufficient balance
/// let status = OrgStorageStatus::Normal;
///
/// // Group with low balance
/// let status = OrgStorageStatus::Warning { days_remaining: 15 };
///
/// // Group with zero balance
/// let status = OrgStorageStatus::Suspended;
///
/// // Group pending deletion
/// let status = OrgStorageStatus::PendingDeletion { days_until_deletion: 20 };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OrgStorageStatus {
    /// Balance covers 30+ days of storage.
    /// Reads and writes allowed.
    Normal,

    /// Balance < 30 days but > 0.
    /// Reads allowed, writes blocked.
    Warning {
        /// Estimated days until balance reaches zero.
        days_remaining: u32,
    },

    /// Balance <= 0.
    /// Reads and writes blocked.
    Suspended,

    /// Suspended for > 0 days, pending deletion after 30 days total.
    /// Reads and writes blocked. Data will be deleted after countdown.
    PendingDeletion {
        /// Days remaining until data deletion (max 30).
        days_until_deletion: u32,
    },
}

impl OrgStorageStatus {
    /// Returns whether writes are allowed in this status.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::OrgStorageStatus;
    ///
    /// assert!(OrgStorageStatus::Normal.can_write());
    /// assert!(!OrgStorageStatus::Warning { days_remaining: 15 }.can_write());
    /// assert!(!OrgStorageStatus::Suspended.can_write());
    /// assert!(!OrgStorageStatus::PendingDeletion { days_until_deletion: 20 }.can_write());
    /// ```
    pub fn can_write(&self) -> bool {
        matches!(self, OrgStorageStatus::Normal)
    }

    /// Returns whether reads are allowed in this status.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::OrgStorageStatus;
    ///
    /// assert!(OrgStorageStatus::Normal.can_read());
    /// assert!(OrgStorageStatus::Warning { days_remaining: 15 }.can_read());
    /// assert!(!OrgStorageStatus::Suspended.can_read());
    /// assert!(!OrgStorageStatus::PendingDeletion { days_until_deletion: 20 }.can_read());
    /// ```
    pub fn can_read(&self) -> bool {
        matches!(
            self,
            OrgStorageStatus::Normal | OrgStorageStatus::Warning { .. }
        )
    }

    /// Returns whether the org is at risk of data loss.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::OrgStorageStatus;
    ///
    /// assert!(!OrgStorageStatus::Normal.is_critical());
    /// assert!(!OrgStorageStatus::Warning { days_remaining: 15 }.is_critical());
    /// assert!(OrgStorageStatus::Suspended.is_critical());
    /// assert!(OrgStorageStatus::PendingDeletion { days_until_deletion: 20 }.is_critical());
    /// ```
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            OrgStorageStatus::Suspended | OrgStorageStatus::PendingDeletion { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_org_storage_usage_new() {
        let usage = OrgStorageUsage::new(
            "org_abc".to_string(),
            "tenant_123".to_string(),
            1_000_000,
            500,
            2_000,
        );

        assert_eq!(usage.org_id, "org_abc");
        assert_eq!(usage.tenant_id, "tenant_123");
        assert_eq!(usage.event_bytes, 1_000_000);
        assert_eq!(usage.keyblob_bytes, 500);
        assert_eq!(usage.ring_bytes, 2_000);
        assert_eq!(usage.total_bytes, 1_002_500);
    }

    #[test]
    fn test_org_storage_usage_total_gb() {
        let usage = OrgStorageUsage::new(
            "org_abc".to_string(),
            "tenant_123".to_string(),
            1_073_741_824, // 1 GB
            0,
            0,
        );

        let gb = usage.total_gb();
        assert!((gb - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_org_storage_usage_total_gb_fractional() {
        let usage = OrgStorageUsage::new(
            "org_abc".to_string(),
            "tenant_123".to_string(),
            536_870_912, // 0.5 GB
            0,
            0,
        );

        let gb = usage.total_gb();
        assert!((gb - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_org_storage_status_can_write() {
        assert!(OrgStorageStatus::Normal.can_write());
        assert!(!OrgStorageStatus::Warning { days_remaining: 15 }.can_write());
        assert!(!OrgStorageStatus::Suspended.can_write());
        assert!(!OrgStorageStatus::PendingDeletion {
            days_until_deletion: 20
        }
        .can_write());
    }

    #[test]
    fn test_org_storage_status_can_read() {
        assert!(OrgStorageStatus::Normal.can_read());
        assert!(OrgStorageStatus::Warning { days_remaining: 15 }.can_read());
        assert!(!OrgStorageStatus::Suspended.can_read());
        assert!(!OrgStorageStatus::PendingDeletion {
            days_until_deletion: 20
        }
        .can_read());
    }

    #[test]
    fn test_org_storage_status_is_critical() {
        assert!(!OrgStorageStatus::Normal.is_critical());
        assert!(!OrgStorageStatus::Warning { days_remaining: 15 }.is_critical());
        assert!(OrgStorageStatus::Suspended.is_critical());
        assert!(OrgStorageStatus::PendingDeletion {
            days_until_deletion: 20
        }
        .is_critical());
    }

    #[test]
    fn test_org_storage_status_serialization() {
        let status = OrgStorageStatus::Warning { days_remaining: 15 };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("warning"));
        assert!(json.contains("days_remaining"));

        let deserialized: OrgStorageStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, deserialized);
    }

    #[test]
    fn test_org_storage_usage_serialization() {
        let usage = OrgStorageUsage::new(
            "org_abc".to_string(),
            "tenant_123".to_string(),
            1_000,
            500,
            200,
        );

        let json = serde_json::to_string(&usage).unwrap();
        let deserialized: OrgStorageUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(usage, deserialized);
    }
}
