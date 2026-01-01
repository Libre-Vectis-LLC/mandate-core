//! Tenant tier system for priority scheduling and service differentiation.
//!
//! Tiers use numeric values (not enums) for fine-grained control and future expansion.
//! Each tier spans 1 million values, allowing for subdivisions without API changes.
//!
//! # Tier Ranges
//!
//! - **Free (0)**: Exact value 0
//! - **Paid (1 to 999,999)**: 1M values for paid tier subdivisions
//! - **Pro (1M to 2M-1)**: 1M values for pro tier subdivisions
//! - **Max (2M+)**: No upper limit for enterprise
//!
//! # Examples
//!
//! ```
//! use mandate_core::billing::{TenantTier, TIER_FREE, TIER_PAID_MIN, tenant_tier_level};
//!
//! let free_tier: TenantTier = TIER_FREE;
//! assert_eq!(tenant_tier_level(free_tier), "free");
//!
//! let paid_tier: TenantTier = 500;
//! assert_eq!(tenant_tier_level(paid_tier), "paid");
//!
//! let pro_tier: TenantTier = 1_500_000;
//! assert_eq!(tenant_tier_level(pro_tier), "pro");
//! ```

/// Tenant tier as numeric value (not enum) for fine-grained control.
///
/// Each tier spans 1 million values, allowing future subdivisions without breaking changes.
pub type TenantTier = u64;

/// Free tier (exact value).
pub const TIER_FREE: u64 = 0;

/// Paid tier start.
pub const TIER_PAID_MIN: u64 = 1;

/// Paid tier end (1M - 1).
pub const TIER_PAID_MAX: u64 = 999_999;

/// Pro tier start (1M).
pub const TIER_PRO_MIN: u64 = 1_000_000;

/// Pro tier end (2M - 1).
pub const TIER_PRO_MAX: u64 = 1_999_999;

/// Max tier start (2M).
pub const TIER_MAX_MIN: u64 = 2_000_000;

/// Get human-readable tier level name.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::{tenant_tier_level, TIER_FREE, TIER_PAID_MIN, TIER_PRO_MIN, TIER_MAX_MIN};
///
/// assert_eq!(tenant_tier_level(TIER_FREE), "free");
/// assert_eq!(tenant_tier_level(500), "paid");
/// assert_eq!(tenant_tier_level(1_500_000), "pro");
/// assert_eq!(tenant_tier_level(3_000_000), "max");
/// ```
pub fn tenant_tier_level(tier: TenantTier) -> &'static str {
    match tier {
        0 => "free",
        1..=999_999 => "paid",
        1_000_000..=1_999_999 => "pro",
        _ => "max",
    }
}

/// Check if tier A has priority over tier B (for scheduling).
///
/// Higher tier values have higher priority. Used by the scheduler to prioritize
/// verification tasks from higher-tier tenants.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::{has_priority_over, TIER_FREE, TIER_PAID_MIN, TIER_PRO_MIN};
///
/// assert!(has_priority_over(TIER_PRO_MIN, TIER_PAID_MIN));
/// assert!(has_priority_over(TIER_PAID_MIN, TIER_FREE));
/// assert!(!has_priority_over(TIER_FREE, TIER_PAID_MIN));
/// assert!(!has_priority_over(100, 100)); // Equal tiers have no priority
/// ```
pub fn has_priority_over(tier_a: TenantTier, tier_b: TenantTier) -> bool {
    tier_a > tier_b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_level_free() {
        assert_eq!(tenant_tier_level(TIER_FREE), "free");
        assert_eq!(tenant_tier_level(0), "free");
    }

    #[test]
    fn test_tier_level_paid() {
        assert_eq!(tenant_tier_level(TIER_PAID_MIN), "paid");
        assert_eq!(tenant_tier_level(1), "paid");
        assert_eq!(tenant_tier_level(500), "paid");
        assert_eq!(tenant_tier_level(999_999), "paid");
        assert_eq!(tenant_tier_level(TIER_PAID_MAX), "paid");
    }

    #[test]
    fn test_tier_level_pro() {
        assert_eq!(tenant_tier_level(TIER_PRO_MIN), "pro");
        assert_eq!(tenant_tier_level(1_000_000), "pro");
        assert_eq!(tenant_tier_level(1_500_000), "pro");
        assert_eq!(tenant_tier_level(1_999_999), "pro");
        assert_eq!(tenant_tier_level(TIER_PRO_MAX), "pro");
    }

    #[test]
    fn test_tier_level_max() {
        assert_eq!(tenant_tier_level(TIER_MAX_MIN), "max");
        assert_eq!(tenant_tier_level(2_000_000), "max");
        assert_eq!(tenant_tier_level(3_000_000), "max");
        assert_eq!(tenant_tier_level(u64::MAX), "max");
    }

    #[test]
    fn test_priority_higher_beats_lower() {
        assert!(has_priority_over(TIER_MAX_MIN, TIER_PRO_MIN));
        assert!(has_priority_over(TIER_PRO_MIN, TIER_PAID_MIN));
        assert!(has_priority_over(TIER_PAID_MIN, TIER_FREE));
    }

    #[test]
    fn test_priority_lower_does_not_beat_higher() {
        assert!(!has_priority_over(TIER_FREE, TIER_PAID_MIN));
        assert!(!has_priority_over(TIER_PAID_MIN, TIER_PRO_MIN));
        assert!(!has_priority_over(TIER_PRO_MIN, TIER_MAX_MIN));
    }

    #[test]
    fn test_priority_equal_tiers() {
        assert!(!has_priority_over(TIER_FREE, TIER_FREE));
        assert!(!has_priority_over(100, 100));
        assert!(!has_priority_over(TIER_PRO_MIN, TIER_PRO_MIN));
    }

    #[test]
    fn test_priority_within_tier_range() {
        // Within paid tier (1 to 999,999)
        assert!(has_priority_over(999_999, 1));
        assert!(has_priority_over(500_000, 100));

        // Within pro tier (1M to 2M-1)
        assert!(has_priority_over(1_999_999, 1_000_000));
        assert!(has_priority_over(1_500_000, 1_200_000));
    }
}
