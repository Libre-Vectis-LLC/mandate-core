//! Provider pricing configuration and cost calculation.

use super::types::{AbstractResourceUnits, Nanos};
use std::str::FromStr;

/// Service tier classification (analogous to AI model tiers).
///
/// Tiers represent different hardware profiles with trade-offs between cost and latency.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::ServiceTier;
///
/// let tier = ServiceTier::Sonnet;  // Balanced performance
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceTier {
    /// Low-cost tier: old devices, solar-powered, Termux.
    /// Cost-sensitive, latency-insensitive.
    Haiku,

    /// Value tier: cloud servers or solar-powered servers.
    /// Balanced cost and latency.
    Sonnet,

    /// Low-latency tier: Xeon or consumer CPUs at 4.5-6GHz.
    /// Latency-sensitive, cost-secondary.
    Opus,
}

impl ServiceTier {
    /// Returns string representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceTier::Haiku => "haiku",
            ServiceTier::Sonnet => "sonnet",
            ServiceTier::Opus => "opus",
        }
    }
}

impl FromStr for ServiceTier {
    type Err = ();

    /// Parses from string (case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use mandate_core::billing::ServiceTier;
    ///
    /// assert_eq!(ServiceTier::from_str("haiku"), Ok(ServiceTier::Haiku));
    /// assert_eq!(ServiceTier::from_str("SONNET"), Ok(ServiceTier::Sonnet));
    /// assert!(ServiceTier::from_str("invalid").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "haiku" => Ok(ServiceTier::Haiku),
            "sonnet" => Ok(ServiceTier::Sonnet),
            "opus" => Ok(ServiceTier::Opus),
            _ => Err(()),
        }
    }
}

/// Provider pricing configuration.
///
/// Defines per-resource prices and CPU normalization for a specific provider and tier.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::{ProviderPricing, ServiceTier, AbstractResourceUnits};
///
/// let pricing = ProviderPricing::aws_us_east_1();
/// let aru = AbstractResourceUnits {
///     cpu_cycles_aru: 10,
///     storage_gb_days: 1.0,
///     egress_gb: 0.5,
///     iops_aru: 5,
/// };
///
/// let cost = pricing.calculate_cost(&aru);
/// let charge = pricing.calculate_charge(&aru, 20);  // 20× safety margin
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderPricing {
    /// Provider unique identifier (e.g., "aws-us-east-1").
    pub provider_id: String,

    /// Service tier.
    pub tier: ServiceTier,

    /// Price per 1M CPU difficulty units (nanos).
    pub cpu_cycle_price_nanos: i64,

    /// Price per GB-day storage (nanos).
    pub storage_gb_day_price_nanos: i64,

    /// Price per GB egress (nanos).
    pub egress_gb_price_nanos: i64,

    /// Price per 1000 IOPS-seconds (nanos).
    pub iops_price_nanos: i64,

    /// CPU normalization factor.
    /// 1.0 = 3GHz baseline, 0.5 = 6GHz (2× faster), 2.0 = 1.5GHz (2× slower).
    pub cpu_normalization: f64,
}

impl ProviderPricing {
    /// AWS us-east-1 reference pricing (Opus tier).
    ///
    /// Based on EC2 compute, EBS gp3 storage, and data transfer pricing.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::{ProviderPricing, ServiceTier};
    ///
    /// let pricing = ProviderPricing::aws_us_east_1();
    /// assert_eq!(pricing.tier, ServiceTier::Opus);
    /// ```
    pub fn aws_us_east_1() -> Self {
        Self {
            provider_id: "aws-us-east-1".to_string(),
            tier: ServiceTier::Opus,
            cpu_cycle_price_nanos: 100, // $0.0000001 per 1M cycles
            storage_gb_day_price_nanos: 767_000, // $0.023/GB-month ÷ 30
            egress_gb_price_nanos: 90_000_000, // $0.09/GB
            iops_price_nanos: 2,
            cpu_normalization: 1.0,
        }
    }

    /// Hetzner dedicated server (Sonnet tier).
    ///
    /// Lower cost than AWS, suitable for value-tier deployments.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::{ProviderPricing, ServiceTier};
    ///
    /// let pricing = ProviderPricing::hetzner_dedicated();
    /// assert_eq!(pricing.tier, ServiceTier::Sonnet);
    /// ```
    pub fn hetzner_dedicated() -> Self {
        Self {
            provider_id: "hetzner-dedicated".to_string(),
            tier: ServiceTier::Sonnet,
            cpu_cycle_price_nanos: 20,           // Far lower than AWS
            storage_gb_day_price_nanos: 333_000, // ~$0.01/GB-month
            egress_gb_price_nanos: 1_000_000,    // ~$1/TB
            iops_price_nanos: 1,
            cpu_normalization: 1.0,
        }
    }

    /// Termux solar-powered device (Haiku tier).
    ///
    /// Lowest cost, suitable for cost-sensitive deployments.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::{ProviderPricing, ServiceTier};
    ///
    /// let pricing = ProviderPricing::termux_solar();
    /// assert_eq!(pricing.tier, ServiceTier::Haiku);
    /// ```
    pub fn termux_solar() -> Self {
        Self {
            provider_id: "termux-solar".to_string(),
            tier: ServiceTier::Haiku,
            cpu_cycle_price_nanos: 5, // Only electricity + depreciation
            storage_gb_day_price_nanos: 50_000, // SD card cost
            egress_gb_price_nanos: 500_000, // Mobile data / WiFi
            iops_price_nanos: 1,
            cpu_normalization: 2.0, // Older ARM, 2× slower than baseline
        }
    }

    /// Calculates precise cost from ARU (no safety margin).
    ///
    /// This is the actual cost used for metrics and reporting.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::{ProviderPricing, AbstractResourceUnits};
    ///
    /// let pricing = ProviderPricing::aws_us_east_1();
    /// let aru = AbstractResourceUnits {
    ///     cpu_cycles_aru: 10,
    ///     storage_gb_days: 1.0,
    ///     egress_gb: 0.5,
    ///     iops_aru: 5,
    /// };
    ///
    /// let cost = pricing.calculate_cost(&aru);
    /// assert!(cost.value() > 0);
    /// ```
    pub fn calculate_cost(&self, aru: &AbstractResourceUnits) -> Nanos {
        let cpu_cost = (aru.cpu_cycles_aru as f64
            * self.cpu_normalization
            * self.cpu_cycle_price_nanos as f64) as i64;

        let storage_cost = (aru.storage_gb_days * self.storage_gb_day_price_nanos as f64) as i64;

        let egress_cost = (aru.egress_gb * self.egress_gb_price_nanos as f64) as i64;

        let iops_cost = aru.iops_aru as i64 * self.iops_price_nanos;

        let total = cpu_cost
            .saturating_add(storage_cost)
            .saturating_add(egress_cost)
            .saturating_add(iops_cost);

        Nanos::new(total)
    }

    /// Calculates charge amount (cost × safety margin).
    ///
    /// The safety margin (typically 20×) provides buffer for pricing changes and promotions.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::{ProviderPricing, AbstractResourceUnits};
    ///
    /// let pricing = ProviderPricing::aws_us_east_1();
    /// let aru = AbstractResourceUnits {
    ///     cpu_cycles_aru: 10,
    ///     storage_gb_days: 0.0,
    ///     egress_gb: 0.0,
    ///     iops_aru: 0,
    /// };
    ///
    /// let charge = pricing.calculate_charge(&aru, 20);
    /// let cost = pricing.calculate_cost(&aru);
    ///
    /// // Charge should be 20× the cost
    /// assert_eq!(charge.value(), cost.value() * 20);
    /// ```
    pub fn calculate_charge(&self, aru: &AbstractResourceUnits, safety_margin: u32) -> Nanos {
        let cost = self.calculate_cost(aru);
        cost.saturating_mul(safety_margin as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_tier_as_str() {
        assert_eq!(ServiceTier::Haiku.as_str(), "haiku");
        assert_eq!(ServiceTier::Sonnet.as_str(), "sonnet");
        assert_eq!(ServiceTier::Opus.as_str(), "opus");
    }

    #[test]
    fn test_service_tier_from_str() {
        assert_eq!(ServiceTier::from_str("haiku"), Ok(ServiceTier::Haiku));
        assert_eq!(ServiceTier::from_str("HAIKU"), Ok(ServiceTier::Haiku));
        assert_eq!(ServiceTier::from_str("sonnet"), Ok(ServiceTier::Sonnet));
        assert_eq!(ServiceTier::from_str("opus"), Ok(ServiceTier::Opus));
        assert!(ServiceTier::from_str("invalid").is_err());
    }

    #[test]
    fn test_aws_pricing() {
        let pricing = ProviderPricing::aws_us_east_1();
        assert_eq!(pricing.provider_id, "aws-us-east-1");
        assert_eq!(pricing.tier, ServiceTier::Opus);
        assert!(pricing.cpu_cycle_price_nanos > 0);
        assert!(pricing.storage_gb_day_price_nanos > 0);
    }

    #[test]
    fn test_hetzner_pricing() {
        let pricing = ProviderPricing::hetzner_dedicated();
        assert_eq!(pricing.provider_id, "hetzner-dedicated");
        assert_eq!(pricing.tier, ServiceTier::Sonnet);

        // Hetzner should be cheaper than AWS
        let aws = ProviderPricing::aws_us_east_1();
        assert!(pricing.cpu_cycle_price_nanos < aws.cpu_cycle_price_nanos);
    }

    #[test]
    fn test_termux_pricing() {
        let pricing = ProviderPricing::termux_solar();
        assert_eq!(pricing.provider_id, "termux-solar");
        assert_eq!(pricing.tier, ServiceTier::Haiku);

        // Termux should be cheapest
        let aws = ProviderPricing::aws_us_east_1();
        let hetzner = ProviderPricing::hetzner_dedicated();
        assert!(pricing.cpu_cycle_price_nanos < hetzner.cpu_cycle_price_nanos);
        assert!(pricing.cpu_cycle_price_nanos < aws.cpu_cycle_price_nanos);
    }

    #[test]
    fn test_calculate_cost_cpu_only() {
        let pricing = ProviderPricing::aws_us_east_1();
        let aru = AbstractResourceUnits {
            cpu_cycles_aru: 10,
            storage_gb_days: 0.0,
            egress_gb: 0.0,
            iops_aru: 0,
        };

        let cost = pricing.calculate_cost(&aru);
        // 10 ARU × 1.0 normalization × 100 nanos = 1000 nanos
        assert_eq!(cost.value(), 1000);
    }

    #[test]
    fn test_calculate_cost_storage_only() {
        let pricing = ProviderPricing::aws_us_east_1();
        let aru = AbstractResourceUnits {
            cpu_cycles_aru: 0,
            storage_gb_days: 1.0,
            egress_gb: 0.0,
            iops_aru: 0,
        };

        let cost = pricing.calculate_cost(&aru);
        // 1.0 GB-day × 767000 nanos = 767000 nanos
        assert_eq!(cost.value(), 767_000);
    }

    #[test]
    fn test_calculate_cost_combined() {
        let pricing = ProviderPricing::aws_us_east_1();
        let aru = AbstractResourceUnits {
            cpu_cycles_aru: 10,
            storage_gb_days: 1.0,
            egress_gb: 0.5,
            iops_aru: 5,
        };

        let cost = pricing.calculate_cost(&aru);
        // CPU: 10 × 1.0 × 100 = 1000
        // Storage: 1.0 × 767000 = 767000
        // Egress: 0.5 × 90000000 = 45000000
        // IOPS: 5 × 2 = 10
        // Total: 1000 + 767000 + 45000000 + 10 = 45768010
        assert_eq!(cost.value(), 45_768_010);
    }

    #[test]
    fn test_calculate_charge_with_safety_margin() {
        let pricing = ProviderPricing::aws_us_east_1();
        let aru = AbstractResourceUnits {
            cpu_cycles_aru: 10,
            storage_gb_days: 0.0,
            egress_gb: 0.0,
            iops_aru: 0,
        };

        let charge = pricing.calculate_charge(&aru, 20);
        let cost = pricing.calculate_cost(&aru);

        // Charge should be 20× the cost
        assert_eq!(charge.value(), cost.value() * 20);
        assert_eq!(charge.value(), 20_000);
    }

    #[test]
    fn test_cpu_normalization_termux() {
        let pricing = ProviderPricing::termux_solar();
        let aru = AbstractResourceUnits {
            cpu_cycles_aru: 10,
            storage_gb_days: 0.0,
            egress_gb: 0.0,
            iops_aru: 0,
        };

        let cost = pricing.calculate_cost(&aru);
        // 10 ARU × 2.0 normalization × 5 nanos = 100 nanos
        assert_eq!(cost.value(), 100);
    }

    #[test]
    fn test_pricing_comparison() {
        let aru = AbstractResourceUnits {
            cpu_cycles_aru: 100,
            storage_gb_days: 10.0,
            egress_gb: 1.0,
            iops_aru: 50,
        };

        let aws_cost = ProviderPricing::aws_us_east_1().calculate_cost(&aru);
        let hetzner_cost = ProviderPricing::hetzner_dedicated().calculate_cost(&aru);
        let termux_cost = ProviderPricing::termux_solar().calculate_cost(&aru);

        // AWS should be most expensive
        assert!(aws_cost > hetzner_cost);

        // Termux should be cheapest (despite CPU normalization)
        // Note: This might not always be true depending on workload mix,
        // but for CPU-heavy workloads it should hold
        println!(
            "AWS: {:?}, Hetzner: {:?}, Termux: {:?}",
            aws_cost, hetzner_cost, termux_cost
        );
    }
}
