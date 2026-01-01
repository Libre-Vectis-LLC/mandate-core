//! Billing and cost models for the Mandate protocol.
//!
//! This module provides provider-agnostic cost modeling using Abstract Resource Units (ARU).
//! All code is WASM-compatible (pure math, no I/O).
//!
//! # Design
//!
//! - Abstract Resource Units (ARU): Normalize resources across providers
//! - Verification Cost Model: Estimate CPU cost for Nazgul signature verification
//! - POW Verification Cost Model: Estimate CPU cost for rspow proof verification
//! - Provider Pricing: Convert ARU to monetary cost (Nanos = 10^-9 USD)
//!
//! # Examples
//!
//! ```
//! use mandate_core::billing::{ProviderPricing, AbstractResourceUnits, Nanos};
//!
//! let pricing = ProviderPricing::aws_us_east_1();
//! let aru = AbstractResourceUnits {
//!     cpu_cycles_aru: 10,
//!     storage_gb_days: 1.0,
//!     egress_gb: 0.5,
//!     iops_aru: 5,
//! };
//!
//! let cost = pricing.calculate_cost(&aru);
//! let charge = pricing.calculate_charge(&aru, 20); // 20× safety margin
//! ```

mod cost_models;
mod difficulty;
mod pow_state;
mod pricing;
mod types;

pub use cost_models::{PowVerificationCostModel, VerificationCostModel};
pub use difficulty::PowDifficultyCalculator;
pub use pow_state::{EscalationStrategy, GroupPowConfig, GroupPowState, RecoveryStrategy};
pub use pricing::{ProviderPricing, ServiceTier};
pub use types::{AbstractResourceUnits, Nanos};
