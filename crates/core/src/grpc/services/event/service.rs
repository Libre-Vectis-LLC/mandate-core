//! EventService implementation struct and constructors.
//!
//! This module is gated behind `#[cfg(not(target_arch = "wasm32"))]` at the crate root,
//! so all code here is host-only (no WASM).

use crate::billing::{
    default_egress_meter, OrgPowConfig, PowDifficultyCalculator, SharedEgressMeter,
    VerificationCostModel,
};
use crate::billing::OrgPowState;
use crate::ids::{OrganizationId, TenantId};
use crate::pow::PowVerifier;
use crate::storage::facade::StorageFacade;
use dashmap::DashMap;
use std::sync::Arc;

/// Composite key for per-tenant, per-org POW state tracking.
type PowStateKey = (TenantId, OrganizationId);

/// EventService implementation with integrated POW defense.
///
/// Tracks per-(tenant, org) verification failure history and enforces
/// proof-of-work requirements when failure thresholds are exceeded.
#[derive(Clone)]
pub struct EventServiceImpl {
    pub(super) store: StorageFacade,
    pub(super) verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
    pub(super) egress_meter: SharedEgressMeter,

    /// Per-(tenant, org) POW state machine tracking verification failures.
    pub(super) pow_states: Arc<DashMap<PowStateKey, OrgPowState>>,

    /// POW verifier for replay detection and proof validation.
    pub(super) pow_verifier: Arc<PowVerifier>,

    /// POW configuration (shared across all orgs; per-org config is a future enhancement).
    pub(super) pow_config: OrgPowConfig,

    /// POW difficulty calculator for generating challenge parameters.
    pub(super) pow_calculator: Arc<PowDifficultyCalculator>,
}

impl EventServiceImpl {
    /// Create a new EventService with the default no-op egress meter.
    pub fn new(
        store: StorageFacade,
        verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
    ) -> Self {
        Self {
            store,
            verifier,
            egress_meter: default_egress_meter(),
            pow_states: Arc::new(DashMap::new()),
            pow_verifier: Arc::new(PowVerifier::new(100_000, 300)),
            pow_config: OrgPowConfig::default(),
            pow_calculator: Arc::new(Self::default_pow_calculator()),
        }
    }

    /// Create a new EventService with a custom egress meter.
    pub fn with_egress_meter(
        store: StorageFacade,
        verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
        egress_meter: SharedEgressMeter,
    ) -> Self {
        Self {
            store,
            verifier,
            egress_meter,
            pow_states: Arc::new(DashMap::new()),
            pow_verifier: Arc::new(PowVerifier::new(100_000, 300)),
            pow_config: OrgPowConfig::default(),
            pow_calculator: Arc::new(Self::default_pow_calculator()),
        }
    }

    /// Default POW difficulty calculator using benchmark-derived coefficients.
    fn default_pow_calculator() -> PowDifficultyCalculator {
        PowDifficultyCalculator::new(
            VerificationCostModel {
                per_byte_difficulty: 12.5,
                per_member_difficulty: 77750.0,
                base_difficulty: 8000.0,
                reference_device: "AMD Ryzen 9 5900X @ 3.7GHz".to_string(),
            },
            50_000, // cycles per proof (from rspow benchmarks)
            10,     // minimum proofs floor
            7,      // fixed bits per proof
        )
    }
}
