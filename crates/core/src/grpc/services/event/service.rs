//! EventService implementation struct and constructors.
//!
//! This module is gated behind `#[cfg(not(target_arch = "wasm32"))]` at the crate root,
//! so all code here is host-only (no WASM).

use crate::billing::OrgPowState;
use crate::billing::{
    default_egress_meter, default_verification_meter, OrgPowConfig, PowDifficultyCalculator,
    SharedEgressMeter, SharedVerificationMeter, VerificationCostModel,
};
use crate::ids::{OrganizationId, RingHash, TenantId};
use crate::pow::PowVerifier;
use crate::storage::facade::StorageFacade;
use dashmap::DashMap;
use moka::future::Cache;
use nazgul::ring::Ring;
use std::sync::Arc;
use std::time::Duration;

/// Composite key for per-tenant, per-org POW state tracking.
type PowStateKey = (TenantId, OrganizationId);
/// Cache key for derived per-poll vote signing rings.
type VoteSigningRingCacheKey = (TenantId, OrganizationId, RingHash, String);

/// EventService implementation with integrated POW defense.
///
/// Tracks per-(tenant, org) verification failure history and enforces
/// proof-of-work requirements when failure thresholds are exceeded.
#[derive(Clone)]
pub struct EventServiceImpl {
    pub(super) store: StorageFacade,
    pub(super) verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
    pub(super) egress_meter: SharedEgressMeter,
    pub(super) verification_meter: SharedVerificationMeter,

    /// Per-(tenant, org) POW state machine tracking verification failures.
    pub(super) pow_states: Arc<DashMap<PowStateKey, OrgPowState>>,

    /// POW verifier for replay detection and proof validation.
    pub(super) pow_verifier: Arc<PowVerifier>,

    /// POW configuration (shared across all orgs; per-org config is a future enhancement).
    pub(super) pow_config: OrgPowConfig,

    /// POW difficulty calculator for generating challenge parameters.
    pub(super) pow_calculator: Arc<PowDifficultyCalculator>,

    /// Derived vote signing ring cache keyed by (tenant, org, poll ring, poll id).
    pub(super) vote_signing_ring_cache: Arc<Cache<VoteSigningRingCacheKey, Arc<Ring>>>,
}

impl EventServiceImpl {
    /// Create a new EventService with default no-op meters.
    pub fn new(
        store: StorageFacade,
        verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
    ) -> Self {
        Self {
            store,
            verifier,
            egress_meter: default_egress_meter(),
            verification_meter: default_verification_meter(),
            pow_states: Arc::new(DashMap::new()),
            pow_verifier: Arc::new(PowVerifier::new(100_000, 300)),
            pow_config: OrgPowConfig::default(),
            pow_calculator: Arc::new(Self::default_pow_calculator()),
            vote_signing_ring_cache: Arc::new(Self::default_vote_signing_ring_cache()),
        }
    }

    /// Create a new EventService with custom meters.
    pub fn with_meters(
        store: StorageFacade,
        verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
        egress_meter: SharedEgressMeter,
        verification_meter: SharedVerificationMeter,
    ) -> Self {
        Self {
            store,
            verifier,
            egress_meter,
            verification_meter,
            pow_states: Arc::new(DashMap::new()),
            pow_verifier: Arc::new(PowVerifier::new(100_000, 300)),
            pow_config: OrgPowConfig::default(),
            pow_calculator: Arc::new(Self::default_pow_calculator()),
            vote_signing_ring_cache: Arc::new(Self::default_vote_signing_ring_cache()),
        }
    }

    /// Create a new EventService with a custom egress meter and default verification meter.
    pub fn with_egress_meter(
        store: StorageFacade,
        verifier: Arc<dyn crate::crypto::verifier::SignatureVerifier>,
        egress_meter: SharedEgressMeter,
    ) -> Self {
        Self::with_meters(store, verifier, egress_meter, default_verification_meter())
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

    fn default_vote_signing_ring_cache() -> Cache<VoteSigningRingCacheKey, Arc<Ring>> {
        Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(15 * 60))
            .build()
    }
}
