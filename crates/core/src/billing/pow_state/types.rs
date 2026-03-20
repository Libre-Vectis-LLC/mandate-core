//! Core type definitions for POW state machine.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::VecDeque;

use super::constants::{default_max_multiplier, normalize_max_multiplier};
use super::event::VerificationEvent;

/// Custom deserializer for max_multiplier to handle backward compatibility.
///
/// Treats 0 or negative values as default (1000.0).
fn deserialize_max_multiplier<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = f64::deserialize(deserializer)?;
    Ok(normalize_max_multiplier(value))
}

fn default_time_window_secs() -> u64 {
    60
}

/// Organization POW configuration (set by org owner).
///
/// Controls when POW is triggered and how difficulty escalates/recovers.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::{OrgPowConfig, UpgradeStrategy, EscalationStrategy, RecoveryStrategy};
///
/// // Conservative config: trigger POW immediately, escalate linearly on later failures
/// let config = OrgPowConfig {
///     upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
///         trigger_threshold: 1,
///         escalate_every: 1,
///         growth: EscalationStrategy::Linear { step: 1.0 },
///     },
///     initial_multiplier: 3.0,
///     max_multiplier: 1000.0,
///     recovery_success_count: 10,
///     recovery_strategy: RecoveryStrategy::Gradual { steps: 3 },
///     time_window_secs: 60,
///     max_event_history: 1000,
/// };
///
/// // Time-window config: trigger if >5 failures in 60s with <90% success rate
/// let time_window_config = OrgPowConfig {
///     upgrade_strategy: UpgradeStrategy::TimeWindowBased {
///         window_secs: 60,
///         failure_threshold: 5,
///         min_success_rate: 0.90,
///         growth: EscalationStrategy::Linear { step: 1.0 },
///     },
///     initial_multiplier: 3.0,
///     max_multiplier: 1000.0,
///     recovery_success_count: 10,
///     recovery_strategy: RecoveryStrategy::Immediate,
///     time_window_secs: 60,
///     max_event_history: 1000,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrgPowConfig {
    /// Strategy for triggering and escalating POW.
    pub upgrade_strategy: UpgradeStrategy,

    /// Initial POW multiplier when first triggered (default: 3.0).
    ///
    /// Meaning: POW cost = verification cost × initial_multiplier
    pub initial_multiplier: f64,

    /// Maximum POW multiplier allowed before capping escalation (default: 1000.0).
    ///
    /// Prevents unbounded difficulty growth. If 0 or negative, defaults to 1000.0.
    #[serde(
        default = "default_max_multiplier",
        deserialize_with = "deserialize_max_multiplier"
    )]
    pub max_multiplier: f64,

    /// Number of consecutive successes needed to recover (de-escalate or disable POW).
    pub recovery_success_count: u32,

    /// How to recover when successes meet threshold.
    pub recovery_strategy: RecoveryStrategy,

    /// Time window in seconds for issued POW challenges.
    #[serde(default = "default_time_window_secs")]
    pub time_window_secs: u64,

    /// Maximum number of verification events to keep in history.
    ///
    /// Used by TimeWindowBased and RateBased strategies. Events older than
    /// the strategy's window are automatically pruned.
    pub max_event_history: usize,
}

impl Default for OrgPowConfig {
    fn default() -> Self {
        Self {
            upgrade_strategy: UpgradeStrategy::default(),
            initial_multiplier: 3.0,
            max_multiplier: default_max_multiplier(),
            recovery_success_count: 10,
            recovery_strategy: RecoveryStrategy::Gradual { steps: 1 },
            time_window_secs: default_time_window_secs(),
            max_event_history: 1000,
        }
    }
}

/// POW difficulty escalation strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EscalationStrategy {
    /// Linear escalation: multiplier increases by `step` each failure.
    ///
    /// Example with step=1.0: 3 → 4 → 5 → 6 → ...
    Linear { step: f64 },

    /// Exponential escalation: multiplier multiplies by `base` each failure.
    ///
    /// Example with base=2.0: 3 → 6 → 12 → 24 → ...
    Exponential { base: f64 },
}

/// Recovery strategy when verification successes meet threshold.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RecoveryStrategy {
    /// Immediately return to no POW state.
    Immediate,

    /// Gradually reduce difficulty one level at a time after each recovery streak.
    ///
    /// `steps` is retained for serialized compatibility with earlier configs.
    Gradual { steps: u32 },
}

/// Upgrade (trigger/escalation) strategy for POW activation.
///
/// Determines **when** POW should be triggered or escalated.
/// Each variant supports linear or exponential difficulty growth.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::{UpgradeStrategy, EscalationStrategy};
///
/// // Time-window based: trigger if >5 failures in 60s with <90% success rate
/// let time_window = UpgradeStrategy::TimeWindowBased {
///     window_secs: 60,
///     failure_threshold: 5,
///     min_success_rate: 0.90,
///     growth: EscalationStrategy::Linear { step: 1.0 },
/// };
///
/// // Consecutive failure: trigger on the first failure
/// let consecutive = UpgradeStrategy::ConsecutiveFailure {
///     trigger_threshold: 1,
///     escalate_every: 1,
///     growth: EscalationStrategy::Exponential { base: 2.0 },
/// };
///
/// // Rate-based: trigger if failure rate exceeds 10% in 30s window
/// let rate_based = UpgradeStrategy::RateBased {
///     rate_window_secs: 30,
///     max_failure_rate: 0.10,
///     growth: EscalationStrategy::Linear { step: 0.5 },
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UpgradeStrategy {
    /// Time-window based triggering.
    ///
    /// Triggers when failure count exceeds threshold within time window
    /// AND success rate falls below minimum.
    TimeWindowBased {
        /// Time window in seconds for failure counting.
        window_secs: u64,
        /// Number of failures within window to trigger POW.
        failure_threshold: u32,
        /// Minimum success rate required (0.0-1.0, e.g., 0.90 = 90%).
        /// Below this rate, POW is triggered.
        min_success_rate: f64,
        /// How difficulty grows on escalation.
        growth: EscalationStrategy,
    },

    /// Consecutive failure triggering (simplest, stateless).
    ///
    /// Triggers after N consecutive failures. Escalates every M additional failures.
    ConsecutiveFailure {
        /// Number of consecutive failures to trigger POW.
        trigger_threshold: u32,
        /// Escalate difficulty every N additional failures after trigger.
        escalate_every: u32,
        /// How difficulty grows on escalation.
        growth: EscalationStrategy,
    },

    /// Rate-based triggering (responsive to bursts).
    ///
    /// Triggers when failure rate exceeds threshold.
    RateBased {
        /// Time window in seconds for rate calculation.
        rate_window_secs: u64,
        /// Maximum allowed failure rate (0.0-1.0, e.g., 0.10 = 10%).
        /// Exceeding this rate triggers POW.
        max_failure_rate: f64,
        /// How difficulty grows on escalation.
        growth: EscalationStrategy,
    },
}

impl Default for UpgradeStrategy {
    fn default() -> Self {
        // Default to simple consecutive failure strategy.
        UpgradeStrategy::ConsecutiveFailure {
            trigger_threshold: 1,
            escalate_every: 1,
            growth: EscalationStrategy::Linear { step: 1.0 },
        }
    }
}

impl UpgradeStrategy {
    /// Returns the growth (escalation) strategy for this upgrade strategy.
    pub fn growth(&self) -> &EscalationStrategy {
        match self {
            UpgradeStrategy::TimeWindowBased { growth, .. } => growth,
            UpgradeStrategy::ConsecutiveFailure { growth, .. } => growth,
            UpgradeStrategy::RateBased { growth, .. } => growth,
        }
    }
}

/// Current POW state for an org.
///
/// Tracks whether POW is required and at what difficulty level.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::OrgPowState;
///
/// let mut state = OrgPowState::default();
/// assert!(!state.pow_required);
/// assert_eq!(state.current_multiplier, 1.0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrgPowState {
    /// Whether POW is currently required for this org.
    pub pow_required: bool,

    /// Current POW cost multiplier (1.0 = no POW, >1.0 = POW active).
    pub current_multiplier: f64,

    /// Monotonic version for the active POW difficulty semantics.
    ///
    /// Incremented whenever the effective challenge difficulty changes so
    /// previously issued proofs cannot be replayed across difficulty epochs.
    #[serde(default)]
    pub difficulty_version: u64,

    /// Number of consecutive verification failures.
    pub consecutive_failures: u32,

    /// Number of consecutive verification successes.
    pub consecutive_successes: u32,

    /// Verification event history for time-window and rate-based strategies.
    ///
    /// Events are stored in chronological order (oldest first).
    /// Automatically pruned when exceeding max_event_history.
    #[serde(default)]
    pub event_history: VecDeque<VerificationEvent>,
}

impl Default for OrgPowState {
    fn default() -> Self {
        Self {
            pow_required: false,
            current_multiplier: 1.0,
            difficulty_version: 0,
            consecutive_failures: 0,
            consecutive_successes: 0,
            event_history: VecDeque::new(),
        }
    }
}
