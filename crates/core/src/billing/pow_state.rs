//! Group POW state machine for DOS defense.
//!
//! Manages per-group POW requirements based on verification success/failure history.
//!
//! # State Transitions
//!
//! ```text
//! ┌──────────┐   failure   ┌──────────┐   failure   ┌──────────┐
//! │ No POW   │ ─────────▶ │  POW ×3  │ ─────────▶ │  POW ×N  │
//! │          │             │          │             │(escalate)│
//! └──────────┘             └──────────┘             └──────────┘
//!      ▲                                                    │
//!      │               M consecutive successes             │
//!      └────────────────────────────────────────────────────┘
//! ```
//!
//! # Upgrade Strategies
//!
//! Three strategies are available for triggering and escalating POW:
//!
//! - **TimeWindowBased**: Trigger when failure count exceeds threshold within time window
//!   and success rate falls below minimum
//! - **ConsecutiveFailure**: Trigger after N consecutive failures (simplest, stateless)
//! - **RateBased**: Trigger when failure rate exceeds threshold (responsive to bursts)
//!
//! Each strategy supports linear or exponential growth modes.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

#[cfg(not(target_arch = "wasm32"))]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
use js_sys;

/// Group POW configuration (set by group owner).
///
/// Controls when POW is triggered and how difficulty escalates/recovers.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::{GroupPowConfig, UpgradeStrategy, EscalationStrategy, RecoveryStrategy};
///
/// // Conservative config: trigger POW after 3 consecutive failures, escalate linearly
/// let config = GroupPowConfig {
///     upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
///         trigger_threshold: 3,
///         escalate_every: 1,
///         growth: EscalationStrategy::Linear { step: 1.0 },
///     },
///     initial_multiplier: 3.0,
///     recovery_success_count: 10,
///     recovery_strategy: RecoveryStrategy::Gradual { steps: 3 },
///     max_event_history: 1000,
/// };
///
/// // Time-window config: trigger if >5 failures in 60s with <90% success rate
/// let time_window_config = GroupPowConfig {
///     upgrade_strategy: UpgradeStrategy::TimeWindowBased {
///         window_secs: 60,
///         failure_threshold: 5,
///         min_success_rate: 0.90,
///         growth: EscalationStrategy::Linear { step: 1.0 },
///     },
///     initial_multiplier: 3.0,
///     recovery_success_count: 10,
///     recovery_strategy: RecoveryStrategy::Immediate,
///     max_event_history: 1000,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupPowConfig {
    /// Strategy for triggering and escalating POW.
    pub upgrade_strategy: UpgradeStrategy,

    /// Initial POW multiplier when first triggered (default: 3.0).
    ///
    /// Meaning: POW cost = verification cost × initial_multiplier
    pub initial_multiplier: f64,

    /// Number of consecutive successes needed to recover (de-escalate or disable POW).
    pub recovery_success_count: u32,

    /// How to recover when successes meet threshold.
    pub recovery_strategy: RecoveryStrategy,

    /// Maximum number of verification events to keep in history.
    ///
    /// Used by TimeWindowBased and RateBased strategies. Events older than
    /// the strategy's window are automatically pruned.
    pub max_event_history: usize,
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

    /// Gradually reduce multiplier over `steps` successes before disabling POW.
    ///
    /// Example with steps=3: 12 → 8 → 4 → 0 (disabled)
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
/// // Consecutive failure: trigger after 3 consecutive failures
/// let consecutive = UpgradeStrategy::ConsecutiveFailure {
///     trigger_threshold: 3,
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
        // Default to simple consecutive failure strategy (backward compatible)
        UpgradeStrategy::ConsecutiveFailure {
            trigger_threshold: 3,
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

/// A verification event record with timestamp.
///
/// Used by time-window-based and rate-based strategies to track
/// verification history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationEvent {
    /// Timestamp in milliseconds since UNIX epoch.
    pub timestamp_ms: u64,
    /// Whether this was a successful verification.
    pub success: bool,
}

impl VerificationEvent {
    /// Creates a new verification event with current timestamp.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn now(success: bool) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64;
        Self {
            timestamp_ms,
            success,
        }
    }

    /// Creates a new verification event with current timestamp (WASM version).
    #[cfg(target_arch = "wasm32")]
    pub fn now(success: bool) -> Self {
        // In WASM, use js_sys::Date for timestamp
        let timestamp_ms = js_sys::Date::now() as u64;
        Self {
            timestamp_ms,
            success,
        }
    }

    /// Creates a verification event with explicit timestamp (for testing).
    pub fn with_timestamp(timestamp_ms: u64, success: bool) -> Self {
        Self {
            timestamp_ms,
            success,
        }
    }
}

/// Current POW state for a group.
///
/// Tracks whether POW is required and at what difficulty level.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::GroupPowState;
///
/// let mut state = GroupPowState::default();
/// assert!(!state.pow_required);
/// assert_eq!(state.current_multiplier, 1.0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupPowState {
    /// Whether POW is currently required for this group.
    pub pow_required: bool,

    /// Current POW cost multiplier (1.0 = no POW, >1.0 = POW active).
    pub current_multiplier: f64,

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

impl Default for GroupPowConfig {
    fn default() -> Self {
        Self {
            upgrade_strategy: UpgradeStrategy::default(),
            initial_multiplier: 3.0,
            recovery_success_count: 10,
            recovery_strategy: RecoveryStrategy::Immediate,
            max_event_history: 1000,
        }
    }
}

impl Default for GroupPowState {
    fn default() -> Self {
        Self {
            pow_required: false,
            current_multiplier: 1.0,
            consecutive_failures: 0,
            consecutive_successes: 0,
            event_history: VecDeque::new(),
        }
    }
}

impl GroupPowState {
    /// Creates a new POW state (no POW required initially).
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles a verification failure event.
    ///
    /// If failures exceed threshold (based on upgrade strategy), triggers POW or escalates difficulty.
    ///
    /// # Parameters
    ///
    /// - `config`: Group POW configuration
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::{GroupPowState, GroupPowConfig};
    ///
    /// let mut state = GroupPowState::new();
    /// let config = GroupPowConfig::default();
    ///
    /// // First failure
    /// state.on_verification_failure(&config);
    /// assert!(!state.pow_required);
    /// assert_eq!(state.consecutive_failures, 1);
    ///
    /// // Second failure
    /// state.on_verification_failure(&config);
    /// assert!(!state.pow_required);
    ///
    /// // Third failure triggers POW (default threshold=3)
    /// state.on_verification_failure(&config);
    /// assert!(state.pow_required);
    /// assert_eq!(state.current_multiplier, 3.0);
    /// ```
    pub fn on_verification_failure(&mut self, config: &GroupPowConfig) {
        // Reset success counter
        self.consecutive_successes = 0;

        // Increment failure counter
        self.consecutive_failures += 1;

        // Record event for time-window strategies
        self.record_event(false, config);

        if !self.pow_required {
            // Not in POW mode yet - check if we should trigger
            if self.should_trigger(config) {
                // Trigger POW with initial multiplier
                self.pow_required = true;
                self.current_multiplier = config.initial_multiplier;
            }
        } else {
            // Already in POW mode - escalate
            self.escalate(config);
        }
    }

    /// Records a verification event in history (for time-window strategies).
    fn record_event(&mut self, success: bool, config: &GroupPowConfig) {
        let event = VerificationEvent::now(success);
        self.event_history.push_back(event);

        // Prune old events exceeding max history
        while self.event_history.len() > config.max_event_history {
            self.event_history.pop_front();
        }
    }

    /// Records a verification event with explicit timestamp (for testing).
    #[cfg(test)]
    #[allow(dead_code)] // Reserved for Phase 5.7 POW E2E tests
    fn record_event_at(&mut self, timestamp_ms: u64, success: bool, config: &GroupPowConfig) {
        let event = VerificationEvent::with_timestamp(timestamp_ms, success);
        self.event_history.push_back(event);

        // Prune old events exceeding max history
        while self.event_history.len() > config.max_event_history {
            self.event_history.pop_front();
        }
    }

    /// Checks if POW should be triggered based on upgrade strategy.
    fn should_trigger(&self, config: &GroupPowConfig) -> bool {
        match &config.upgrade_strategy {
            UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold, ..
            } => self.consecutive_failures >= *trigger_threshold,
            UpgradeStrategy::TimeWindowBased {
                window_secs,
                failure_threshold,
                min_success_rate,
                ..
            } => {
                let (failures, total) = self.count_events_in_window(*window_secs);
                if total == 0 {
                    return false;
                }
                let success_rate = (total - failures) as f64 / total as f64;
                failures >= *failure_threshold && success_rate < *min_success_rate
            }
            UpgradeStrategy::RateBased {
                rate_window_secs,
                max_failure_rate,
                ..
            } => {
                let (failures, total) = self.count_events_in_window(*rate_window_secs);
                if total == 0 {
                    return false;
                }
                let failure_rate = failures as f64 / total as f64;
                failure_rate > *max_failure_rate
            }
        }
    }

    /// Counts failures and total events within the time window.
    fn count_events_in_window(&self, window_secs: u64) -> (u32, u32) {
        let now_ms = Self::current_timestamp_ms();
        let window_start_ms = now_ms.saturating_sub(window_secs * 1000);

        let mut failures = 0u32;
        let mut total = 0u32;

        for event in self.event_history.iter() {
            if event.timestamp_ms >= window_start_ms {
                total += 1;
                if !event.success {
                    failures += 1;
                }
            }
        }

        (failures, total)
    }

    /// Returns the current timestamp in milliseconds.
    #[cfg(not(target_arch = "wasm32"))]
    fn current_timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64
    }

    /// Returns the current timestamp in milliseconds (WASM version).
    #[cfg(target_arch = "wasm32")]
    fn current_timestamp_ms() -> u64 {
        js_sys::Date::now() as u64
    }

    /// Handles a verification success event.
    ///
    /// If successes meet threshold, recovers (de-escalates or disables POW).
    ///
    /// # Parameters
    ///
    /// - `config`: Group POW configuration
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::{GroupPowState, GroupPowConfig};
    ///
    /// let mut state = GroupPowState::new();
    /// let mut config = GroupPowConfig::default();
    /// config.recovery_success_count = 2;
    ///
    /// // Trigger POW
    /// for _ in 0..3 {
    ///     state.on_verification_failure(&config);
    /// }
    /// assert!(state.pow_required);
    ///
    /// // First success
    /// state.on_verification_success(&config);
    /// assert!(state.pow_required); // Still required
    ///
    /// // Second success triggers recovery (threshold=2)
    /// state.on_verification_success(&config);
    /// assert!(!state.pow_required); // Immediate recovery
    /// ```
    pub fn on_verification_success(&mut self, config: &GroupPowConfig) {
        // Reset failure counter
        self.consecutive_failures = 0;

        // Record event for time-window strategies
        self.record_event(true, config);

        if self.pow_required {
            // Increment success counter
            self.consecutive_successes += 1;

            // Check if we should recover
            if self.consecutive_successes >= config.recovery_success_count {
                self.recover(config);
            }
        }
    }

    /// Escalates POW difficulty based on upgrade strategy's growth mode.
    fn escalate(&mut self, config: &GroupPowConfig) {
        let growth = config.upgrade_strategy.growth();
        self.current_multiplier = match growth {
            EscalationStrategy::Linear { step } => self.current_multiplier + step,
            EscalationStrategy::Exponential { base } => self.current_multiplier * base,
        };
    }

    /// Recovers from POW mode based on recovery strategy.
    fn recover(&mut self, config: &GroupPowConfig) {
        match config.recovery_strategy {
            RecoveryStrategy::Immediate => {
                // Immediately disable POW
                self.pow_required = false;
                self.current_multiplier = 1.0;
                self.consecutive_successes = 0;
            }
            RecoveryStrategy::Gradual { steps: _ } => {
                // Gradually reduce multiplier by reversing one escalation step
                // This makes recovery symmetric with escalation
                let growth = config.upgrade_strategy.growth();
                let reduction = match growth {
                    EscalationStrategy::Linear { step } => *step,
                    EscalationStrategy::Exponential { base } => {
                        // For exponential, divide by base (inverse of multiplication)
                        self.current_multiplier - (self.current_multiplier / base)
                    }
                };

                self.current_multiplier -= reduction;

                // If we've reduced to or below initial multiplier, disable POW
                if self.current_multiplier <= config.initial_multiplier {
                    self.pow_required = false;
                    self.current_multiplier = 1.0;
                }

                // Reset success counter for next recovery step
                self.consecutive_successes = 0;
            }
        }
    }

    /// Returns whether POW is currently required.
    pub fn should_require_pow(&self) -> bool {
        self.pow_required
    }

    /// Returns the current POW cost multiplier.
    pub fn get_current_multiplier(&self) -> f64 {
        self.current_multiplier
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let state = GroupPowState::new();
        assert!(!state.should_require_pow());
        assert_eq!(state.get_current_multiplier(), 1.0);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.consecutive_successes, 0);
    }

    #[test]
    fn test_trigger_pow_after_threshold() {
        let mut state = GroupPowState::new();
        let config = GroupPowConfig::default(); // threshold=3

        // First two failures don't trigger
        state.on_verification_failure(&config);
        assert!(!state.should_require_pow());
        state.on_verification_failure(&config);
        assert!(!state.should_require_pow());

        // Third failure triggers POW
        state.on_verification_failure(&config);
        assert!(state.should_require_pow());
        assert_eq!(state.get_current_multiplier(), 3.0);
    }

    #[test]
    fn test_linear_escalation() {
        let mut state = GroupPowState::new();
        let config = GroupPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 1.5 },
            },
            initial_multiplier: 3.0,
            recovery_success_count: 10,
            recovery_strategy: RecoveryStrategy::Immediate,
            max_event_history: 1000,
        };

        // Trigger POW
        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 3.0);

        // Escalate linearly: +1.5 each time
        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 4.5);

        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 6.0);

        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 7.5);
    }

    #[test]
    fn test_exponential_escalation() {
        let mut state = GroupPowState::new();
        let config = GroupPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Exponential { base: 2.0 },
            },
            initial_multiplier: 3.0,
            recovery_success_count: 10,
            recovery_strategy: RecoveryStrategy::Immediate,
            max_event_history: 1000,
        };

        // Trigger POW
        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 3.0);

        // Escalate exponentially: ×2 each time
        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 6.0);

        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 12.0);

        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 24.0);
    }

    #[test]
    fn test_immediate_recovery() {
        let mut state = GroupPowState::new();
        let config = GroupPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 1.0 },
            },
            initial_multiplier: 3.0,
            recovery_success_count: 2,
            recovery_strategy: RecoveryStrategy::Immediate,
            max_event_history: 1000,
        };

        // Trigger and escalate POW
        state.on_verification_failure(&config);
        state.on_verification_failure(&config);
        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 5.0); // 3 + 1 + 1

        // First success
        state.on_verification_success(&config);
        assert!(state.should_require_pow());
        assert_eq!(state.consecutive_successes, 1);

        // Second success triggers immediate recovery
        state.on_verification_success(&config);
        assert!(!state.should_require_pow());
        assert_eq!(state.get_current_multiplier(), 1.0);
        assert_eq!(state.consecutive_successes, 0);
    }

    #[test]
    fn test_gradual_recovery() {
        let mut state = GroupPowState::new();
        let config = GroupPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 3.0 },
            },
            initial_multiplier: 3.0,
            recovery_success_count: 2,
            recovery_strategy: RecoveryStrategy::Gradual { steps: 3 },
            max_event_history: 1000,
        };

        // Escalate to 12.0:
        // - Failure 1: triggers POW at 3.0
        // - Failure 2: escalate to 6.0
        // - Failure 3: escalate to 9.0
        // - Failure 4: escalate to 12.0
        state.on_verification_failure(&config);
        state.on_verification_failure(&config);
        state.on_verification_failure(&config);
        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 12.0);

        // Step size = (12 - 3) / 3 = 3.0
        // Recovery step 1: 12 → 9
        for _ in 0..config.recovery_success_count {
            state.on_verification_success(&config);
        }
        assert_eq!(state.get_current_multiplier(), 9.0);
        assert!(state.should_require_pow());

        // Recovery step 2: 9 → 6
        for _ in 0..config.recovery_success_count {
            state.on_verification_success(&config);
        }
        assert_eq!(state.get_current_multiplier(), 6.0);

        // Recovery step 3: 6 → 3 (below or equal to initial, disables POW)
        for _ in 0..config.recovery_success_count {
            state.on_verification_success(&config);
        }
        assert!(!state.should_require_pow());
        assert_eq!(state.get_current_multiplier(), 1.0);
    }

    #[test]
    fn test_success_resets_failures() {
        let mut state = GroupPowState::new();
        let config = GroupPowConfig::default(); // threshold=3

        // Two failures
        state.on_verification_failure(&config);
        state.on_verification_failure(&config);
        assert_eq!(state.consecutive_failures, 2);

        // Success resets failure counter
        state.on_verification_success(&config);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.consecutive_successes, 0); // Not in POW mode yet

        // Need 3 consecutive failures again to trigger
        state.on_verification_failure(&config);
        state.on_verification_failure(&config);
        assert!(!state.should_require_pow());
    }

    #[test]
    fn test_failure_resets_successes() {
        let mut state = GroupPowState::new();
        let config = GroupPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 1.0 },
            },
            initial_multiplier: 3.0,
            recovery_success_count: 3,
            recovery_strategy: RecoveryStrategy::Immediate,
            max_event_history: 1000,
        };

        // Trigger POW
        state.on_verification_failure(&config);
        assert!(state.should_require_pow());

        // Two successes
        state.on_verification_success(&config);
        state.on_verification_success(&config);
        assert_eq!(state.consecutive_successes, 2);

        // Failure resets success counter and escalates
        state.on_verification_failure(&config);
        assert_eq!(state.consecutive_successes, 0);
        assert_eq!(state.get_current_multiplier(), 4.0); // Escalated
    }

    #[test]
    fn test_default_config() {
        let config = GroupPowConfig::default();
        assert_eq!(
            config.upgrade_strategy,
            UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 3,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 1.0 },
            }
        );
        assert_eq!(config.initial_multiplier, 3.0);
        assert_eq!(config.recovery_success_count, 10);
        assert_eq!(config.recovery_strategy, RecoveryStrategy::Immediate);
        assert_eq!(config.max_event_history, 1000);
    }

    #[test]
    fn test_serialization() {
        let config = GroupPowConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: GroupPowConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);

        let state = GroupPowState::new();
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: GroupPowState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }
}
