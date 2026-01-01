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

use serde::{Deserialize, Serialize};

/// Group POW configuration (set by group owner).
///
/// Controls when POW is triggered and how difficulty escalates/recovers.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::{GroupPowConfig, EscalationStrategy, RecoveryStrategy};
///
/// // Conservative config: trigger POW after 3 failures, escalate linearly
/// let config = GroupPowConfig {
///     failure_threshold: 3,
///     escalation_strategy: EscalationStrategy::Linear { step: 1.0 },
///     initial_multiplier: 3.0,
///     recovery_success_count: 10,
///     recovery_strategy: RecoveryStrategy::Gradual { steps: 3 },
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupPowConfig {
    /// Number of consecutive verification failures before triggering POW.
    pub failure_threshold: u32,

    /// How to escalate difficulty on repeated failures.
    pub escalation_strategy: EscalationStrategy,

    /// Initial POW multiplier when first triggered (default: 3.0).
    ///
    /// Meaning: POW cost = verification cost × initial_multiplier
    pub initial_multiplier: f64,

    /// Number of consecutive successes needed to recover (de-escalate or disable POW).
    pub recovery_success_count: u32,

    /// How to recover when successes meet threshold.
    pub recovery_strategy: RecoveryStrategy,
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
}

impl Default for GroupPowConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            escalation_strategy: EscalationStrategy::Linear { step: 1.0 },
            initial_multiplier: 3.0,
            recovery_success_count: 10,
            recovery_strategy: RecoveryStrategy::Immediate,
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
    /// If failures exceed threshold, triggers POW or escalates difficulty.
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
    /// // Third failure triggers POW (threshold=3)
    /// state.on_verification_failure(&config);
    /// assert!(state.pow_required);
    /// assert_eq!(state.current_multiplier, 3.0);
    /// ```
    pub fn on_verification_failure(&mut self, config: &GroupPowConfig) {
        // Reset success counter
        self.consecutive_successes = 0;

        // Increment failure counter
        self.consecutive_failures += 1;

        if !self.pow_required {
            // Not in POW mode yet - check if we should trigger
            if self.consecutive_failures >= config.failure_threshold {
                // Trigger POW with initial multiplier
                self.pow_required = true;
                self.current_multiplier = config.initial_multiplier;
            }
        } else {
            // Already in POW mode - escalate
            self.escalate(config);
        }
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
    /// use mandate_core::billing::{GroupPowState, GroupPowConfig, EscalationStrategy};
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

        if self.pow_required {
            // Increment success counter
            self.consecutive_successes += 1;

            // Check if we should recover
            if self.consecutive_successes >= config.recovery_success_count {
                self.recover(config);
            }
        }
    }

    /// Escalates POW difficulty based on escalation strategy.
    fn escalate(&mut self, config: &GroupPowConfig) {
        self.current_multiplier = match config.escalation_strategy {
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
                let reduction = match config.escalation_strategy {
                    EscalationStrategy::Linear { step } => step,
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
            failure_threshold: 1,
            escalation_strategy: EscalationStrategy::Linear { step: 1.5 },
            initial_multiplier: 3.0,
            recovery_success_count: 10,
            recovery_strategy: RecoveryStrategy::Immediate,
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
            failure_threshold: 1,
            escalation_strategy: EscalationStrategy::Exponential { base: 2.0 },
            initial_multiplier: 3.0,
            recovery_success_count: 10,
            recovery_strategy: RecoveryStrategy::Immediate,
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
            failure_threshold: 1,
            escalation_strategy: EscalationStrategy::Linear { step: 1.0 },
            initial_multiplier: 3.0,
            recovery_success_count: 2,
            recovery_strategy: RecoveryStrategy::Immediate,
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
            failure_threshold: 1,
            escalation_strategy: EscalationStrategy::Linear { step: 3.0 },
            initial_multiplier: 3.0,
            recovery_success_count: 2,
            recovery_strategy: RecoveryStrategy::Gradual { steps: 3 },
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
            failure_threshold: 1,
            escalation_strategy: EscalationStrategy::Linear { step: 1.0 },
            initial_multiplier: 3.0,
            recovery_success_count: 3,
            recovery_strategy: RecoveryStrategy::Immediate,
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
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.initial_multiplier, 3.0);
        assert_eq!(config.recovery_success_count, 10);
        assert_eq!(
            config.escalation_strategy,
            EscalationStrategy::Linear { step: 1.0 }
        );
        assert_eq!(config.recovery_strategy, RecoveryStrategy::Immediate);
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
