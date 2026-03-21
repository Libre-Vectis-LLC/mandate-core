//! Organization POW state machine for DOS defense.
//!
//! Manages per-org POW requirements based on verification success/failure history.
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

mod constants;
mod event;
mod state_machine;
mod time;
mod types;

// Re-export public types for backward compatibility
pub use event::VerificationEvent;
pub use types::{EscalationStrategy, OrgPowConfig, OrgPowState, RecoveryStrategy, UpgradeStrategy};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let state = OrgPowState::new();
        assert!(!state.should_require_pow());
        assert_eq!(state.get_current_multiplier(), 1.0);
        assert_eq!(state.get_difficulty_version(), 0);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.consecutive_successes, 0);
    }

    #[test]
    fn test_trigger_pow_on_first_failure_by_default() {
        let mut state = OrgPowState::new();
        let config = OrgPowConfig::default();

        // First failure immediately triggers POW
        state.on_verification_failure(&config);
        assert!(state.should_require_pow());
        assert_eq!(state.get_current_multiplier(), 3.0);
        assert_eq!(state.get_difficulty_version(), 1);
        assert_eq!(state.consecutive_failures, 1);
    }

    #[test]
    fn test_linear_escalation() {
        let mut state = OrgPowState::new();
        let config = OrgPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 1.5 },
            },
            initial_multiplier: 3.0,
            max_multiplier: 1000.0,
            recovery_success_count: 10,
            recovery_strategy: RecoveryStrategy::Immediate,
            time_window_secs: 60,
            max_event_history: 1000,
        };

        // Trigger POW
        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 3.0);
        assert_eq!(state.get_difficulty_version(), 1);

        // Escalate linearly: +1.5 each time
        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 4.5);
        assert_eq!(state.get_difficulty_version(), 2);

        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 6.0);
        assert_eq!(state.get_difficulty_version(), 3);

        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 7.5);
        assert_eq!(state.get_difficulty_version(), 4);
    }

    #[test]
    fn test_exponential_escalation() {
        let mut state = OrgPowState::new();
        let config = OrgPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Exponential { base: 2.0 },
            },
            initial_multiplier: 3.0,
            max_multiplier: 1000.0,
            recovery_success_count: 10,
            recovery_strategy: RecoveryStrategy::Immediate,
            time_window_secs: 60,
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
        let mut state = OrgPowState::new();
        let config = OrgPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 1.0 },
            },
            initial_multiplier: 3.0,
            max_multiplier: 1000.0,
            recovery_success_count: 2,
            recovery_strategy: RecoveryStrategy::Immediate,
            time_window_secs: 60,
            max_event_history: 1000,
        };

        // Trigger and escalate POW
        state.on_verification_failure(&config);
        state.on_verification_failure(&config);
        state.on_verification_failure(&config);
        assert_eq!(state.get_current_multiplier(), 5.0); // 3 + 1 + 1
        assert_eq!(state.get_difficulty_version(), 3);

        // First success
        state.on_verification_success(&config);
        assert!(state.should_require_pow());
        assert_eq!(state.consecutive_successes, 1);

        // Second success triggers immediate recovery
        state.on_verification_success(&config);
        assert!(!state.should_require_pow());
        assert_eq!(state.get_current_multiplier(), 1.0);
        assert_eq!(state.get_difficulty_version(), 4);
        assert_eq!(state.consecutive_successes, 0);
    }

    #[test]
    fn test_gradual_recovery_hysteresis_decrements_one_level_per_streak() {
        let mut state = OrgPowState {
            pow_required: true,
            current_multiplier: 30.0,
            ..OrgPowState::default()
        };
        let config = OrgPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 1.0 },
            },
            initial_multiplier: 3.0,
            max_multiplier: 1000.0,
            recovery_success_count: 10,
            recovery_strategy: RecoveryStrategy::Gradual { steps: 3 },
            time_window_secs: 60,
            max_event_history: 1000,
        };

        // Recovery step 1: 30 -> 29 after 10 consecutive successes
        for _ in 0..config.recovery_success_count {
            state.on_verification_success(&config);
        }
        assert_eq!(state.get_current_multiplier(), 29.0);
        assert!(state.should_require_pow());
        assert_eq!(state.consecutive_successes, 0);

        // Recovery step 2: 29 -> 28 after another 10 successes
        for _ in 0..config.recovery_success_count {
            state.on_verification_success(&config);
        }
        assert_eq!(state.get_current_multiplier(), 28.0);
        assert!(state.should_require_pow());
    }

    #[test]
    fn test_success_resets_failures() {
        let mut state = OrgPowState::new();
        let config = OrgPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 2,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 1.0 },
            },
            ..OrgPowConfig::default()
        };

        // A single failure does not trigger with this custom threshold.
        state.on_verification_failure(&config);
        assert_eq!(state.consecutive_failures, 1);
        assert!(!state.should_require_pow());

        // Success resets failure counter
        state.on_verification_success(&config);
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.consecutive_successes, 0); // Not in POW mode yet

        // Need 2 consecutive failures again to trigger
        state.on_verification_failure(&config);
        assert!(!state.should_require_pow());
        state.on_verification_failure(&config);
        assert!(state.should_require_pow());
    }

    #[test]
    fn test_failure_resets_successes() {
        let mut state = OrgPowState::new();
        let config = OrgPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 1.0 },
            },
            initial_multiplier: 3.0,
            max_multiplier: 1000.0,
            recovery_success_count: 3,
            recovery_strategy: RecoveryStrategy::Immediate,
            time_window_secs: 60,
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
        assert_eq!(state.get_difficulty_version(), 2);
    }

    #[test]
    fn test_default_config() {
        let config = OrgPowConfig::default();
        assert_eq!(
            config.upgrade_strategy,
            UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 1.0 },
            }
        );
        assert_eq!(config.initial_multiplier, 3.0);
        assert_eq!(config.max_multiplier, 1000.0);
        assert_eq!(config.recovery_success_count, 10);
        assert_eq!(
            config.recovery_strategy,
            RecoveryStrategy::Gradual { steps: 1 }
        );
        assert_eq!(config.time_window_secs, 60);
        assert_eq!(config.max_event_history, 1000);
    }

    #[test]
    fn test_max_multiplier_enforced() {
        let config = OrgPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 100.0 },
            },
            initial_multiplier: 3.0,
            max_multiplier: 50.0, // Set low cap for testing
            recovery_success_count: 10,
            recovery_strategy: RecoveryStrategy::Immediate,
            time_window_secs: 60,
            max_event_history: 1000,
        };

        let mut state = OrgPowState::new();

        // First failure triggers POW at initial_multiplier
        state.on_verification_failure(&config);
        assert!(state.pow_required);
        assert_eq!(state.current_multiplier, 3.0);

        // Second failure escalates, but should be capped at max_multiplier
        state.on_verification_failure(&config);
        // Without cap, would be 3.0 + 100.0 = 103.0
        // With cap, should be limited to 50.0
        assert_eq!(state.current_multiplier, 50.0);

        // Further failures should not increase beyond cap
        state.on_verification_failure(&config);
        assert_eq!(state.current_multiplier, 50.0);
    }

    #[test]
    fn test_max_multiplier_default_normalization() {
        // Test that 0 or negative max_multiplier defaults to 1000.0
        let json_with_zero = r#"{
            "upgrade_strategy": {"ConsecutiveFailure": {"trigger_threshold": 1, "escalate_every": 1, "growth": {"Linear": {"step": 1.0}}}},
            "initial_multiplier": 3.0,
            "max_multiplier": 0.0,
            "recovery_success_count": 10,
            "recovery_strategy": "Immediate",
            "time_window_secs": 60,
            "max_event_history": 1000
        }"#;
        let config: OrgPowConfig = serde_json::from_str(json_with_zero).unwrap();
        assert_eq!(config.max_multiplier, 1000.0);
        assert_eq!(config.time_window_secs, 60);

        let json_with_negative = r#"{
            "upgrade_strategy": {"ConsecutiveFailure": {"trigger_threshold": 1, "escalate_every": 1, "growth": {"Linear": {"step": 1.0}}}},
            "initial_multiplier": 3.0,
            "max_multiplier": -5.0,
            "recovery_success_count": 10,
            "recovery_strategy": "Immediate",
            "time_window_secs": 60,
            "max_event_history": 1000
        }"#;
        let config: OrgPowConfig = serde_json::from_str(json_with_negative).unwrap();
        assert_eq!(config.max_multiplier, 1000.0);
        assert_eq!(config.time_window_secs, 60);

        // Test that missing max_multiplier uses default
        let json_without_field = r#"{
            "upgrade_strategy": {"ConsecutiveFailure": {"trigger_threshold": 1, "escalate_every": 1, "growth": {"Linear": {"step": 1.0}}}},
            "initial_multiplier": 3.0,
            "recovery_success_count": 10,
            "recovery_strategy": "Immediate",
            "max_event_history": 1000
        }"#;
        let config: OrgPowConfig = serde_json::from_str(json_without_field).unwrap();
        assert_eq!(config.max_multiplier, 1000.0);
        assert_eq!(config.time_window_secs, 60);
    }

    #[test]
    fn test_serialization() {
        let config = OrgPowConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: OrgPowConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, deserialized);

        let state = OrgPowState::new();
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: OrgPowState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    /// Verify K=1 trigger semantics with default config: the very first signature
    /// verification failure must activate PoW immediately, increment the difficulty
    /// version, and set the initial multiplier.
    #[test]
    fn test_pow_k1_trigger_semantics() {
        let config = OrgPowConfig::default();
        let mut state = OrgPowState::new();

        // Precondition: no PoW required before any failure
        assert!(!state.should_require_pow());
        assert_eq!(state.get_difficulty_version(), 0);
        assert_eq!(state.get_current_multiplier(), 1.0);

        // K=1: first failure must activate PoW
        state.on_verification_failure(&config);
        assert!(
            state.should_require_pow(),
            "K=1 trigger: first failure should activate PoW"
        );
        assert!(
            state.get_difficulty_version() > 0,
            "difficulty version must increment on trigger"
        );
        assert_eq!(
            state.get_current_multiplier(),
            config.initial_multiplier,
            "multiplier must equal initial_multiplier on first trigger"
        );
    }

    /// Test recovery using default config (Gradual recovery, recovery_success_count=10).
    ///
    /// With the default `RecoveryStrategy::Gradual { steps: 1 }` and `initial_multiplier: 3.0`,
    /// after trigger the multiplier is 3.0. Each recovery streak of 10 successes decrements
    /// the multiplier by 1.0 until it reaches 1.0 (PoW disabled).
    #[test]
    fn test_pow_recovery_default_config() {
        let config = OrgPowConfig::default();
        let mut state = OrgPowState::new();

        // Trigger PoW
        state.on_verification_failure(&config);
        assert!(state.should_require_pow());
        assert_eq!(state.get_current_multiplier(), 3.0);

        // First recovery streak: 3.0 -> 2.0 (still active)
        for _ in 0..config.recovery_success_count {
            state.on_verification_success(&config);
        }
        assert!(
            state.should_require_pow(),
            "should still require PoW at multiplier 2.0"
        );
        assert_eq!(state.get_current_multiplier(), 2.0);

        // Second recovery streak: 2.0 -> 1.0 (PoW disabled)
        for _ in 0..config.recovery_success_count {
            state.on_verification_success(&config);
        }
        assert!(
            !state.should_require_pow(),
            "should recover after multiplier reaches 1.0"
        );
        assert_eq!(state.get_current_multiplier(), 1.0);
    }

    /// Test difficulty escalation across consecutive failures (K=1 default config).
    ///
    /// With the default `ConsecutiveFailure { trigger_threshold: 1, escalate_every: 1,
    /// growth: Linear { step: 1.0 } }`, each subsequent failure should escalate the
    /// difficulty version and multiplier.
    #[test]
    fn test_pow_difficulty_escalation_default() {
        let config = OrgPowConfig::default();
        let mut state = OrgPowState::new();

        // First failure triggers
        state.on_verification_failure(&config);
        let v1 = state.get_difficulty_version();
        assert_eq!(v1, 1);

        // Second failure should escalate
        state.on_verification_failure(&config);
        let v2 = state.get_difficulty_version();

        assert!(
            v2 > v1,
            "second failure should escalate difficulty: v1={v1}, v2={v2}"
        );
        assert_eq!(
            state.get_current_multiplier(),
            config.initial_multiplier + 1.0,
            "linear escalation should add step to multiplier"
        );
    }
}
