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
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.consecutive_successes, 0);
    }

    #[test]
    fn test_trigger_pow_after_threshold() {
        let mut state = OrgPowState::new();
        let config = OrgPowConfig::default(); // threshold=3

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
        let mut state = OrgPowState::new();
        let config = OrgPowConfig {
            upgrade_strategy: UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 1,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 3.0 },
            },
            initial_multiplier: 3.0,
            max_multiplier: 1000.0,
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
        let mut state = OrgPowState::new();
        let config = OrgPowConfig::default(); // threshold=3

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
        let config = OrgPowConfig::default();
        assert_eq!(
            config.upgrade_strategy,
            UpgradeStrategy::ConsecutiveFailure {
                trigger_threshold: 3,
                escalate_every: 1,
                growth: EscalationStrategy::Linear { step: 1.0 },
            }
        );
        assert_eq!(config.initial_multiplier, 3.0);
        assert_eq!(config.max_multiplier, 1000.0);
        assert_eq!(config.recovery_success_count, 10);
        assert_eq!(config.recovery_strategy, RecoveryStrategy::Immediate);
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
            "upgrade_strategy": {"ConsecutiveFailure": {"trigger_threshold": 3, "escalate_every": 1, "growth": {"Linear": {"step": 1.0}}}},
            "initial_multiplier": 3.0,
            "max_multiplier": 0.0,
            "recovery_success_count": 10,
            "recovery_strategy": "Immediate",
            "max_event_history": 1000
        }"#;
        let config: OrgPowConfig = serde_json::from_str(json_with_zero).unwrap();
        assert_eq!(config.max_multiplier, 1000.0);

        let json_with_negative = r#"{
            "upgrade_strategy": {"ConsecutiveFailure": {"trigger_threshold": 3, "escalate_every": 1, "growth": {"Linear": {"step": 1.0}}}},
            "initial_multiplier": 3.0,
            "max_multiplier": -5.0,
            "recovery_success_count": 10,
            "recovery_strategy": "Immediate",
            "max_event_history": 1000
        }"#;
        let config: OrgPowConfig = serde_json::from_str(json_with_negative).unwrap();
        assert_eq!(config.max_multiplier, 1000.0);

        // Test that missing max_multiplier uses default
        let json_without_field = r#"{
            "upgrade_strategy": {"ConsecutiveFailure": {"trigger_threshold": 3, "escalate_every": 1, "growth": {"Linear": {"step": 1.0}}}},
            "initial_multiplier": 3.0,
            "recovery_success_count": 10,
            "recovery_strategy": "Immediate",
            "max_event_history": 1000
        }"#;
        let config: OrgPowConfig = serde_json::from_str(json_without_field).unwrap();
        assert_eq!(config.max_multiplier, 1000.0);
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
}
