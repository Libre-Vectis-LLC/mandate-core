//! POW state machine implementation (trigger, escalate, recover logic).

use super::event::VerificationEvent;
use super::time::current_timestamp_ms;
use super::types::{
    EscalationStrategy, OrgPowConfig, OrgPowState, RecoveryStrategy, UpgradeStrategy,
};

impl OrgPowState {
    /// Creates a new POW state (no POW required initially).
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles a verification failure event.
    ///
    /// If failures meet the configured threshold, triggers POW or escalates difficulty.
    ///
    /// # Parameters
    ///
    /// - `config`: Org POW configuration
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::{OrgPowState, OrgPowConfig};
    ///
    /// let mut state = OrgPowState::new();
    /// let config = OrgPowConfig::default();
    ///
    /// // First failure triggers POW with the default config
    /// state.on_verification_failure(&config);
    /// assert!(state.pow_required);
    /// assert_eq!(state.consecutive_failures, 1);
    /// assert_eq!(state.current_multiplier, 3.0);
    /// ```
    pub fn on_verification_failure(&mut self, config: &OrgPowConfig) {
        let previous_pow_required = self.pow_required;
        let previous_multiplier = self.current_multiplier;

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

        self.bump_difficulty_version_if_changed(previous_pow_required, previous_multiplier);
    }

    /// Handles a verification success event.
    ///
    /// If successes meet threshold, recovers (de-escalates or disables POW).
    ///
    /// # Parameters
    ///
    /// - `config`: Org POW configuration
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::{OrgPowState, OrgPowConfig, RecoveryStrategy};
    ///
    /// let mut state = OrgPowState::new();
    /// let mut config = OrgPowConfig::default();
    /// config.recovery_success_count = 2;
    /// config.recovery_strategy = RecoveryStrategy::Immediate;
    ///
    /// // Trigger POW
    /// state.on_verification_failure(&config);
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
    pub fn on_verification_success(&mut self, config: &OrgPowConfig) {
        let previous_pow_required = self.pow_required;
        let previous_multiplier = self.current_multiplier;

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

        self.bump_difficulty_version_if_changed(previous_pow_required, previous_multiplier);
    }

    /// Full reset: clears POW requirement, counters, AND event history.
    ///
    /// Unlike `Default::default()`, this preserves and increments
    /// `difficulty_version` to prevent nonce replay across reset boundaries.
    ///
    /// # What is cleared
    /// - `pow_required` → false
    /// - `current_multiplier` → 1.0
    /// - `consecutive_failures` → 0
    /// - `consecutive_successes` → 0
    /// - `event_history` → empty
    ///
    /// # What is preserved
    /// - `difficulty_version` (incremented to invalidate outstanding challenges)
    ///
    /// # What is NOT affected (external to this struct)
    /// - POW config (`OrgPowConfig`)
    /// - Nonce replay records
    pub fn full_reset(&mut self) {
        self.pow_required = false;
        self.current_multiplier = 1.0;
        self.consecutive_failures = 0;
        self.consecutive_successes = 0;
        self.event_history.clear();
        // Increment difficulty_version so previously issued challenges are
        // invalidated, but never decrease the global baseline.
        self.difficulty_version = self.difficulty_version.wrapping_add(1);
    }

    /// Returns whether POW is currently required.
    pub fn should_require_pow(&self) -> bool {
        self.pow_required
    }

    /// Returns the current POW cost multiplier.
    pub fn get_current_multiplier(&self) -> f64 {
        self.current_multiplier
    }

    /// Returns the current challenge binding version.
    pub fn get_difficulty_version(&self) -> u64 {
        self.difficulty_version
    }

    /// Records a verification event in history (for time-window strategies).
    fn record_event(&mut self, success: bool, config: &OrgPowConfig) {
        let event = VerificationEvent::now(success);
        self.event_history.push_back(event);

        // Prune old events exceeding max history
        while self.event_history.len() > config.max_event_history {
            self.event_history.pop_front();
        }
    }

    fn bump_difficulty_version_if_changed(
        &mut self,
        previous_pow_required: bool,
        previous_multiplier: f64,
    ) {
        if self.pow_required != previous_pow_required
            || self.current_multiplier != previous_multiplier
        {
            self.difficulty_version = self.difficulty_version.wrapping_add(1);
        }
    }

    /// Records a verification event with explicit timestamp (for testing).
    /// Reserved for Phase 5.7 POW E2E tests.
    #[cfg(test)]
    pub(crate) fn _record_event_at(
        &mut self,
        timestamp_ms: u64,
        success: bool,
        config: &OrgPowConfig,
    ) {
        let event = VerificationEvent::with_timestamp(timestamp_ms, success);
        self.event_history.push_back(event);

        // Prune old events exceeding max history
        while self.event_history.len() > config.max_event_history {
            self.event_history.pop_front();
        }
    }

    /// Checks if POW should be triggered based on upgrade strategy.
    fn should_trigger(&self, config: &OrgPowConfig) -> bool {
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
        let now_ms = current_timestamp_ms();
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

    /// Escalates POW difficulty based on upgrade strategy's growth mode.
    ///
    /// The multiplier is capped at `config.max_multiplier` to prevent unbounded growth.
    fn escalate(&mut self, config: &OrgPowConfig) {
        let growth = config.upgrade_strategy.growth();
        let new_multiplier = match growth {
            EscalationStrategy::Linear { step } => self.current_multiplier + step,
            EscalationStrategy::Exponential { base } => self.current_multiplier * base,
        };
        // Cap at max_multiplier to prevent DoS via infinite difficulty growth
        self.current_multiplier = new_multiplier.min(config.max_multiplier);
    }

    /// Recovers from POW mode based on recovery strategy.
    fn recover(&mut self, config: &OrgPowConfig) {
        match config.recovery_strategy {
            RecoveryStrategy::Immediate => {
                // Immediately disable POW
                self.pow_required = false;
                self.current_multiplier = 1.0;
                self.consecutive_successes = 0;
            }
            RecoveryStrategy::Gradual { steps: _ } => {
                // Recovery hysteresis lowers the effective difficulty one level per
                // success streak instead of resetting directly to the initial level.
                self.current_multiplier = (self.current_multiplier - 1.0).max(1.0);

                if self.current_multiplier <= 1.0 {
                    self.pow_required = false;
                    self.current_multiplier = 1.0;
                }

                // Reset success counter for next recovery step
                self.consecutive_successes = 0;
            }
        }
    }
}
