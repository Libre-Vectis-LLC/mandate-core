//! POW difficulty calculation based on verification costs.
//!
//! Calculates POW parameters (proof count) such that:
//! POW computation cost ≥ verification cost × multiplier

use super::VerificationCostModel;

#[cfg(not(target_arch = "wasm32"))]
use crate::pow::PowParams;

/// POW difficulty calculator.
///
/// Determines POW parameters based on verification cost to ensure
/// that attackers must spend at least as much CPU computing POW
/// as the server spends verifying signatures.
///
/// # Design
///
/// - POW difficulty scales linearly with verification cost
/// - Uses bundle mechanism (N proofs) instead of exponential bits
/// - Fixed bits per proof (recommended: 7) for predictable client behavior
///
/// # Examples
///
/// ```
/// use mandate_core::billing::{PowDifficultyCalculator, VerificationCostModel};
///
/// let verification_model = VerificationCostModel {
///     per_byte_difficulty: 12.5,
///     per_member_difficulty: 77750.0,
///     base_difficulty: 8000.0,
///     reference_device: "test".to_string(),
/// };
///
/// let calculator = PowDifficultyCalculator::new(
///     verification_model,
///     50_000,  // cycles per proof
///     10,      // min proofs
///     7,       // fixed bits
/// );
///
/// // Ring size 16, message 1KB, initial multiplier 3.0
/// #[cfg(not(target_arch = "wasm32"))]
/// {
///     let params = calculator.calculate_pow_params(16, 1024, 3.0);
///     assert!(params.required_proofs >= 10);
///     assert_eq!(params.bits, 7);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct PowDifficultyCalculator {
    /// Nazgul verification cost model.
    verification_model: VerificationCostModel,

    /// Average CPU cycles to compute one rspow proof (from benchmarks).
    pow_cycles_per_proof: u64,

    /// Minimum number of proofs (safety floor).
    min_proofs: usize,

    /// Fixed bits per proof (recommend 7 for predictable client UX).
    fixed_bits: u32,
}

impl PowDifficultyCalculator {
    /// Creates a new POW difficulty calculator.
    ///
    /// # Parameters
    ///
    /// - `verification_model`: Cost model for signature verification
    /// - `pow_cycles_per_proof`: Average CPU cycles to compute one proof
    /// - `min_proofs`: Minimum proof count (safety floor)
    /// - `fixed_bits`: Bits per proof (typically 7)
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::{PowDifficultyCalculator, VerificationCostModel};
    ///
    /// let model = VerificationCostModel {
    ///     per_byte_difficulty: 12.5,
    ///     per_member_difficulty: 77750.0,
    ///     base_difficulty: 8000.0,
    ///     reference_device: "test".to_string(),
    /// };
    ///
    /// let calculator = PowDifficultyCalculator::new(model, 50_000, 10, 7);
    /// ```
    pub fn new(
        verification_model: VerificationCostModel,
        pow_cycles_per_proof: u64,
        min_proofs: usize,
        fixed_bits: u32,
    ) -> Self {
        Self {
            verification_model,
            pow_cycles_per_proof,
            min_proofs,
            fixed_bits,
        }
    }

    /// Calculates POW parameters based on verification cost.
    ///
    /// # Formula
    ///
    /// ```text
    /// verify_cycles = verification_model.verification_cost_function(ring_size, message_bytes)
    /// target_cycles = verify_cycles × cost_multiplier
    /// required_proofs = max(ceil(target_cycles / pow_cycles_per_proof), min_proofs)
    /// ```
    ///
    /// Note: Uses ceiling division to ensure POW cost always meets or exceeds target.
    ///
    /// # Parameters
    ///
    /// - `ring_size`: Number of ring members
    /// - `message_bytes`: Signed message length
    /// - `cost_multiplier`: POW cost multiplier (typically 3.0 initially)
    ///
    /// # Returns
    ///
    /// POW parameters with calculated proof count.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::{PowDifficultyCalculator, VerificationCostModel};
    ///
    /// let model = VerificationCostModel {
    ///     per_byte_difficulty: 12.5,
    ///     per_member_difficulty: 77750.0,
    ///     base_difficulty: 8000.0,
    ///     reference_device: "test".to_string(),
    /// };
    ///
    /// let calculator = PowDifficultyCalculator::new(model, 50_000, 10, 7);
    ///
    /// #[cfg(not(target_arch = "wasm32"))]
    /// {
    ///     // Large ring (128 members), 2KB message, 3× multiplier
    ///     let params = calculator.calculate_pow_params(128, 2048, 3.0);
    ///     assert!(params.required_proofs > 100);
    ///     assert_eq!(params.bits, 7);
    ///     assert_eq!(params.time_window_secs, 60);
    /// }
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn calculate_pow_params(
        &self,
        ring_size: usize,
        message_bytes: usize,
        cost_multiplier: f64,
    ) -> PowParams {
        // Calculate verification cost in CPU cycles
        let verify_cycles = self
            .verification_model
            .verification_cost_function(ring_size, message_bytes);

        // Target: POW computation cost ≥ verification cost × multiplier
        let target_cycles = (verify_cycles as f64 * cost_multiplier) as u64;

        // Calculate required proof count using ceiling division
        // to ensure POW cost >= verification cost × multiplier
        let required_proofs = target_cycles
            .div_ceil(self.pow_cycles_per_proof)
            .max(self.min_proofs as u64) as usize;

        PowParams {
            bits: self.fixed_bits,
            required_proofs,
            time_window_secs: 60, // 1 minute validity
        }
    }

    /// Returns the verification cost model.
    pub fn verification_model(&self) -> &VerificationCostModel {
        &self.verification_model
    }

    /// Returns the POW cycles per proof.
    pub fn pow_cycles_per_proof(&self) -> u64 {
        self.pow_cycles_per_proof
    }

    /// Returns the minimum proof count.
    pub fn min_proofs(&self) -> usize {
        self.min_proofs
    }

    /// Returns the fixed bits per proof.
    pub fn fixed_bits(&self) -> u32 {
        self.fixed_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_model() -> VerificationCostModel {
        VerificationCostModel {
            per_byte_difficulty: 12.5,
            per_member_difficulty: 77750.0,
            base_difficulty: 8000.0,
            reference_device: "test".to_string(),
        }
    }

    fn test_calculator() -> PowDifficultyCalculator {
        PowDifficultyCalculator::new(
            test_model(),
            50_000, // 50k cycles per proof
            10,     // min 10 proofs
            7,      // 7 bits per proof
        )
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_calculate_pow_params_small_ring() {
        let calc = test_calculator();

        // Small ring (2 members), small message (100 bytes)
        let params = calc.calculate_pow_params(2, 100, 3.0);

        // verify_cycles = 12.5*100 + 77750*2 + 8000 = 164750
        // target = 164750 * 3 = 494250
        // required = 494250 / 50000 = 9.885 → rounds to 10 (meets min)
        assert_eq!(params.required_proofs, 10); // min proofs
        assert_eq!(params.bits, 7);
        assert_eq!(params.time_window_secs, 60);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_calculate_pow_params_medium_ring() {
        let calc = test_calculator();

        // Medium ring (16 members), 1KB message
        let params = calc.calculate_pow_params(16, 1024, 3.0);

        // verify_cycles = 12.5*1024 + 77750*16 + 8000 = 1264800
        // target = 1264800 * 3 = 3794400
        // required = ceil(3794400 / 50000) = ceil(75.888) = 76
        assert_eq!(params.required_proofs, 76);
        assert_eq!(params.bits, 7);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_calculate_pow_params_large_ring() {
        let calc = test_calculator();

        // Large ring (128 members), 2KB message
        let params = calc.calculate_pow_params(128, 2048, 3.0);

        // verify_cycles = 12.5*2048 + 77750*128 + 8000 = 25600 + 9958000 + 8000 = 9985600
        // target = 9985600 * 3 = 29956800
        // required = ceil(29956800 / 50000) = ceil(599.136) = 600
        assert_eq!(params.required_proofs, 600);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_calculate_pow_params_escalation() {
        let calc = test_calculator();

        // Same ring, increasing multiplier simulates escalation
        let ring_size = 16;
        let msg_bytes = 1024;

        let params_3x = calc.calculate_pow_params(ring_size, msg_bytes, 3.0);
        let params_6x = calc.calculate_pow_params(ring_size, msg_bytes, 6.0);
        let params_12x = calc.calculate_pow_params(ring_size, msg_bytes, 12.0);

        // Proofs should approximately double each time (exponential escalation)
        // Using ceiling division: 3794400/50000=76, 7588800/50000=152, 15177600/50000=304
        assert_eq!(params_3x.required_proofs, 76);
        assert_eq!(params_6x.required_proofs, 152);
        assert_eq!(params_12x.required_proofs, 304);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_calculate_pow_params_linear_escalation() {
        let calc = test_calculator();

        let ring_size = 16;
        let msg_bytes = 1024;

        let params_3x = calc.calculate_pow_params(ring_size, msg_bytes, 3.0);
        let params_4x = calc.calculate_pow_params(ring_size, msg_bytes, 4.0);
        let params_5x = calc.calculate_pow_params(ring_size, msg_bytes, 5.0);

        // Linear escalation: +1x each time
        // verify_cycles = 1264800, using ceiling division
        // 3x: ceil(3794400/50000)=76, 4x: ceil(5059200/50000)=102, 5x: ceil(6324000/50000)=127
        assert_eq!(params_3x.required_proofs, 76);
        assert_eq!(params_4x.required_proofs, 102);
        assert_eq!(params_5x.required_proofs, 127);
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_min_proofs_floor() {
        let calc = PowDifficultyCalculator::new(
            test_model(),
            1_000_000, // Very expensive POW (unrealistic)
            100,       // High min proofs
            7,
        );

        // Even tiny verification cost should trigger min proofs
        let params = calc.calculate_pow_params(2, 10, 1.0);
        assert_eq!(params.required_proofs, 100); // min proofs enforced
    }

    #[test]
    fn test_accessors() {
        let calc = test_calculator();

        assert_eq!(calc.pow_cycles_per_proof(), 50_000);
        assert_eq!(calc.min_proofs(), 10);
        assert_eq!(calc.fixed_bits(), 7);
        assert_eq!(
            calc.verification_model().reference_device,
            "test".to_string()
        );
    }
}
