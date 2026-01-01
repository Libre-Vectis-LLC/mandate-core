//! Cost models for verification operations.

/// Nazgul signature verification cost model (bilinear).
///
/// Models verification cost as: `difficulty = a × message_bytes + b × ring_size + c`
///
/// - `a` (per_byte_difficulty): Cost per byte of signed message
/// - `b` (per_member_difficulty): Cost per ring member
/// - `c` (base_difficulty): Base overhead
///
/// Coefficients are derived from benchmark data via linear regression.
///
/// # Examples
///
/// ```
/// use mandate_core::billing::VerificationCostModel;
///
/// let model = VerificationCostModel {
///     per_byte_difficulty: 12.5,
///     per_member_difficulty: 77750.0,
///     base_difficulty: 8000.0,
///     reference_device: "AMD Ryzen 9 5900X @ 3.7GHz".to_string(),
/// };
///
/// let difficulty = model.estimate_difficulty(16, 1024);  // 16 members, 1KB message
/// let aru = model.to_cpu_aru(16, 1024);  // Convert to ARU
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationCostModel {
    /// Per-byte difficulty coefficient (a).
    pub per_byte_difficulty: f64,

    /// Per-member difficulty coefficient (b).
    pub per_member_difficulty: f64,

    /// Base difficulty (c).
    pub base_difficulty: f64,

    /// Reference device used for benchmarking (for documentation/audit).
    pub reference_device: String,
}

impl VerificationCostModel {
    /// Estimates verification difficulty (CPU cycles, normalized).
    ///
    /// Formula: `difficulty = a × message_bytes + b × ring_size + c`
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::VerificationCostModel;
    ///
    /// let model = VerificationCostModel {
    ///     per_byte_difficulty: 12.5,
    ///     per_member_difficulty: 77750.0,
    ///     base_difficulty: 8000.0,
    ///     reference_device: "test".to_string(),
    /// };
    ///
    /// let difficulty = model.estimate_difficulty(4, 512);
    /// assert!(difficulty > 0);
    /// ```
    pub fn estimate_difficulty(&self, ring_size: usize, message_bytes: usize) -> u64 {
        let difficulty = self.per_byte_difficulty * message_bytes as f64
            + self.per_member_difficulty * ring_size as f64
            + self.base_difficulty;
        difficulty.ceil() as u64
    }

    /// Converts verification difficulty to CPU ARU (1 ARU = 1M difficulty units).
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::VerificationCostModel;
    ///
    /// let model = VerificationCostModel {
    ///     per_byte_difficulty: 12.5,
    ///     per_member_difficulty: 77750.0,
    ///     base_difficulty: 8000.0,
    ///     reference_device: "test".to_string(),
    /// };
    ///
    /// let aru = model.to_cpu_aru(16, 1024);
    /// assert!(aru > 0);
    /// ```
    pub fn to_cpu_aru(&self, ring_size: usize, message_bytes: usize) -> u64 {
        self.estimate_difficulty(ring_size, message_bytes) / 1_000_000
    }

    /// Cost function for POW parameter calculation.
    ///
    /// This is the core function used to determine POW difficulty based on verification cost.
    pub fn verification_cost_function(&self, ring_size: usize, message_bytes: usize) -> u64 {
        self.estimate_difficulty(ring_size, message_bytes)
    }
}

/// POW (rspow) verification cost model.
///
/// Models the CPU cost of verifying EquiX proofs. Each proof verification is O(1),
/// and bundles scale linearly (N proofs = N × single_proof_cost).
///
/// # Examples
///
/// ```
/// use mandate_core::billing::PowVerificationCostModel;
///
/// let model = PowVerificationCostModel {
///     cycles_per_proof: 50_000,
///     reference_clock_mhz: 3700.0,
/// };
///
/// let cycles = model.estimate_cycles(10);  // 10 proofs
/// let aru = model.to_cpu_aru(10);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PowVerificationCostModel {
    /// CPU cycles to verify one proof.
    pub cycles_per_proof: u64,

    /// Reference clock frequency (MHz) used for benchmarking.
    pub reference_clock_mhz: f64,
}

impl PowVerificationCostModel {
    /// Estimates total CPU cycles for verifying a bundle.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::PowVerificationCostModel;
    ///
    /// let model = PowVerificationCostModel {
    ///     cycles_per_proof: 50_000,
    ///     reference_clock_mhz: 3700.0,
    /// };
    ///
    /// assert_eq!(model.estimate_cycles(10), 500_000);
    /// ```
    pub fn estimate_cycles(&self, proof_count: usize) -> u64 {
        self.cycles_per_proof * proof_count as u64
    }

    /// Converts verification cycles to CPU ARU (1 ARU = 1M difficulty units).
    ///
    /// Normalizes cycles based on reference clock frequency.
    ///
    /// # Examples
    ///
    /// ```
    /// use mandate_core::billing::PowVerificationCostModel;
    ///
    /// let model = PowVerificationCostModel {
    ///     cycles_per_proof: 50_000,
    ///     reference_clock_mhz: 3000.0,  // 3GHz reference
    /// };
    ///
    /// let aru = model.to_cpu_aru(20);  // 20 proofs
    /// assert!(aru > 0);
    /// ```
    pub fn to_cpu_aru(&self, proof_count: usize) -> u64 {
        let cycles = self.estimate_cycles(proof_count);
        // Normalize to 3GHz reference (3000 MHz)
        let normalized = (cycles as f64 * (3000.0 / self.reference_clock_mhz)) as u64;
        normalized / 1_000_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_cost_model_estimate_difficulty() {
        let model = VerificationCostModel {
            per_byte_difficulty: 12.5,
            per_member_difficulty: 77750.0,
            base_difficulty: 8000.0,
            reference_device: "AMD Ryzen 9 5900X @ 3.7GHz".to_string(),
        };

        // Small ring (2 members), small message (100 bytes)
        let difficulty = model.estimate_difficulty(2, 100);
        assert!(difficulty > 0);
        // Expected: 12.5*100 + 77750*2 + 8000 = 1250 + 155500 + 8000 = 164750
        assert_eq!(difficulty, 164_750);

        // Larger ring (16 members), 1KB message
        let difficulty = model.estimate_difficulty(16, 1024);
        // Expected: 12.5*1024 + 77750*16 + 8000 = 12800 + 1244000 + 8000 = 1264800
        assert_eq!(difficulty, 1_264_800);
    }

    #[test]
    fn test_verification_cost_model_to_cpu_aru() {
        let model = VerificationCostModel {
            per_byte_difficulty: 12.5,
            per_member_difficulty: 77750.0,
            base_difficulty: 8000.0,
            reference_device: "test".to_string(),
        };

        let aru = model.to_cpu_aru(2, 100);
        // 164750 / 1000000 = 0 (rounds down)
        assert_eq!(aru, 0);

        let aru = model.to_cpu_aru(16, 1024);
        // 1264800 / 1000000 = 1
        assert_eq!(aru, 1);

        // Large ring (1024 members), large message (10KB)
        let aru = model.to_cpu_aru(1024, 10240);
        // Expected: 12.5*10240 + 77750*1024 + 8000 = 128000 + 79616000 + 8000 = 79752000
        // 79752000 / 1000000 = 79
        assert_eq!(aru, 79);
    }

    #[test]
    fn test_pow_verification_cost_model_estimate_cycles() {
        let model = PowVerificationCostModel {
            cycles_per_proof: 50_000,
            reference_clock_mhz: 3700.0,
        };

        assert_eq!(model.estimate_cycles(1), 50_000);
        assert_eq!(model.estimate_cycles(10), 500_000);
        assert_eq!(model.estimate_cycles(100), 5_000_000);
    }

    #[test]
    fn test_pow_verification_cost_model_to_cpu_aru() {
        let model = PowVerificationCostModel {
            cycles_per_proof: 50_000,
            reference_clock_mhz: 3000.0, // 3GHz reference
        };

        // 10 proofs: 50000 * 10 = 500000 cycles
        // Normalized: 500000 * (3000/3000) = 500000
        // ARU: 500000 / 1000000 = 0
        assert_eq!(model.to_cpu_aru(10), 0);

        // 20 proofs: 50000 * 20 = 1000000 cycles
        // ARU: 1000000 / 1000000 = 1
        assert_eq!(model.to_cpu_aru(20), 1);

        // 100 proofs: 50000 * 100 = 5000000 cycles
        // ARU: 5000000 / 1000000 = 5
        assert_eq!(model.to_cpu_aru(100), 5);
    }

    #[test]
    fn test_pow_verification_normalization() {
        // Faster CPU (6GHz) should reduce ARU
        let fast_model = PowVerificationCostModel {
            cycles_per_proof: 50_000,
            reference_clock_mhz: 6000.0,
        };

        // Slower CPU (1.5GHz) should increase ARU
        let slow_model = PowVerificationCostModel {
            cycles_per_proof: 50_000,
            reference_clock_mhz: 1500.0,
        };

        let fast_aru = fast_model.to_cpu_aru(100);
        let slow_aru = slow_model.to_cpu_aru(100);

        // Faster CPU has lower ARU due to normalization
        assert!(fast_aru < slow_aru);
    }
}
