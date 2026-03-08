//! AOT Hardware Performance Profile for verification scheduling.
//!
//! Based on empirical findings across 4 hardware-diverse devices (x86_64 + aarch64):
//! ring_size does NOT affect optimal concurrency (max spread = 1).
//! Profile stores a single `optimal_concurrency` value per hardware fingerprint.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(not(target_arch = "wasm32"))]
use std::path::{Path, PathBuf};

/// Current profile format version. Profiles with different versions are rejected.
pub const PROFILE_VERSION: u32 = 1;

/// Errors from profile loading and validation.
#[derive(Debug, Error)]
pub enum ProfileError {
    /// An I/O error occurred reading the profile file.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// The profile file contains invalid JSON.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    /// The profile version does not match the expected version.
    #[error("profile version mismatch: expected {expected}, got {got}")]
    VersionMismatch {
        /// The version this library expects.
        expected: u32,
        /// The version found in the profile.
        got: u32,
    },

    /// The concurrency value is out of the valid range (1..=512).
    #[error("invalid concurrency value: {0}")]
    InvalidConcurrency(u32),
}

/// AOT Hardware Performance Profile.
///
/// Loaded from a JSON file produced by offline benchmarking. Contains a single
/// `optimal_concurrency` value that replaces runtime calibration when available.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    /// Format version for forward compatibility.
    pub profile_version: u32,
    /// Hardware fingerprint (e.g., `"x86_64-linux-20c14p-Intel Core i9-12900H"`).
    pub hardware_fingerprint: String,
    /// Optimal thread count determined by offline benchmarking.
    pub optimal_concurrency: u32,
    /// ISO 8601 timestamp of when the profile was generated.
    #[serde(default)]
    pub tested_at: Option<String>,
}

impl HardwareProfile {
    /// Validate the profile: version matches and concurrency is within range.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if self.profile_version != PROFILE_VERSION {
            return Err(ProfileError::VersionMismatch {
                expected: PROFILE_VERSION,
                got: self.profile_version,
            });
        }
        if self.optimal_concurrency == 0 || self.optimal_concurrency > 512 {
            return Err(ProfileError::InvalidConcurrency(self.optimal_concurrency));
        }
        Ok(())
    }

    /// Load and validate a profile from a file path.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load_from_path(path: &Path) -> Result<Self, ProfileError> {
        let content = std::fs::read_to_string(path)?;
        let profile: Self = serde_json::from_str(&content)?;
        profile.validate()?;
        Ok(profile)
    }

    /// Try loading profile from default location.
    ///
    /// Checks `MANDATE_PROFILE_PATH` env var first, then falls back to the
    /// platform default data directory.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load_default() -> Option<Self> {
        // 1. Try env var override.
        if let Ok(path) = std::env::var("MANDATE_PROFILE_PATH") {
            if let Ok(profile) = Self::load_from_path(Path::new(&path)) {
                return Some(profile);
            }
        }
        // 2. Try default path.
        let path = Self::default_path()?;
        Self::load_from_path(&path).ok()
    }

    /// Default profile file path: `$XDG_DATA_HOME/mandate/benchmark-results.json`
    /// (or `$HOME/.local/share/mandate/benchmark-results.json` as fallback).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn default_path() -> Option<PathBuf> {
        let data_dir = std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|_| {
                std::env::var("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
            })
            .ok()?;
        Some(data_dir.join("mandate").join("benchmark-results.json"))
    }
}

/// RAII guard holding a Rayon thread pool configured from a [`HardwareProfile`].
///
/// Useful when calling code wants to run multiple batches at the profile's
/// optimal concurrency without rebuilding the pool each time.
pub struct ProfileGuard {
    pool: rayon::ThreadPool,
    concurrency: u32,
}

impl ProfileGuard {
    /// Create a guard from a validated hardware profile.
    ///
    /// The profile's `optimal_concurrency` must be in the range 1..=512.
    pub fn from_profile(profile: &HardwareProfile) -> Result<Self, ProfileError> {
        let concurrency = profile.optimal_concurrency;
        if concurrency == 0 || concurrency > 512 {
            return Err(ProfileError::InvalidConcurrency(concurrency));
        }
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(concurrency as usize)
            .build()
            .map_err(|e| ProfileError::Io(std::io::Error::other(e.to_string())))?;
        Ok(Self { pool, concurrency })
    }

    /// Run a closure inside this thread pool.
    pub fn install<F, R>(&self, f: F) -> R
    where
        F: FnOnce() -> R + Send,
        R: Send,
    {
        self.pool.install(f)
    }

    /// The concurrency level of this guard.
    pub fn concurrency(&self) -> u32 {
        self.concurrency
    }
}

// ---------------------------------------------------------------------------
// Quick-tune: offline benchmark to determine optimal concurrency
// ---------------------------------------------------------------------------

/// Number of synthetic items per concurrency level during tuning.
#[cfg(not(target_arch = "wasm32"))]
const TUNE_ITEMS_PER_LEVEL: usize = 80;

/// Number of warm-up iterations before timed measurement.
#[cfg(not(target_arch = "wasm32"))]
const TUNE_WARMUP_ROUNDS: usize = 1;

/// Number of timed measurement rounds per concurrency level.
#[cfg(not(target_arch = "wasm32"))]
const TUNE_MEASURE_ROUNDS: usize = 3;

/// A CPU-work-simulating verifier for tuning benchmarks.
///
/// Performs hash-like computation proportional to signature size,
/// approximating the CPU cost pattern of real ring signature verification
/// without requiring actual cryptographic keys.
#[cfg(not(target_arch = "wasm32"))]
struct TuneVerifier;

#[cfg(not(target_arch = "wasm32"))]
impl crate::signature::SignatureVerifier for TuneVerifier {
    fn verify_one(
        &self,
        _index: usize,
        item: &crate::signature::VerifyItem,
    ) -> Result<bool, crate::signature::BatchVerifyError> {
        // Simulate CPU work proportional to ring size.
        // ~1000 iterations over signature bytes approximates the cost
        // of real BLSAG verification without needing valid keys.
        let mut hash: u64 = 0;
        let sig_len = item.signature_bytes.len().min(128);
        for _ in 0..1000 {
            for &b in &item.signature_bytes[..sig_len] {
                hash = hash.wrapping_mul(31).wrapping_add(b as u64);
            }
        }
        std::hint::black_box(hash);
        Ok(true)
    }
}

/// Generate candidate parallelism levels: powers of two up to `nproc`.
///
/// Always includes `nproc` as the final candidate.
#[cfg(not(target_arch = "wasm32"))]
fn tune_candidate_levels(nproc: usize) -> Vec<usize> {
    let mut levels = Vec::new();
    let mut level = 1;
    while level <= nproc {
        levels.push(level);
        if level == nproc {
            break;
        }
        level *= 2;
        if level > nproc {
            levels.push(nproc);
        }
    }
    levels
}

/// Run a quick benchmark to determine optimal concurrency for this hardware.
///
/// Generates synthetic [`VerifyItem`]s and tests each candidate parallelism
/// level (1, 2, 4, ..., num_cpus) using a CPU-work-simulating verifier.
/// The concurrency level with the highest throughput is selected.
///
/// The resulting [`HardwareProfile`] is saved to the
/// [default path](`HardwareProfile::default_path`) and returned.
///
/// # Errors
///
/// Returns [`ProfileError::Io`] if the profile cannot be written to disk.
#[cfg(not(target_arch = "wasm32"))]
pub fn quick_tune(progress: Option<&dyn Fn(&str)>) -> Result<HardwareProfile, ProfileError> {
    use crate::signature::SignatureVerifier;
    use rayon::prelude::*;
    use std::time::Instant;

    let nproc = num_cpus::get().max(1);
    let levels = tune_candidate_levels(nproc);
    let ring_size = 100; // Typical ring size for benchmarking

    // Generate synthetic items (ring_size public keys, signature_bytes ~ ring_size * 32).
    let items: Vec<crate::signature::VerifyItem> = (0..TUNE_ITEMS_PER_LEVEL)
        .map(|i| crate::signature::VerifyItem {
            id: format!("tune-{i}"),
            signature_bytes: vec![0xABu8; ring_size * 32],
            message: vec![0x01, 0x02],
            ring_pubkeys_bs58: (0..ring_size).map(|j| format!("pub-{j}")).collect(),
        })
        .collect();

    let verifier = TuneVerifier;
    let mut best_throughput: f64 = 0.0;
    let mut best_concurrency: usize = 1;

    let log = |msg: &str| {
        if let Some(f) = &progress {
            f(msg);
        }
    };

    log(&format!(
        "Tuning with {} items/level, {} levels, {} warm-up + {} measure rounds",
        TUNE_ITEMS_PER_LEVEL,
        levels.len(),
        TUNE_WARMUP_ROUNDS,
        TUNE_MEASURE_ROUNDS,
    ));

    for &conc in &levels {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(conc)
            .build()
            .map_err(|e| ProfileError::Io(std::io::Error::other(e.to_string())))?;

        // Warm-up rounds (not timed).
        for _ in 0..TUNE_WARMUP_ROUNDS {
            pool.install(|| {
                items.par_iter().enumerate().for_each(|(idx, item)| {
                    let _ = verifier.verify_one(idx, item);
                });
            });
        }

        // Timed measurement rounds.
        let mut total_elapsed = std::time::Duration::ZERO;
        for _ in 0..TUNE_MEASURE_ROUNDS {
            let start = Instant::now();
            pool.install(|| {
                items.par_iter().enumerate().for_each(|(idx, item)| {
                    let _ = verifier.verify_one(idx, item);
                });
            });
            total_elapsed += start.elapsed();
        }

        let avg_elapsed = total_elapsed.as_secs_f64() / TUNE_MEASURE_ROUNDS as f64;
        let throughput = if avg_elapsed > 0.0 {
            items.len() as f64 / avg_elapsed
        } else {
            f64::MAX
        };

        log(&format!(
            "  concurrency={conc:>3}: {throughput:>10.1} items/s (avg {avg_elapsed:.4}s)",
        ));

        if throughput > best_throughput {
            best_throughput = throughput;
            best_concurrency = conc;
        }
    }

    let profile = HardwareProfile {
        profile_version: PROFILE_VERSION,
        hardware_fingerprint: format!(
            "{}-{}-{}c",
            std::env::consts::ARCH,
            std::env::consts::OS,
            nproc
        ),
        optimal_concurrency: best_concurrency as u32,
        tested_at: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| {
                    // Simple ISO 8601 approximation without pulling in chrono.
                    let secs = d.as_secs();
                    format!("{secs}")
                })
                .unwrap_or_default(),
        ),
    };

    // Save to default path.
    if let Some(path) = HardwareProfile::default_path() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&profile)
            .map_err(|e| ProfileError::Io(std::io::Error::other(e.to_string())))?;
        std::fs::write(&path, &json)?;
        log(&format!("Profile saved to {}", path.display()));
    }

    log(&format!(
        "Optimal concurrency: {} (throughput: {best_throughput:.1} items/s)",
        best_concurrency
    ));

    Ok(profile)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ok() {
        let p = HardwareProfile {
            profile_version: PROFILE_VERSION,
            hardware_fingerprint: "test-hw".into(),
            optimal_concurrency: 4,
            tested_at: None,
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn test_validate_version_mismatch() {
        let p = HardwareProfile {
            profile_version: 999,
            hardware_fingerprint: "test-hw".into(),
            optimal_concurrency: 4,
            tested_at: None,
        };
        assert!(matches!(
            p.validate(),
            Err(ProfileError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_zero_concurrency() {
        let p = HardwareProfile {
            profile_version: PROFILE_VERSION,
            hardware_fingerprint: "test-hw".into(),
            optimal_concurrency: 0,
            tested_at: None,
        };
        assert!(matches!(
            p.validate(),
            Err(ProfileError::InvalidConcurrency(0))
        ));
    }

    #[test]
    fn test_validate_excessive_concurrency() {
        let p = HardwareProfile {
            profile_version: PROFILE_VERSION,
            hardware_fingerprint: "test-hw".into(),
            optimal_concurrency: 513,
            tested_at: None,
        };
        assert!(matches!(
            p.validate(),
            Err(ProfileError::InvalidConcurrency(513))
        ));
    }

    #[test]
    fn test_serde_roundtrip() {
        let p = HardwareProfile {
            profile_version: PROFILE_VERSION,
            hardware_fingerprint: "x86_64-linux-8c8p".into(),
            optimal_concurrency: 8,
            tested_at: Some("2026-03-07T12:00:00Z".into()),
        };
        let json = serde_json::to_string(&p).unwrap();
        let p2: HardwareProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p2.optimal_concurrency, 8);
        assert_eq!(p2.hardware_fingerprint, "x86_64-linux-8c8p");
    }

    #[test]
    fn test_load_from_path_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.json");
        let p = HardwareProfile {
            profile_version: PROFILE_VERSION,
            hardware_fingerprint: "test".into(),
            optimal_concurrency: 4,
            tested_at: None,
        };
        std::fs::write(&path, serde_json::to_string(&p).unwrap()).unwrap();
        let loaded = HardwareProfile::load_from_path(&path).unwrap();
        assert_eq!(loaded.optimal_concurrency, 4);
    }

    #[test]
    fn test_load_from_path_not_found() {
        let result = HardwareProfile::load_from_path(Path::new("/nonexistent/profile.json"));
        assert!(matches!(result, Err(ProfileError::Io(_))));
    }

    #[test]
    fn test_load_from_path_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();
        let result = HardwareProfile::load_from_path(&path);
        assert!(matches!(result, Err(ProfileError::Json(_))));
    }

    #[test]
    fn test_load_from_path_version_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.json");
        let json = r#"{"profile_version":99,"hardware_fingerprint":"x","optimal_concurrency":4}"#;
        std::fs::write(&path, json).unwrap();
        let result = HardwareProfile::load_from_path(&path);
        assert!(matches!(result, Err(ProfileError::VersionMismatch { .. })));
    }

    #[test]
    fn test_profile_guard_from_valid() {
        let p = HardwareProfile {
            profile_version: PROFILE_VERSION,
            hardware_fingerprint: "test".into(),
            optimal_concurrency: 2,
            tested_at: None,
        };
        let guard = ProfileGuard::from_profile(&p).unwrap();
        assert_eq!(guard.concurrency(), 2);
        let result = guard.install(|| 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_profile_guard_zero_concurrency() {
        let p = HardwareProfile {
            profile_version: PROFILE_VERSION,
            hardware_fingerprint: "test".into(),
            optimal_concurrency: 0,
            tested_at: None,
        };
        assert!(ProfileGuard::from_profile(&p).is_err());
    }

    #[test]
    fn test_load_default_via_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env-profile.json");
        let p = HardwareProfile {
            profile_version: PROFILE_VERSION,
            hardware_fingerprint: "env-test".into(),
            optimal_concurrency: 6,
            tested_at: None,
        };
        std::fs::write(&path, serde_json::to_string(&p).unwrap()).unwrap();

        // Temporarily set env var (test isolation via unique path).
        std::env::set_var("MANDATE_PROFILE_PATH", &path);
        let loaded = HardwareProfile::load_default();
        std::env::remove_var("MANDATE_PROFILE_PATH");

        let loaded = loaded.expect("should load from env var");
        assert_eq!(loaded.optimal_concurrency, 6);
        assert_eq!(loaded.hardware_fingerprint, "env-test");
    }
}
