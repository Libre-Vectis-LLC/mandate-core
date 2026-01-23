//! Verification event tracking.

use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
use js_sys;

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
