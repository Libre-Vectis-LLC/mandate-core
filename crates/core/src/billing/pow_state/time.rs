//! Cross-platform timestamp utilities.

#[cfg(not(target_arch = "wasm32"))]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
use js_sys;

/// Returns the current timestamp in milliseconds since UNIX epoch.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

/// Returns the current timestamp in milliseconds since UNIX epoch (WASM version).
#[cfg(target_arch = "wasm32")]
pub(crate) fn current_timestamp_ms() -> u64 {
    js_sys::Date::now() as u64
}
