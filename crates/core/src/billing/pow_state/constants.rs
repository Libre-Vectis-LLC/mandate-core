//! Constants for POW state machine.

/// Default maximum POW multiplier to prevent unbounded difficulty growth.
pub(crate) const DEFAULT_MAX_MULTIPLIER: f64 = 1000.0;

/// Provides default value for max_multiplier field.
pub(crate) fn default_max_multiplier() -> f64 {
    DEFAULT_MAX_MULTIPLIER
}

/// Normalizes max_multiplier: treats 0 or negative as default.
pub(crate) fn normalize_max_multiplier(value: f64) -> f64 {
    if value <= 0.0 {
        DEFAULT_MAX_MULTIPLIER
    } else {
        value
    }
}
