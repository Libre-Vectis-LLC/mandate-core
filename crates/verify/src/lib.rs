// Mandate verification engine

pub mod bundle;
pub mod calibration;
pub mod cross_validate;
pub mod derivation;
pub mod export;
pub mod i18n;
pub mod key_image;
pub mod pipeline;
pub mod profile;
pub mod registry;
pub mod shuffle;
pub mod signature;
pub mod tally;

// Re-export key pipeline types for public API convenience.
pub use pipeline::{
    verify_poll, PollSummary, RevocationCheck, VerificationReport, VerifyError, VerifyInput,
    VerifyOptions,
};

// Re-export AOT hardware profile types.
pub use profile::{HardwareProfile, ProfileError, ProfileGuard};

// Re-export quick_tune for CLI usage.
#[cfg(not(target_arch = "wasm32"))]
pub use profile::quick_tune;
