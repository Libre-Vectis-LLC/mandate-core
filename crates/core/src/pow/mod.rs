//! Proof-of-Work (POW) defense system integration.
//!
//! Integrates rspow (EquiX-based POW) for DOS defense. All POW code is behind
//! `#[cfg(not(target_arch = "wasm32"))]` as EquiX does not compile to WASM.
//!
//! # Design
//!
//! - POW difficulty is calculated based on verification cost (ring size, message length)
//! - Uses bundle mechanism: N proofs instead of exponential bits
//! - Near-stateless server with replay cache
//! - Supports resume for difficulty escalation

#[cfg(not(target_arch = "wasm32"))]
pub mod types;

#[cfg(not(target_arch = "wasm32"))]
pub mod verifier;

#[cfg(not(target_arch = "wasm32"))]
pub use types::{PowParams, PowSubmission, PowVerifyResult};

#[cfg(not(target_arch = "wasm32"))]
pub use verifier::PowVerifier;
