//! Test-only helpers shared across unit and integration tests.
//!
//! IMPORTANT: Mandate requires at least 256-bit security for user keys.
//! Use 24-word BIP39 mnemonics in production; 12-word (128-bit) mnemonics are not allowed.

/// Fixed 24‑word BIP39 mnemonic used in tests for deterministic key derivations.
pub const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
