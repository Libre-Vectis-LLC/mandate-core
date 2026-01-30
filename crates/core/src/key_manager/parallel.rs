//! Parallel encryption for Edge access tokens.
//!
//! Uses Rayon's work-stealing thread pool to encrypt access tokens for
//! multiple recipients concurrently. This is the recommended path for
//! server-side token generation where the ring may contain many members.
//!
//! Only available on non-WASM targets (Rayon requires OS threads).

use super::manager::{encrypt_access_token_for_recipient, KeyManagerError};
use rayon::prelude::*;

/// Encrypt an Edge access token for multiple recipients in parallel.
///
/// Each recipient receives an independently encrypted copy of `token`.
/// Uses Rayon's parallel iterator to distribute CPU-intensive age/X25519
/// encryption across available cores.
///
/// Returns one `Result` per recipient, in the same order as `recipients`.
pub fn encrypt_access_tokens_parallel(
    token: &[u8; 32],
    recipients: &[age::x25519::Recipient],
) -> Vec<Result<Vec<u8>, KeyManagerError>> {
    recipients
        .par_iter()
        .map(|recipient| encrypt_access_token_for_recipient(token, recipient))
        .collect()
}
