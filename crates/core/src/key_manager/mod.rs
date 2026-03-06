pub mod manager;
#[cfg(not(target_arch = "wasm32"))]
pub mod parallel;
#[cfg(test)]
mod tests;

pub use manager::KeyManager;
pub use manager::KeyManagerError;
pub use manager::MandateDerivable;
pub use manager::{
    decrypt_access_token_blob, decrypt_event_content, derive_event_identity, derive_poll_key_bytes,
    encrypt_access_token_for_recipient, encrypt_event_content,
};
#[cfg(not(target_arch = "wasm32"))]
pub use parallel::encrypt_access_tokens_parallel;
