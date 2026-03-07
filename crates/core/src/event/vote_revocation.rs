use crate::crypto::ciphertext::Ciphertext;
use crate::hashing::CanonicalHashError;
use crate::ids::{ContentHash, OrganizationId, RingHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoteRevocation {
    pub org_id: OrganizationId,
    /// Hash of the per-poll derived signing ring used for this vote revocation signature.
    /// Same derivation as Vote.
    pub ring_hash: RingHash,
    pub poll_id: String,
    /// Hash of the vote event being revoked (optional).
    pub vote_event_hash: Option<ContentHash>,
    pub reason: Option<Ciphertext>,
}

impl VoteRevocation {
    /// Produce the canonical bytes used for signing.
    /// Follows the same pattern as Event::to_signing_bytes() but for this inner struct,
    /// although it doesn't have sequence_no or previous_event_hash fields.
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>, CanonicalHashError> {
        crate::hashing::canonical_json(self)
    }
}
