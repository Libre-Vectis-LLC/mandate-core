use crate::hashing::CanonicalHashError;
use crate::ids::{ContentHash, OrganizationId};
use serde::{Deserialize, Serialize};

/// A management event indicating that a poll bundle has been published.
///
/// This event triggers the `Sealed` → `VerificationOpen` phase transition.
/// It is signed by the owner/delegate (NOT per-poll ring signing), similar to
/// `BanCreate`/`BanRevoke`/`RingUpdate`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollBundlePublished {
    pub org_id: OrganizationId,
    pub poll_id: String,
    /// Hash of the poll bundle content, computed by the publisher.
    pub bundle_hash: ContentHash,
}

impl PollBundlePublished {
    /// Produce the canonical bytes used for signing.
    /// Follows the same pattern as `VoteRevocation::to_signing_bytes()`.
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>, CanonicalHashError> {
        crate::hashing::canonical_json(self)
    }
}
