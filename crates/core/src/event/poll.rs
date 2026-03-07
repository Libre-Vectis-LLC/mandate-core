use crate::crypto::ciphertext::Ciphertext;
use crate::hashing::poll_hash_sha3_256;
use crate::hashing::CanonicalHashError;
use crate::ids::{ContentHash, OrganizationId, RingHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Poll {
    pub org_id: OrganizationId,
    pub ring_hash: RingHash,
    pub poll_id: String,
    pub questions: Vec<PollQuestion>,
    pub created_at: u64,
    pub instructions: Option<Ciphertext>,
    /// Voting end time (epoch seconds). When `None`, the poll has no deadline
    /// and remains in the `Voting` phase indefinitely (legacy behavior).
    pub deadline: Option<u64>,
    /// Duration in seconds of the sealed period between voting end (`deadline`)
    /// and the start of the verification window. Defaults to `None` (no sealed period).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_duration_secs: Option<u64>,
    /// Duration in seconds of the verification window during which vote
    /// revocations are accepted. Defaults to `None` (no verification window).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_window_secs: Option<u64>,
}

impl Poll {
    /// Compute the canonical poll hash (ID-sorted, domain separated).
    pub fn hash(&self) -> Result<ContentHash, CanonicalHashError> {
        poll_hash_sha3_256(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollQuestion {
    pub question_id: String,
    pub title: Ciphertext,
    pub kind: PollQuestionKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollOption {
    pub id: String,
    pub text: Ciphertext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PollQuestionKind {
    SingleChoice { options: Vec<PollOption> },
    MultipleChoice { options: Vec<PollOption>, max: u32 },
    FillInTheBlank,
}
