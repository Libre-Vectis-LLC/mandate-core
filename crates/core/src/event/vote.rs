use crate::crypto::ciphertext::Ciphertext;
use crate::hashing::vote_hash_sha3_256;
use crate::hashing::CanonicalHashError;
use crate::ids::{ContentHash, GroupId, RingHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vote {
    pub group_id: GroupId,
    pub ring_hash: RingHash,
    pub poll_id: String,
    pub poll_hash: ContentHash,
    /// The ring hash that was active when the poll was created.
    /// Used to validate that voters use the same ring as poll creation.
    pub poll_ring_hash: RingHash,
    pub selections: Vec<VoteSelection>,
}

impl Vote {
    /// Compute the canonical vote hash (ID-sorted, domain separated).
    pub fn hash(&self) -> Result<ContentHash, CanonicalHashError> {
        vote_hash_sha3_256(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoteSelection {
    pub question_id: String,
    pub option_ids: Vec<String>,
    pub write_in: Option<Ciphertext>,
}
