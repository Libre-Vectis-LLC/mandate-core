use crate::crypto::ciphertext::Ciphertext;
use crate::ids::{GroupId, RingHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnonymousMessage {
    pub group_id: GroupId,
    pub ring_hash: RingHash,
    pub message_id: String,
    pub content: Ciphertext,
    pub sent_at: u64,
}
