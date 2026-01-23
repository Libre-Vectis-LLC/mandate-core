use crate::ids::{EventId, GroupId, KeyImage, RingHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BanCreate {
    pub group_id: GroupId,
    pub ring_hash: RingHash,
    pub target: KeyImage,
    pub reason: String,
    pub scope: BanScope,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BanScope {
    BanPost,
    BanVote,
    BanAll,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BanRevoke {
    pub group_id: GroupId,
    pub ban_event_id: EventId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOfInnocence {
    pub group_id: GroupId,
    pub historical_ring_hash: RingHash,
}
