use crate::ids::{EventId, KeyImage, RingHash, ContentHash, MasterPublicKey};
use crate::crypto::ciphertext::Ciphertext;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: EventId,
    pub previous_id: EventId,
    pub group_id: String,
    pub processed_at: u64,
    pub serialization_version: u8,
    pub event_type: EventType,
    pub signature: Option<Vec<u8>>, // Placeholder for Nazgul signature
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    PollCreate(Poll),
    VoteCast(Vote),
    MessageCreate(AnonymousMessage),
    RingUpdate(RingUpdate),
    BanCreate(BanCreate),
    BanRevoke(BanRevoke),
    ProofOfInnocence(ProofOfInnocence),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Poll {
    pub group_id: String,
    pub ring_hash: RingHash,
    pub poll_id: String,
    pub questions: Vec<PollQuestion>,
    pub created_at: u64,
    pub instructions: Option<Ciphertext>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Vote {
    pub group_id: String,
    pub ring_hash: RingHash,
    pub poll_id: String,
    pub poll_hash: ContentHash,
    pub selections: Vec<VoteSelection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoteSelection {
    pub question_id: String,
    pub option_ids: Vec<String>,
    pub write_in: Option<Ciphertext>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnonymousMessage {
    pub group_id: String,
    pub ring_hash: RingHash,
    pub message_id: String,
    pub content: Ciphertext,
    pub sent_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RingUpdate {
    pub group_id: String,
    pub ring_hash: RingHash,
    pub operations: Vec<RingOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RingOperation {
    AddMember { public_key: MasterPublicKey },
    RemoveMember { public_key: MasterPublicKey },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BanCreate {
    pub group_id: String,
    pub target: KeyImage,
    pub reason: String,
    pub scope: BanScope,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BanScope {
    BanPost,
    BanVote,
    BanAll,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BanRevoke {
    pub group_id: String,
    pub ban_event_id: EventId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOfInnocence {
    pub group_id: String,
    pub historical_ring_hash: RingHash,
}
