use crate::crypto::ciphertext::Ciphertext;
use crate::crypto::signature::Signature;
use crate::ids::{ContentHash, EventId, KeyImage, MasterPublicKey, RingHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: EventId,
    pub previous_id: EventId,
    pub group_id: String,
    pub processed_at: u64,
    pub serialization_version: u8,
    pub event_type: EventType,
    pub signature: Option<Signature>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signature::{sign_contextual, SignatureKind, StorageMode};
    use crate::hashing::ring_hash_sha3_256;
    use nazgul::keypair::KeyPair;
    use nazgul::ring::Ring;
    use rand::rngs::OsRng;

    fn make_ring(size: usize) -> (KeyPair, Ring) {
        let mut csprng = OsRng;
        let signer = KeyPair::generate(&mut csprng);
        let mut members: Vec<_> = (0..size - 1)
            .map(|_| *KeyPair::generate(&mut csprng).public())
            .collect();
        members.push(*signer.public());
        (signer, Ring::new(members))
    }

    #[test]
    fn event_signature_roundtrip() {
        let (signer, ring) = make_ring(4);
        let msg = b"audit";
        let sig = sign_contextual(
            SignatureKind::Anonymous,
            StorageMode::Compact,
            &signer,
            &ring,
            msg,
        )
        .expect("sign");

        let event = Event {
            id: EventId([1u8; 32]),
            previous_id: EventId([0u8; 32]),
            group_id: "g".into(),
            processed_at: 123,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                group_id: "g".into(),
                ring_hash: ring_hash_sha3_256(&ring),
                message_id: "m1".into(),
                content: Ciphertext(b"hello".to_vec()),
                sent_at: 123,
            }),
            signature: Some(sig),
        };

        let json = serde_json::to_string(&event).expect("serialize");
        let decoded: Event = serde_json::from_str(&json).expect("deserialize");
        let sig = decoded.signature.expect("signature present");
        assert!(sig.verify(Some(&ring), msg));
    }
}
