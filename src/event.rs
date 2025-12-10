use crate::crypto::ciphertext::Ciphertext;
use crate::crypto::signature::Signature;
use crate::hashing::CanonicalHashError;
use crate::hashing::{event_hash_sha3_256, poll_hash_sha3_256, vote_hash_sha3_256};
use crate::ids::{ContentHash, EventId, GroupId, KeyImage, MasterPublicKey, RingHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: EventId,
    pub previous_id: EventId,
    pub group_id: GroupId,
    /// Monotonic sequence assigned by storage; not part of content hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_no: Option<i64>,
    pub processed_at: u64,
    pub serialization_version: u8,
    pub event_type: EventType,
    pub signature: Option<Signature>,
}

impl Event {
    /// Compute the canonical content hash of the event (excludes signature).
    pub fn content_hash(&self) -> Result<ContentHash, CanonicalHashError> {
        event_hash_sha3_256(self)
    }
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
    pub group_id: GroupId,
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
    pub group_id: GroupId,
    pub ring_hash: RingHash,
    pub poll_id: String,
    pub poll_hash: ContentHash,
    pub selections: Vec<VoteSelection>,
}

impl Poll {
    /// Compute the canonical poll hash (ID-sorted, domain separated).
    pub fn hash(&self) -> Result<ContentHash, CanonicalHashError> {
        poll_hash_sha3_256(self)
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnonymousMessage {
    pub group_id: GroupId,
    pub ring_hash: RingHash,
    pub message_id: String,
    pub content: Ciphertext,
    pub sent_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RingUpdate {
    pub group_id: GroupId,
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
    pub group_id: GroupId,
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
    pub group_id: GroupId,
    pub ban_event_id: EventId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOfInnocence {
    pub group_id: GroupId,
    pub historical_ring_hash: RingHash,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signature::{sign_contextual, SignatureKind, StorageMode};
    use crate::hashing::ring_hash_sha3_256;
    use crate::ids::GroupId;
    use nazgul::keypair::KeyPair;
    use nazgul::ring::Ring;
    use rand::rngs::OsRng;
    use ulid::Ulid;

    fn make_ring(size: usize) -> (KeyPair, Ring) {
        let mut csprng = OsRng;
        let signer = KeyPair::generate(&mut csprng);
        let mut members: Vec<_> = (0..size - 1)
            .map(|_| *KeyPair::generate(&mut csprng).public())
            .collect();
        members.push(*signer.public());
        (signer, Ring::new(members))
    }

    fn gid() -> GroupId {
        GroupId(Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").expect("static ulid"))
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
            group_id: gid(),
            sequence_no: Some(0),
            processed_at: 123,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                group_id: gid(),
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

    #[test]
    fn poll_hash_sorts_questions_and_options() {
        let poll_unsorted = Poll {
            group_id: gid(),
            ring_hash: RingHash([1u8; 32]),
            poll_id: "poll".into(),
            created_at: 1,
            instructions: None,
            questions: vec![
                PollQuestion {
                    question_id: "q2".into(),
                    title: Ciphertext(b"t2".to_vec()),
                    kind: PollQuestionKind::SingleChoice {
                        options: vec![
                            PollOption {
                                id: "b".into(),
                                text: Ciphertext(b"b".to_vec()),
                            },
                            PollOption {
                                id: "a".into(),
                                text: Ciphertext(b"a".to_vec()),
                            },
                        ],
                    },
                },
                PollQuestion {
                    question_id: "q1".into(),
                    title: Ciphertext(b"t1".to_vec()),
                    kind: PollQuestionKind::FillInTheBlank,
                },
            ],
        };

        let mut poll_sorted = poll_unsorted.clone();
        poll_sorted
            .questions
            .sort_by(|a, b| a.question_id.cmp(&b.question_id));
        if let PollQuestionKind::SingleChoice { options } = &mut poll_sorted.questions[1].kind {
            options.sort_by(|a, b| a.id.cmp(&b.id));
        }

        let h1 = poll_unsorted.hash().expect("hash unsorted");
        let h2 = poll_sorted.hash().expect("hash sorted");
        assert_eq!(h1, h2, "poll hash must be independent of ID ordering");
    }

    #[test]
    fn vote_hash_sorts_selections_and_option_ids() {
        let vote_unsorted = Vote {
            group_id: gid(),
            ring_hash: RingHash([2u8; 32]),
            poll_id: "p".into(),
            poll_hash: ContentHash([3u8; 32]),
            selections: vec![
                VoteSelection {
                    question_id: "q2".into(),
                    option_ids: vec!["b".into(), "a".into()],
                    write_in: None,
                },
                VoteSelection {
                    question_id: "q1".into(),
                    option_ids: vec!["y".into(), "x".into()],
                    write_in: Some(Ciphertext(b"w".to_vec())),
                },
            ],
        };

        let mut vote_sorted = vote_unsorted.clone();
        vote_sorted
            .selections
            .sort_by(|a, b| a.question_id.cmp(&b.question_id));
        vote_sorted
            .selections
            .iter_mut()
            .for_each(|s| s.option_ids.sort());

        let h1 = vote_unsorted.hash().expect("hash unsorted");
        let h2 = vote_sorted.hash().expect("hash sorted");
        assert_eq!(h1, h2, "vote hash must be independent of ID ordering");
    }

    #[test]
    fn event_hash_ignores_signature_field() {
        let (signer, ring) = make_ring(3);
        let base_event = Event {
            id: EventId([9u8; 32]),
            previous_id: EventId([8u8; 32]),
            group_id: gid(),
            sequence_no: Some(1),
            processed_at: 10,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                group_id: gid(),
                ring_hash: RingHash([7u8; 32]),
                message_id: "m".into(),
                content: Ciphertext(b"hi".to_vec()),
                sent_at: 10,
            }),
            signature: None,
        };

        let mut signed = base_event.clone();
        let sig = sign_contextual(
            SignatureKind::Anonymous,
            StorageMode::Compact,
            &signer,
            &ring,
            b"msg",
        )
        .expect("sign");
        signed.signature = Some(sig);

        let h_base = base_event.content_hash().expect("hash base");
        let h_signed = signed.content_hash().expect("hash signed");
        assert_eq!(h_base, h_signed, "signature must not affect content hash");
    }
}
