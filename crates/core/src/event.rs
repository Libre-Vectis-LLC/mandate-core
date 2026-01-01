use crate::crypto::ciphertext::Ciphertext;
use crate::crypto::signature::Signature;
use crate::hashing::CanonicalHashError;
use crate::hashing::{event_hash_sha3_256, poll_hash_sha3_256, vote_hash_sha3_256};
use crate::ids::{ContentHash, EventId, EventUlid, GroupId, KeyImage, MasterPublicKey, RingHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub event_ulid: EventUlid,
    pub previous_event_hash: EventId,
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
    /// Compute the canonical content hash of the event (excludes signature and storage metadata).
    pub fn content_hash(&self) -> Result<ContentHash, CanonicalHashError> {
        event_hash_sha3_256(self)
    }

    /// Produce the canonical bytes used for signing (excludes signature and sequence_no).
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>, CanonicalHashError> {
        // We reuse the logic from event_hash_sha3_256 but return bytes instead of hash.
        // The hashing module likely has a helper for this, or we duplicate the stripping logic.
        // Let's verify hashing::event_hash_sha3_256 implementation.
        // It likely serializes a "CanonicalEvent" intermediate struct.
        // Ideally we expose that serialization.
        //
        // For now, I'll replicate the stripping:
        let mut clone = self.clone();
        clone.signature = None;
        clone.sequence_no = None;
        crate::hashing::canonical_json(&clone)
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

impl EventType {
    /// Returns the ring hash associated with this event type.
    ///
    /// For most event types, this is the `ring_hash` field.
    /// For `ProofOfInnocence`, this returns `historical_ring_hash`.
    pub fn ring_hash(&self) -> RingHash {
        match self {
            EventType::PollCreate(p) => p.ring_hash,
            EventType::VoteCast(v) => v.ring_hash,
            EventType::MessageCreate(m) => m.ring_hash,
            EventType::RingUpdate(r) => r.ring_hash,
            EventType::BanCreate(b) => b.ring_hash,
            EventType::BanRevoke(b) => b.ring_hash,
            EventType::ProofOfInnocence(p) => p.historical_ring_hash,
        }
    }
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
    /// The ring hash that was active when the poll was created.
    /// Used to validate that voters use the same ring as poll creation.
    pub poll_ring_hash: RingHash,
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
    pub ring_hash: RingHash,
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
    use crate::test_utils::test_group_id;
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
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            group_id: test_group_id(),
            sequence_no: Some(0),
            processed_at: 123,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                group_id: test_group_id(),
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
        assert!(sig.verify(Some(&ring), msg).expect("verify"));
    }

    #[test]
    fn poll_hash_sorts_questions_and_options() {
        let poll_unsorted = Poll {
            group_id: test_group_id(),
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
            group_id: test_group_id(),
            ring_hash: RingHash([2u8; 32]),
            poll_id: "p".into(),
            poll_hash: ContentHash([3u8; 32]),
            poll_ring_hash: RingHash([2u8; 32]),
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
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([8u8; 32]),
            group_id: test_group_id(),
            sequence_no: Some(1),
            processed_at: 10,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                group_id: test_group_id(),
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

    #[test]
    fn event_hash_ignores_sequence_no_field() {
        let base_event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([9u8; 32]),
            group_id: test_group_id(),
            sequence_no: None,
            processed_at: 42,
            serialization_version: 1,
            event_type: EventType::MessageCreate(AnonymousMessage {
                group_id: test_group_id(),
                ring_hash: RingHash([7u8; 32]),
                message_id: "m".into(),
                content: Ciphertext(b"hi".to_vec()),
                sent_at: 42,
            }),
            signature: None,
        };

        let mut with_sequence = base_event.clone();
        with_sequence.sequence_no = Some(123);

        let h_base = base_event.content_hash().expect("hash base");
        let h_seq = with_sequence.content_hash().expect("hash with sequence");
        assert_eq!(h_base, h_seq, "sequence_no must not affect content hash");
    }

    #[test]
    fn event_type_ring_hash_extraction() {
        let ring_hash = RingHash([42u8; 32]);
        let historical_hash = RingHash([99u8; 32]);
        let group = test_group_id();

        // Test each event type returns correct ring_hash
        let poll = EventType::PollCreate(Poll {
            group_id: group,
            ring_hash,
            poll_id: "p1".into(),
            questions: vec![],
            created_at: 1,
            instructions: None,
        });
        assert_eq!(poll.ring_hash(), ring_hash);

        let vote = EventType::VoteCast(Vote {
            group_id: group,
            ring_hash,
            poll_id: "p1".into(),
            poll_hash: ContentHash([0u8; 32]),
            poll_ring_hash: ring_hash,
            selections: vec![],
        });
        assert_eq!(vote.ring_hash(), ring_hash);

        let msg = EventType::MessageCreate(AnonymousMessage {
            group_id: group,
            ring_hash,
            message_id: "m1".into(),
            content: Ciphertext(b"test".to_vec()),
            sent_at: 1,
        });
        assert_eq!(msg.ring_hash(), ring_hash);

        let ring_update = EventType::RingUpdate(RingUpdate {
            group_id: group,
            ring_hash,
            operations: vec![],
        });
        assert_eq!(ring_update.ring_hash(), ring_hash);

        let ban_create = EventType::BanCreate(BanCreate {
            group_id: group,
            ring_hash,
            target: KeyImage::default(),
            reason: "test".into(),
            scope: BanScope::BanAll,
        });
        assert_eq!(ban_create.ring_hash(), ring_hash);

        let ban_revoke = EventType::BanRevoke(BanRevoke {
            group_id: group,
            ring_hash,
            ban_event_id: EventId([0u8; 32]),
        });
        assert_eq!(ban_revoke.ring_hash(), ring_hash);

        // ProofOfInnocence uses historical_ring_hash
        let proof = EventType::ProofOfInnocence(ProofOfInnocence {
            group_id: group,
            historical_ring_hash: historical_hash,
        });
        assert_eq!(proof.ring_hash(), historical_hash);
    }
}
