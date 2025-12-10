//! Hashing helpers with a SHA3-first policy.
//!
//! - Default digest: SHA3-256.
//! - SHA3-512 is available when a longer digest is strictly required.
//! - Provides helpers for raw bytes, ciphertexts, and ring consensus hashes
//!   using nazgul's `Ring::consensus_hash`.

use crate::crypto::ciphertext::Ciphertext;
use crate::event::{
    AnonymousMessage, BanCreate, BanRevoke, Event, EventType, Poll, PollOption, PollQuestion,
    PollQuestionKind, RingUpdate, Vote, VoteSelection,
};
use crate::ids::{ContentHash, EventId, GroupId};
use nazgul::ring::{Ring, RingHash};
use serde::Serialize;
use serde_json::Value;
use sha3::{Digest, Sha3_256, Sha3_512};
use thiserror::Error;

/// 256-bit hash output type (newtype for stronger typing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; 32]> for Hash256 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 512-bit hash output type (newtype for stronger typing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hash512(pub [u8; 64]);

impl Hash512 {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub fn into_inner(self) -> [u8; 64] {
        self.0
    }
}

impl From<[u8; 64]> for Hash512 {
    fn from(value: [u8; 64]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; 64]> for Hash512 {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Hash arbitrary bytes with SHA3-256.
pub fn sha3_256_bytes(data: impl AsRef<[u8]>) -> Hash256 {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    Hash256(hasher.finalize().into())
}

/// Hash arbitrary bytes with SHA3-512 (use only when digest extension is required).
pub fn sha3_512_bytes(data: impl AsRef<[u8]>) -> Hash512 {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    Hash512(hasher.finalize().into())
}

/// Compute a `ContentHash` for plaintext bytes using SHA3-256.
pub fn content_hash_bytes(data: impl AsRef<[u8]>) -> ContentHash {
    ContentHash(sha3_256_bytes(data).into_inner())
}

/// Compute a `ContentHash` over an encrypted payload.
pub fn content_hash_ciphertext(ciphertext: &Ciphertext) -> ContentHash {
    ContentHash(sha3_256_bytes(&ciphertext.0).into_inner())
}

/// Derive a deterministic ring hash using nazgul's consensus hash with SHA3-256.
/// The underlying `Ring` already sorts members, so the result is order-invariant.
pub fn ring_hash_sha3_256(ring: &Ring) -> RingHash {
    let bytes: [u8; 32] = ring.consensus_hash::<Sha3_256>().into();
    RingHash(bytes)
}

/// Domain prefixes for hashing distinct mandate payloads.
pub mod domain {
    /// Domain prefix for events.
    pub const EVENT: &[u8] = b"mandate:event";
    /// Domain prefix for polls.
    pub const POLL: &[u8] = b"mandate:poll";
    /// Domain prefix for votes.
    pub const VOTE: &[u8] = b"mandate:vote";
    /// Domain prefix for messages.
    pub const MESSAGE: &[u8] = b"mandate:message";
    /// Domain prefix for ring snapshots or deltas.
    pub const RING: &[u8] = b"mandate:ring";
}

/// Errors from canonical serialization and hashing.
#[derive(Debug, Error)]
pub enum CanonicalHashError {
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Digest trait to allow future hash algorithm swaps (e.g., BLAKE3) without API breakage.
pub trait DigestAlgorithm {
    type Output;

    /// Hash `domain || message`, returning the algorithm-specific output type.
    fn hash_with_domain(domain: &[u8], message: &[u8]) -> Self::Output;
}

/// SHA3-256 digest algorithm (default).
pub struct Sha3_256Digest;

impl DigestAlgorithm for Sha3_256Digest {
    type Output = Hash256;

    fn hash_with_domain(domain: &[u8], message: &[u8]) -> Self::Output {
        let mut hasher = Sha3_256::new();
        hasher.update(domain);
        hasher.update(message);
        Hash256(hasher.finalize().into())
    }
}

/// SHA3-512 digest algorithm for extended outputs.
pub struct Sha3_512Digest;

impl DigestAlgorithm for Sha3_512Digest {
    type Output = Hash512;

    fn hash_with_domain(domain: &[u8], message: &[u8]) -> Self::Output {
        let mut hasher = Sha3_512::new();
        hasher.update(domain);
        hasher.update(message);
        Hash512(hasher.finalize().into())
    }
}

/// Serialize to canonical JSON (sorted keys, no whitespace) for stable hashing.
pub fn canonical_json_bytes(value: &impl Serialize) -> Result<Vec<u8>, CanonicalHashError> {
    let mut v = serde_json::to_value(value)?;
    normalize_value(&mut v);
    let mut buf = Vec::new();
    serde_json::to_writer(&mut buf, &v)?;
    Ok(buf)
}

fn normalize_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> =
                map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            map.clear();
            for (k, mut v) in entries {
                normalize_value(&mut v);
                map.insert(k, v);
            }
        }
        Value::Array(items) => {
            for v in items.iter_mut() {
                normalize_value(v);
            }
        }
        _ => {}
    }
}

/// Compute a canonical content hash using SHA3-256 with domain separation.
pub fn canonical_content_hash_sha3_256(
    domain: &[u8],
    value: &impl Serialize,
) -> Result<ContentHash, CanonicalHashError> {
    let json = canonical_json_bytes(value)?;
    let hash = Sha3_256Digest::hash_with_domain(domain, &json);
    Ok(ContentHash(hash.into_inner()))
}

/// Hash an event (excluding its signature) using canonical JSON and the EVENT domain.
pub fn event_hash_sha3_256(event: &Event) -> Result<ContentHash, CanonicalHashError> {
    let canonical = CanonicalEvent::from(event);
    canonical_content_hash_sha3_256(domain::EVENT, &canonical)
}

/// Hash a poll with ID-sorted questions/options using the POLL domain.
pub fn poll_hash_sha3_256(poll: &Poll) -> Result<ContentHash, CanonicalHashError> {
    let canonical = CanonicalPoll::from(poll);
    canonical_content_hash_sha3_256(domain::POLL, &canonical)
}

/// Hash a vote with ID-sorted selections/option IDs using the VOTE domain.
pub fn vote_hash_sha3_256(vote: &Vote) -> Result<ContentHash, CanonicalHashError> {
    let canonical = CanonicalVote::from(vote);
    canonical_content_hash_sha3_256(domain::VOTE, &canonical)
}

#[derive(Serialize)]
struct CanonicalEvent<'a> {
    id: EventId,
    previous_id: EventId,
    group_id: GroupId,
    processed_at: u64,
    serialization_version: u8,
    event_type: CanonicalEventType<'a>,
}

impl<'a> From<&'a Event> for CanonicalEvent<'a> {
    fn from(event: &'a Event) -> Self {
        Self {
            id: event.id,
            previous_id: event.previous_id,
            group_id: event.group_id,
            processed_at: event.processed_at,
            serialization_version: event.serialization_version,
            event_type: CanonicalEventType::from(&event.event_type),
        }
    }
}

#[derive(Serialize)]
enum CanonicalEventType<'a> {
    PollCreate(CanonicalPoll<'a>),
    VoteCast(CanonicalVote<'a>),
    MessageCreate(&'a AnonymousMessage),
    RingUpdate(&'a RingUpdate),
    BanCreate(&'a BanCreate),
    BanRevoke(&'a BanRevoke),
    ProofOfInnocence(&'a crate::event::ProofOfInnocence),
}

impl<'a> From<&'a EventType> for CanonicalEventType<'a> {
    fn from(value: &'a EventType) -> Self {
        match value {
            EventType::PollCreate(p) => CanonicalEventType::PollCreate(CanonicalPoll::from(p)),
            EventType::VoteCast(v) => CanonicalEventType::VoteCast(CanonicalVote::from(v)),
            EventType::MessageCreate(m) => CanonicalEventType::MessageCreate(m),
            EventType::RingUpdate(r) => CanonicalEventType::RingUpdate(r),
            EventType::BanCreate(b) => CanonicalEventType::BanCreate(b),
            EventType::BanRevoke(b) => CanonicalEventType::BanRevoke(b),
            EventType::ProofOfInnocence(p) => CanonicalEventType::ProofOfInnocence(p),
        }
    }
}

#[derive(Serialize)]
struct CanonicalPoll<'a> {
    group_id: GroupId,
    ring_hash: RingHash,
    poll_id: &'a str,
    questions: Vec<CanonicalPollQuestion<'a>>,
    created_at: u64,
    instructions: Option<&'a Ciphertext>,
}

impl<'a> From<&'a Poll> for CanonicalPoll<'a> {
    fn from(poll: &'a Poll) -> Self {
        let mut questions: Vec<&'a PollQuestion> = poll.questions.iter().collect();
        questions.sort_by(|a, b| a.question_id.cmp(&b.question_id));

        let questions = questions
            .into_iter()
            .map(CanonicalPollQuestion::from)
            .collect();

        Self {
            group_id: poll.group_id,
            ring_hash: poll.ring_hash,
            poll_id: &poll.poll_id,
            questions,
            created_at: poll.created_at,
            instructions: poll.instructions.as_ref(),
        }
    }
}

#[derive(Serialize)]
struct CanonicalPollQuestion<'a> {
    question_id: &'a str,
    title: &'a Ciphertext,
    kind: CanonicalPollQuestionKind<'a>,
}

impl<'a> From<&'a PollQuestion> for CanonicalPollQuestion<'a> {
    fn from(q: &'a PollQuestion) -> Self {
        Self {
            question_id: &q.question_id,
            title: &q.title,
            kind: CanonicalPollQuestionKind::from(&q.kind),
        }
    }
}

#[derive(Serialize)]
enum CanonicalPollQuestionKind<'a> {
    SingleChoice {
        options: Vec<CanonicalPollOption<'a>>,
    },
    MultipleChoice {
        options: Vec<CanonicalPollOption<'a>>,
        max: u32,
    },
    FillInTheBlank,
}

impl<'a> From<&'a PollQuestionKind> for CanonicalPollQuestionKind<'a> {
    fn from(kind: &'a PollQuestionKind) -> Self {
        match kind {
            PollQuestionKind::SingleChoice { options } => Self::SingleChoice {
                options: canonical_options(options),
            },
            PollQuestionKind::MultipleChoice { options, max } => Self::MultipleChoice {
                options: canonical_options(options),
                max: *max,
            },
            PollQuestionKind::FillInTheBlank => Self::FillInTheBlank,
        }
    }
}

#[derive(Serialize)]
struct CanonicalPollOption<'a> {
    id: &'a str,
    text: &'a Ciphertext,
}

fn canonical_options<'a>(options: &'a [PollOption]) -> Vec<CanonicalPollOption<'a>> {
    let mut opts: Vec<&'a PollOption> = options.iter().collect();
    opts.sort_by(|a, b| a.id.cmp(&b.id));
    opts.into_iter()
        .map(|o| CanonicalPollOption {
            id: &o.id,
            text: &o.text,
        })
        .collect()
}

#[derive(Serialize)]
struct CanonicalVote<'a> {
    group_id: GroupId,
    ring_hash: RingHash,
    poll_id: &'a str,
    poll_hash: crate::ids::ContentHash,
    selections: Vec<CanonicalVoteSelection<'a>>,
}

impl<'a> From<&'a Vote> for CanonicalVote<'a> {
    fn from(v: &'a Vote) -> Self {
        let mut selections: Vec<&'a VoteSelection> = v.selections.iter().collect();
        selections.sort_by(|a, b| a.question_id.cmp(&b.question_id));

        let selections = selections
            .into_iter()
            .map(CanonicalVoteSelection::from)
            .collect();

        Self {
            group_id: v.group_id,
            ring_hash: v.ring_hash,
            poll_id: &v.poll_id,
            poll_hash: v.poll_hash,
            selections,
        }
    }
}

#[derive(Serialize)]
struct CanonicalVoteSelection<'a> {
    question_id: &'a str,
    option_ids: Vec<&'a str>,
    write_in: Option<&'a Ciphertext>,
}

impl<'a> From<&'a VoteSelection> for CanonicalVoteSelection<'a> {
    fn from(sel: &'a VoteSelection) -> Self {
        let mut option_ids: Vec<&'a str> = sel.option_ids.iter().map(String::as_str).collect();
        option_ids.sort_unstable();
        Self {
            question_id: &sel.question_id,
            option_ids,
            write_in: sel.write_in.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use hex::encode;
    use proptest::prelude::*;
    use serde::Serialize;
    use sha3::Sha3_512;
    use ulid::Ulid;

    fn point(label: &[u8]) -> RistrettoPoint {
        RistrettoPoint::hash_from_bytes::<Sha3_512>(label)
    }

    #[test]
    fn sha3_256_deterministic() {
        let h1 = sha3_256_bytes(b"mandate");
        let h2 = sha3_256_bytes(b"mandate");
        assert_eq!(h1, h2);
    }

    #[test]
    fn ring_hash_order_invariant() {
        let p1 = point(b"member-1");
        let p2 = point(b"member-2");
        let p3 = point(b"member-3");

        let ring_a = Ring::new(vec![p1, p2, p3]);
        let ring_b = Ring::new(vec![p3, p1, p2]);

        let ha = ring_hash_sha3_256(&ring_a);
        let hb = ring_hash_sha3_256(&ring_b);

        assert_eq!(ha, hb, "ring hash should be independent of input order");
    }

    #[test]
    fn content_hash_ciphertext_matches_bytes() {
        let payload = b"sealed".to_vec();
        let ct = Ciphertext(payload.clone());
        assert_eq!(
            content_hash_ciphertext(&ct).0,
            content_hash_bytes(&payload).0
        );
    }

    #[derive(Serialize)]
    struct DemoObj {
        b: u8,
        a: u8,
    }

    #[test]
    fn canonical_json_sorts_keys_and_hashes() {
        let obj1 = DemoObj { a: 1, b: 2 };
        let obj2 = DemoObj { b: 2, a: 1 };

        let j1 = canonical_json_bytes(&obj1).expect("json");
        let j2 = canonical_json_bytes(&obj2).expect("json");
        assert_eq!(j1, j2, "canonical JSON must be order independent");

        let h1 = canonical_content_hash_sha3_256(domain::EVENT, &obj1).expect("hash");
        let h2 = canonical_content_hash_sha3_256(domain::EVENT, &obj2).expect("hash");
        assert_eq!(h1, h2, "hash should ignore map insertion order");
    }

    #[test]
    fn domain_separation_alters_hash() {
        let obj = DemoObj { a: 7, b: 9 };
        let h_event =
            canonical_content_hash_sha3_256(domain::EVENT, &obj).expect("hash event domain");
        let h_poll = canonical_content_hash_sha3_256(domain::POLL, &obj).expect("hash poll domain");
        assert_ne!(h_event, h_poll, "domain separator must change digest");
    }

    #[derive(Serialize)]
    struct WithArray {
        items: Vec<u8>,
    }

    #[test]
    fn arrays_preserve_order() {
        let ascending = WithArray {
            items: vec![1, 2, 3],
        };
        let descending = WithArray {
            items: vec![3, 2, 1],
        };

        let h1 = canonical_content_hash_sha3_256(domain::EVENT, &ascending).expect("hash");
        let h2 = canonical_content_hash_sha3_256(domain::EVENT, &descending).expect("hash");
        assert_ne!(h1, h2, "array order must remain significant");
    }

    proptest! {
        #[test]
        fn canonical_json_order_invariant_prop(kvs in prop::collection::hash_map("[a-z]{1,6}", 0u8..16u8, 1..8)) {
            // Build two maps with different insertion orders but same entries.
            let mut map_a = serde_json::Map::new();
            for (k, v) in kvs.iter() {
                map_a.insert(k.clone(), Value::from(*v as u64));
            }
            let mut keys: Vec<_> = kvs.keys().cloned().collect();
            keys.reverse();
            let mut map_b = serde_json::Map::new();
            for k in keys {
                let v = kvs.get(&k).unwrap();
                map_b.insert(k.clone(), Value::from(*v as u64));
            }

            let a = canonical_json_bytes(&Value::Object(map_a)).expect("canon a");
            let b = canonical_json_bytes(&Value::Object(map_b)).expect("canon b");
            prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn golden_content_hash() {
        let h = content_hash_bytes(b"mandate");
        assert_eq!(
            encode(h.0),
            "5baed7d21dfe60b2a6bc50770f83d4c6e3ded56bb474784a1b7847c8c83c0dc2"
        );
    }

    #[test]
    fn golden_ring_hash() {
        let p1 = point(b"member-a");
        let p2 = point(b"member-b");
        let ring = Ring::new(vec![p1, p2]);
        let h = ring_hash_sha3_256(&ring);
        assert_eq!(
            encode(h.0),
            "5fa7ac38764b3f2222db3881b8272804fefaed7dca731d49f0e70d9f5ed792b5"
        );
    }

    #[test]
    fn golden_poll_hash() {
        let poll = PollFixture::poll();
        let h = poll_hash_sha3_256(&poll).expect("hash poll");
        assert_eq!(
            encode(h.0),
            "3a78765011ce19aa8064e5f33af17b9253f4b90f104d0900709423e2e043f234"
        );
    }

    #[derive(Clone)]
    struct PollFixture;

    impl PollFixture {
        fn poll() -> crate::event::Poll {
            crate::event::Poll {
                group_id: gid(),
                ring_hash: RingHash([0x11; 32]),
                poll_id: "poll-1".into(),
                created_at: 42,
                instructions: Some(Ciphertext(b"how-to".to_vec())),
                questions: vec![
                    crate::event::PollQuestion {
                        question_id: "q1".into(),
                        title: Ciphertext(b"title".to_vec()),
                        kind: crate::event::PollQuestionKind::MultipleChoice {
                            options: vec![
                                crate::event::PollOption {
                                    id: "b".into(),
                                    text: Ciphertext(b"opt-b".to_vec()),
                                },
                                crate::event::PollOption {
                                    id: "a".into(),
                                    text: Ciphertext(b"opt-a".to_vec()),
                                },
                            ],
                            max: 2,
                        },
                    },
                    crate::event::PollQuestion {
                        question_id: "q2".into(),
                        title: Ciphertext(b"second".to_vec()),
                        kind: crate::event::PollQuestionKind::FillInTheBlank,
                    },
                ],
            }
        }
    }

    fn gid() -> GroupId {
        GroupId(Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").expect("static ulid"))
    }
}
