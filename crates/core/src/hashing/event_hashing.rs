//! Event-specific hashing functions.

use crate::crypto::ciphertext::Ciphertext;
use crate::event::{
    AnonymousMessage, BanCreate, BanRevoke, Event, EventType, Poll, PollOption, PollQuestion,
    PollQuestionKind, RingUpdate, Vote, VoteSelection,
};
use crate::ids::{ContentHash, EventId, EventUlid, OrganizationId};
use nazgul::ring::RingHash;
use serde::Serialize;

use super::canonical::{canonical_content_hash_sha3_256, CanonicalHashError};
use super::primitives::domain;

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
    event_ulid: EventUlid,
    previous_event_hash: EventId,
    org_id: OrganizationId,
    // sequence_no intentionally excluded from canonical hash (storage ordering only)
    processed_at: u64,
    serialization_version: u8,
    event_type: CanonicalEventType<'a>,
}

impl<'a> From<&'a Event> for CanonicalEvent<'a> {
    fn from(event: &'a Event) -> Self {
        Self {
            event_ulid: event.event_ulid,
            previous_event_hash: event.previous_event_hash,
            org_id: event.org_id,
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
    VoteRevocation(&'a crate::event::VoteRevocation),
    MessageCreate(&'a AnonymousMessage),
    RingUpdate(&'a RingUpdate),
    BanCreate(&'a BanCreate),
    BanRevoke(&'a BanRevoke),
    ProofOfInnocence(&'a crate::event::ProofOfInnocence),
    PollBundlePublished(&'a crate::event::PollBundlePublished),
    Unknown,
}

impl<'a> From<&'a EventType> for CanonicalEventType<'a> {
    fn from(value: &'a EventType) -> Self {
        match value {
            EventType::PollCreate(p) => CanonicalEventType::PollCreate(CanonicalPoll::from(p)),
            EventType::VoteCast(v) => CanonicalEventType::VoteCast(CanonicalVote::from(v)),
            EventType::VoteRevocation(vr) => CanonicalEventType::VoteRevocation(vr),
            EventType::MessageCreate(m) => CanonicalEventType::MessageCreate(m),
            EventType::RingUpdate(r) => CanonicalEventType::RingUpdate(r),
            EventType::BanCreate(b) => CanonicalEventType::BanCreate(b),
            EventType::BanRevoke(b) => CanonicalEventType::BanRevoke(b),
            EventType::ProofOfInnocence(p) => CanonicalEventType::ProofOfInnocence(p),
            EventType::PollBundlePublished(pb) => CanonicalEventType::PollBundlePublished(pb),
            EventType::Unknown => CanonicalEventType::Unknown,
        }
    }
}

#[derive(Serialize)]
struct CanonicalPoll<'a> {
    org_id: OrganizationId,
    ring_hash: RingHash,
    poll_id: &'a str,
    questions: Vec<CanonicalPollQuestion<'a>>,
    created_at: u64,
    instructions: Option<&'a Ciphertext>,
    deadline: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_duration_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_window_secs: Option<u64>,
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
            org_id: poll.org_id,
            ring_hash: poll.ring_hash,
            poll_id: &poll.poll_id,
            questions,
            created_at: poll.created_at,
            instructions: poll.instructions.as_ref(),
            deadline: poll.deadline,
            sealed_duration_secs: poll.sealed_duration_secs,
            verification_window_secs: poll.verification_window_secs,
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
    org_id: OrganizationId,
    ring_hash: RingHash,
    poll_id: &'a str,
    poll_hash: crate::ids::ContentHash,
    /// The ring hash that was active when the poll was created.
    poll_ring_hash: RingHash,
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
            org_id: v.org_id,
            ring_hash: v.ring_hash,
            poll_id: &v.poll_id,
            poll_hash: v.poll_hash,
            poll_ring_hash: v.poll_ring_hash,
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
