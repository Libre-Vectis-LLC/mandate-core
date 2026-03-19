//! Poll-related gRPC handlers: get_poll_results and get_poll_bundle.

use super::service::EventServiceImpl;
use crate::event::{ElectionPhase, Event, EventType};
use crate::ids::OrganizationId;
use crate::key_manager::decrypt_event_content;
use crate::proto::ring_hash_to_hash32;
use age::x25519::Identity as RageIdentity;
use mandate_proto::mandate::v1::{
    GetPollBundleRequest, GetPollBundleResponse, GetPollResultsRequest, GetPollResultsResponse,
    PollOption as ProtoPollOption, PollVoteData,
};
use nazgul::traits::LocalByteConvertible;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};

use super::super::{extract_tenant_id, to_status};

/// Safety cap on events loaded per poll tallying request.
///
/// Poll results scan the org event stream for votes, revocations, and
/// bundle-published markers.  This cap prevents unbounded memory growth
/// while remaining far above any realistic poll size.
///
/// If the org has more events than this, results are computed from the
/// most recent `MAX_POLL_EVENTS` events.  A `tracing::warn!` is emitted
/// so operators can investigate.
///
/// TODO: Add poll-specific storage queries to avoid scanning the entire
/// org event stream.  That removes the need for this cap entirely.
const MAX_POLL_EVENTS: usize = 100_000;

/// Map an `ElectionPhase` to its wire-format string for the proto response.
fn election_phase_to_string(phase: ElectionPhase) -> String {
    match phase {
        ElectionPhase::Voting => "voting".to_string(),
        ElectionPhase::Sealed => "sealed".to_string(),
        ElectionPhase::VerificationOpen => "verification_open".to_string(),
        ElectionPhase::Finalized => "finalized".to_string(),
    }
}

impl EventServiceImpl {
    /// Find the `processed_at` timestamp of the `PollBundlePublished` event
    /// for the given `poll_id`, if one exists.
    fn find_bundle_published_at(events: &[Event], poll_id: &str) -> Option<u64> {
        events.iter().find_map(|event| {
            if let EventType::PollBundlePublished(ref bundle) = event.event_type {
                if bundle.poll_id == poll_id {
                    return Some(event.processed_at);
                }
            }
            None
        })
    }

    pub(super) async fn get_poll_results(
        &self,
        request: Request<GetPollResultsRequest>,
    ) -> Result<Response<GetPollResultsResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();

        // 1. Parse request fields
        let org_id = OrganizationId(
            crate::proto::parse_ulid(&body.org_id)
                .map_err(|e| Status::invalid_argument(format!("invalid org_id: {e}")))?,
        );

        let event_ulid_proto = body
            .event_ulid
            .ok_or_else(|| Status::invalid_argument("missing event_ulid"))?;
        let event_ulid = crate::ids::EventUlid(
            crate::proto::parse_ulid(&event_ulid_proto.value)
                .map_err(|e| Status::invalid_argument(format!("invalid event_ulid: {e}")))?,
        );

        // 2. Decode poll_key hex to age Identity
        let poll_key_bytes: [u8; 32] = hex::decode(&body.poll_key)
            .map_err(|e| Status::invalid_argument(format!("invalid poll_key hex: {e}")))?
            .try_into()
            .map_err(|_| Status::invalid_argument("poll_key must be exactly 32 bytes"))?;

        let identity = RageIdentity::from_secret_bytes(poll_key_bytes);

        // 3. Find the Poll event
        let event_records = self
            .store
            .stream_events(tenant, org_id, None, MAX_POLL_EVENTS)
            .await
            .map_err(to_status)?;

        // Deserialize all events
        let mut events: Vec<Event> = Vec::new();
        for (_event_id, event_bytes, _seq) in &event_records {
            let event: Event = serde_json::from_slice(event_bytes)
                .map_err(|e| Status::internal(format!("failed to deserialize event: {e}")))?;
            events.push(event);
        }

        let poll_event = events
            .iter()
            .find(|event| event.event_ulid == event_ulid)
            .ok_or_else(|| Status::not_found("poll event not found"))?;

        let poll = match &poll_event.event_type {
            crate::event::EventType::PollCreate(p) => p,
            _ => {
                return Err(Status::invalid_argument(
                    "specified event is not a poll creation event",
                ))
            }
        };

        // 4. Decrypt and validate poll_key by attempting to decrypt the question title
        let question_bytes = decrypt_event_content(&identity, &poll.questions[0].title.0)
            .map_err(|_| Status::permission_denied("invalid poll_key: decryption failed"))?;

        let question_title = String::from_utf8_lossy(&question_bytes).to_string();

        // 5. Determine election phase
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs();

        let bundle_published_at = Self::find_bundle_published_at(&events, &poll.poll_id);
        let phase = poll.election_phase(current_time, bundle_published_at);

        // 6. Decrypt option labels and build option_id -> (index, label) map
        let mut option_map: HashMap<String, (usize, String)> = HashMap::new();

        if let Some(first_question) = poll.questions.first() {
            let options_vec = match &first_question.kind {
                crate::event::PollQuestionKind::SingleChoice { options } => options,
                crate::event::PollQuestionKind::MultipleChoice { options, .. } => options,
                crate::event::PollQuestionKind::FillInTheBlank => {
                    // No options to decrypt for fill-in-the-blank
                    &vec![]
                }
            };

            for (idx, opt) in options_vec.iter().enumerate() {
                let label_bytes = decrypt_event_content(&identity, &opt.text.0).map_err(|e| {
                    Status::internal(format!("failed to decrypt option label: {e}"))
                })?;

                let label = String::from_utf8_lossy(&label_bytes).to_string();
                option_map.insert(opt.id.clone(), (idx, label));
            }
        }

        // 7. Count votes only if Finalized (hide intermediate results).
        //    Legacy polls (no deadline) always show results — they have no lifecycle.
        let show_results = phase == ElectionPhase::Finalized || poll.deadline.is_none();
        let (vote_counts, total_votes) = if show_results {
            // Collect key images from VoteRevocation events so revoked votes
            // are excluded from the tally.
            let mut revoked_key_images: HashSet<[u8; 32]> = HashSet::new();
            for event in events.iter() {
                if let crate::event::EventType::VoteRevocation(revocation) = &event.event_type {
                    if revocation.poll_id == poll.poll_id {
                        if let Some(sig) = &event.signature {
                            revoked_key_images.insert(sig.key_image().to_bytes());
                        }
                    }
                }
            }

            let mut counts: HashMap<String, u32> = HashMap::new();

            for event in events.iter() {
                if let crate::event::EventType::VoteCast(vote) = &event.event_type {
                    if vote.poll_id == poll.poll_id {
                        // Skip votes that have been revoked
                        if let Some(sig) = &event.signature {
                            if revoked_key_images.contains(&sig.key_image().to_bytes()) {
                                continue;
                            }
                        }
                        for selection in &vote.selections {
                            for option_id in &selection.option_ids {
                                *counts.entry(option_id.clone()).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }

            let total: u32 = counts.values().sum();
            (counts, total)
        } else {
            // Before Finalized: return zero counts to prevent intermediate
            // results from influencing voter behavior or enabling
            // strategic voting.
            (HashMap::new(), 0)
        };

        // 8. Build response
        let mut proto_options: Vec<ProtoPollOption> = option_map
            .iter()
            .map(|(option_id, (idx, label))| ProtoPollOption {
                index: *idx as u32,
                label: label.clone(),
                vote_count: vote_counts.get(option_id).copied().unwrap_or(0),
            })
            .collect();

        // Sort by index to maintain option order
        proto_options.sort_by_key(|opt| opt.index);

        let is_open = phase == ElectionPhase::Voting;

        Ok(Response::new(GetPollResultsResponse {
            question: question_title,
            created_at: poll.created_at as i64,
            options: proto_options,
            total_votes,
            ring_hash: Some(ring_hash_to_hash32(&poll.ring_hash)),
            is_open,
            election_phase: election_phase_to_string(phase),
        }))
    }

    pub(super) async fn get_poll_bundle(
        &self,
        request: Request<GetPollBundleRequest>,
    ) -> Result<Response<GetPollBundleResponse>, Status> {
        let tenant = extract_tenant_id(&request, &self.store).await?;
        let body = request.into_inner();

        // 1. Parse request fields
        let org_id = OrganizationId(
            crate::proto::parse_ulid(&body.org_id)
                .map_err(|e| Status::invalid_argument(format!("invalid org_id: {e}")))?,
        );

        let event_ulid_proto = body
            .event_ulid
            .ok_or_else(|| Status::invalid_argument("missing event_ulid"))?;
        let event_ulid = crate::ids::EventUlid(
            crate::proto::parse_ulid(&event_ulid_proto.value)
                .map_err(|e| Status::invalid_argument(format!("invalid event_ulid: {e}")))?,
        );

        // 2. Decode poll_key hex to age Identity
        let poll_key_bytes: [u8; 32] = hex::decode(&body.poll_key)
            .map_err(|e| Status::invalid_argument(format!("invalid poll_key hex: {e}")))?
            .try_into()
            .map_err(|_| Status::invalid_argument("poll_key must be exactly 32 bytes"))?;

        let identity = RageIdentity::from_secret_bytes(poll_key_bytes);

        // 3. Stream all events for this org
        let event_records = self
            .store
            .stream_events(tenant, org_id, None, MAX_POLL_EVENTS)
            .await
            .map_err(to_status)?;

        // 4. Find poll event and validate poll_key by attempting decryption
        let mut poll_event_opt: Option<(Event, Vec<u8>, i64)> = None;

        for (_event_id, event_bytes, seq) in &event_records {
            let event: Event = serde_json::from_slice(event_bytes)
                .map_err(|e| Status::internal(format!("failed to deserialize event: {e}")))?;

            if event.event_ulid == event_ulid {
                let poll = match &event.event_type {
                    crate::event::EventType::PollCreate(p) => p,
                    _ => {
                        return Err(Status::invalid_argument(
                            "specified event is not a poll creation event",
                        ))
                    }
                };

                // Validate poll_key by attempting to decrypt the first question title
                let _question_bytes = decrypt_event_content(&identity, &poll.questions[0].title.0)
                    .map_err(|_| {
                        Status::permission_denied("invalid poll_key: decryption failed")
                    })?;

                poll_event_opt = Some((event, event_bytes.to_vec(), seq.0));
                break;
            }
        }

        let (poll_event, poll_event_bytes, _poll_seq) =
            poll_event_opt.ok_or_else(|| Status::not_found("poll event not found"))?;

        let poll = match &poll_event.event_type {
            crate::event::EventType::PollCreate(p) => p,
            _ => unreachable!(),
        };

        // 5. Collect all vote and revocation events for this poll
        let mut vote_data_vec: Vec<PollVoteData> = Vec::new();
        let mut revocation_data_vec: Vec<PollVoteData> = Vec::new();

        for (_event_id, event_bytes, seq) in &event_records {
            let event: Event = serde_json::from_slice(event_bytes)
                .map_err(|e| Status::internal(format!("failed to deserialize event: {e}")))?;

            if let crate::event::EventType::VoteCast(vote) = &event.event_type {
                if vote.poll_id == poll.poll_id {
                    let sig = event
                        .signature
                        .as_ref()
                        .ok_or_else(|| Status::internal("vote event missing signature"))?;

                    let key_image_bytes = sig.key_image().to_bytes();
                    let key_image_hex = hex::encode(key_image_bytes);

                    let event_json = serde_json::to_string(&event)
                        .map_err(|e| Status::internal(format!("failed to serialize event: {e}")))?;

                    vote_data_vec.push(PollVoteData {
                        event_ulid: event.event_ulid.0.to_string(),
                        sequence_no: seq.0,
                        key_image_hex,
                        event_bytes: event_bytes.to_vec(),
                        event_json,
                    });
                }
            } else if let crate::event::EventType::VoteRevocation(revocation) = &event.event_type {
                if revocation.poll_id == poll.poll_id {
                    let sig = event
                        .signature
                        .as_ref()
                        .ok_or_else(|| Status::internal("revocation event missing signature"))?;

                    let key_image_bytes = sig.key_image().to_bytes();
                    let key_image_hex = hex::encode(key_image_bytes);

                    let event_json = serde_json::to_string(&event)
                        .map_err(|e| Status::internal(format!("failed to serialize event: {e}")))?;

                    revocation_data_vec.push(PollVoteData {
                        event_ulid: event.event_ulid.0.to_string(),
                        sequence_no: seq.0,
                        key_image_hex,
                        event_bytes: event_bytes.to_vec(),
                        event_json,
                    });
                }
            }
        }

        // Sort by sequence number for deterministic ordering
        vote_data_vec.sort_by_key(|v| v.sequence_no);
        revocation_data_vec.sort_by_key(|v| v.sequence_no);

        // 6. Build response
        let poll_hash = crate::hashing::sha3_256_bytes(&poll_event_bytes);
        let poll_hash_hex = hex::encode(poll_hash.0);

        let ring_hash_hex = hex::encode(poll.ring_hash.0);
        let poll_key_hex = hex::encode(poll_key_bytes);

        // Convert poll_key to age-secret format for external tools
        let poll_key_age_secret = format!(
            "AGE-SECRET-KEY-1{}",
            bs58::encode(&poll_key_bytes).into_string().to_uppercase()
        );

        let poll_event_json = serde_json::to_string(&poll_event)
            .map_err(|e| Status::internal(format!("failed to serialize poll event: {e}")))?;

        Ok(Response::new(GetPollBundleResponse {
            org_id: org_id.0.to_string(),
            poll_id: poll.poll_id.to_string(),
            poll_event_ulid: event_ulid.0.to_string(),
            poll_hash_hex,
            ring_hash_hex,
            poll_key_hex,
            poll_key_age_secret,
            vote_count: vote_data_vec.len() as u32,
            poll_event_bytes,
            poll_event_json,
            votes: vote_data_vec,
            revocations: revocation_data_vec,
        }))
    }
}
