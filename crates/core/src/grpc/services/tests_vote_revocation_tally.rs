//! P6.1: Vote Revocation tally exclusion and bundle verification test.
//!
//! Extracted from `tests_vote_revocation.rs` to keep individual test modules under 800 lines.

use super::tests::{make_push_event_request, sign_event_archival};
use super::tests_vote_revocation::{
    push_bundle, push_vote, setup_two_member_org, test_event, VotePushRequest,
};
use crate::crypto::ciphertext::Ciphertext;
use crate::event::{Event, EventType, Poll, PollQuestion, PollQuestionKind};
use crate::hashing::ring_hash;
use crate::ids::{EventId, EventUlid, Ulid};
use crate::key_manager::manager::{derive_poll_signing_ring, MandateDerivable};
use mandate_proto::mandate::v1::event_service_server::EventService;

/// Scenario 8: Full election lifecycle with tally exclusion and bundle verification.
///
/// Two members vote on a SingleChoice poll, one revokes, then verify:
/// - `get_poll_results` excludes the revoked vote from the tally
/// - `get_poll_bundle` includes revocations in the response
///
/// Uses `verification_window_secs = 0` so the poll enters Finalized immediately
/// after bundle publication, making results visible. The push_event revocation
/// check only requires `bundle_published_at.is_some()`, so the revocation is
/// still accepted even though the phase is technically Finalized by wall-clock.
#[tokio::test]
async fn vote_revocation_tally_exclusion_and_bundle() {
    use crate::event::{PollOption as EventPollOption, VoteRevocation};
    use crate::key_manager::{derive_poll_key_bytes, encrypt_event_content};
    use mandate_proto::mandate::v1::{GetPollBundleRequest, GetPollResultsRequest};

    let (services, tenant, org_id, owner, member2, ring, member_ring_hash) =
        setup_two_member_org().await;
    let poll_id = "poll-tally-exclusion";

    // Generate poll_event_ulid upfront so we can derive poll_key for encryption
    let poll_event_ulid = EventUlid(Ulid::new());
    let shared_secret = [0x42u8; 32]; // arbitrary test shared secret
    let poll_key_bytes = derive_poll_key_bytes(&shared_secret, &poll_event_ulid);
    let poll_identity = age::x25519::Identity::from_secret_bytes(poll_key_bytes);

    // Create SingleChoice poll with age-encrypted content
    let encrypt = |plaintext: &[u8]| -> Vec<u8> {
        encrypt_event_content(&poll_identity, plaintext).expect("encrypt")
    };
    let poll = Poll {
        org_id,
        ring_hash: member_ring_hash,
        poll_id: poll_id.into(),
        questions: vec![PollQuestion {
            question_id: "q1".into(),
            title: Ciphertext(encrypt(b"Best color?")),
            kind: PollQuestionKind::SingleChoice {
                options: vec![
                    EventPollOption {
                        id: "opt_a".into(),
                        text: Ciphertext(encrypt(b"Red")),
                    },
                    EventPollOption {
                        id: "opt_b".into(),
                        text: Ciphertext(encrypt(b"Blue")),
                    },
                ],
            },
        }],
        created_at: 1,
        instructions: None,
        deadline: Some(1000),
        sealed_duration_secs: Some(60),
        verification_window_secs: Some(0), // immediate finalization after bundle
    };
    let poll_hash = poll.hash().expect("poll hash");

    let mut poll_event = Event {
        event_ulid: poll_event_ulid,
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 2,
        serialization_version: 1,
        event_type: EventType::PollCreate(poll),
        signature: None,
    };
    sign_event_archival(&mut poll_event, &owner, &ring);
    services
        .event
        .push_event(make_push_event_request(tenant, &poll_event))
        .await
        .expect("poll accepted");

    // Derive per-poll signing keys
    let vote_signing_ring = derive_poll_signing_ring(&org_id, &member_ring_hash, poll_id, &ring);
    let vote_signing_ring_hash = ring_hash(&vote_signing_ring);
    let owner_vote_signer = owner.derive_poll_signing(&org_id, &member_ring_hash, poll_id);
    let member2_vote_signer = member2.derive_poll_signing(&org_id, &member_ring_hash, poll_id);

    // Owner votes for opt_a, member2 votes for opt_b
    push_vote(VotePushRequest {
        services: &services,
        tenant,
        org_id,
        poll_id,
        poll_hash,
        poll_ring_hash: member_ring_hash,
        vote_ring_hash: vote_signing_ring_hash,
        signer: &owner_vote_signer,
        vote_signing_ring: &vote_signing_ring,
        option_ids: vec!["opt_a".into()],
        processed_at: 3,
    })
    .await;
    push_vote(VotePushRequest {
        services: &services,
        tenant,
        org_id,
        poll_id,
        poll_hash,
        poll_ring_hash: member_ring_hash,
        vote_ring_hash: vote_signing_ring_hash,
        signer: &member2_vote_signer,
        vote_signing_ring: &vote_signing_ring,
        option_ids: vec!["opt_b".into()],
        processed_at: 4,
    })
    .await;

    // Publish bundle → Finalized (verification_window = 0)
    push_bundle(&services, tenant, org_id, &owner, poll_id, 5).await;

    // Owner revokes their vote
    let mut revocation_event = test_event(
        org_id,
        EventType::VoteRevocation(VoteRevocation {
            org_id,
            ring_hash: vote_signing_ring_hash,
            poll_id: poll_id.into(),
            vote_event_hash: None,
            reason: None,
        }),
        6,
    );
    sign_event_archival(
        &mut revocation_event,
        owner_vote_signer.as_keypair(),
        &vote_signing_ring,
    );
    services
        .event
        .push_event(make_push_event_request(tenant, &revocation_event))
        .await
        .expect("vote revocation accepted");

    // --- Verify get_poll_results: revoked vote excluded from tally ---
    let poll_key_hex = hex::encode(poll_key_bytes);
    let mut results_req = tonic::Request::new(GetPollResultsRequest {
        org_id: org_id.0.to_string(),
        event_ulid: Some(mandate_proto::mandate::v1::Ulid {
            value: poll_event_ulid.0.to_string(),
        }),
        poll_key: poll_key_hex.clone(),
    });
    results_req.extensions_mut().insert(tenant);

    let results = services
        .event
        .get_poll_results(results_req)
        .await
        .expect("get_poll_results must succeed")
        .into_inner();

    assert_eq!(results.election_phase, "finalized");
    assert_eq!(results.options.len(), 2, "poll must have 2 options");
    let opt_a = results.options.iter().find(|o| o.label == "Red");
    let opt_b = results.options.iter().find(|o| o.label == "Blue");
    assert_eq!(
        opt_a.expect("Red present").vote_count,
        0,
        "revoked vote for Red must be excluded"
    );
    assert_eq!(
        opt_b.expect("Blue present").vote_count,
        1,
        "non-revoked vote for Blue must be counted"
    );
    assert_eq!(results.total_votes, 1, "total excludes revoked vote");

    // --- Verify get_poll_bundle: revocations included ---
    let mut bundle_req = tonic::Request::new(GetPollBundleRequest {
        org_id: org_id.0.to_string(),
        event_ulid: Some(mandate_proto::mandate::v1::Ulid {
            value: poll_event_ulid.0.to_string(),
        }),
        poll_key: poll_key_hex,
    });
    bundle_req.extensions_mut().insert(tenant);

    let bundle = services
        .event
        .get_poll_bundle(bundle_req)
        .await
        .expect("get_poll_bundle must succeed")
        .into_inner();

    assert_eq!(bundle.vote_count, 2, "bundle reports all votes cast");
    assert_eq!(bundle.votes.len(), 2, "bundle includes all vote events");
    assert_eq!(bundle.revocations.len(), 1, "bundle includes revocation");

    // Verify revocation key_image matches owner's vote
    let owner_vote_ki = bundle
        .votes
        .iter()
        .find(|v| {
            let ev: Event = serde_json::from_slice(&v.event_bytes).expect("parse");
            matches!(&ev.event_type, EventType::VoteCast(vote)
                if vote.selections.iter().any(|s| s.option_ids.contains(&"opt_a".into())))
        })
        .expect("must find owner's vote (opt_a)");
    assert_eq!(
        bundle.revocations[0].key_image_hex, owner_vote_ki.key_image_hex,
        "revocation key_image must match revoked vote"
    );
}
