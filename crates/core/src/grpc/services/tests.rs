use super::*;
use crate::grpc::wiring::CoreServices;
use crate::ids::{OrganizationId, TenantId};
use mandate_proto::mandate::v1::event_service_server::EventService;
use mandate_proto::mandate::v1::organization_service_server::OrganizationService;
use mandate_proto::mandate::v1::storage_service_server::StorageService;
use mandate_proto::mandate::v1::{
    CreateOrganizationRequest, KeyBlob, NazgulMasterPublicKey, PushEventRequest, RagePublicKey,
    SetOwnerPublicKeyRequest, UploadKeyBlobsRequest,
};

/// Create an organization owned by the given tenant for tests that need BOLA checks.
pub(super) async fn create_test_org(services: &CoreServices, tenant: TenantId) -> OrganizationId {
    let mut req = Request::new(CreateOrganizationRequest {
        tenant_id: tenant.0.to_string(),
        tg_group_id: "test-group".to_string(),
    });
    req.extensions_mut().insert(tenant);
    let resp = services
        .organization
        .create_organization(req)
        .await
        .expect("create test org");
    OrganizationId(ulid::Ulid::from_string(&resp.into_inner().org_id).expect("parse org_id"))
}

pub(super) async fn set_test_owner_key(
    services: &CoreServices,
    tenant: TenantId,
    org_id: OrganizationId,
    owner: &KeyPair,
) {
    let mut req = Request::new(SetOwnerPublicKeyRequest {
        org_id: org_id.to_string(),
        owner_pubkey: Some(NazgulMasterPublicKey {
            value: owner.public().compress().to_bytes().to_vec(),
        }),
    });
    req.extensions_mut().insert(tenant);
    services
        .organization
        .set_owner_public_key(req)
        .await
        .expect("set owner public key");
}
use crate::crypto::ciphertext::Ciphertext;
use crate::crypto::signature::{sign_contextual, SignatureKind, StorageMode};
use crate::event::{
    AnonymousMessage, Event, EventType, Poll, PollQuestion, PollQuestionKind, Vote, VoteSelection,
};
use crate::hashing::ring_hash;
use crate::ids::{EventId, EventUlid, Ulid};
use crate::key_manager::manager::{derive_poll_signing_ring, MandateDerivable};
use nazgul::keypair::KeyPair;
use nazgul::ring::Ring;
use rand::rngs::OsRng;
use tonic::Code;

fn make_signing_ring(size: usize) -> (KeyPair, Ring) {
    let mut csprng = OsRng;
    let signer = KeyPair::generate(&mut csprng);
    let mut members: Vec<_> = (0..size - 1)
        .map(|_| *KeyPair::generate(&mut csprng).public())
        .collect();
    members.push(*signer.public());
    (signer, Ring::new(members))
}

pub(super) fn sign_event_archival(event: &mut Event, signer: &KeyPair, ring: &Ring) {
    let signing_bytes = event.to_signing_bytes().expect("signing bytes");
    let signature = sign_contextual(
        SignatureKind::Anonymous,
        StorageMode::Archival,
        signer,
        ring,
        &signing_bytes,
    )
    .expect("sign archival event");
    event.signature = Some(signature);
}

fn sign_event_compact(event: &mut Event, signer: &KeyPair, ring: &Ring) {
    let signing_bytes = event.to_signing_bytes().expect("signing bytes");
    let signature = sign_contextual(
        SignatureKind::Anonymous,
        StorageMode::Compact,
        signer,
        ring,
        &signing_bytes,
    )
    .expect("sign compact event");
    event.signature = Some(signature);
}

pub(super) fn make_push_event_request(
    tenant: TenantId,
    event: &Event,
) -> Request<PushEventRequest> {
    let event_bytes = serde_json::to_vec(event).expect("serialize");
    let mut req = Request::new(PushEventRequest {
        event_bytes,
        pow_submission: None,
    });
    req.extensions_mut().insert(tenant);
    req
}

#[tokio::test]
async fn push_event_rejects_oversized_event_bytes() {
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());

    let mut req = Request::new(PushEventRequest {
        event_bytes: vec![0u8; max_event_bytes() + 1],
        pow_submission: None,
    });
    req.extensions_mut().insert(tenant);

    let err = services.event.push_event(req).await.expect_err("reject");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn upload_key_blobs_rejects_oversized_blob() {
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = ulid::Ulid::new().to_string();

    let mut req = Request::new(UploadKeyBlobsRequest {
        org_id,
        blobs: vec![KeyBlob {
            rage_pub: Some(RagePublicKey {
                value: vec![7u8; 32],
            }),
            blob: vec![0u8; keyblobs_max_blob_bytes() + 1],
        }],
    });
    req.extensions_mut().insert(tenant);

    let err = services
        .storage
        .upload_key_blobs(req)
        .await
        .expect_err("reject");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn upload_key_blobs_rejects_too_many_entries() {
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = ulid::Ulid::new().to_string();

    let blobs = (0..(keyblobs_max_count() + 1))
        .map(|_| KeyBlob {
            rage_pub: Some(RagePublicKey {
                value: vec![7u8; 32],
            }),
            blob: vec![0u8; 1],
        })
        .collect();

    let mut req = Request::new(UploadKeyBlobsRequest { org_id, blobs });
    req.extensions_mut().insert(tenant);

    let err = services
        .storage
        .upload_key_blobs(req)
        .await
        .expect_err("reject");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn push_event_rejects_oversized_poll_id() {
    use crate::crypto::ciphertext::Ciphertext;
    use crate::event::{Event, EventType, Poll, PollQuestion, PollQuestionKind};
    use crate::ids::{EventId, EventUlid, RingHash, Ulid};

    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;

    // Create a poll event with an oversized poll_id
    let oversized_poll_id = "x".repeat(max_poll_id_length() + 1);
    let poll = Poll {
        org_id,
        ring_hash: RingHash([0u8; 32]),
        poll_id: oversized_poll_id,
        questions: vec![PollQuestion {
            question_id: "q1".into(),
            title: Ciphertext(b"test".to_vec()),
            kind: PollQuestionKind::FillInTheBlank,
        }],
        created_at: 123,
        instructions: None,
        deadline: None,
        sealed_duration_secs: None,
        verification_window_secs: None,
    };

    let event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id: poll.org_id,
        sequence_no: None,
        processed_at: 123,
        serialization_version: 1,
        event_type: EventType::PollCreate(poll),
        signature: None,
    };

    let event_bytes = serde_json::to_vec(&event).expect("serialize");
    let mut req = Request::new(PushEventRequest {
        event_bytes,
        pow_submission: None,
    });
    req.extensions_mut().insert(tenant);

    let err = services.event.push_event(req).await.expect_err("reject");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("poll_id"));
}

#[tokio::test]
async fn push_event_rejects_oversized_message_content() {
    use crate::crypto::ciphertext::Ciphertext;
    use crate::event::{AnonymousMessage, Event, EventType};
    use crate::ids::{EventId, EventUlid, RingHash, Ulid};

    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;

    // Create a message event with oversized content (in UTF-8 characters)
    let oversized_content = "x".repeat(max_message_content_chars() + 1);
    let message = AnonymousMessage {
        org_id,
        ring_hash: RingHash([0u8; 32]),
        message_id: Ulid::new().to_string(),
        content: Ciphertext(oversized_content.into_bytes()),
        sent_at: 123,
    };

    let event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 123,
        serialization_version: 1,
        event_type: EventType::MessageCreate(message),
        signature: None,
    };

    let event_bytes = serde_json::to_vec(&event).expect("serialize");
    let mut req = Request::new(PushEventRequest {
        event_bytes,
        pow_submission: None,
    });
    req.extensions_mut().insert(tenant);

    let err = services.event.push_event(req).await.expect_err("reject");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("message_content"));
}

// --- TB-B-001: VoteCast must be bound to the ring snapshot at poll creation ---

#[tokio::test]
async fn push_event_rejects_vote_when_poll_ring_hash_mismatches() {
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;

    let mut csprng = OsRng;
    let owner = KeyPair::generate(&mut csprng);
    let extra = KeyPair::generate(&mut csprng);
    let ring_at_poll = Ring::new(vec![*owner.public()]);
    let ring_after = Ring::new(vec![*owner.public(), *extra.public()]);
    let ring_hash_at_poll = ring_hash(&ring_at_poll);
    let ring_hash_after = ring_hash(&ring_after);

    // Create poll with original ring
    let poll = Poll {
        org_id,
        ring_hash: ring_hash_at_poll,
        poll_id: "poll-ring-binding-reject".into(),
        questions: vec![PollQuestion {
            question_id: "q1".into(),
            title: Ciphertext(b"question".to_vec()),
            kind: PollQuestionKind::FillInTheBlank,
        }],
        created_at: 1,
        instructions: None,
        deadline: None,
        sealed_duration_secs: None,
        verification_window_secs: None,
    };
    let poll_hash = poll.hash().expect("poll hash");

    let mut poll_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 1,
        serialization_version: 1,
        event_type: EventType::PollCreate(poll.clone()),
        signature: None,
    };
    sign_event_archival(&mut poll_event, &owner, &ring_at_poll);
    services
        .event
        .push_event(make_push_event_request(tenant, &poll_event))
        .await
        .expect("poll accepted");

    // Vote claims a DIFFERENT ring hash than what the poll was created with
    let vote = Vote {
        org_id,
        ring_hash: ring_hash_after,
        poll_id: poll.poll_id.clone(),
        poll_hash,
        poll_ring_hash: ring_hash_after, // mismatch: poll was created with ring_hash_at_poll
        selections: vec![VoteSelection {
            question_id: "q1".into(),
            option_ids: vec![],
            write_in: None,
        }],
    };

    let mut vote_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 2,
        serialization_version: 1,
        event_type: EventType::VoteCast(vote),
        signature: None,
    };
    sign_event_archival(&mut vote_event, &owner, &ring_after);

    let err = services
        .event
        .push_event(make_push_event_request(tenant, &vote_event))
        .await
        .expect_err("vote must be rejected");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err
        .message()
        .contains("vote.poll_ring_hash does not match poll snapshot"));
}

#[tokio::test]
async fn push_event_accepts_vote_when_ring_matches_poll_snapshot() {
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;

    let mut csprng = OsRng;
    let owner = KeyPair::generate(&mut csprng);
    set_test_owner_key(&services, tenant, org_id, &owner).await;
    let ring = Ring::new(vec![*owner.public()]);
    let member_ring_hash = ring_hash(&ring);

    let poll = Poll {
        org_id,
        ring_hash: member_ring_hash,
        poll_id: "poll-ring-binding-accept".into(),
        questions: vec![PollQuestion {
            question_id: "q1".into(),
            title: Ciphertext(b"question".to_vec()),
            kind: PollQuestionKind::FillInTheBlank,
        }],
        created_at: 1,
        instructions: None,
        deadline: None,
        sealed_duration_secs: None,
        verification_window_secs: None,
    };
    let poll_hash = poll.hash().expect("poll hash");

    let mut poll_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 1,
        serialization_version: 1,
        event_type: EventType::PollCreate(poll.clone()),
        signature: None,
    };
    sign_event_archival(&mut poll_event, &owner, &ring);
    services
        .event
        .push_event(make_push_event_request(tenant, &poll_event))
        .await
        .expect("poll accepted");

    let vote_signing_ring =
        derive_poll_signing_ring(&org_id, &member_ring_hash, &poll.poll_id, &ring);
    let vote_signing_ring_hash = ring_hash(&vote_signing_ring);
    let vote_signer = owner.derive_poll_signing(&org_id, &member_ring_hash, &poll.poll_id);

    let vote = Vote {
        org_id,
        ring_hash: vote_signing_ring_hash,
        poll_id: poll.poll_id.clone(),
        poll_hash,
        poll_ring_hash: member_ring_hash, // matches poll creation ring
        selections: vec![VoteSelection {
            question_id: "q1".into(),
            option_ids: vec![],
            write_in: None,
        }],
    };

    let mut vote_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 2,
        serialization_version: 1,
        event_type: EventType::VoteCast(vote),
        signature: None,
    };
    sign_event_archival(
        &mut vote_event,
        vote_signer.as_keypair(),
        &vote_signing_ring,
    );

    services
        .event
        .push_event(make_push_event_request(tenant, &vote_event))
        .await
        .expect("vote accepted");
}

#[tokio::test]
async fn push_event_rejects_vote_signed_with_master_ring_instead_of_poll_ring() {
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;

    let mut csprng = OsRng;
    let owner = KeyPair::generate(&mut csprng);
    set_test_owner_key(&services, tenant, org_id, &owner).await;
    let ring = Ring::new(vec![*owner.public()]);
    let member_ring_hash = ring_hash(&ring);

    let poll = Poll {
        org_id,
        ring_hash: member_ring_hash,
        poll_id: "poll-reject-master-signing".into(),
        questions: vec![PollQuestion {
            question_id: "q1".into(),
            title: Ciphertext(b"question".to_vec()),
            kind: PollQuestionKind::FillInTheBlank,
        }],
        created_at: 1,
        instructions: None,
        deadline: None,
        sealed_duration_secs: None,
        verification_window_secs: None,
    };
    let poll_hash = poll.hash().expect("poll hash");

    let mut poll_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 1,
        serialization_version: 1,
        event_type: EventType::PollCreate(poll.clone()),
        signature: None,
    };
    sign_event_archival(&mut poll_event, &owner, &ring);
    services
        .event
        .push_event(make_push_event_request(tenant, &poll_event))
        .await
        .expect("poll accepted");

    // Legacy/master-ring signing path: should now be rejected.
    let vote = Vote {
        org_id,
        ring_hash: member_ring_hash,
        poll_id: poll.poll_id.clone(),
        poll_hash,
        poll_ring_hash: member_ring_hash,
        selections: vec![VoteSelection {
            question_id: "q1".into(),
            option_ids: vec![],
            write_in: None,
        }],
    };

    let mut vote_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 2,
        serialization_version: 1,
        event_type: EventType::VoteCast(vote),
        signature: None,
    };
    sign_event_archival(&mut vote_event, &owner, &ring);

    let err = services
        .event
        .push_event(make_push_event_request(tenant, &vote_event))
        .await
        .expect_err("legacy vote must be rejected");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err
        .message()
        .contains("vote.ring_hash does not match derived per-poll signing ring"));
}

#[tokio::test]
async fn push_event_accepts_compact_vote_when_ring_matches_poll_snapshot() {
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;

    let mut csprng = OsRng;
    let owner = KeyPair::generate(&mut csprng);
    set_test_owner_key(&services, tenant, org_id, &owner).await;
    let ring = Ring::new(vec![*owner.public()]);
    let member_ring_hash = ring_hash(&ring);

    let poll = Poll {
        org_id,
        ring_hash: member_ring_hash,
        poll_id: "poll-compact-accept".into(),
        questions: vec![PollQuestion {
            question_id: "q1".into(),
            title: Ciphertext(b"question".to_vec()),
            kind: PollQuestionKind::FillInTheBlank,
        }],
        created_at: 1,
        instructions: None,
        deadline: None,
        sealed_duration_secs: None,
        verification_window_secs: None,
    };
    let poll_hash = poll.hash().expect("poll hash");

    let mut poll_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 1,
        serialization_version: 1,
        event_type: EventType::PollCreate(poll.clone()),
        signature: None,
    };
    sign_event_archival(&mut poll_event, &owner, &ring);
    services
        .event
        .push_event(make_push_event_request(tenant, &poll_event))
        .await
        .expect("poll accepted");

    let vote_signing_ring =
        derive_poll_signing_ring(&org_id, &member_ring_hash, &poll.poll_id, &ring);
    let vote_signing_ring_hash = ring_hash(&vote_signing_ring);
    let vote_signer = owner.derive_poll_signing(&org_id, &member_ring_hash, &poll.poll_id);

    let vote = Vote {
        org_id,
        ring_hash: vote_signing_ring_hash,
        poll_id: poll.poll_id.clone(),
        poll_hash,
        poll_ring_hash: member_ring_hash,
        selections: vec![VoteSelection {
            question_id: "q1".into(),
            option_ids: vec![],
            write_in: None,
        }],
    };

    let mut vote_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 2,
        serialization_version: 1,
        event_type: EventType::VoteCast(vote),
        signature: None,
    };
    sign_event_compact(
        &mut vote_event,
        vote_signer.as_keypair(),
        &vote_signing_ring,
    );

    services
        .event
        .push_event(make_push_event_request(tenant, &vote_event))
        .await
        .expect("compact vote accepted");
}

#[tokio::test]
async fn push_event_rejects_compact_vote_signed_with_master_ring() {
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;

    let mut csprng = OsRng;
    let owner = KeyPair::generate(&mut csprng);
    set_test_owner_key(&services, tenant, org_id, &owner).await;
    let ring = Ring::new(vec![*owner.public()]);
    let ring_hash = ring_hash(&ring);

    let poll = Poll {
        org_id,
        ring_hash,
        poll_id: "poll-compact-reject-master".into(),
        questions: vec![PollQuestion {
            question_id: "q1".into(),
            title: Ciphertext(b"question".to_vec()),
            kind: PollQuestionKind::FillInTheBlank,
        }],
        created_at: 1,
        instructions: None,
        deadline: None,
        sealed_duration_secs: None,
        verification_window_secs: None,
    };
    let poll_hash = poll.hash().expect("poll hash");

    let mut poll_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 1,
        serialization_version: 1,
        event_type: EventType::PollCreate(poll.clone()),
        signature: None,
    };
    sign_event_archival(&mut poll_event, &owner, &ring);
    services
        .event
        .push_event(make_push_event_request(tenant, &poll_event))
        .await
        .expect("poll accepted");

    let vote = Vote {
        org_id,
        ring_hash,
        poll_id: poll.poll_id.clone(),
        poll_hash,
        poll_ring_hash: ring_hash,
        selections: vec![VoteSelection {
            question_id: "q1".into(),
            option_ids: vec![],
            write_in: None,
        }],
    };

    let mut vote_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 2,
        serialization_version: 1,
        event_type: EventType::VoteCast(vote),
        signature: None,
    };
    sign_event_compact(&mut vote_event, &owner, &ring);

    let err = services
        .event
        .push_event(make_push_event_request(tenant, &vote_event))
        .await
        .expect_err("legacy compact vote must be rejected");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err
        .message()
        .contains("vote.ring_hash does not match derived per-poll signing ring"));
}

// --- TB-B-003: Archival ring_hash consistency ---

#[tokio::test]
async fn push_event_rejects_archival_signature_ring_hash_mismatch() {
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;

    let (signer, signing_ring) = make_signing_ring(4);
    // Declare a ring_hash that doesn't match the actual signing ring
    let mut declared_ring_hash = ring_hash(&signing_ring);
    declared_ring_hash.0[0] ^= 0x01;

    let mut event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 123,
        serialization_version: 1,
        event_type: EventType::MessageCreate(AnonymousMessage {
            org_id,
            ring_hash: declared_ring_hash,
            message_id: Ulid::new().to_string(),
            content: Ciphertext(b"hello".to_vec()),
            sent_at: 123,
        }),
        signature: None,
    };
    sign_event_archival(&mut event, &signer, &signing_ring);

    let err = services
        .event
        .push_event(make_push_event_request(tenant, &event))
        .await
        .expect_err("reject mismatched archival ring hash");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("ring_hash"));
}

#[tokio::test]
async fn push_event_accepts_archival_signature_when_ring_hash_matches() {
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;

    let (signer, signing_ring) = make_signing_ring(4);
    let declared_ring_hash = ring_hash(&signing_ring);

    let mut event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 123,
        serialization_version: 1,
        event_type: EventType::MessageCreate(AnonymousMessage {
            org_id,
            ring_hash: declared_ring_hash,
            message_id: Ulid::new().to_string(),
            content: Ciphertext(b"hello".to_vec()),
            sent_at: 123,
        }),
        signature: None,
    };
    sign_event_archival(&mut event, &signer, &signing_ring);

    let resp = services
        .event
        .push_event(make_push_event_request(tenant, &event))
        .await
        .expect("accept");
    assert!(resp.into_inner().event_ulid.is_some());
}

#[test]
fn to_status_not_found_does_not_leak_internal_ids() {
    use crate::ids::{OrganizationId, TenantId, Ulid};
    use crate::storage::{NotFound, StorageError};

    let status = to_status(StorageError::NotFound(NotFound::KeyBlob {
        tenant: TenantId(Ulid::new()),
        org_id: OrganizationId(Ulid::new()),
        rage_pub: [7u8; 32],
    }));

    assert_eq!(status.code(), Code::NotFound);
    assert!(status.message().contains("key_blob not found"));
    assert!(!status.message().contains("TenantId"));
    assert!(!status.message().contains("OrganizationId"));
    assert!(!status.message().contains("rage_pub"));
}
