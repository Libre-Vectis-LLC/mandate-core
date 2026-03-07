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
async fn create_test_org(services: &CoreServices, tenant: TenantId) -> OrganizationId {
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

async fn set_test_owner_key(
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
use crate::hashing::ring_hash_sha3_256;
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

fn sign_event_archival(event: &mut Event, signer: &KeyPair, ring: &Ring) {
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

fn make_push_event_request(tenant: TenantId, event: &Event) -> Request<PushEventRequest> {
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
    let ring_hash_at_poll = ring_hash_sha3_256(&ring_at_poll);
    let ring_hash_after = ring_hash_sha3_256(&ring_after);

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
    let ring_hash = ring_hash_sha3_256(&ring);

    let poll = Poll {
        org_id,
        ring_hash,
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

    let vote_signing_ring = derive_poll_signing_ring(&org_id, &ring_hash, &poll.poll_id, &ring);
    let vote_signing_ring_hash = ring_hash_sha3_256(&vote_signing_ring);
    let vote_signer = owner.derive_poll_signing(&org_id, &ring_hash, &poll.poll_id);

    let vote = Vote {
        org_id,
        ring_hash: vote_signing_ring_hash,
        poll_id: poll.poll_id.clone(),
        poll_hash,
        poll_ring_hash: ring_hash, // matches poll creation ring
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
    let ring_hash = ring_hash_sha3_256(&ring);

    let poll = Poll {
        org_id,
        ring_hash,
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
    let ring_hash = ring_hash_sha3_256(&ring);

    let poll = Poll {
        org_id,
        ring_hash,
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

    let vote_signing_ring = derive_poll_signing_ring(&org_id, &ring_hash, &poll.poll_id, &ring);
    let vote_signing_ring_hash = ring_hash_sha3_256(&vote_signing_ring);
    let vote_signer = owner.derive_poll_signing(&org_id, &ring_hash, &poll.poll_id);

    let vote = Vote {
        org_id,
        ring_hash: vote_signing_ring_hash,
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
    let ring_hash = ring_hash_sha3_256(&ring);

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
    let mut declared_ring_hash = ring_hash_sha3_256(&signing_ring);
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
    let declared_ring_hash = ring_hash_sha3_256(&signing_ring);

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

// --- P6.1: Vote Revocation Protocol integration tests ---

/// Helper to sign an event with the owner's delegate key (for admin events like
/// PollBundlePublished, BanCreate, RingUpdate, etc.).
fn sign_event_delegate_archival(event: &mut Event, owner: &KeyPair, org_id: &OrganizationId) {
    let delegate = owner.derive_delegate(org_id);
    let delegate_ring = Ring::new(vec![*delegate.public()]);
    sign_event_archival(event, delegate.as_keypair(), &delegate_ring);
}

/// Helper struct holding the common test state for vote revocation tests.
struct VoteRevocationTestSetup {
    services: CoreServices,
    tenant: TenantId,
    org_id: OrganizationId,
    owner: KeyPair,
    _ring: Ring,
    ring_hash: crate::ids::RingHash,
    poll_id: String,
    vote_signing_ring: Ring,
    vote_signing_ring_hash: crate::ids::RingHash,
    vote_signer: crate::key_manager::manager::SessionNazgulKeyPair,
}

impl VoteRevocationTestSetup {
    /// Create a poll with a deadline and verification window, cast a vote, and
    /// return the fully-initialized test state.
    async fn new(poll_id: &str, deadline: Option<u64>, verification_window: Option<u64>) -> Self {
        let services = CoreServices::new_in_memory().expect("in-memory services");
        let tenant = TenantId(ulid::Ulid::new());
        let org_id = create_test_org(&services, tenant).await;

        let mut csprng = OsRng;
        let owner = KeyPair::generate(&mut csprng);
        set_test_owner_key(&services, tenant, org_id, &owner).await;
        let ring = Ring::new(vec![*owner.public()]);
        let ring_hash = ring_hash_sha3_256(&ring);

        let poll = Poll {
            org_id,
            ring_hash,
            poll_id: poll_id.into(),
            questions: vec![PollQuestion {
                question_id: "q1".into(),
                title: Ciphertext(b"test question".to_vec()),
                kind: PollQuestionKind::FillInTheBlank,
            }],
            created_at: 1,
            instructions: None,
            deadline,
            sealed_duration_secs: Some(60),
            verification_window_secs: verification_window,
        };

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

        let vote_signing_ring = derive_poll_signing_ring(&org_id, &ring_hash, poll_id, &ring);
        let vote_signing_ring_hash = ring_hash_sha3_256(&vote_signing_ring);
        let vote_signer = owner.derive_poll_signing(&org_id, &ring_hash, poll_id);

        Self {
            services,
            tenant,
            org_id,
            owner,
            _ring: ring,
            ring_hash,
            poll_id: poll_id.into(),
            vote_signing_ring,
            vote_signing_ring_hash,
            vote_signer,
        }
    }

    /// Cast a vote on the poll and return the event.
    async fn cast_vote(&self) -> Event {
        let poll_hash = Poll {
            org_id: self.org_id,
            ring_hash: self.ring_hash,
            poll_id: self.poll_id.clone(),
            questions: vec![PollQuestion {
                question_id: "q1".into(),
                title: Ciphertext(b"test question".to_vec()),
                kind: PollQuestionKind::FillInTheBlank,
            }],
            created_at: 1,
            instructions: None,
            deadline: None, // Not used for hash
            sealed_duration_secs: None,
            verification_window_secs: None,
        }
        .hash()
        .expect("poll hash");

        let vote = Vote {
            org_id: self.org_id,
            ring_hash: self.vote_signing_ring_hash,
            poll_id: self.poll_id.clone(),
            poll_hash,
            poll_ring_hash: self.ring_hash,
            selections: vec![VoteSelection {
                question_id: "q1".into(),
                option_ids: vec![],
                write_in: None,
            }],
        };

        let mut vote_event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id: self.org_id,
            sequence_no: None,
            processed_at: 2,
            serialization_version: 1,
            event_type: EventType::VoteCast(vote),
            signature: None,
        };
        sign_event_archival(
            &mut vote_event,
            self.vote_signer.as_keypair(),
            &self.vote_signing_ring,
        );

        self.services
            .event
            .push_event(make_push_event_request(self.tenant, &vote_event))
            .await
            .expect("vote accepted");

        vote_event
    }

    /// Push a PollBundlePublished event (delegate-signed).
    async fn publish_bundle(&self) {
        use crate::event::PollBundlePublished;
        let bundle_published = PollBundlePublished {
            org_id: self.org_id,
            poll_id: self.poll_id.clone(),
            bundle_hash: crate::ids::ContentHash([0xAB; 32]),
        };
        let mut bundle_event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id: self.org_id,
            sequence_no: None,
            processed_at: 3,
            serialization_version: 1,
            event_type: EventType::PollBundlePublished(bundle_published),
            signature: None,
        };
        sign_event_delegate_archival(&mut bundle_event, &self.owner, &self.org_id);
        self.services
            .event
            .push_event(make_push_event_request(self.tenant, &bundle_event))
            .await
            .expect("bundle published accepted");
    }

    /// Create a VoteRevocation event (signed with the per-poll signing ring).
    fn make_vote_revocation_event(&self) -> Event {
        use crate::event::VoteRevocation;
        let vr = VoteRevocation {
            org_id: self.org_id,
            ring_hash: self.vote_signing_ring_hash,
            poll_id: self.poll_id.clone(),
            vote_event_hash: None,
            reason: None,
        };
        let mut revocation_event = Event {
            event_ulid: EventUlid(Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id: self.org_id,
            sequence_no: None,
            processed_at: 4,
            serialization_version: 1,
            event_type: EventType::VoteRevocation(vr),
            signature: None,
        };
        sign_event_archival(
            &mut revocation_event,
            self.vote_signer.as_keypair(),
            &self.vote_signing_ring,
        );
        revocation_event
    }
}

/// Scenario 1: Normal election lifecycle.
///
/// Create poll with deadline → cast vote → publish bundle → revoke vote during
/// VerificationOpen → verify revocation accepted.
#[tokio::test]
async fn vote_revocation_accepted_during_verification_open() {
    let setup = VoteRevocationTestSetup::new(
        "poll-revocation-lifecycle",
        Some(1000),  // deadline in the past (epoch)
        Some(86400), // 24h verification window
    )
    .await;

    // Cast a vote
    setup.cast_vote().await;

    // Publish bundle (transitions to VerificationOpen)
    setup.publish_bundle().await;

    // Submit VoteRevocation (should be accepted during VerificationOpen)
    let revocation_event = setup.make_vote_revocation_event();
    let resp = setup
        .services
        .event
        .push_event(make_push_event_request(setup.tenant, &revocation_event))
        .await
        .expect("vote revocation accepted during VerificationOpen");
    assert!(resp.into_inner().event_ulid.is_some());
}

/// Scenario 2: VoteRevocation rejected outside VerificationOpen.
///
/// Before bundle is published, the poll is in Sealed phase (or Voting if
/// before deadline). VoteRevocation should be rejected.
#[tokio::test]
async fn vote_revocation_rejected_before_bundle_published() {
    let setup = VoteRevocationTestSetup::new(
        "poll-revocation-reject-phase",
        Some(1000),  // deadline
        Some(86400), // verification window
    )
    .await;

    // Cast a vote
    setup.cast_vote().await;

    // Do NOT publish bundle — poll is in Sealed phase

    // Submit VoteRevocation — should be rejected
    let revocation_event = setup.make_vote_revocation_event();
    let err = setup
        .services
        .event
        .push_event(make_push_event_request(setup.tenant, &revocation_event))
        .await
        .expect_err("vote revocation must be rejected before bundle published");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err
        .message()
        .contains("poll bundle has not been published yet"));
}

/// Scenario 3: KeyImage mismatch rejection.
///
/// A VoteRevocation with a different key image (i.e., from a different member
/// who never voted) should be rejected because no matching vote exists.
///
/// Uses a 2-member ring so that member2 has a valid key in the per-poll signing
/// ring but never cast a vote.
#[tokio::test]
async fn vote_revocation_rejected_key_image_mismatch() {
    use crate::event::{
        MemberIdentity, PollBundlePublished, RingOperation, RingUpdate, VoteRevocation,
    };
    use crate::ids::MasterPublicKey;

    let mut csprng = OsRng;
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;
    let owner = KeyPair::generate(&mut csprng);
    let member2 = KeyPair::generate(&mut csprng);
    set_test_owner_key(&services, tenant, org_id, &owner).await;

    // After set_test_owner_key, ring has 1 member (owner). Add member2 via RingUpdate.
    let owner_only_ring = Ring::new(vec![*owner.public()]);
    let owner_only_ring_hash = ring_hash_sha3_256(&owner_only_ring);
    let member2_mpk = MasterPublicKey(member2.public().compress().to_bytes());

    let ring_update = RingUpdate {
        org_id,
        ring_hash: owner_only_ring_hash,
        operations: vec![RingOperation::AddMember {
            public_key: member2_mpk,
            identity: MemberIdentity::standalone("member2", None),
        }],
    };
    let mut ring_update_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 1,
        serialization_version: 1,
        event_type: EventType::RingUpdate(ring_update),
        signature: None,
    };
    sign_event_delegate_archival(&mut ring_update_event, &owner, &org_id);
    services
        .event
        .push_event(make_push_event_request(tenant, &ring_update_event))
        .await
        .expect("ring update accepted");

    // Now the ring has 2 members: owner + member2
    let ring = Ring::new(vec![*owner.public(), *member2.public()]);
    let ring_hash = ring_hash_sha3_256(&ring);
    let poll_id = "poll-ki-mismatch-2member";

    // Create poll
    let poll = Poll {
        org_id,
        ring_hash,
        poll_id: poll_id.into(),
        questions: vec![PollQuestion {
            question_id: "q1".into(),
            title: Ciphertext(b"test".to_vec()),
            kind: PollQuestionKind::FillInTheBlank,
        }],
        created_at: 1,
        instructions: None,
        deadline: Some(1000),
        sealed_duration_secs: Some(60),
        verification_window_secs: Some(86400),
    };
    let poll_hash = poll.hash().expect("hash");

    let mut poll_event = Event {
        event_ulid: EventUlid(Ulid::new()),
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

    let vote_signing_ring = derive_poll_signing_ring(&org_id, &ring_hash, poll_id, &ring);
    let vote_signing_ring_hash = ring_hash_sha3_256(&vote_signing_ring);

    // Cast vote with owner's per-poll key (only owner votes)
    let owner_vote_signer = owner.derive_poll_signing(&org_id, &ring_hash, poll_id);
    let vote = Vote {
        org_id,
        ring_hash: vote_signing_ring_hash,
        poll_id: poll_id.into(),
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
        processed_at: 3,
        serialization_version: 1,
        event_type: EventType::VoteCast(vote),
        signature: None,
    };
    sign_event_archival(
        &mut vote_event,
        owner_vote_signer.as_keypair(),
        &vote_signing_ring,
    );
    services
        .event
        .push_event(make_push_event_request(tenant, &vote_event))
        .await
        .expect("vote accepted");

    // Publish bundle
    let pb = PollBundlePublished {
        org_id,
        poll_id: poll_id.into(),
        bundle_hash: crate::ids::ContentHash([0xAB; 32]),
    };
    let mut pb_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 4,
        serialization_version: 1,
        event_type: EventType::PollBundlePublished(pb),
        signature: None,
    };
    sign_event_delegate_archival(&mut pb_event, &owner, &org_id);
    services
        .event
        .push_event(make_push_event_request(tenant, &pb_event))
        .await
        .expect("bundle published");

    // VoteRevocation with member2's per-poll key (member2 never voted)
    let member2_vote_signer = member2.derive_poll_signing(&org_id, &ring_hash, poll_id);
    let vr = VoteRevocation {
        org_id,
        ring_hash: vote_signing_ring_hash,
        poll_id: poll_id.into(),
        vote_event_hash: None,
        reason: None,
    };
    let mut revocation_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 5,
        serialization_version: 1,
        event_type: EventType::VoteRevocation(vr),
        signature: None,
    };
    sign_event_archival(
        &mut revocation_event,
        member2_vote_signer.as_keypair(),
        &vote_signing_ring,
    );

    let err = services
        .event
        .push_event(make_push_event_request(tenant, &revocation_event))
        .await
        .expect_err("revocation must be rejected: no matching vote for this key image");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("no vote found for this key image"));
}

/// Scenario 4: Duplicate revocation rejection.
///
/// After a successful revocation, a second revocation with the same key image
/// should be rejected.
#[tokio::test]
async fn vote_revocation_duplicate_rejected() {
    let setup =
        VoteRevocationTestSetup::new("poll-revocation-duplicate", Some(1000), Some(86400)).await;

    setup.cast_vote().await;
    setup.publish_bundle().await;

    // First revocation: accepted
    let revocation_event = setup.make_vote_revocation_event();
    setup
        .services
        .event
        .push_event(make_push_event_request(setup.tenant, &revocation_event))
        .await
        .expect("first revocation accepted");

    // Second revocation: rejected (duplicate)
    let revocation_event2 = setup.make_vote_revocation_event();
    let err = setup
        .services
        .event
        .push_event(make_push_event_request(setup.tenant, &revocation_event2))
        .await
        .expect_err("duplicate revocation must be rejected");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("vote has already been revoked"));
}

/// Scenario 5: Zero revocations backward compatibility.
///
/// A poll without deadline (legacy) works normally — votes are accepted,
/// no revocations are possible, and it remains in the Voting phase.
#[tokio::test]
async fn legacy_poll_without_deadline_backward_compatible() {
    let setup = VoteRevocationTestSetup::new(
        "poll-legacy-no-deadline",
        None,        // no deadline → always Voting
        Some(86400), // verification_window (irrelevant without deadline)
    )
    .await;

    // Cast a vote — should succeed normally
    let vote_event = setup.cast_vote().await;
    assert!(vote_event.signature.is_some());

    // VoteRevocation should be rejected because bundle is never published
    // (no deadline means the poll never enters Sealed, so no bundle publication)
    let revocation_event = setup.make_vote_revocation_event();
    let err = setup
        .services
        .event
        .push_event(make_push_event_request(setup.tenant, &revocation_event))
        .await
        .expect_err("revocation rejected for legacy poll");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err
        .message()
        .contains("poll bundle has not been published yet"));
}

/// PollBundlePublished is rejected when poll doesn't exist.
#[tokio::test]
async fn poll_bundle_published_rejected_for_nonexistent_poll() {
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;

    let mut csprng = OsRng;
    let owner = KeyPair::generate(&mut csprng);
    set_test_owner_key(&services, tenant, org_id, &owner).await;

    use crate::event::PollBundlePublished;
    let pb = PollBundlePublished {
        org_id,
        poll_id: "nonexistent-poll".into(),
        bundle_hash: crate::ids::ContentHash([0xAB; 32]),
    };
    let mut pb_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at: 1,
        serialization_version: 1,
        event_type: EventType::PollBundlePublished(pb),
        signature: None,
    };
    sign_event_delegate_archival(&mut pb_event, &owner, &org_id);

    let err = services
        .event
        .push_event(make_push_event_request(tenant, &pb_event))
        .await
        .expect_err("bundle published rejected for nonexistent poll");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("poll does not exist"));
}

/// PollBundlePublished duplicate is rejected.
#[tokio::test]
async fn poll_bundle_published_duplicate_rejected() {
    let setup = VoteRevocationTestSetup::new("poll-bundle-dup", Some(1000), Some(86400)).await;

    // Publish bundle first time: accepted
    setup.publish_bundle().await;

    // Publish bundle second time: rejected
    use crate::event::PollBundlePublished;
    let pb = PollBundlePublished {
        org_id: setup.org_id,
        poll_id: setup.poll_id.clone(),
        bundle_hash: crate::ids::ContentHash([0xCD; 32]),
    };
    let mut pb_event = Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id: setup.org_id,
        sequence_no: None,
        processed_at: 5,
        serialization_version: 1,
        event_type: EventType::PollBundlePublished(pb),
        signature: None,
    };
    sign_event_delegate_archival(&mut pb_event, &setup.owner, &setup.org_id);

    let err = setup
        .services
        .event
        .push_event(make_push_event_request(setup.tenant, &pb_event))
        .await
        .expect_err("duplicate bundle publication rejected");
    assert_eq!(err.code(), Code::FailedPrecondition);
    assert!(err.message().contains("bundle"));
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
