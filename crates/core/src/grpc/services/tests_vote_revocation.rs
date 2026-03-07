//! P6.1: Vote Revocation Protocol integration tests.
//!
//! Extracted from `tests.rs` to keep individual test modules under 800 lines.

use super::tests::{
    create_test_org, make_push_event_request, set_test_owner_key, sign_event_archival,
};
use crate::crypto::ciphertext::Ciphertext;
use crate::event::{Event, EventType, Poll, PollQuestion, PollQuestionKind, Vote, VoteSelection};
use crate::hashing::ring_hash_sha3_256;
use crate::ids::{EventId, EventUlid, OrganizationId, TenantId, Ulid};
use crate::key_manager::manager::{derive_poll_signing_ring, MandateDerivable};
use mandate_proto::mandate::v1::event_service_server::EventService;
use nazgul::keypair::KeyPair;
use nazgul::ring::Ring;
use rand::rngs::OsRng;
use tonic::Code;

use crate::grpc::wiring::CoreServices;

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
/// Create poll with deadline -> cast vote -> publish bundle -> revoke vote during
/// VerificationOpen -> verify revocation accepted.
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

    // Do NOT publish bundle -- poll is in Sealed phase

    // Submit VoteRevocation -- should be rejected
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
/// A poll without deadline (legacy) works normally -- votes are accepted,
/// no revocations are possible, and it remains in the Voting phase.
#[tokio::test]
async fn legacy_poll_without_deadline_backward_compatible() {
    let setup = VoteRevocationTestSetup::new(
        "poll-legacy-no-deadline",
        None,        // no deadline -> always Voting
        Some(86400), // verification_window (irrelevant without deadline)
    )
    .await;

    // Cast a vote -- should succeed normally
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
