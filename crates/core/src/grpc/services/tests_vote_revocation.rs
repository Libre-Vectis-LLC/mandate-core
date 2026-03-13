//! P6.1: Vote Revocation Protocol integration tests.
//!
//! Extracted from `tests.rs` to keep individual test modules under 800 lines.

use super::tests::{
    create_test_org, make_push_event_request, set_test_owner_key, sign_event_archival,
};
use crate::crypto::ciphertext::Ciphertext;
use crate::event::{Event, EventType, Poll, PollQuestion, PollQuestionKind, Vote, VoteSelection};
use crate::hashing::ring_hash;
use crate::ids::{EventId, EventUlid, OrganizationId, TenantId, Ulid};
use crate::key_manager::manager::{derive_poll_signing_ring, MandateDerivable};
use mandate_proto::mandate::v1::event_service_server::EventService;
use nazgul::keypair::KeyPair;
use nazgul::ring::Ring;
use rand::rngs::OsRng;
use tonic::Code;

use crate::grpc::wiring::CoreServices;

/// Build an unsigned Event with common test defaults.
pub(super) fn test_event(
    org_id: OrganizationId,
    event_type: EventType,
    processed_at: u64,
) -> Event {
    Event {
        event_ulid: EventUlid(Ulid::new()),
        previous_event_hash: EventId([0u8; 32]),
        org_id,
        sequence_no: None,
        processed_at,
        serialization_version: 1,
        event_type,
        signature: None,
    }
}

/// Sign an event with the owner's delegate key (for admin events).
pub(super) fn sign_event_delegate_archival(
    event: &mut Event,
    owner: &KeyPair,
    org_id: &OrganizationId,
) {
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
        let member_ring_hash = ring_hash(&ring);

        let poll = Poll {
            org_id,
            ring_hash: member_ring_hash,
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

        let mut poll_event = test_event(org_id, EventType::PollCreate(poll.clone()), 1);
        sign_event_archival(&mut poll_event, &owner, &ring);
        services
            .event
            .push_event(make_push_event_request(tenant, &poll_event))
            .await
            .expect("poll accepted");

        let vote_signing_ring =
            derive_poll_signing_ring(&org_id, &member_ring_hash, poll_id, &ring);
        let vote_signing_ring_hash = ring_hash(&vote_signing_ring);
        let vote_signer = owner.derive_poll_signing(&org_id, &member_ring_hash, poll_id);

        Self {
            services,
            tenant,
            org_id,
            owner,
            _ring: ring,
            ring_hash: member_ring_hash,
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

        let mut vote_event = test_event(self.org_id, EventType::VoteCast(vote), 2);
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
        let mut bundle_event = test_event(
            self.org_id,
            EventType::PollBundlePublished(PollBundlePublished {
                org_id: self.org_id,
                poll_id: self.poll_id.clone(),
                bundle_hash: crate::ids::ContentHash([0xAB; 32]),
            }),
            3,
        );
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
        let mut revocation_event = test_event(
            self.org_id,
            EventType::VoteRevocation(VoteRevocation {
                org_id: self.org_id,
                ring_hash: self.vote_signing_ring_hash,
                poll_id: self.poll_id.clone(),
                vote_event_hash: None,
                reason: None,
            }),
            4,
        );
        sign_event_archival(
            &mut revocation_event,
            self.vote_signer.as_keypair(),
            &self.vote_signing_ring,
        );
        revocation_event
    }
}

/// Helper: set up a 2-member org (owner + member2) with RingUpdate already applied.
/// Returns (services, tenant, org_id, owner, member2, ring, ring_hash).
pub(super) async fn setup_two_member_org() -> (
    CoreServices,
    TenantId,
    OrganizationId,
    KeyPair,
    KeyPair,
    Ring,
    crate::ids::RingHash,
) {
    use crate::event::{MemberIdentity, RingOperation, RingUpdate};
    use crate::ids::MasterPublicKey;

    let mut csprng = OsRng;
    let services = CoreServices::new_in_memory().expect("in-memory services");
    let tenant = TenantId(ulid::Ulid::new());
    let org_id = create_test_org(&services, tenant).await;
    let owner = KeyPair::generate(&mut csprng);
    let member2 = KeyPair::generate(&mut csprng);
    set_test_owner_key(&services, tenant, org_id, &owner).await;

    let owner_only_ring = Ring::new(vec![*owner.public()]);
    let owner_only_ring_hash = ring_hash(&owner_only_ring);
    let member2_mpk = MasterPublicKey(member2.public().compress().to_bytes());

    let mut ring_update_event = test_event(
        org_id,
        EventType::RingUpdate(RingUpdate {
            org_id,
            ring_hash: owner_only_ring_hash,
            operations: vec![RingOperation::AddMember {
                public_key: member2_mpk,
                identity: MemberIdentity::standalone("member2", None),
            }],
        }),
        1,
    );
    sign_event_delegate_archival(&mut ring_update_event, &owner, &org_id);
    services
        .event
        .push_event(make_push_event_request(tenant, &ring_update_event))
        .await
        .expect("ring update accepted");

    let ring = Ring::new(vec![*owner.public(), *member2.public()]);
    let member_ring_hash = ring_hash(&ring);
    (
        services,
        tenant,
        org_id,
        owner,
        member2,
        ring,
        member_ring_hash,
    )
}

/// Helper: push a PollBundlePublished event.
pub(super) async fn push_bundle(
    svc: &CoreServices,
    t: TenantId,
    org: OrganizationId,
    o: &KeyPair,
    pid: &str,
    ts: u64,
) {
    let mut ev = test_event(
        org,
        EventType::PollBundlePublished(crate::event::PollBundlePublished {
            org_id: org,
            poll_id: pid.into(),
            bundle_hash: crate::ids::ContentHash([0xAB; 32]),
        }),
        ts,
    );
    sign_event_delegate_archival(&mut ev, o, &org);
    svc.event
        .push_event(make_push_event_request(t, &ev))
        .await
        .expect("bundle published");
}

/// Helper: push a signed vote event.
pub(super) struct VotePushRequest<'a> {
    pub(super) services: &'a CoreServices,
    pub(super) tenant: TenantId,
    pub(super) org_id: OrganizationId,
    pub(super) poll_id: &'a str,
    pub(super) poll_hash: crate::ids::ContentHash,
    pub(super) poll_ring_hash: crate::ids::RingHash,
    pub(super) vote_ring_hash: crate::ids::RingHash,
    pub(super) signer: &'a crate::key_manager::manager::SessionNazgulKeyPair,
    pub(super) vote_signing_ring: &'a Ring,
    pub(super) option_ids: Vec<String>,
    pub(super) processed_at: u64,
}

pub(super) async fn push_vote(request: VotePushRequest<'_>) {
    let VotePushRequest {
        services,
        tenant,
        org_id,
        poll_id,
        poll_hash,
        poll_ring_hash,
        vote_ring_hash,
        signer,
        vote_signing_ring,
        option_ids,
        processed_at,
    } = request;

    let mut ev = test_event(
        org_id,
        EventType::VoteCast(Vote {
            org_id,
            ring_hash: vote_ring_hash,
            poll_id: poll_id.into(),
            poll_hash,
            poll_ring_hash,
            selections: vec![VoteSelection {
                question_id: "q1".into(),
                option_ids,
                write_in: None,
            }],
        }),
        processed_at,
    );
    sign_event_archival(&mut ev, signer.as_keypair(), vote_signing_ring);
    services
        .event
        .push_event(make_push_event_request(tenant, &ev))
        .await
        .expect("vote accepted");
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

    setup.cast_vote().await;

    // Do NOT publish bundle -- poll is in Sealed phase
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
#[tokio::test]
async fn vote_revocation_rejected_key_image_mismatch() {
    use crate::event::VoteRevocation;

    let (services, tenant, org_id, owner, member2, ring, member_ring_hash) =
        setup_two_member_org().await;
    let poll_id = "poll-ki-mismatch-2member";

    // Create poll
    let poll = Poll {
        org_id,
        ring_hash: member_ring_hash,
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

    let mut poll_event = test_event(org_id, EventType::PollCreate(poll), 2);
    sign_event_archival(&mut poll_event, &owner, &ring);
    services
        .event
        .push_event(make_push_event_request(tenant, &poll_event))
        .await
        .expect("poll accepted");

    let vote_signing_ring = derive_poll_signing_ring(&org_id, &member_ring_hash, poll_id, &ring);
    let vote_signing_ring_hash = ring_hash(&vote_signing_ring);

    // Cast vote with owner's per-poll key (only owner votes)
    let owner_vote_signer = owner.derive_poll_signing(&org_id, &member_ring_hash, poll_id);
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
        option_ids: vec![],
        processed_at: 3,
    })
    .await;

    push_bundle(&services, tenant, org_id, &owner, poll_id, 4).await;

    // VoteRevocation with member2's per-poll key (member2 never voted)
    let member2_vote_signer = member2.derive_poll_signing(&org_id, &member_ring_hash, poll_id);
    let mut revocation_event = test_event(
        org_id,
        EventType::VoteRevocation(VoteRevocation {
            org_id,
            ring_hash: vote_signing_ring_hash,
            poll_id: poll_id.into(),
            vote_event_hash: None,
            reason: None,
        }),
        5,
    );
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

    let vote_event = setup.cast_vote().await;
    assert!(vote_event.signature.is_some());

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

    let mut pb_event = test_event(
        org_id,
        EventType::PollBundlePublished(crate::event::PollBundlePublished {
            org_id,
            poll_id: "nonexistent-poll".into(),
            bundle_hash: crate::ids::ContentHash([0xAB; 32]),
        }),
        1,
    );
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

    setup.publish_bundle().await;

    use crate::event::PollBundlePublished;
    let pb = PollBundlePublished {
        org_id: setup.org_id,
        poll_id: setup.poll_id.clone(),
        bundle_hash: crate::ids::ContentHash([0xCD; 32]),
    };
    let mut pb_event = test_event(setup.org_id, EventType::PollBundlePublished(pb), 5);
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
