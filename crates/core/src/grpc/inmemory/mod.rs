/// In-memory storage implementations for all domain modules.
///
/// This module provides pluggable in-memory backends for development,
/// testing, and the Community Edition reference server.
///
/// # Architecture
///
/// Each submodule implements storage traits for a specific domain:
/// - `tenant`: Tenant token resolution
/// - `event`: Event streaming and append-only log
/// - `ring`: Ring delta log and reconstruction
/// - `billing`: Tenant/organization balance tracking and gift cards
/// - `member`: Pending member queue
/// - `key_blob`: Encrypted key blob storage
/// - `organization`: Organization metadata
/// - `ban`: Ban index for moderation
/// - `vote`: Vote key image deduplication
/// - `poll`: Poll ring hash index
pub mod ban;
pub mod billing;
pub mod bundle_published;
pub mod event;
pub mod invite_code;
pub mod key_blob;
pub mod member;
pub mod organization;
pub mod poll;
pub mod ring;
pub mod tenant;
pub mod vote;
pub mod vote_revocation;

// Re-export all public types for backward compatibility
pub use ban::{InMemoryBanIndex, NoopBanIndex};
pub use billing::{InMemoryBilling, InMemoryGiftCards};
pub use bundle_published::InMemoryBundlePublished;
pub use event::InMemoryEvents;
pub use invite_code::InMemoryInviteCodeStore;
pub use key_blob::InMemoryKeyBlobs;
pub use member::InMemoryPendingMembers;
pub use organization::InMemoryOrgs;
pub use poll::{InMemoryPollRingHashes, NoopPollRingHashes};
pub use ring::InMemoryRings;
pub use tenant::InMemoryTenantTokens;
pub use vote::{InMemoryVoteKeyImages, NoopVoteKeyImages};
pub use vote_revocation::InMemoryVoteRevocations;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventType, MemberIdentity, RingOperation, RingUpdate};
    use crate::hashing::ring_hash;
    use crate::hashing::Blake3_512;
    use crate::ids::{
        EventId, EventUlid, MasterPublicKey, Nanos, OrganizationId, RingHash, TenantId,
    };
    use crate::key_manager::KeyManager;
    use crate::storage::{
        BanIndex, BannedOperation, BillingStore, EventWriter, OrganizationMetadataStore,
        PendingMemberStore, RingView, RingWriter, VoteKeyImageIndex,
    };
    use crate::test_utils::TEST_MNEMONIC;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::Scalar;
    use nazgul::traits::{Derivable, LocalByteConvertible};
    use std::sync::Arc;

    fn mpk(label: &[u8]) -> MasterPublicKey {
        let km = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid test mnemonic");
        let master = km.derive_nazgul_master_keypair();
        let child = master.0.derive_child::<Blake3_512>(label);
        MasterPublicKey(child.public().to_bytes())
    }

    #[tokio::test]
    async fn ring_writer_roundtrip() {
        let rings = InMemoryRings::new();
        let tenant = TenantId(ulid::Ulid::new());
        let org = OrganizationId(ulid::Ulid::new());

        let h1 = rings
            .append_delta(tenant, org, crate::ring_log::RingDelta::Add(mpk(b"a")))
            .await
            .expect("append should succeed");
        let ring = rings.current_ring(tenant, org).await.expect("ring exists");
        assert_eq!(ring_hash(&ring), h1);

        // Path from scratch to current should contain founder delta.
        let path = rings
            .ring_delta_path(tenant, org, None, h1)
            .await
            .expect("delta path should exist");
        assert_eq!(path.deltas.len(), 1);
        assert_eq!(path.to, h1);
    }

    #[tokio::test]
    async fn pending_members_only_list_pending_after_ring_add() {
        let tenant = TenantId(ulid::Ulid::new());
        let org = OrganizationId(ulid::Ulid::new());
        let pending = Arc::new(InMemoryPendingMembers::new());
        let events = InMemoryEvents::new(
            Arc::new(InMemoryBanIndex::new()),
            Arc::new(InMemoryVoteKeyImages::new()),
            pending.clone(),
        );

        let member_key = MasterPublicKey([0x11; 32]);
        pending
            .submit(tenant, org, "tg-user", member_key, [0x22; 32])
            .await
            .expect("pending submit");

        let event = Event {
            event_ulid: EventUlid(ulid::Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            org_id: org,
            sequence_no: None,
            processed_at: 0,
            serialization_version: 1,
            event_type: EventType::RingUpdate(RingUpdate {
                org_id: org,
                ring_hash: RingHash([7u8; 32]),
                operations: vec![RingOperation::AddMember {
                    public_key: member_key,
                    identity: MemberIdentity::telegram("tg-user", None),
                }],
            }),
            signature: None,
        };

        events
            .append(
                tenant,
                org,
                serde_json::to_vec(&event).expect("serialize").into(),
            )
            .await
            .expect("append event");

        let (members, _) = pending
            .list(tenant, org, 10, None)
            .await
            .expect("list pending");
        assert!(members.is_empty());
    }

    #[tokio::test]
    async fn rings_are_scoped_by_org() {
        let rings = InMemoryRings::new();
        let tenant = TenantId(ulid::Ulid::new());
        let g1 = OrganizationId(ulid::Ulid::new());
        let g2 = OrganizationId(ulid::Ulid::new());

        let h = rings
            .append_delta(tenant, g1, crate::ring_log::RingDelta::Add(mpk(b"a")))
            .await
            .expect("append should succeed");

        rings
            .ring_by_hash(tenant, g1, &h)
            .await
            .expect("ring exists for g1");

        let err = rings
            .ring_by_hash(tenant, g2, &h)
            .await
            .expect_err("g2 must not see g1 ring state");
        assert!(matches!(
            err,
            crate::storage::StorageError::NotFound(crate::storage::NotFound::Ring {
                tenant: t,
                org_id,
                hash
            }) if t == tenant && org_id == g2 && hash == h
        ));

        let h2 = rings
            .append_delta(tenant, g2, crate::ring_log::RingDelta::Add(mpk(b"a")))
            .await
            .expect("append should succeed");
        assert_eq!(
            h2, h,
            "ring hashes match when membership sets are identical"
        );
        rings
            .ring_by_hash(tenant, g2, &h)
            .await
            .expect("ring exists for g2 after append");
    }

    #[tokio::test]
    async fn ban_index_respects_scope_and_revoke() {
        let ban_index = InMemoryBanIndex::new();
        let tenant = TenantId(ulid::Ulid::new());
        let org = OrganizationId(ulid::Ulid::new());
        let key_image = RistrettoPoint::default();
        let ban_event_id = EventId([42u8; 32]);

        // Create a dummy ring hash for testing
        let ring_hash = RingHash([0u8; 32]);
        ban_index
            .record_ban(
                tenant,
                org,
                key_image,
                crate::event::BanScope::BanVote,
                ban_event_id,
                ring_hash,
            )
            .expect("ban recorded");

        let banned_vote = ban_index
            .is_banned(tenant, org, &key_image, BannedOperation::CastVote)
            .await
            .expect("ban check");
        assert!(banned_vote);

        let banned_post = ban_index
            .is_banned(tenant, org, &key_image, BannedOperation::PostMessage)
            .await
            .expect("ban check");
        assert!(!banned_post);

        ban_index.revoke_ban(ban_event_id).expect("ban revoked");

        let banned_after = ban_index
            .is_banned(tenant, org, &key_image, BannedOperation::CastVote)
            .await
            .expect("ban check");
        assert!(!banned_after);
    }

    #[tokio::test]
    async fn vote_key_images_block_duplicates() {
        let vote_index = InMemoryVoteKeyImages::new();
        let tenant = TenantId(ulid::Ulid::new());
        let org = OrganizationId(ulid::Ulid::new());
        let key_image = RistrettoPoint::default();
        let poll_id = "poll-1";

        let used = vote_index
            .is_used(tenant, org, poll_id, &key_image)
            .await
            .expect("check");
        assert!(!used);

        vote_index
            .record_vote(tenant, org, poll_id, key_image)
            .expect("record vote");

        let used = vote_index
            .is_used(tenant, org, poll_id, &key_image)
            .await
            .expect("check");
        assert!(used);

        let err = vote_index
            .record_vote(tenant, org, poll_id, key_image)
            .expect_err("duplicate vote");
        assert!(matches!(
            err,
            crate::storage::StorageError::PreconditionFailed(_)
        ));
    }

    #[tokio::test]
    async fn billing_transfer_updates_org_balance() {
        let tenant = TenantId(ulid::Ulid::new());
        let orgs = InMemoryOrgs::new();
        let org_id = orgs
            .create_organization(tenant, "tg-group")
            .await
            .expect("org created");
        let billing = InMemoryBilling::new(orgs.shared());

        let balance = billing
            .credit_tenant(tenant, "tg-user", Nanos::new(100))
            .await
            .expect("tenant credited");
        assert_eq!(balance, Nanos::new(100));

        let org_balance = billing
            .transfer_to_organization(tenant, org_id, Nanos::new(60))
            .await
            .expect("transfer succeeds");
        assert_eq!(org_balance, Nanos::new(60));

        let org_balance = billing
            .get_organization_balance(org_id)
            .await
            .expect("balance query succeeds");
        assert_eq!(org_balance, Nanos::new(60));
    }

    #[tokio::test]
    async fn billing_rejects_overdraft() {
        let tenant = TenantId(ulid::Ulid::new());
        let orgs = InMemoryOrgs::new();
        let org_id = orgs
            .create_organization(tenant, "tg-group")
            .await
            .expect("org created");
        let billing = InMemoryBilling::new(orgs.shared());

        billing
            .credit_tenant(tenant, "tg-user", Nanos::new(40))
            .await
            .expect("tenant credited");

        let err = billing
            .transfer_to_organization(tenant, org_id, Nanos::new(60))
            .await
            .expect_err("overdraft rejected");

        assert!(matches!(
            err,
            crate::storage::StorageError::PreconditionFailed(_)
        ));
    }

    #[tokio::test]
    async fn billing_idempotency_keys_are_tenant_scoped() {
        let tenant_a = TenantId(ulid::Ulid::new());
        let tenant_b = TenantId(ulid::Ulid::new());
        let orgs = InMemoryOrgs::new();
        let org_a = orgs
            .create_organization(tenant_a, "tg-org-a")
            .await
            .expect("org A created");
        let org_b = orgs
            .create_organization(tenant_b, "tg-org-b")
            .await
            .expect("org B created");
        let billing = InMemoryBilling::new(orgs.shared());

        billing
            .credit_tenant(tenant_a, "tg-user-a", Nanos::new(200))
            .await
            .expect("tenant A credited");
        billing
            .credit_tenant(tenant_b, "tg-user-b", Nanos::new(200))
            .await
            .expect("tenant B credited");

        let shared_key = "same-idempotency-key";
        let first = billing
            .transfer_to_organization_idempotent(
                tenant_a,
                org_a,
                Nanos::new(70),
                Some(shared_key),
                60,
            )
            .await
            .expect("tenant A transfer");
        let second = billing
            .transfer_to_organization_idempotent(
                tenant_b,
                org_b,
                Nanos::new(30),
                Some(shared_key),
                60,
            )
            .await
            .expect("tenant B transfer");

        assert_eq!(
            first,
            crate::storage::IdempotencyResult::Success { balance_nanos: 70 }
        );
        assert_eq!(
            second,
            crate::storage::IdempotencyResult::Success { balance_nanos: 30 }
        );
        assert_eq!(
            billing
                .get_organization_balance(org_a)
                .await
                .expect("org A balance"),
            Nanos::new(70)
        );
        assert_eq!(
            billing
                .get_organization_balance(org_b)
                .await
                .expect("org B balance"),
            Nanos::new(30)
        );
    }

    #[tokio::test]
    async fn ban_index_counts_bans_per_ring_hash() {
        let ban_index = InMemoryBanIndex::new();
        let tenant = TenantId(ulid::Ulid::new());
        let org = OrganizationId(ulid::Ulid::new());

        let ring_hash_a = RingHash([1u8; 32]);
        let ring_hash_b = RingHash([2u8; 32]);

        // Initially, count should be 0
        let count_a = ban_index
            .count_bans_for_ring(tenant, org, &ring_hash_a)
            .await
            .expect("count query");
        assert_eq!(count_a, 0, "should have 0 bans initially");

        // Add 3 bans for ring_hash_a
        for i in 0..3u8 {
            let key_image = RistrettoPoint::mul_base(&Scalar::from(i as u64));
            let event_id = EventId([i; 32]);
            ban_index
                .record_ban(
                    tenant,
                    org,
                    key_image,
                    crate::event::BanScope::BanAll,
                    event_id,
                    ring_hash_a,
                )
                .expect("ban recorded");
        }

        // Count should be 3 for ring_hash_a
        let count_a = ban_index
            .count_bans_for_ring(tenant, org, &ring_hash_a)
            .await
            .expect("count query");
        assert_eq!(count_a, 3, "should have 3 bans for ring_hash_a");

        // Count should be 0 for ring_hash_b (different ring)
        let count_b = ban_index
            .count_bans_for_ring(tenant, org, &ring_hash_b)
            .await
            .expect("count query");
        assert_eq!(count_b, 0, "should have 0 bans for ring_hash_b");

        // Add 1 ban for ring_hash_b
        let key_image_b = RistrettoPoint::mul_base(&Scalar::from(99u64));
        let event_id_b = EventId([99u8; 32]);
        ban_index
            .record_ban(
                tenant,
                org,
                key_image_b,
                crate::event::BanScope::BanPost,
                event_id_b,
                ring_hash_b,
            )
            .expect("ban recorded");

        // Verify counts are independent
        let count_a = ban_index
            .count_bans_for_ring(tenant, org, &ring_hash_a)
            .await
            .expect("count query");
        let count_b = ban_index
            .count_bans_for_ring(tenant, org, &ring_hash_b)
            .await
            .expect("count query");

        assert_eq!(count_a, 3, "ring_hash_a should still have 3 bans");
        assert_eq!(count_b, 1, "ring_hash_b should have 1 ban");
    }
}
