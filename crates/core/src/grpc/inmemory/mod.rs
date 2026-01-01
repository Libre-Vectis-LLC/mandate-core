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
/// - `billing`: Tenant/group balance tracking and gift cards
/// - `member`: Pending member queue
/// - `key_blob`: Encrypted key blob storage
/// - `group`: Group metadata
/// - `ban`: Ban index for moderation
/// - `vote`: Vote key image deduplication
/// - `poll`: Poll ring hash index
pub mod ban;
pub mod billing;
pub mod event;
pub mod group;
pub mod key_blob;
pub mod member;
pub mod poll;
pub mod ring;
pub mod tenant;
pub mod vote;

// Re-export all public types for backward compatibility
pub use ban::{InMemoryBanIndex, NoopBanIndex};
pub use billing::{InMemoryBilling, InMemoryGiftCards};
pub use event::InMemoryEvents;
pub use group::InMemoryGroups;
pub use key_blob::InMemoryKeyBlobs;
pub use member::InMemoryPendingMembers;
pub use poll::{InMemoryPollRingHashes, NoopPollRingHashes};
pub use ring::InMemoryRings;
pub use tenant::InMemoryTenantTokens;
pub use vote::{InMemoryVoteKeyImages, NoopVoteKeyImages};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Event, EventType, RingOperation, RingUpdate};
    use crate::hashing::ring_hash_sha3_256;
    use crate::ids::{EventId, EventUlid, GroupId, MasterPublicKey, Nanos, RingHash, TenantId};
    use crate::key_manager::KeyManager;
    use crate::storage::{
        BanIndex, BannedOperation, BillingStore, EventWriter, GroupMetadataStore,
        PendingMemberStore, RingView, RingWriter, VoteKeyImageIndex,
    };
    use crate::test_utils::TEST_MNEMONIC;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use nazgul::traits::{Derivable, LocalByteConvertible};
    use sha3::Sha3_512;
    use std::sync::Arc;

    fn mpk(label: &[u8]) -> MasterPublicKey {
        let km = KeyManager::from_mnemonic(TEST_MNEMONIC, None).expect("valid test mnemonic");
        let master = km.derive_nazgul_master_keypair();
        let child = master.0.derive_child::<Sha3_512>(label);
        MasterPublicKey(child.public().to_bytes())
    }

    #[tokio::test]
    async fn ring_writer_roundtrip() {
        let rings = InMemoryRings::new();
        let tenant = TenantId(ulid::Ulid::new());
        let group = GroupId(ulid::Ulid::new());

        let h1 = rings
            .append_delta(tenant, group, crate::ring_log::RingDelta::Add(mpk(b"a")))
            .await
            .expect("append should succeed");
        let ring = rings
            .current_ring(tenant, group)
            .await
            .expect("ring exists");
        assert_eq!(ring_hash_sha3_256(&ring), h1);

        // Path from scratch to current should contain founder delta.
        let path = rings
            .ring_delta_path(tenant, group, None, h1)
            .await
            .expect("delta path should exist");
        assert_eq!(path.deltas.len(), 1);
        assert_eq!(path.to, h1);
    }

    #[tokio::test]
    async fn pending_members_only_list_pending_after_ring_add() {
        let tenant = TenantId(ulid::Ulid::new());
        let group = GroupId(ulid::Ulid::new());
        let pending = Arc::new(InMemoryPendingMembers::new());
        let events = InMemoryEvents::new(
            Arc::new(InMemoryBanIndex::new()),
            Arc::new(InMemoryVoteKeyImages::new()),
            pending.clone(),
        );

        let member_key = MasterPublicKey([0x11; 32]);
        pending
            .submit(tenant, group, "tg-user", member_key, [0x22; 32])
            .await
            .expect("pending submit");

        let event = Event {
            event_ulid: EventUlid(ulid::Ulid::new()),
            previous_event_hash: EventId([0u8; 32]),
            group_id: group,
            sequence_no: None,
            processed_at: 0,
            serialization_version: 1,
            event_type: EventType::RingUpdate(RingUpdate {
                group_id: group,
                ring_hash: RingHash([7u8; 32]),
                operations: vec![RingOperation::AddMember {
                    public_key: member_key,
                }],
            }),
            signature: None,
        };

        events
            .append(
                tenant,
                group,
                serde_json::to_vec(&event).expect("serialize").into(),
            )
            .await
            .expect("append event");

        let (members, _) = pending
            .list(tenant, group, 10, None)
            .await
            .expect("list pending");
        assert!(members.is_empty());
    }

    #[tokio::test]
    async fn rings_are_scoped_by_group() {
        let rings = InMemoryRings::new();
        let tenant = TenantId(ulid::Ulid::new());
        let g1 = GroupId(ulid::Ulid::new());
        let g2 = GroupId(ulid::Ulid::new());

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
                group_id,
                hash
            }) if t == tenant && group_id == g2 && hash == h
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
        let group = GroupId(ulid::Ulid::new());
        let key_image = RistrettoPoint::default();
        let ban_event_id = EventId([42u8; 32]);

        ban_index
            .record_ban(
                tenant,
                group,
                key_image.clone(),
                crate::event::BanScope::BanVote,
                ban_event_id,
            )
            .expect("ban recorded");

        let banned_vote = ban_index
            .is_banned(tenant, group, &key_image, BannedOperation::CastVote)
            .await
            .expect("ban check");
        assert!(banned_vote);

        let banned_post = ban_index
            .is_banned(tenant, group, &key_image, BannedOperation::PostMessage)
            .await
            .expect("ban check");
        assert!(!banned_post);

        ban_index.revoke_ban(ban_event_id).expect("ban revoked");

        let banned_after = ban_index
            .is_banned(tenant, group, &key_image, BannedOperation::CastVote)
            .await
            .expect("ban check");
        assert!(!banned_after);
    }

    #[tokio::test]
    async fn vote_key_images_block_duplicates() {
        let vote_index = InMemoryVoteKeyImages::new();
        let tenant = TenantId(ulid::Ulid::new());
        let group = GroupId(ulid::Ulid::new());
        let key_image = RistrettoPoint::default();
        let poll_id = "poll-1";

        let used = vote_index
            .is_used(tenant, group, poll_id, &key_image)
            .await
            .expect("check");
        assert!(!used);

        vote_index
            .record_vote(tenant, group, poll_id, key_image.clone())
            .expect("record vote");

        let used = vote_index
            .is_used(tenant, group, poll_id, &key_image)
            .await
            .expect("check");
        assert!(used);

        let err = vote_index
            .record_vote(tenant, group, poll_id, key_image)
            .expect_err("duplicate vote");
        assert!(matches!(
            err,
            crate::storage::StorageError::PreconditionFailed(_)
        ));
    }

    #[tokio::test]
    async fn billing_transfer_updates_group_balance() {
        let tenant = TenantId(ulid::Ulid::new());
        let groups = InMemoryGroups::new();
        let group_id = groups
            .create_group(tenant, "tg-group")
            .await
            .expect("group created");
        let billing = InMemoryBilling::new(groups.shared());

        let balance = billing
            .credit_tenant(tenant, "tg-user", Nanos::new(100))
            .await
            .expect("tenant credited");
        assert_eq!(balance, Nanos::new(100));

        let group_balance = billing
            .transfer_to_group(tenant, group_id, Nanos::new(60))
            .await
            .expect("transfer succeeds");
        assert_eq!(group_balance, Nanos::new(60));

        let group_balance = billing
            .get_group_balance(group_id)
            .await
            .expect("balance query succeeds");
        assert_eq!(group_balance, Nanos::new(60));
    }

    #[tokio::test]
    async fn billing_rejects_overdraft() {
        let tenant = TenantId(ulid::Ulid::new());
        let groups = InMemoryGroups::new();
        let group_id = groups
            .create_group(tenant, "tg-group")
            .await
            .expect("group created");
        let billing = InMemoryBilling::new(groups.shared());

        billing
            .credit_tenant(tenant, "tg-user", Nanos::new(40))
            .await
            .expect("tenant credited");

        let err = billing
            .transfer_to_group(tenant, group_id, Nanos::new(60))
            .await
            .expect_err("overdraft rejected");

        assert!(matches!(
            err,
            crate::storage::StorageError::PreconditionFailed(_)
        ));
    }
}
