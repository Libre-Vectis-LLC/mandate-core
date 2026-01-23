use std::sync::Arc;

use super::StorageFacade;
use crate::ids::{GroupId, KeyImage, RingHash, TenantId};
use crate::ring_log::RingDelta;
use crate::storage::{BannedOperation, RingDeltaPath, StorageError};
use nazgul::ring::Ring;

impl StorageFacade {
    // ─────────────────────────────────────────────────────────────────────────
    // Ring methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Get a ring by its hash.
    pub async fn ring_by_hash(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        hash: &RingHash,
    ) -> Result<Arc<Ring>, StorageError> {
        self.ring_view.ring_by_hash(tenant, group_id, hash).await
    }

    /// Get the current ring for a group.
    pub async fn current_ring(
        &self,
        tenant: TenantId,
        group_id: GroupId,
    ) -> Result<Arc<Ring>, StorageError> {
        self.ring_view.current_ring(tenant, group_id).await
    }

    /// Get the delta path between two ring hashes.
    pub async fn ring_delta_path(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        from: Option<RingHash>,
        to: RingHash,
    ) -> Result<RingDeltaPath, StorageError> {
        self.ring_view
            .ring_delta_path(tenant, group_id, from, to)
            .await
    }

    /// Append a ring delta to the ring log.
    pub async fn append_ring_delta(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        delta: RingDelta,
    ) -> Result<RingHash, StorageError> {
        self.ring_writer.append_delta(tenant, group_id, delta).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ban index methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Check if a key image is banned for a specific operation.
    pub async fn is_banned(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        key_image: &KeyImage,
        operation: BannedOperation,
    ) -> Result<bool, StorageError> {
        self.ban_index
            .is_banned(tenant, group_id, key_image, operation)
            .await
    }

    /// Count the number of bans for a specific ring hash.
    ///
    /// Used for OOM protection to limit the number of bans per ring state.
    pub async fn count_bans_for_ring(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        ring_hash: &RingHash,
    ) -> Result<usize, StorageError> {
        self.ban_index
            .count_bans_for_ring(tenant, group_id, ring_hash)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Vote key image methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Check if a vote key image has been used for a poll.
    pub async fn is_vote_key_image_used(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
        key_image: &KeyImage,
    ) -> Result<bool, StorageError> {
        self.vote_key_images
            .is_used(tenant, group_id, poll_id, key_image)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Poll ring hash methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Store the ring hash for a newly created poll.
    ///
    /// This should be called when processing a `PollCreate` event to record
    /// the ring that was in effect at poll creation time.
    pub async fn store_poll_ring_hash(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
        ring_hash: RingHash,
    ) -> Result<(), StorageError> {
        self.poll_ring_hashes
            .store(tenant, group_id, poll_id, ring_hash)
            .await
    }

    /// Retrieve the ring hash for a poll.
    ///
    /// This is used during vote verification to get the ring against which
    /// the vote's ring signature must be verified.
    pub async fn get_poll_ring_hash(
        &self,
        tenant: TenantId,
        group_id: GroupId,
        poll_id: &str,
    ) -> Result<RingHash, StorageError> {
        self.poll_ring_hashes.get(tenant, group_id, poll_id).await
    }
}
