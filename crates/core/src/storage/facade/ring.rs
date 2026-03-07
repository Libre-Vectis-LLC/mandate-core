use std::sync::Arc;

use super::StorageFacade;
use crate::ids::{KeyImage, OrganizationId, RingHash, TenantId};
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
        org_id: OrganizationId,
        hash: &RingHash,
    ) -> Result<Arc<Ring>, StorageError> {
        self.ring_view.ring_by_hash(tenant, org_id, hash).await
    }

    /// Get the current ring for an org.
    pub async fn current_ring(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
    ) -> Result<Arc<Ring>, StorageError> {
        self.ring_view.current_ring(tenant, org_id).await
    }

    /// Get the delta path between two ring hashes.
    pub async fn ring_delta_path(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        from: Option<RingHash>,
        to: RingHash,
    ) -> Result<RingDeltaPath, StorageError> {
        self.ring_view
            .ring_delta_path(tenant, org_id, from, to)
            .await
    }

    /// Append a ring delta to the ring log.
    pub async fn append_ring_delta(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        delta: RingDelta,
    ) -> Result<RingHash, StorageError> {
        self.ring_writer.append_delta(tenant, org_id, delta).await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ban index methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Check if a key image is banned for a specific operation.
    pub async fn is_banned(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        key_image: &KeyImage,
        operation: BannedOperation,
    ) -> Result<bool, StorageError> {
        self.ban_index
            .is_banned(tenant, org_id, key_image, operation)
            .await
    }

    /// Count the number of bans for a specific ring hash.
    ///
    /// Used for OOM protection to limit the number of bans per ring state.
    pub async fn count_bans_for_ring(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        ring_hash: &RingHash,
    ) -> Result<usize, StorageError> {
        self.ban_index
            .count_bans_for_ring(tenant, org_id, ring_hash)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Vote key image methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Check if a vote key image has been used for a poll.
    pub async fn is_vote_key_image_used(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
        key_image: &KeyImage,
    ) -> Result<bool, StorageError> {
        self.vote_key_images
            .is_used(tenant, org_id, poll_id, key_image)
            .await
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Vote revocation methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Check if a vote has been revoked for a key image in a poll.
    ///
    /// Returns `Ok(false)` if the vote revocation index is not configured.
    pub async fn is_vote_revoked(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
        key_image: &KeyImage,
    ) -> Result<bool, StorageError> {
        match &self.vote_revocations {
            Some(index) => {
                index
                    .is_vote_revoked(tenant, org_id, poll_id, key_image)
                    .await
            }
            None => Ok(false),
        }
    }

    /// Record a vote revocation for a key image in a poll.
    ///
    /// Returns an error if the vote revocation index is not configured.
    pub async fn store_vote_revocation(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
        key_image: &KeyImage,
        revocation_event_id: &crate::ids::EventId,
    ) -> Result<(), StorageError> {
        match &self.vote_revocations {
            Some(index) => {
                index
                    .store_vote_revocation(tenant, org_id, poll_id, key_image, revocation_event_id)
                    .await
            }
            None => Err(StorageError::Backend(
                "vote revocation index not configured".into(),
            )),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bundle published methods
    // ─────────────────────────────────────────────────────────────────────────

    /// Get the timestamp when a poll bundle was published.
    ///
    /// Returns `Ok(None)` if the bundle published index is not configured
    /// or if no bundle has been published for this poll.
    pub async fn get_bundle_published_at(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
    ) -> Result<Option<u64>, StorageError> {
        match &self.bundle_published {
            Some(index) => index.get_bundle_published_at(tenant, org_id, poll_id).await,
            None => Ok(None),
        }
    }

    /// Store the timestamp when a poll bundle was published.
    ///
    /// Returns an error if the bundle published index is not configured.
    pub async fn store_bundle_published_at(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
        published_at: u64,
    ) -> Result<(), StorageError> {
        match &self.bundle_published {
            Some(index) => {
                index
                    .store_bundle_published_at(tenant, org_id, poll_id, published_at)
                    .await
            }
            None => Err(StorageError::Backend(
                "bundle published index not configured".into(),
            )),
        }
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
        org_id: OrganizationId,
        poll_id: &str,
        ring_hash: RingHash,
    ) -> Result<(), StorageError> {
        self.poll_ring_hashes
            .store(tenant, org_id, poll_id, ring_hash)
            .await
    }

    /// Retrieve the ring hash for a poll.
    ///
    /// This is used during vote verification to get the ring against which
    /// the vote's ring signature must be verified.
    pub async fn get_poll_ring_hash(
        &self,
        tenant: TenantId,
        org_id: OrganizationId,
        poll_id: &str,
    ) -> Result<RingHash, StorageError> {
        self.poll_ring_hashes.get(tenant, org_id, poll_id).await
    }
}
